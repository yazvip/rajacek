use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    config::AppConfig,
    error::AppError,
    models::{AuthSessionResponse, GoogleCallbackQuery, LocalLoginRequest, SessionClaims},
};

const ADMIN_SESSION_COOKIE: &str = "rv_admin_session";
const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);
const SESSION_TTL_SECONDS: i64 = 8 * 60 * 60;
const DEVELOPMENT_SESSION_SECRET: &str =
    "rajacek-development-only-session-secret-change-before-sharing";
const LOCAL_ADMIN_EMAIL: &str = "bunny.admin@local.test";
const LOCAL_ADMIN_PASSWORD: &str = "BunnyAdmin!2026";
const LOCAL_MEMBER_EMAIL: &str = "dummy.member@local.test";
const LOCAL_MEMBER_PASSWORD: &str = "DummyMember!2026";

#[derive(Clone, Debug)]
pub struct AdminPrincipal {
    pub email: String,
    pub name: String,
    pub source: &'static str,
    /// JWT id for server-side revocation; empty for the dev-token principal
    /// (which carries no JWT and only exists outside production).
    pub jti: String,
}

/// Local-login brute-force throttle (per email, in-memory, prune-on-write).
const LOCAL_LOGIN_ATTEMPT_LIMIT: u32 = 10;
const LOCAL_LOGIN_ATTEMPT_WINDOW: Duration = Duration::from_secs(300);

fn local_login_attempt_table() -> &'static Mutex<HashMap<String, (u32, Instant)>> {
    static TABLE: OnceLock<Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn local_login_throttled(email: &str) -> bool {
    let Ok(table) = local_login_attempt_table().try_lock() else {
        return false;
    };
    matches!(table.get(email), Some((count, started))
        if started.elapsed() <= LOCAL_LOGIN_ATTEMPT_WINDOW && *count >= LOCAL_LOGIN_ATTEMPT_LIMIT)
}

fn record_local_login_failure(email: &str) {
    let Ok(mut table) = local_login_attempt_table().try_lock() else {
        return;
    };
    table.retain(|_, (_, started)| started.elapsed() <= LOCAL_LOGIN_ATTEMPT_WINDOW);
    let entry = table
        .entry(email.to_owned())
        .or_insert((0, Instant::now()));
    if entry.1.elapsed() > LOCAL_LOGIN_ATTEMPT_WINDOW {
        *entry = (0, Instant::now());
    }
    entry.0 += 1;
}

fn clear_local_login_failures(email: &str) {
    if let Ok(mut table) = local_login_attempt_table().try_lock() {
        table.remove(email);
    }
}

// ---------------------------------------------------------------------------
// OAuth start throttling (per client IP, in-memory; audit flow K18)
// ---------------------------------------------------------------------------
// Same shape as the login throttles: a light limit (30 starts / 5 min
// per IP) so a flood of unauthenticated starts cannot evict legitimate
// in-flight states from the 1000-entry cap. The cap + 10-minute TTL in
// OAuthStateStore::issue are unchanged. Lock contention fails open
// (returns allowed), matching the other throttles.

const OAUTH_START_LIMIT: u32 = 30;
const OAUTH_START_WINDOW: Duration = Duration::from_secs(300);

fn oauth_start_table() -> &'static std::sync::Mutex<HashMap<String, (u32, Instant)>> {
    static TABLE: OnceLock<std::sync::Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();
    TABLE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Record one OAuth start attempt for `ip`. Returns `true` when the
/// attempt is within the limit (and counts it); `false` when throttled
/// (the attempt is not counted further, so the count saturates at the
/// limit until the window rolls over).
pub(crate) fn oauth_start_allowed(ip: &str) -> bool {
    let Ok(mut table) = oauth_start_table().lock() else {
        return true;
    };
    table.retain(|_, (_, started)| started.elapsed() <= OAUTH_START_WINDOW);
    let entry = table.entry(ip.to_owned()).or_insert((0, Instant::now()));
    if entry.1.elapsed() > OAUTH_START_WINDOW {
        *entry = (0, Instant::now());
    }
    if entry.0 >= OAUTH_START_LIMIT {
        return false;
    }
    entry.0 += 1;
    true
}

/// Which sign-in flow an OAuth state belongs to. The callback for one flow
/// must never accept a state issued for the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OAuthPurpose {
    Admin,
    Member,
}

#[derive(Clone)]
struct PendingGoogleState {
    code_verifier: String,
    expires_at: Instant,
    purpose: OAuthPurpose,
}

/// Temporary server-side OAuth state holder. For multi-replica production deployment this
/// interface should be backed by Redis, while preserving the same single-use/expiry behavior.
pub struct OAuthStateStore {
    states: Mutex<HashMap<String, PendingGoogleState>>,
}

impl OAuthStateStore {
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }

    async fn issue(&self, purpose: OAuthPurpose) -> (String, String) {
        let state = secure_token(32);
        let verifier = secure_token(48);
        let mut states = self.states.lock().await;
        states.retain(|_, pending| pending.expires_at > Instant::now());
        // Bounded (audit 2026-10-25, A7): without a cap, the unauthenticated
        // start endpoint could grow this map without bound. Evicting the
        // earliest-expiring entry only costs the victim a login retry.
        if states.len() >= 1000 {
            if let Some(oldest) = states
                .iter()
                .min_by_key(|(_, pending)| pending.expires_at)
                .map(|(key, _)| key.clone())
            {
                states.remove(&oldest);
            }
        }
        states.insert(
            state.clone(),
            PendingGoogleState {
                code_verifier: verifier.clone(),
                expires_at: Instant::now() + OAUTH_STATE_TTL,
                purpose,
            },
        );
        (state, verifier)
    }

    async fn consume(&self, state: &str) -> Option<PendingGoogleState> {
        let mut states = self.states.lock().await;
        states.retain(|_, pending| pending.expires_at > Instant::now());
        states.remove(state)
    }
}

/// Build the Google authorize URL for either sign-in flow.
pub(crate) async fn google_authorize_redirect(
    config: &AppConfig,
    states: &OAuthStateStore,
    purpose: OAuthPurpose,
    redirect_uri: &str,
) -> Result<Redirect, AppError> {
    let (state, verifier) = states.issue(purpose).await;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
        .map_err(|_| AppError::internal("URL login Google tidak dapat disiapkan"))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair(
            "client_id",
            config.google_client_id.as_deref().unwrap_or_default(),
        );
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("response_type", "code");
        query.append_pair("scope", "openid email profile");
        query.append_pair("state", &state);
        query.append_pair("code_challenge", &challenge);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("prompt", "select_account");
    }
    Ok(Redirect::temporary(url.as_str()))
}

pub async fn google_login_start(
    config: Arc<AppConfig>,
    states: Arc<OAuthStateStore>,
) -> Result<Redirect, AppError> {
    if !config.google_login_is_configured() {
        return Err(AppError::service_unavailable(
            "Login Google belum dikonfigurasi. Lengkapi GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, DATABASE_URL, REDIS_URL, dan DASHBOARD_SESSION_SECRET.",
        ));
    }
    google_authorize_redirect(
        &config,
        &states,
        OAuthPurpose::Admin,
        config.google_redirect_uri.as_deref().unwrap_or_default(),
    )
    .await
}

/// Exchange an authorization code and load the verified Google profile.
/// Shared by the admin and member callbacks; allowlist/role decisions stay
/// with the callers. `purpose` is verified against the stored state so a
/// state issued for one flow cannot be redeemed at the other.
pub(crate) async fn fetch_google_user(
    config: &AppConfig,
    states: &OAuthStateStore,
    query: &GoogleCallbackQuery,
    purpose: OAuthPurpose,
    redirect_uri: &str,
) -> Result<GoogleUserInfo, AppError> {
    if let Some(error) = &query.error {
        tracing::warn!(error = %error, description = ?query.error_description, "Login Google ditolak");
        return Err(AppError::unauthorized(
            "Login Google dibatalkan atau ditolak",
        ));
    }
    let code = query
        .code
        .as_deref()
        .ok_or_else(|| AppError::bad_request("Kode login Google tidak ditemukan"))?;
    let state = query
        .state
        .as_deref()
        .ok_or_else(|| AppError::bad_request("State login Google tidak ditemukan"))?;
    let pending = states
        .consume(state)
        .await
        .ok_or_else(|| AppError::unauthorized("State login tidak valid atau sudah kedaluwarsa"))?;
    if pending.purpose != purpose {
        return Err(AppError::unauthorized(
            "State login tidak cocok dengan alur masuk ini",
        ));
    }

    let http = Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| AppError::internal("Klien login Google tidak dapat dibuat"))?;

    let token_response = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            (
                "client_id",
                config.google_client_id.as_deref().unwrap_or_default(),
            ),
            (
                "client_secret",
                config.google_client_secret.as_deref().unwrap_or_default(),
            ),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", pending.code_verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "Pertukaran kode Google gagal");
            AppError::service_unavailable("Google belum dapat memproses login. Coba kembali.")
        })?;

    if !token_response.status().is_success() {
        tracing::warn!(status = %token_response.status(), "Google token endpoint menolak permintaan");
        return Err(AppError::unauthorized(
            "Kode login Google tidak dapat diverifikasi",
        ));
    }

    let token = token_response
        .json::<GoogleTokenResponse>()
        .await
        .map_err(|_| AppError::unauthorized("Respons login Google tidak valid"))?;

    let user = http
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "Pengambilan profil Google gagal");
            AppError::service_unavailable("Profil Google belum dapat dibaca. Coba kembali.")
        })?;

    if !user.status().is_success() {
        return Err(AppError::unauthorized(
            "Profil Google tidak dapat diverifikasi",
        ));
    }

    let user = user
        .json::<GoogleUserInfo>()
        .await
        .map_err(|_| AppError::unauthorized("Profil Google tidak valid"))?;

    if user.sub.trim().is_empty()
        || user.email.trim().is_empty()
        || user.email_verified != Some(true)
    {
        return Err(AppError::forbidden(
            "Akun Google harus memiliki alamat email yang terverifikasi",
        ));
    }
    Ok(user)
}

/// Whether an address is the local-development admin account. Exposed
/// (no logic change) so the API handler can record admin local logins
/// in the audit log without duplicating the allowlist here.
pub fn is_local_admin_email(email: &str) -> bool {
    email.trim().to_ascii_lowercase() == LOCAL_ADMIN_EMAIL
}

pub async fn google_login_callback(
    config: Arc<AppConfig>,
    states: Arc<OAuthStateStore>,
    query: GoogleCallbackQuery,
) -> Result<(Response, String), AppError> {
    if !config.google_login_is_configured() {
        return Err(AppError::service_unavailable(
            "Login Google belum dikonfigurasi",
        ));
    }
    let user = fetch_google_user(
        &config,
        &states,
        &query,
        OAuthPurpose::Admin,
        config.google_redirect_uri.as_deref().unwrap_or_default(),
    )
    .await?;

    let email = user.email.trim().to_ascii_lowercase();
    if config.admin_google_emails.is_empty() || !config.admin_google_emails.contains(&email) {
        return Err(AppError::forbidden(
            "Akun Google ini tidak memiliki akses administrator",
        ));
    }

    let now = chrono::Utc::now();
    let claims = SessionClaims {
        sub: user.sub,
        email: email.clone(),
        name: user.name.unwrap_or_else(|| "Administrator".to_owned()),
        role: "admin".to_owned(),
        exp: (now + chrono::Duration::seconds(SESSION_TTL_SECONDS)).timestamp() as usize,
        jti: uuid::Uuid::now_v7().to_string(),
        source: "google".to_owned(),
        iat: now.timestamp() as usize,
    };
    let mut response = Redirect::to("/admin").into_response();
    append_session_cookie(&mut response, &config, &claims)?;
    // Audit 2026-10-25, B12: return the verified admin email alongside
    // the redirect so the handler can record the login. No auth logic
    // changes — the email is the same value already in the claims.
    Ok((response, email))
}

pub fn local_login_response(
    config: &AppConfig,
    input: LocalLoginRequest,
) -> Result<Response, AppError> {
    if !config.environment.is_development() {
        return Err(AppError::not_found(
            "Login lokal hanya tersedia pada mode development",
        ));
    }

    let email = input.email.trim().to_ascii_lowercase();
    // Brute-force throttle per email (audit 2026-10-25, A6): local login
    // previously had no throttle at all.
    if local_login_throttled(&email) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Terlalu banyak percobaan masuk lokal. Coba lagi dalam beberapa menit.",
        ));
    }
    let (name, role, expected_password) = match email.as_str() {
        LOCAL_ADMIN_EMAIL => (
            "Bunny Administrator",
            "admin",
            std::env::var("DEVELOPMENT_ADMIN_PASSWORD")
                .unwrap_or_else(|_| LOCAL_ADMIN_PASSWORD.to_owned()),
        ),
        LOCAL_MEMBER_EMAIL => (
            "Dummy Member",
            "member",
            std::env::var("DEVELOPMENT_MEMBER_PASSWORD")
                .unwrap_or_else(|_| LOCAL_MEMBER_PASSWORD.to_owned()),
        ),
        _ => {
            record_local_login_failure(&email);
            return Err(AppError::unauthorized(
                "Email atau password lokal tidak valid",
            ));
        }
    };
    // Env override first: the hardcoded dev credentials remain only as a
    // fallback, and this whole handler 404s outside explicit development
    // mode (fail-closed APP_ENV default, audit 2026-10-25, B7).
    if !constant_time_eq(&input.password, &expected_password) {
        record_local_login_failure(&email);
        return Err(AppError::unauthorized(
            "Email atau password lokal tidak valid",
        ));
    }
    clear_local_login_failures(&email);

    let now = chrono::Utc::now();
    let claims = SessionClaims {
        sub: format!("local:{email}"),
        email,
        name: name.to_owned(),
        role: role.to_owned(),
        exp: (now + chrono::Duration::seconds(SESSION_TTL_SECONDS)).timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: uuid::Uuid::now_v7().to_string(),
        source: "local".to_owned(),
    };
    let mut response = Json(AuthSessionResponse {
        authenticated: true,
        email: Some(claims.email.clone()),
        name: Some(claims.name.clone()),
        role: Some(claims.role.clone()),
        google_login_configured: config.google_login_is_configured(),
        development_access_available: config.development_admin_token.is_some(),
        local_login_available: true,
    })
    .into_response();
    append_session_cookie(&mut response, config, &claims)?;
    Ok(response)
}

pub fn session_from_headers(config: &AppConfig, headers: &HeaderMap) -> Option<AdminPrincipal> {
    let claims = claims_from_headers(config, headers)?;
    if claims.role != "admin" {
        return None;
    }
    // The mint source must be distinguishable (audit 2026-10-25, A5): a
    // local-dev token must never pass as a Google token in production.
    // Tokens minted before the source claim existed are rejected in
    // production; the next login re-issues a sourced token.
    if config.environment.is_production() && claims.source != "google" {
        return None;
    }
    let is_local_admin = config.environment.is_development()
        && claims.sub == format!("local:{LOCAL_ADMIN_EMAIL}")
        && claims.email == LOCAL_ADMIN_EMAIL;
    let is_google_admin = config.admin_google_emails.contains(&claims.email);
    if !is_local_admin && !is_google_admin {
        return None;
    }
    Some(AdminPrincipal {
        email: claims.email,
        name: claims.name,
        source: if is_local_admin {
            "local_session"
        } else {
            "google_session"
        },
        jti: claims.jti,
    })
}

fn claims_from_headers(config: &AppConfig, headers: &HeaderMap) -> Option<SessionClaims> {
    let token = cookie_value(headers, ADMIN_SESSION_COOKIE)?;
    let secret = session_secret(config)?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = ["exp"].into_iter().map(str::to_owned).collect();
    let decoded = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;
    Some(decoded.claims)
}

pub fn require_admin(config: &AppConfig, headers: &HeaderMap) -> Result<AdminPrincipal, AppError> {
    if !config.environment.is_production() {
        if let Some(expected_token) = config.development_admin_token.as_deref() {
            if headers
                .get("x-admin-token")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|token| constant_time_eq(token, expected_token))
            {
                return Ok(AdminPrincipal {
                    email: "admin@local.dev".to_owned(),
                    name: "Administrator Lokal".to_owned(),
                    source: "development_token",
                    jti: String::new(),
                });
            }
        }
    }

    session_from_headers(config, headers).ok_or_else(|| {
        AppError::unauthorized(
            "Sesi administrator tidak ditemukan. Masuk dengan Google atau gunakan token pengembangan.",
        )
    })
}

pub fn auth_session_response(config: &AppConfig, headers: &HeaderMap) -> AuthSessionResponse {
    if let Some(claims) = claims_from_headers(config, headers) {
        return AuthSessionResponse {
            authenticated: true,
            email: Some(claims.email),
            name: Some(claims.name),
            role: Some(claims.role),
            google_login_configured: config.google_login_is_configured(),
            development_access_available: !config.environment.is_production()
                && config.development_admin_token.is_some(),
            local_login_available: config.environment.is_development(),
        };
    }

    fallback_session_response(config, headers)
}

fn fallback_session_response(config: &AppConfig, headers: &HeaderMap) -> AuthSessionResponse {
    let development_authenticated = !config.environment.is_production()
        && config
            .development_admin_token
            .as_deref()
            .is_some_and(|expected| {
                headers
                    .get("x-admin-token")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|token| constant_time_eq(token, expected))
            });
    AuthSessionResponse {
        authenticated: development_authenticated,
        email: development_authenticated.then(|| "admin@local.dev".to_owned()),
        name: development_authenticated.then(|| "Administrator Lokal".to_owned()),
        role: development_authenticated.then(|| "admin".to_owned()),
        google_login_configured: config.google_login_is_configured(),
        development_access_available: !config.environment.is_production()
            && config.development_admin_token.is_some(),
        local_login_available: config.environment.is_development(),
    }
}

/// (token id, expiry) of the admin JWT in the request, if it carries one.
/// Used for logout revocation and for the session endpoint's revoked check.
pub fn session_token_from_headers(
    config: &AppConfig,
    headers: &HeaderMap,
) -> Option<(String, usize)> {
    let claims = claims_from_headers(config, headers)?;
    if claims.jti.is_empty() {
        return None;
    }
    Some((claims.jti, claims.exp))
}

/// Session endpoint with the revocation check applied: a logged-out token
/// reports unauthenticated even before its expiry.
pub async fn auth_session_response_checked(
    config: &AppConfig,
    headers: &HeaderMap,
    revocation: &crate::session_revocation::SessionRevocation,
) -> AuthSessionResponse {
    if let Some((jti, _)) = session_token_from_headers(config, headers) {
        if revocation.is_revoked(&jti).await {
            return fallback_session_response(config, headers);
        }
    }
    auth_session_response(config, headers)
}

pub(crate) fn session_secret(config: &AppConfig) -> Option<&str> {
    config.dashboard_session_secret.as_deref().or_else(|| {
        config
            .environment
            .is_development()
            .then_some(DEVELOPMENT_SESSION_SECRET)
    })
}

fn append_session_cookie(
    response: &mut Response,
    config: &AppConfig,
    claims: &SessionClaims,
) -> Result<(), AppError> {
    let secret = session_secret(config).ok_or_else(|| {
        AppError::service_unavailable("Rahasia sesi dashboard belum dikonfigurasi")
    })?;
    let jwt = encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AppError::internal("Sesi dashboard tidak dapat dibuat"))?;
    // Domain=.rajacek.com agar sesi berlaku di domain polos MAUPUN www:
    // callback Google mendarat di domain polos, sedangkan halaman admin
    // dialihkan ke www — tanpa Domain, cookie host-only tertinggal dan sesi
    // terbaca invalid. Header kedua menghapus cookie host-only lama agar
    // tidak membayangi cookie baru.
    let cookie = session_cookie(&jwt, config.dashboard_cookie_secure());
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| AppError::internal("Cookie sesi tidak dapat dibuat"))?,
    );
    // K19: the legacy host-only clear carries the same Secure flag as
    // the cookie it deletes (logout_response already did; this login
    // path did not). Browser verification of the old host-only Secure
    // cookie removal is still pending (coordinator).
    let legacy_secure = if config.dashboard_cookie_secure() {
        "; Secure"
    } else {
        ""
    };
    let legacy_clear = format!(
        "{ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{legacy_secure}"
    );
    if let Ok(value) = HeaderValue::from_str(&legacy_clear) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(())
}

pub fn logout_response(config: &AppConfig) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let secure = if config.dashboard_cookie_secure() {
        "; Secure"
    } else {
        ""
    };
    // Hapus kedua varian: cookie domain (baru) dan host-only (lama).
    for cookie in [
        format!("{ADMIN_SESSION_COOKIE}=; Domain=.rajacek.com; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"),
        format!("{ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"),
    ] {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn session_cookie(token: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{ADMIN_SESSION_COOKIE}={token}; Domain=.rajacek.com; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}{secure}"
    )
}

pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn secure_token(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
pub(crate) struct GoogleUserInfo {
    pub(crate) sub: String,
    pub(crate) email: String,
    pub(crate) email_verified: Option<bool>,
    pub(crate) name: Option<String>,
    pub(crate) picture: Option<String>,
}

#[cfg(test)]
mod oauth_start_throttle_tests {
    use super::{oauth_start_allowed, OAUTH_START_LIMIT};
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_IP_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn fresh_test_ip() -> String {
        let n = TEST_IP_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("oauth-test-{n}")
    }

    #[test]
    fn first_attempts_allowed_then_throttled() {
        let ip = fresh_test_ip();
        for _ in 0..OAUTH_START_LIMIT {
            assert!(oauth_start_allowed(&ip));
        }
        assert!(!oauth_start_allowed(&ip));
    }

    #[test]
    fn different_ips_have_independent_budgets() {
        let first = fresh_test_ip();
        let second = fresh_test_ip();
        for _ in 0..OAUTH_START_LIMIT {
            assert!(oauth_start_allowed(&first));
        }
        assert!(!oauth_start_allowed(&first));
        assert!(oauth_start_allowed(&second));
    }
}

//! Member portal: API-key holders sign in with their key and get a signed,
//! prefix-scoped session cookie. Every handler derives the prefix from the
//! session token, never from client input, so a member can only ever see
//! their own key, quota, and validation history.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        effective_client_ip, record_admin_activity, record_admin_activity_with_entity, AppState,
    },
    auth::{
        cookie_value, fetch_google_user, google_authorize_redirect, oauth_state_clear_cookie,
        oauth_state_cookie_from_headers, session_secret, AdminPrincipal, OAuthPurpose,
    },

    error::AppError,
    models::{
        GoogleCallbackQuery, MemberAccount, MemberDailyCount, MemberUsageData,
        ValidationHistoryFilters, ValidationProduct,
    },
    store::ip_trial_limit_reached,
};

pub const MEMBER_SESSION_COOKIE: &str = "rajacek_member_session";
/// Member sessions last 12 hours; the API key itself is never stored anywhere.
const MEMBER_SESSION_TTL_SECONDS: u64 = 12 * 60 * 60;
const LOGIN_ATTEMPT_LIMIT: u32 = 10;
const LOGIN_ATTEMPT_WINDOW: Duration = Duration::from_secs(300);

#[derive(Serialize, Deserialize)]
struct MemberClaims {
    /// The API key prefix this session is scoped to.
    sub: String,
    exp: usize,
    iat: usize,
    /// Token id for server-side revocation (audit 2026-10-25, B8).
    /// Tokens minted before this field existed decode it as empty.
    #[serde(default)]
    jti: String,
    /// How the session was minted: "google" | "api_key" | "local" (dev).
    /// Tokens minted before this field existed decode it as empty.
    #[serde(default)]
    source: String,
    /// Key prefix this member-id session is bound to (audit flow B3).
    /// Tokens minted before this field existed decode it as empty and
    /// are rejected on member-id resolve (one re-login), so a stolen
    /// session cannot survive a key regeneration and reveal the new key.
    #[serde(default)]
    key_prefix: String,
}

// ---------------------------------------------------------------------------
// Login attempt throttling (per client IP, in-memory)
// ---------------------------------------------------------------------------

fn attempt_table() -> &'static Mutex<HashMap<String, (u32, Instant)>> {
    static TABLE: OnceLock<Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn login_is_throttled(ip: &str) -> bool {
    let table = attempt_table();
    let Ok(mut table) = table.lock() else {
        return false;
    };
    match table.get_mut(ip) {
        Some((count, started)) if started.elapsed() <= LOGIN_ATTEMPT_WINDOW => {
            *count >= LOGIN_ATTEMPT_LIMIT
        }
        _ => false,
    }
}

fn record_login_failure(ip: &str) {
    let table = attempt_table();
    if let Ok(mut table) = table.lock() {
        // Prune stale entries on every write so the table cannot grow
        // without bound from IPs that stopped trying (audit 2026-10-25, F11).
        table.retain(|_, (_, started)| started.elapsed() <= LOGIN_ATTEMPT_WINDOW);
        let entry = table.entry(ip.to_owned()).or_insert((0, Instant::now()));
        if entry.1.elapsed() > LOGIN_ATTEMPT_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }
}

fn clear_login_failures(ip: &str) {
    if let Ok(mut table) = attempt_table().lock() {
        table.remove(ip);
    }
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

/// Decode and validate the member session cookie. Besides the signature and
/// expiry this enforces (audit 2026-10-25): `exp` is a required claim, the
/// token must carry a known mint source in production, and a revoked token
/// id (logout) is rejected even before its expiry.
async fn member_session_claims(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<MemberClaims, AppError> {
    let token = cookie_value(headers, MEMBER_SESSION_COOKIE)
        .ok_or_else(|| AppError::unauthorized("Sesi member tidak ditemukan"))?;
    let secret = session_secret(&state.config)
        .ok_or_else(|| AppError::service_unavailable("Rahasia sesi belum dikonfigurasi"))?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = ["exp"].into_iter().map(str::to_owned).collect();
    let decoded = decode::<MemberClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::unauthorized("Sesi member tidak valid atau sudah kedaluwarsa"))?;
    let claims = decoded.claims;
    if claims.sub.is_empty() {
        return Err(AppError::unauthorized("Sesi member tidak valid"));
    }
    // Sessions minted before the source claim existed, and local-dev
    // sessions, are not accepted in production; the next login re-issues
    // a token that carries its source.
    if state.config.environment.is_production()
        && claims.source != "google"
        && claims.source != "api_key"
    {
        return Err(AppError::unauthorized("Sesi member tidak valid"));
    }
    // B19 fail-closed (Fase 3, D1): revoked -> 401, dan pemeriksaan yang
    // tidak bisa dipastikan (Redis terkonfigurasi tapi tak terhubung)
    // -> 503, bukan lolos diam-diam seperti dulu.
    if !claims.jti.is_empty() {
        match state.session_revocation.check_revoked(&claims.jti).await {
            crate::session_revocation::RevocationCheck::Revoked => {
                return Err(AppError::unauthorized("Sesi member tidak valid"));
            }
            crate::session_revocation::RevocationCheck::Unavailable => {
                return Err(AppError::service_unavailable(
                    "Pemeriksaan sesi tidak tersedia (Redis tidak terhubung); coba lagi sesaat lagi.",
                ));
            }
            crate::session_revocation::RevocationCheck::Clear => {}
        }
    }
    Ok(claims)
}



/// A resolved member session: the account (Google members) plus the API key
/// prefix every data handler scopes to. Legacy key-only sessions have no
/// account and scope directly to the prefix stored in the token.
#[derive(Debug)]
pub struct MemberSession {
    pub member: Option<MemberAccount>,
    pub prefix: String,
}

/// Whether a member-id session's key binding still matches the member's
/// current key (audit flow B3). Pure so it is unit-testable without a
/// database: the binding check runs before any key-availability error.
/// - Bound claim + same current prefix: session survives (grant/assign
///   never change the prefix, so only regeneration forces re-login).
/// - Bound claim + different prefix: regeneration happened — reject.
/// - Empty claim + current key present: legacy pre-binding session —
///   reject once; the next login mints a bound session.
/// - Empty claim + no current key: nothing to mismatch, so the binding
///   itself passes; the caller still fails closed below on the missing
///   key (the member re-logs in, which provisions a key and binds the
///   new session). This case covers a member with no key at all
///   (revoked-only accounts re-login into a fresh key, never into a
///   session bound to nothing while a key exists).
/// - Bound claim + no current key: reject (the key is gone entirely).
fn session_key_binding_matches(claimed_prefix: &str, current_prefix: Option<&str>) -> bool {
    match (claimed_prefix.is_empty(), current_prefix) {
        (true, None) => true,
        (true, Some(_)) => false,
        (false, Some(current)) => claimed_prefix == current,
        (false, None) => false,
    }
}

/// Resolve the session cookie to a member session. New sessions carry the
/// member id (Google sign-in, or a key that belongs to a member); older
/// sessions carry the key prefix directly.
async fn resolve_session(state: &AppState, headers: &HeaderMap) -> Result<MemberSession, AppError> {
    let claims = member_session_claims(state, headers).await?;
    let sub = claims.sub;
    if let Ok(id) = uuid::Uuid::parse_str(&sub) {
        if let Some(member) = state.store.member_by_id(id).await? {
            if member.status != "active" {
                return Err(AppError::forbidden(
                    "Akun member dinonaktifkan. Hubungi admin untuk bantuan.",
                ));
            }
            let current = state.store.member_key(id).await;
            // B3: a member-id session is bound to the key prefix it was
            // minted with. A regenerated key has a new prefix, so the old
            // session is rejected here and can no longer reveal the new
            // key — regeneration finally kills stolen sessions too.
            if !session_key_binding_matches(
                &claims.key_prefix,
                current.as_ref().map(|(summary, _)| summary.prefix.as_str()),
            ) {
                return Err(AppError::unauthorized(
                    "Sesi tidak lagi sesuai dengan kunci member saat ini. Masuk ulang.",
                ));
            }
            let (summary, _) =
                current.ok_or_else(|| AppError::unauthorized("Kunci member tidak tersedia"))?;
            // Key status is enforced here (audit 2026-10-25, B2): a revoked
            // or disabled key must not keep serving a live portal session,
            // and the key's plaintext must not stay revealable. An EXPIRED
            // key still resolves so the member can reach the buy page and
            // renew — blocking it would deadlock renewal.
            if summary.status == "revoked" || summary.status == "disabled" {
                return Err(AppError::unauthorized("Kunci member sudah tidak aktif"));
            }
            return Ok(MemberSession {
                member: Some(member),
                prefix: summary.prefix,
            });
        }
        // UUID-shaped subject with no member behind it: fail closed instead
        // of degrading to a ghost prefix session (audit 2026-10-25, F9).
        return Err(AppError::unauthorized("Sesi member tidak valid"));
    }
    // Prefix session (API-key login): the key itself must still be valid.
    let summary = state
        .store
        .key_summary_by_prefix(&sub)
        .await
        .ok_or_else(|| AppError::unauthorized("Sesi member tidak valid"))?;
    // B3, prefix variant: the subject IS the prefix, so it binds the
    // session by itself; a non-empty claim that disagrees with it is
    // rejected as a safety net. An empty claim (legacy token) stays
    // usable here because revocation/disabling of that prefix still
    // blocks it below — unlike member-id sessions, a regenerated key
    // has a different prefix, so the old subject no longer resolves to
    // a live key at all.
    if !claims.key_prefix.is_empty() && claims.key_prefix != summary.prefix {
        return Err(AppError::unauthorized("Sesi member tidak valid"));
    }
    if summary.status == "revoked" || summary.status == "disabled" {
        return Err(AppError::unauthorized("Kunci member sudah tidak aktif"));
    }
    if let Some(member_id) = summary.member_id {
        // K29: mirror the UUID branch (fail-closed). A prefix whose
        // member row is gone must not degrade to a ghost member-None
        // session that can still reveal and sandbox; only a key with
        // no owning member at all (member_id None, standalone key)
        // legitimately resolves with member None below.
        let member = state
            .store
            .member_by_id(member_id)
            .await?
            .ok_or_else(|| AppError::unauthorized("Sesi member tidak valid"))?;
        if member.status != "active" {
            return Err(AppError::forbidden(
                "Akun member dinonaktifkan. Hubungi admin untuk bantuan.",
            ));
        }
        return Ok(MemberSession {
            member: Some(member),
            prefix: summary.prefix,
        });
    }
    Ok(MemberSession {
        member: None,
        prefix: summary.prefix,
    })

}

/// Public profile view shared by the session and overview responses.
#[derive(Serialize)]
pub struct MemberProfileView {
    name: Option<String>,
    email: String,
    picture_url: Option<String>,
    plan_kind: String,
}

impl From<&MemberAccount> for MemberProfileView {
    fn from(member: &MemberAccount) -> Self {
        Self {
            name: member.name.clone(),
            email: member.email.clone(),
            picture_url: member.picture_url.clone(),
            plan_kind: member.plan_kind.clone(),
        }
    }
}

/// Encode a member session JWT for the given subject (member id or prefix),
/// bound to the key prefix it was minted with (audit flow B3). Pass an
/// empty `key_prefix` only when the member currently has no key; such a
/// session cannot resolve to a live key until the member re-logs in.
fn issue_member_session(
    state: &AppState,
    sub: &str,
    source: &str,
    key_prefix: &str,
) -> Result<String, AppError> {
    let secret = session_secret(&state.config).ok_or_else(|| {
        AppError::service_unavailable("Rahasia sesi dashboard belum dikonfigurasi")
    })?;
    let now = Utc::now().timestamp();
    let claims = MemberClaims {
        sub: sub.to_owned(),
        iat: now as usize,
        exp: (now + MEMBER_SESSION_TTL_SECONDS as i64) as usize,
        jti: uuid::Uuid::now_v7().to_string(),
        source: source.to_owned(),
        key_prefix: key_prefix.to_owned(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AppError::internal("Sesi member tidak dapat dibuat"))
}

fn session_cookie_header(state: &AppState, token: &str, max_age: u64) -> HeaderValue {
    let secure = if state.config.dashboard_cookie_secure() {
        "; Secure"
    } else {
        ""
    };
    // Sama seperti sesi admin: Domain=.rajacek.com agar sesi member berlaku
    // di domain polos maupun www (callback Google di domain polos, portal
    // dialihkan ke www).
    let value = format!(
        "{MEMBER_SESSION_COOKIE}={token}; Domain=.rajacek.com; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    );
    HeaderValue::from_str(&value).expect("cookie sesi member selalu valid")
}

/// Clear the host-only (pre-24-Okt-fix) variant of the member cookie, so a
/// stale host-only cookie can never shadow the domain cookie (audit
/// 2026-10-25, F6; mirrors the admin login/logout handling). The clear
/// carries the same `Secure` flag as the cookie it deletes (audit flow
/// K19): a clear without `Secure` may not remove a cookie that was
/// stored as Secure in some browsers. Browser verification of the old
/// host-only Secure cookie removal is still pending (coordinator).
fn host_only_clear_header(state: &AppState) -> HeaderValue {
    let secure = if state.config.dashboard_cookie_secure() {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{MEMBER_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
    ))
    .expect("cookie clear member selalu valid")
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LoginResponse {
    authenticated: bool,
    prefix: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    let ip = effective_client_ip(&headers, address.ip()).to_string();
    if login_is_throttled(&ip) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Terlalu banyak percobaan masuk. Coba lagi dalam beberapa menit.",
        ));
    }
    // The validate endpoints accept x-api-key or Authorization: Bearer;
    // login accepts both too (audit 2026-10-25, F12).
    let raw_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| AppError::unauthorized("API key tidak ditemukan"))?;
    let context = match state.store.authenticate_api_key(raw_key).await {
        Ok(context) => context,
        Err(error) => {
            record_login_failure(&ip);
            return Err(error);
        }
    };
    clear_login_failures(&ip);

    // Login and session must agree: a key whose owner account is disabled
    // must not yield a session (audit 2026-10-25, F16).
    if let Some(owner_id) = context.owner_id {
        match state.store.member_by_id(owner_id).await? {
            Some(member) if member.status == "active" => {}
            Some(_) => {
                return Err(AppError::forbidden(
                    "Akun member dinonaktifkan. Hubungi admin untuk bantuan.",
                ));
            }
            None => {
                return Err(AppError::unauthorized("Akun member tidak ditemukan"));
            }
        }
    }

    // Keys owned by a member account get a member-scoped session (same as
    // Google sign-in); standalone keys keep the legacy prefix session.
    let sub = context
        .owner_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| context.prefix.clone());
    let token = issue_member_session(&state, &sub, "api_key", &context.prefix)?;

    let mut response = Json(LoginResponse {
        authenticated: true,
        prefix: context.prefix,
    })
    .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie_header(&state, &token, MEMBER_SESSION_TTL_SECONDS),
    );
    response
        .headers_mut()
        .append(header::SET_COOKIE, host_only_clear_header(&state));
    Ok(response)
}

#[derive(Serialize)]
pub struct SessionResponse {
    authenticated: bool,
    prefix: Option<String>,
    member: Option<MemberProfileView>,
}

pub async fn session(State(state): State<AppState>, headers: HeaderMap) -> Json<SessionResponse> {
    match resolve_session(&state, &headers).await {
        Ok(session) => Json(SessionResponse {
            authenticated: true,
            prefix: Some(session.prefix),
            member: session.member.as_ref().map(MemberProfileView::from),
        }),
        Err(_) => Json(SessionResponse {
            authenticated: false,
            prefix: None,
            member: None,
        }),
    }
}

#[derive(Serialize)]
pub struct LogoutResponse {
    /// True when the server-side revocation was recorded, or when there
    /// was no revocable token to begin with (already logged out/expired).
    revoked: bool,
    /// Present exactly when `revoked` is false: the browser cookies are
    /// still cleared, but the token may stay valid until its expiry, so
    /// the caller must show this instead of reporting a clean logout
    /// (audit flow B5 — no more silent 204 on a failed revoke).
    warning: Option<String>,
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Server-side revocation, reported honestly: an already-revoked or
    // expired token fails validation here and needs no further action
    // (`revoked: true`); a live token whose revoke fails keeps
    // `revoked: false` + a warning, even though the browser cookies are
    // cleared either way.
    let mut revoked = true;
    if let Ok(claims) = member_session_claims(&state, &headers).await {
        if !claims.jti.is_empty() {
            let ttl = claims.exp.saturating_sub(Utc::now().timestamp() as usize);
            revoked = state
                .session_revocation
                .revoke(&claims.jti, std::time::Duration::from_secs(ttl as u64))
                .await;
        }
    }
    let warning = if revoked {
        None
    } else {
        Some(
            "Sesi server tidak berhasil dicabut (Redis tidak terjangkau). Cookie browser sudah dihapus, tetapi token lama masih bisa berlaku sampai kedaluwarsa. Masuk ulang lalu keluar lagi bila perlu."
                .to_owned(),
        )
    };
    let mut response = Json(LogoutResponse { revoked, warning }).into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, session_cookie_header(&state, "", 0));
    response
        .headers_mut()
        .append(header::SET_COOKIE, host_only_clear_header(&state));
    response
}

// ---------------------------------------------------------------------------
// Data handlers (prefix always comes from the session)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct MemberKeyView {
    name: String,
    prefix: String,
    /// Prefix plus a bullet mask — how the key is displayed by default.
    masked_key: String,
    /// Whether the full key can be revealed (stored encrypted at issue).
    revealable: bool,
    status: String,
    scopes: Vec<String>,
    rate_limit_per_minute: u32,
    quota_total: u64,
    expires_at: Option<DateTime<Utc>>,
    /// Package the key's quota came from, when assigned from one.
    package_name: Option<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct OverviewResponse {
    key: MemberKeyView,
    member: Option<MemberProfileView>,
    remaining_quota: u64,
    /// Bucket FIFO kunci sesi ini (urutan expiry terdekat dulu).
    buckets: Vec<crate::models::QuotaBucketView>,
    checks_today: i64,
    checks_last_30_days: i64,
    /// "database" = durable MySQL history; "memory" = this process only.
    source: &'static str,
    /// Final invalid results consumed from today's free pool (WIB) for
    /// this key, and how many free slots remain (billing rule 2026-10-25:
    /// 100/day/key; 0 remaining once exhausted).
    invalid_free_used_today: u32,
    invalid_free_remaining_today: u32,
}

fn wib() -> FixedOffset {
    FixedOffset::east_opt(7 * 3600).expect("offset WIB valid")
}

fn wib_date(moment: DateTime<Utc>) -> NaiveDate {
    moment.with_timezone(&wib()).date_naive()
}

/// Aggregates from the in-memory history ring (fallback when MySQL is absent).
fn usage_from_memory(items: &[crate::models::ValidationHistoryItem]) -> MemberUsageData {
    let today = wib_date(Utc::now());
    let mut daily_map: HashMap<(NaiveDate, &'static str), i64> = HashMap::new();
    let mut checks_today = 0_i64;
    let mut checks_last_30_days = 0_i64;
    for item in items {
        let date = wib_date(item.occurred_at);
        if date == today {
            checks_today += 1;
        }
        if (today - date).num_days() < 30 {
            checks_last_30_days += 1;
        }
        if (today - date).num_days() < 14 {
            *daily_map.entry((date, item.product.as_str())).or_default() += 1;
        }
    }
    let mut daily: Vec<MemberDailyCount> = daily_map
        .into_iter()
        .map(|((date, product), count)| MemberDailyCount {
            date: date.format("%Y-%m-%d").to_string(),
            product: product.to_owned(),
            count,
        })
        .collect();
    daily.sort_by(|a, b| a.date.cmp(&b.date));
    MemberUsageData {
        checks_today,
        checks_last_30_days,
        daily,
    }
}

/// Usage aggregates for one member from whichever history source is active.
/// Aggregates span all of the member's prefixes (same regeneration caveat
/// as history, audit 2026-10-25, F15).
async fn member_usage(state: &AppState, prefixes: &[String]) -> (MemberUsageData, &'static str) {
    if let Some(data) = state
        .provider_configs
        .member_usage_from_db(prefixes)
        .await
    {
        return (data, "database");
    }
    let filters = ValidationHistoryFilters {
        product: None,
        outcome: None,
        api_key_prefix: None,
        api_key_prefixes: Some(prefixes.to_vec()),
        q: None,
        from: None,
        to_exclusive: None,
    };
    let (items, _, _) = state.store.validation_history(&filters, 500, 0).await;
    (usage_from_memory(&items), "memory")
}

pub async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OverviewResponse>, AppError> {
    let session = resolve_session(&state, &headers).await?;
    let prefix = session.prefix.clone();
    let (summary, remaining_quota) = state
        .store
        .api_key_account(&prefix)
        .await
        .ok_or_else(|| AppError::unauthorized("Kunci API sudah tidak tersedia"))?;
    let usage_prefixes = match session.member.as_ref() {
        Some(member) => state.store.prefixes_for_member(member.id).await,
        None => vec![prefix.clone()],
    };
    let usage_prefixes = if usage_prefixes.is_empty() {
        vec![prefix.clone()]
    } else {
        usage_prefixes
    };
    let (usage, source) = member_usage(&state, &usage_prefixes).await;
    let invalid_free_used_today = state
        .store
        .invalid_free_used_today(&prefix, wib_date(Utc::now()))
        .await;
    let invalid_free_remaining_today = crate::store::INVALID_FREE_DAILY_LIMIT
        .saturating_sub(invalid_free_used_today);
    let buckets = state.store.key_buckets(&prefix).await;
    let package_name = match summary.package_id {
        Some(package_id) => state
            .store
            .list_packages()
            .await
            .into_iter()
            .find(|package| package.id == package_id)
            .map(|package| package.name),
        None => None,
    };
    Ok(Json(OverviewResponse {
        key: MemberKeyView {
            name: summary.name,
            masked_key: format!("{}_••••••••••••", summary.prefix),
            revealable: state.store.key_revealable(&summary.prefix).await,
            prefix: summary.prefix,
            status: summary.status,
            scopes: summary.scopes,
            rate_limit_per_minute: summary.rate_limit_per_minute,
            quota_total: summary.quota_total,
            expires_at: summary.expires_at,
            package_name,
            created_at: summary.created_at,
            last_used_at: summary.last_used_at,
        },
        member: session.member.as_ref().map(MemberProfileView::from),
        remaining_quota,
        buckets,
        checks_today: usage.checks_today,
        checks_last_30_days: usage.checks_last_30_days,
        source,
        invalid_free_used_today,
        invalid_free_remaining_today,
    }))
}

#[derive(Deserialize)]
pub struct MemberHistoryQuery {
    product: Option<String>,
    outcome: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Serialize)]
pub struct HistoryResponse {
    items: Vec<crate::models::ValidationHistoryItem>,
    total: u64,
    limit: u32,
    offset: u32,
    source: &'static str,
    stats: HistoryStats,
}

#[derive(Serialize)]
pub struct HistoryStats {
    hits_last_60s: u64,
    hits_last_3600s: u64,
}

/// Filter produk riwayat member (B2): "pln" diterima, sama seperti jalur
/// riwayat admin. Nilai kosong/absen berarti tanpa filter.
fn parse_member_history_product(value: Option<&str>) -> Result<Option<ValidationProduct>, AppError> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some("bank_account") => Ok(Some(ValidationProduct::BankAccount)),
        Some("ewallet") => Ok(Some(ValidationProduct::Ewallet)),
        Some("whatsapp") => Ok(Some(ValidationProduct::Whatsapp)),
        Some("pln") => Ok(Some(ValidationProduct::Pln)),
        Some(other) => Err(AppError::bad_request(format!(
            "Produk tidak dikenal: {other}"
        ))),
    }
}

pub async fn history(
    State(state): State<AppState>,

    headers: HeaderMap,
    Query(query): Query<MemberHistoryQuery>,
) -> Result<Json<HistoryResponse>, AppError> {
    let session = resolve_session(&state, &headers).await?;
    let limit = query.limit.unwrap_or(15).clamp(1, 100);
    let offset = query.offset.unwrap_or(0);
    let product = parse_member_history_product(query.product.as_deref())?;

    let outcome = query
        .outcome
        .map(|text| text.trim().to_lowercase())
        .filter(|text| !text.is_empty());
    // The prefixes always come from the session; clients cannot widen them.
    // A member sees history across ALL of their keys (audit 2026-10-25,
    // F15): after a regeneration the new prefix alone would show an empty
    // history even though the old checks are still in the database.
    let prefixes = match session.member {
        Some(member) => state.store.prefixes_for_member(member.id).await,
        None => vec![session.prefix.clone()],
    };
    let prefixes = if prefixes.is_empty() {
        vec![session.prefix.clone()]
    } else {
        prefixes
    };
    let filters = ValidationHistoryFilters {
        product,
        outcome,
        api_key_prefix: None,
        api_key_prefixes: Some(prefixes),
        q: None,
        from: None,
        to_exclusive: None,
    };
    if let Some((items, total, hits_last_60s, hits_last_3600s)) = state
        .provider_configs
        .validation_history_from_db(&filters, limit, offset)
        .await
    {
        return Ok(Json(HistoryResponse {
            items,
            total,
            limit,
            offset,
            source: "database",
            stats: HistoryStats {
                hits_last_60s,
                hits_last_3600s,
            },
        }));
    }
    let (items, total, (hits_last_60s, hits_last_3600s)) = state
        .store
        .validation_history(&filters, limit as usize, offset as usize)
        .await;
    Ok(Json(HistoryResponse {
        items,
        total: total as u64,
        limit,
        offset,
        source: "memory",
        stats: HistoryStats {
            hits_last_60s: hits_last_60s as u64,
            hits_last_3600s: hits_last_3600s as u64,
        },
    }))
}

#[derive(Serialize)]
pub struct UsageDay {
    date: String,
    bank_account: i64,
    ewallet: i64,
    whatsapp: i64,
    pln: i64,
    total: i64,
}


#[derive(Serialize)]
pub struct UsageResponse {
    days: Vec<UsageDay>,
    source: &'static str,
}

/// Satu entri agregasi pemakaian harian (B2): kolom pln ikut terisi, produk
/// tak dikenal tetap hanya menaikkan total (perilaku lama untuk `_`).
fn add_usage_entry(day: &mut UsageDay, product: &str, count: i64) {
    match product {
        "bank_account" => day.bank_account += count,
        "ewallet" => day.ewallet += count,
        "whatsapp" => day.whatsapp += count,
        "pln" => day.pln += count,
        _ => {}
    }
    day.total += count;
}

pub async fn usage(
    State(state): State<AppState>,

    headers: HeaderMap,
) -> Result<Json<UsageResponse>, AppError> {
    let session = resolve_session(&state, &headers).await?;
    let prefixes = match session.member.as_ref() {
        Some(member) => state.store.prefixes_for_member(member.id).await,
        None => vec![session.prefix.clone()],
    };
    let prefixes = if prefixes.is_empty() {
        vec![session.prefix.clone()]
    } else {
        prefixes
    };
    let (data, source) = member_usage(&state, &prefixes).await;
    let today = wib_date(Utc::now());
    let mut by_day: HashMap<String, UsageDay> = HashMap::new();
    for entry in &data.daily {
        let day = by_day
            .entry(entry.date.clone())
            .or_insert_with(|| UsageDay {
                date: entry.date.clone(),
                bank_account: 0,
                ewallet: 0,
                whatsapp: 0,
                pln: 0,
                total: 0,
            });
        add_usage_entry(day, entry.product.as_str(), entry.count);

    }
    let mut days = Vec::with_capacity(14);
    for back in (0..14).rev() {
        let date = today - chrono::Duration::days(back);
        let key = format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day());
        days.push(by_day.remove(&key).unwrap_or(UsageDay {
            date: key,
            bank_account: 0,
            ewallet: 0,
            whatsapp: 0,
            pln: 0,
            total: 0,
        }));

    }
    Ok(Json(UsageResponse { days, source }))
}

// ---------------------------------------------------------------------------
// Google sign-in for members (+ trial provisioning)
// ---------------------------------------------------------------------------

/// Trial parameters, admin-adjustable via runtime settings without a deploy.
async fn trial_settings(state: &AppState) -> (u64, i64) {
    let quota = state
        .provider_configs
        .load_runtime_setting("trial.quota_hits")
        .await
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=100_000).contains(value))
        .unwrap_or(10);
    let days = state
        .provider_configs
        .load_runtime_setting("trial.valid_days")
        .await
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (1..=90).contains(value))
        .unwrap_or(7);
    (quota, days)
}

pub async fn google_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    if !state.config.google_member_login_is_configured() {
        return Err(AppError::service_unavailable(
            "Login Google untuk member belum dikonfigurasi",
        ));
    }
    // Light per-IP throttle (audit flow K18; same shape as the login
    // throttle): an unauthenticated start is cheap, but without any
    // throttle a flood could evict legitimate in-flight states from the
    // 1000-entry cap. The cap + 10-minute TTL are unchanged.
    let ip = effective_client_ip(&headers, address.ip()).to_string();
    if !crate::auth::oauth_start_allowed(&ip) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Terlalu banyak percobaan masuk. Coba lagi dalam beberapa menit.",
        ));
    }
    let redirect_uri = state
        .config
        .member_redirect_uri()
        .ok_or_else(|| AppError::internal("Redirect URI member tidak tersedia"))?;
    let redirect = google_authorize_redirect(
        &state.config,
        &state.oauth_states,
        OAuthPurpose::Member,
        &redirect_uri,
    )
    .await?;
    Ok(redirect.into_response())
}

pub async fn google_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<Response, AppError> {

    if !state.config.google_member_login_is_configured() {
        return Err(AppError::service_unavailable(
            "Login Google untuk member belum dikonfigurasi",
        ));
    }
    let redirect_uri = state
        .config
        .member_redirect_uri()
        .ok_or_else(|| AppError::internal("Redirect URI member tidak tersedia"))?;
    let user = fetch_google_user(
        &state.config,
        &state.oauth_states,
        &query,
        oauth_state_cookie_from_headers(&headers),
        OAuthPurpose::Member,
        &redirect_uri,
    )
    .await?;


    let email = user.email.trim().to_ascii_lowercase();
    let (member, is_new) = match state.store.member_by_google_sub(&user.sub).await? {
        Some(member) => (member, false),
        None => {
            match state
                .store
                .create_member(
                    &user.sub,
                    &email,
                    user.name.as_deref(),
                    user.picture.as_deref(),
                )
                .await
            {
                Ok(member) => (member, true),
                Err(error) => {
                    // A concurrent first sign-in for the same Google
                    // account may have won the insert (unique google_sub);
                    // adopt that row instead of failing the login.
                    match state.store.member_by_google_sub(&user.sub).await? {
                        Some(member) => (member, false),
                        None => return Err(error),
                    }
                }
            }
        }
    };
    if member.status != "active" {
        return Err(AppError::forbidden(
            "Akun member dinonaktifkan. Hubungi admin untuk bantuan.",
        ));
    }
    // Only successful logins touch last_login, and the profile follows the
    // identity provider on every sign-in (audit 2026-10-25, F10).
    state.store.touch_member_login(member.id).await;
    state
        .store
        .update_member_profile(member.id, &email, user.name.as_deref(), user.picture.as_deref())
        .await;

    // Key provisioning, serialized per member (audit flow K15, sharing
    // the B4 mechanism): the whole needs_key check + issuance + trial
    // claim runs under the member's provisioning lock, so two concurrent
    // first sign-ins cannot both observe "no key yet" and mint two
    // active keys (trial + empty). The lock is dropped before the
    // session is minted; the session is then bound to whatever key is
    // current, which is correct even if an admin regeneration slipped
    // in between. Trial is a first-ever-sign-in entitlement only; a
    // returning account whose only key was revoked gets a fresh EMPTY key
    // (never a second trial). member_key() deliberately still returns
    // revoked-only keys (grant relies on that distinction), so the
    // revoked case is detected here from the returned status.
    let mut reveal_token: Option<String> = None;
    let mut trial_held = false;
    {
        let _key_lock = state.store.member_key_lock(member.id);
        let _provision_guard = _key_lock.lock().await;
        let needs_key = match state.store.member_key(member.id).await {
            None => true,
            Some((summary, _)) => summary.status == "revoked",
        };
        if needs_key {
            let rate_limit = state.store.default_rate_limit_per_minute();
            if is_new && !state.store.trial_grant_exists(&user.sub).await {
                let (quota, days) = trial_settings(&state).await;
                let expires = Utc::now() + chrono::Duration::days(days);
                let created = state
                    .store
                    .create_member_api_key(&member, quota, Some(expires), rate_limit)
                    .await?;
                // The grant insert is the atomic claim. Only a duplicate
                // claim revokes the key just issued; a transient database
                // error KEEPS it (audit flow K15): the next login sees
                // this active key, so needs_key is false and no second
                // trial is ever issued — the missing trial_grants row
                // costs only trial bookkeeping, never a lost or doubled
                // trial. The key is still shown once below, so a
                // hash-only key is not stranded unseen.
                // Anti-farming (27 Okt 2026): batas 5 grant trial per
                // IP signup per 24 jam rolling. Pre-check ini hanya
                // fast path — klaim bersamaan dari satu IP masih bisa
                // lolos di sini, dan record_trial_grant menahannya di
                // bawah named lock per-IP sebelum INSERT.
                let signup_ip = effective_client_ip(&headers, addr.ip()).to_string();
                let outcome = if ip_trial_limit_reached(
                    state.store.trial_grants_for_ip_24h(&signup_ip).await,
                ) {
                    crate::store::TrialGrantOutcome::IpLimitHeld
                } else {
                    state
                        .store
                        .record_trial_grant(&member, quota, expires, &signup_ip)
                        .await
                };
                match outcome {
                    crate::store::TrialGrantOutcome::Claimed
                    | crate::store::TrialGrantOutcome::TransientError => {
                        reveal_token = Some(stash_key_reveal(
                            &created.plaintext_key,
                            member.id,
                            created.key.prefix.clone(),
                        ));
                    }
                    crate::store::TrialGrantOutcome::AlreadyClaimed => {
                        // Revoke by the exact key id just created:
                        // revoking by prefix could hit a different key if
                        // prefixes ever collide.
                        if let Err(error) = state.store.revoke_api_key(created.key.id).await {
                            tracing::warn!(?error, "Gagal mencabut kunci pecundang balapan trial");
                        }
                    }
                    crate::store::TrialGrantOutcome::IpLimitHeld => {
                        // Soft-deny: login/signup tetap jalan, hanya
                        // trial yang ditahan. Kunci berkuota yang baru
                        // dibuat direvoke lalu diganti kunci kosong
                        // (pola akun tanpa trial), sehingga member
                        // tetap punya akun + kunci yang bisa dibeli
                        // paket — bukan akun tanpa kunci. Penahanan
                        // bersifat terminal untuk akun ini: klaim
                        // hanya jalan saat is_new, jadi tidak ada
                        // "coba lagi nanti" yang diam-diam memberi
                        // trial kedua.
                        if let Err(error) = state.store.revoke_api_key(created.key.id).await {
                            tracing::warn!(?error, "Gagal mencabut kunci trial yang ditahan (batas IP)");
                        }
                        let held_count =
                            state.store.trial_grants_for_ip_24h(&signup_ip).await;
                        tracing::warn!(member_id = %member.id, held_count, "Trial ditahan (batas 5 grant per IP per 24 jam)");
                        record_admin_activity_with_entity(
                            &state,
                            &AdminPrincipal {
                                email: "sistem".to_owned(),
                                name: String::new(),
                                source: "trial_antifarm",
                                jti: String::new(),
                            },
                            "Trial ditahan (batas IP)",
                            format!(
                                "Trial ditahan: batas 5 grant per IP per 24 jam tercapai (grant 24 jam: {held_count})"
                            ),
                            Some("member"),
                            Some(&member.id.to_string()),
                        )
                        .await;
                        trial_held = true;
                        let empty = state
                            .store
                            .create_member_api_key(&member, 0, None, rate_limit)
                            .await?;
                        reveal_token = Some(stash_key_reveal(
                            &empty.plaintext_key,
                            member.id,
                            empty.key.prefix.clone(),
                        ));
                    }
                }
            } else {
                let created = state
                    .store
                    .create_member_api_key(&member, 0, None, rate_limit)
                    .await?;
                reveal_token = Some(stash_key_reveal(
                    &created.plaintext_key,
                    member.id,
                    created.key.prefix.clone(),
                ));
            }
        }
    }

    // B3: bind the new session to the key that is current now.
    let bound_prefix = state
        .store
        .member_key(member.id)
        .await
        .map(|(summary, _)| summary.prefix)
        .unwrap_or_default();
    let token = issue_member_session(&state, &member.id.to_string(), "google", &bound_prefix)?;
    let target = match &reveal_token {
        Some(token) => format!("/member?reveal={token}"),
        None => "/member".to_owned(),
    };
    // Notice sekali tampil untuk trial yang ditahan (portal
    // menghapus param ini setelah dibaca; lihat member.html).
    let target = if trial_held {
        if target.contains('?') {
            format!("{target}&trial=held")
        } else {
            format!("{target}?trial=held")
        }
    } else {
        target
    };
    let mut response = axum::response::Redirect::to(&target).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie_header(&state, &token, MEMBER_SESSION_TTL_SECONDS),
    );
    // B16: binding cookie cleared once the session is minted, mirroring
    // the admin callback.
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&oauth_state_clear_cookie(
            state.config.dashboard_cookie_secure(),
        ))
        .expect("cookie clear pengikat selalu valid"),
    );
    response
        .headers_mut()
        .append(header::SET_COOKIE, host_only_clear_header(&state));
    Ok(response)

}

// ---------------------------------------------------------------------------
// One-time API key reveal (the plaintext is shown exactly once, right after
// Google sign-up creates the key; afterwards only its hash exists)
// ---------------------------------------------------------------------------

const KEY_REVEAL_TTL: Duration = Duration::from_secs(600);

/// One-time reveal token -> (plaintext, expiry, owning member, key prefix).
/// The owner binding (audit 2026-10-25, F7) means a leaked token cannot be
/// redeemed by a different member's session.
fn reveal_table() -> &'static Mutex<HashMap<String, (String, Instant, uuid::Uuid, String)>> {
    static TABLE: OnceLock<Mutex<HashMap<String, (String, Instant, uuid::Uuid, String)>>> =
        OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn stash_key_reveal(
    plaintext_key: &str,
    owner_member: uuid::Uuid,
    owner_prefix: String,
) -> String {
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    if let Ok(mut table) = reveal_table().lock() {
        table.retain(|_, (_, expires, _, _)| *expires > Instant::now());
        table.insert(
            token.clone(),
            (
                plaintext_key.to_owned(),
                Instant::now() + KEY_REVEAL_TTL,
                owner_member,
                owner_prefix,
            ),
        );
    }
    token
}

/// Body POST /v1/member/reveal-key (K33, Fase 3): token satu-kali
/// dikirim di body JSON, BUKAN query URL — query URL tersimpan di log
/// akses/proxy sebelum `replaceState` sempat menghapusnya dari address
/// bar. Struct query lama dihapus bersama rute GET-nya.
#[derive(Deserialize)]
pub struct RevealBody {
    token: String,
}

#[derive(Serialize)]
pub struct RevealResponse {
    api_key: String,
}

#[derive(Serialize)]
pub struct OwnKeyRevealResponse {
    api_key: String,
}

/// The signed-in member views their own full API key. Only possible for
/// keys issued while key encryption was configured (stored ciphertext);
/// older hash-only keys answer 404 with an explanation.
pub async fn reveal_own_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OwnKeyRevealResponse>, AppError> {
    let session = resolve_session(&state, &headers).await?;
    // The session resolver already blocks revoked/disabled keys; an
    // expired key's plaintext is additionally withheld here (it cannot
    // authenticate, so there is nothing useful left to show).
    if let Some(summary) = state
        .store
        .key_summary_by_prefix(&session.prefix)
        .await
    {
        let expired = summary
            .expires_at
            .is_some_and(|expires| expires <= Utc::now());
        if summary.status != "active" || expired {
            return Err(AppError::forbidden(
                "Kunci ini sudah tidak aktif sehingga tidak dapat ditampilkan.",
            ));
        }
    }
    let plaintext = state
        .store
        .reveal_api_key(&session.prefix)
        .await
        .ok_or_else(|| {
            AppError::not_found(
                "Kunci ini dibuat sebelum fitur lihat kunci tersedia, jadi tidak dapat ditampilkan. Minta admin membuatkan kunci baru bila perlu.",
            )
        })?;
    // Self-reveals leave an audit trace (audit 2026-10-25, F13; audit
    // flow K17): besides the log line, a successful self-reveal is now
    // written through the same record_admin_activity path the admin
    // panel uses, so the admin-panel area's persistent audit log
    // (table admin_audit_log) will carry it too — no separate
    // member-side log table is created here. Only successful reveals
    // are recorded, and only the prefix (never the plaintext) is logged.
    tracing::info!(
        prefix = %session.prefix,
        member_id = ?session.member.as_ref().map(|member| member.id),
        "Kunci API member dilihat dari portal"
    );
    {
        let email = session
            .member
            .as_ref()
            .map(|member| member.email.clone())
            .unwrap_or_else(|| format!("member:{}", session.prefix));
        let name = session
            .member
            .as_ref()
            .and_then(|member| member.name.clone())
            .unwrap_or_else(|| "Member".to_owned());
        record_admin_activity(
            &state,
            &AdminPrincipal {
                email,
                name,
                source: "member_self_reveal",
                jti: String::new(),
            },
            "Kunci API dilihat dari portal",
            format!("Kunci {}", session.prefix),
        )
        .await;
    }
    Ok(Json(OwnKeyRevealResponse { api_key: plaintext }))
}

/// Audit trail for a redeemed one-time key reveal (audit flow B17).
/// Mirrors the self-reveal recording in reveal_own_key exactly — same
/// record_admin_activity path, prefix only, never the plaintext — but
/// with its own source ("member_one_time_reveal") so forensics can tell
/// a one-time reveal apart from a later self-reveal or an admin reveal
/// of the same key. Only successful redemptions are recorded; the
/// caller invokes this after the single-use token has been removed.
async fn record_one_time_reveal_activity(state: &AppState, session: &MemberSession) {
    tracing::info!(
        prefix = %session.prefix,
        member_id = ?session.member.as_ref().map(|member| member.id),
        "Kunci API member dilihat lewat tautan satu-kali"
    );
    let email = session
        .member
        .as_ref()
        .map(|member| member.email.clone())
        .unwrap_or_else(|| format!("member:{}", session.prefix));
    let name = session
        .member
        .as_ref()
        .and_then(|member| member.name.clone())
        .unwrap_or_else(|| "Member".to_owned());
    record_admin_activity(
        state,
        &AdminPrincipal {
            email,
            name,
            source: "member_one_time_reveal",
            jti: String::new(),
        },
        "Kunci API dilihat lewat tautan satu-kali",
        format!("Kunci {}", session.prefix),
    )
    .await;
}

pub async fn reveal_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RevealBody>,
) -> Result<Json<RevealResponse>, AppError> {

    // A valid member session is required, the token is single-use, and it
    // is bound to the member + key it was minted for: a leaked token cannot
    // be redeemed by another member's session (a mismatch does NOT consume
    // the token, so probing cannot burn the owner's reveal).
    let session = resolve_session(&state, &headers).await?;
    let plaintext = {
        let mut table = reveal_table()
            .lock()
            .map_err(|_| AppError::internal("Tabel reveal tidak dapat diakses"))?;
        table.retain(|_, (_, expires, _, _)| *expires > Instant::now());
        let owned = table.get(&body.token).is_some_and(|(_, _, owner_member, owner_prefix)| {
            session.member.as_ref().is_some_and(|member| member.id == *owner_member)
                && session.prefix == *owner_prefix
        });
        if !owned {
            return Err(AppError::not_found(
                "Tautan tampilkan kunci tidak valid atau sudah dipakai",
            ));
        }
        table
            .remove(&body.token)
            .map(|(plaintext, _, _, _)| plaintext)
            .ok_or_else(|| {
                AppError::not_found("Tautan tampilkan kunci tidak valid atau sudah dipakai")
            })?
    };
    // B17: a successful one-time reveal leaves a persistent audit row
    // (prefix only, never the plaintext), through the same
    // record_admin_activity path as the self-reveal. Failed redemptions
    // return above and are not recorded.
    record_one_time_reveal_activity(&state, &session).await;
    Ok(Json(RevealResponse { api_key: plaintext }))

}

// ---------------------------------------------------------------------------
// Live-check sandbox: run a real validation from the portal, through the
// exact same pipeline as the public API (rate limit, quota, guard, retry),
// charged to the member's own key and recorded with channel = "portal".
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SandboxCheckRequest {
    product: String,
    bank_code: Option<String>,
    ewallet_provider: Option<String>,
    target: String,
}

pub async fn sandbox_check(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Json(input): Json<SandboxCheckRequest>,
) -> Result<Response, AppError> {
    let request_started = tokio::time::Instant::now();
    let session = resolve_session(&state, &headers).await?;
    let context = state
        .store
        .api_key_context_by_prefix(&session.prefix)
        .await?;
    let request = match input.product.as_str() {
        "bank_account" => {
            crate::api::normalize_bank_request(crate::models::BankAccountValidationRequest {
                bank_code: input
                    .bank_code
                    .ok_or_else(|| AppError::bad_request("Kode bank wajib dipilih"))?,
                account_number: input.target,
            })?
        }
        "ewallet" => {
            crate::api::normalize_ewallet_request(crate::models::EwalletValidationRequest {
                provider: input
                    .ewallet_provider
                    .ok_or_else(|| AppError::bad_request("Provider e-wallet wajib dipilih"))?,
                account_number: input.target,
            })?
        }
        "whatsapp" => {
            crate::api::normalize_whatsapp_request(crate::models::WhatsappValidationRequest {
                phone_number: input.target,
            })?
        }
        "pln" => {
            crate::api::normalize_pln_request(crate::models::PlnValidationRequest {
                customer_id: input.target,
            })?
        }
        other => {
            return Err(AppError::bad_request(format!(
                "Produk tidak dikenal: {other}"
            )))
        }
    };
    let client_ip = effective_client_ip(&headers, address.ip());
    // K11: sandbox memakai kunci idempotensi yang SAMA untuk retry
    // submit yang sama. Dulu server selalu menggenerate kunci baru per
    // submit dan portal mengabaikan header yang dikembalikan, sehingga
    // submit ulang setelah error/timeout selalu menagih cek baru.
    // Kini: portal mengirim kunci yang disimpannya (state halaman) di
    // header `Idempotency-Key`; server memakai kunci itu (divalidasi
    // seperti jalur API publik) dan hanya menggenerate bila klien tidak
    // mengirim. Kunci yang digenerate tetap dikembalikan di header
    // `idempotency-key` untuk klien yang menyimpannya belakangan.
    let (sandbox_key, key_generated) =
        crate::api::idempotency_key_or_generate(&headers)?;
    let mut response = crate::api::execute_validation(
        state,
        context,
        client_ip,
        sandbox_key.clone(),
        request,
        request_started,
        // B25: sandbox memakai generator 10 char yang sama dengan jalur
        // API (dulu UUID 36 char dengan strip, melanggar kontrak
        // "selalu 10 char" di riwayat member/support).
        crate::api::short_request_id(),
        "portal",
    )
    .await?;
    if key_generated {
        if let Ok(value) = HeaderValue::from_str(&sandbox_key) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("idempotency-key"), value);
        }
    }
    Ok(response)
}

#[derive(Serialize)]
pub struct BankOption {
    code: String,
    name: String,
}

pub async fn banks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<BankOption>>, AppError> {
    resolve_session(&state, &headers).await?;
    Ok(Json(
        crate::bank_codes::list()
            .iter()
            .map(|bank| BankOption {
                code: bank.code_bank.clone(),
                name: bank.name_bank.clone(),
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct EwalletOption {
    code: String,
    name: String,
}

pub async fn ewallets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<EwalletOption>>, AppError> {
    resolve_session(&state, &headers).await?;
    Ok(Json(
        crate::ewallet_codes::list()
            .iter()
            .map(|(code, name)| EwalletOption {
                code: (*code).to_owned(),
                name: (*name).to_owned(),
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Pembelian paket mandiri (QRIS Cutiezy)
// ---------------------------------------------------------------------------

use crate::qris::{self, MemberOrderView, PackageOrderRow, QrisClient};

/// Member id pemilik order. Sesi member (Google) membawa id langsung;
/// sesi prefix (login API key) dipetakan ke member pemilik kunci itu.
/// Selain itu 403: pembelian tidak dibuka untuk sesi tanpa akun member.
async fn resolve_order_member(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, AppError> {
    let session = resolve_session(state, headers).await?;
    if let Some(member) = session.member {
        return Ok(member.id);
    }
    let member_id = state
        .store
        .key_member_id_by_prefix(&session.prefix)
        .await
        .ok_or_else(|| AppError::forbidden("Pembelian paket hanya untuk akun member terdaftar"))?;
    match state.store.member_by_id(member_id).await? {
        Some(member) if member.status == "active" => Ok(member.id),
        _ => Err(AppError::forbidden(
            "Akun member dinonaktifkan. Hubungi admin untuk bantuan.",
        )),
    }
}

fn pool_or_unavailable(state: &AppState) -> Result<sqlx::MySqlPool, AppError> {
    state.store.pool().ok_or_else(|| {
        AppError::service_unavailable("Pembayaran belum tersedia (database tidak terpasang).")
    })
}

#[derive(Serialize)]
pub struct MemberPackageView {
    id: String,
    name: String,
    /// Harga yang benar-benar ditagih (harga katalog dipotong promo aktif).
    price_idr: u64,
    original_price_idr: u64,
    promo_percent: u8,
    promo_ends_at: Option<DateTime<Utc>>,
    included_hits: u64,
    rate_limit_per_minute: u32,
    products_label: String,
}

#[derive(Serialize)]
pub struct MemberPackagesResponse {
    enabled: bool,
    valid_days: i64,
    packages: Vec<MemberPackageView>,
}

/// Daftar paket yang bisa dibeli + status kill switch. Dipakai UI untuk
/// menampilkan/menyembunyikan kartu Beli Paket.
pub async fn purchase_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MemberPackagesResponse>, AppError> {
    resolve_session(&state, &headers).await?;
    let packages = state.store.list_packages().await;
    let (enabled, valid_days) = match pool_or_unavailable(&state) {
        Ok(pool) => match qris::load_qris_settings(&pool).await {
            Ok(settings) => (settings.enabled, settings.valid_days),
            Err(_) => (false, 30),
        },
        Err(_) => (false, 30),
    };
    let now = Utc::now();
    Ok(Json(MemberPackagesResponse {
        enabled,
        valid_days,
        packages: packages
            .iter()
            .filter(|package| {
                package.active && crate::models::effective_price(package, now) > 0
            })
            .map(|package| MemberPackageView {
                id: package.id.to_string(),
                name: package.name.clone(),
                price_idr: crate::models::effective_price(package, now),
                original_price_idr: package.price_idr,
                promo_percent: package.promo_percent,
                promo_ends_at: package.promo_ends_at,
                included_hits: package.included_hits,
                rate_limit_per_minute: package.rate_limit_per_minute,
                products_label: crate::api::package_products_label(&package.products),
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
pub struct PurchasePreviewRequest {
    package_id: String,
}

#[derive(Serialize)]
pub struct PurchasePreviewResponse {
    package_id: String,
    package_name: String,
    price_idr: u64,
    original_price_idr: u64,
    promo_percent: u8,
    promo_ends_at: Option<DateTime<Utc>>,
    quota_hits: u64,
    current_remaining: u64,
    current_expires_at: Option<DateTime<Utc>>,
    current_rate_limit_per_minute: u32,
    new_total: u64,
    new_remaining: u64,
    new_expires_at: DateTime<Utc>,
    new_rate_limit_per_minute: u32,
    /// Expiry bucket BARU yang akan dibuat grant (beli + valid_days),
    /// berbeda dari new_expires_at (expiry agregat terdekat setelah
    /// grant, yang bisa berasal dari bucket lama).
    new_bucket_expires_at: DateTime<Utc>,
    /// Bucket kunci SAAT INI (sebelum grant), urutan FIFO. Bucket baru
    /// belum punya id sehingga tidak dimasukkan di sini — expiry-nya
    /// ada di new_bucket_expires_at.
    buckets: Vec<crate::models::QuotaBucketView>,
    /// Trial aktif yang masih bersisa (info kondisional di modal beli):
    /// None bila tidak ada trial aktif bersisa. Berbasis bucket trial
    /// (order None + package None + expiry = expiry grant), BUKAN
    /// plan_kind — grant mengubah plan_kind jadi 'package' padahal
    /// bucket trial masih ada dan masih dipakai dulu.
    trial_active: Option<crate::models::ActiveTrialInfo>,
}

/// Efek pembelian SEBELUM bayar (murni komputasi, tanpa memanggil
/// Cutiezy). Member tanpa kunci melihat efek dari nol.
pub async fn purchase_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PurchasePreviewRequest>,
) -> Result<Json<PurchasePreviewResponse>, AppError> {
    let member_id = resolve_order_member(&state, &headers).await?;
    let pool = pool_or_unavailable(&state)?;
    let settings = qris::load_qris_settings(&pool).await?;
    if !settings.enabled {
        return Err(AppError::forbidden("Pembelian paket sedang tidak tersedia"));
    }
    qris::ensure_key_buyable(&state.store, member_id).await?;
    let package_id = uuid::Uuid::parse_str(&body.package_id)
        .map_err(|_| AppError::bad_request("package_id tidak valid"))?;
    let package = state
        .store
        .list_packages()
        .await
        .into_iter()
        .find(|package| package.id == package_id)
        .ok_or_else(|| AppError::not_found("Paket tidak ditemukan"))?;
    let now = Utc::now();
    let effective = crate::models::effective_price(&package, now);
    if !package.active || effective == 0 {
        return Err(AppError::bad_request("Paket ini tidak dapat dibeli"));
    }
    // Agregat live (total = jumlah bucket, sisa = sisa aktif) + bucket
    // saat ini untuk tampilan. Member tanpa kunci melihat efek dari nol.
    let (current_total, current_remaining, current_expires_at, current_rate, current_key) =
        match state.store.member_key(member_id).await {
            Some((summary, remaining)) => (
                summary.quota_total,
                remaining,
                summary.expires_at,
                summary.rate_limit_per_minute,
                Some(summary),
            ),
            None => (0, 0, None, 0, None),
        };
    let now = Utc::now();
    let new_bucket_expires_at = now + chrono::Duration::days(settings.valid_days);
    let new_total = current_total.saturating_add(package.included_hits);
    let new_remaining = current_remaining.saturating_add(package.included_hits);
    let new_rate_limit_per_minute = current_rate.max(package.rate_limit_per_minute);
    // new_expires_at = expiry agregat terdekat SETELAH grant: hitung dari
    // bucket saat ini + bucket baru (bukan dari current_expires_at —
    // agregat lama bisa berasal dari bucket habis yang tidak lagi
    // bersisa, sehingga min() dengannya akan salah).
    let (buckets, new_expires_at, trial_active) = match &current_key {
        Some(summary) => {
            let views = state.store.key_buckets(&summary.prefix).await;
            let raw = state.store.key_bucket_list(&summary.prefix).await;
            // Info trial dihitung dari bucket SAAT INI (sebelum bucket
            // pembelian ditambahkan) + baris trial_grants member ini.
            let grant_expiry = state
                .store
                .trial_expiry_by_member()
                .await
                .get(&member_id)
                .copied();
            let trial_active =
                crate::models::active_trial_bucket(grant_expiry, &raw, now);
            let mut raw_with_new = raw;
            raw_with_new.push(crate::models::new_purchase_bucket(
                summary.id,
                Some(member_id),
                None,
                Some(package.id),
                package.included_hits,
                settings.valid_days,
                now,
            ));
            let (_, _, expiry) = crate::models::bucket_aggregate(&raw_with_new, now);
            // Setelah grant selalu ada bucket baru bersisa, jadi agregat
            // tidak pernah jatuh ke fallback kosong — tapi pertahankan
            // fallback defensif ke expiry bucket baru.
            (
                views,
                expiry.unwrap_or(new_bucket_expires_at),
                trial_active,
            )
        }
        None => (Vec::new(), new_bucket_expires_at, None),
    };
    Ok(Json(PurchasePreviewResponse {
        package_id: package.id.to_string(),
        package_name: package.name,
        price_idr: effective,
        original_price_idr: package.price_idr,
        promo_percent: package.promo_percent,
        promo_ends_at: package.promo_ends_at,
        quota_hits: package.included_hits,
        current_remaining,
        current_expires_at,
        current_rate_limit_per_minute: current_rate,
        new_total,
        new_remaining,
        new_expires_at,
        new_rate_limit_per_minute,
        new_bucket_expires_at,
        buckets,
        trial_active,
    }))
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    package_id: String,
}

/// Buat order + QRIS. 201 bila order baru, 200 bila mengembalikan order
/// waiting yang sudah ada (satu waiting per member).
pub async fn create_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateOrderRequest>,
) -> Result<(StatusCode, Json<MemberOrderView>), AppError> {
    let member_id = resolve_order_member(&state, &headers).await?;
    let package_id = uuid::Uuid::parse_str(&body.package_id)
        .map_err(|_| AppError::bad_request("package_id tidak valid"))?;
    let package = state
        .store
        .list_packages()
        .await
        .into_iter()
        .find(|package| package.id == package_id)
        .ok_or_else(|| AppError::not_found("Paket tidak ditemukan"))?;
    let (view, created) =
        qris::create_member_order(&state.store, &state.config, member_id, &package).await?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(view),
    ))
}

pub async fn list_orders(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<MemberOrderView>>, AppError> {
    let member_id = resolve_order_member(&state, &headers).await?;
    let pool = pool_or_unavailable(&state)?;
    let rows = qris::list_orders_for_member(&pool, &member_id, 50).await?;
    Ok(Json(
        rows.iter().map(PackageOrderRow::member_view).collect(),
    ))
}

async fn own_order(
    state: &AppState,
    headers: &HeaderMap,
    order_id: &str,
) -> Result<PackageOrderRow, AppError> {
    let member_id = resolve_order_member(state, headers).await?;
    let pool = pool_or_unavailable(state)?;
    let id = uuid::Uuid::parse_str(order_id)
        .map_err(|_| AppError::bad_request("ID order tidak valid"))?;
    qris::get_order_for_member(&pool, &id, &member_id)
        .await?
        .ok_or_else(|| AppError::not_found("Order tidak ditemukan"))
}

pub async fn get_order_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(order_id): axum::extract::Path<String>,
) -> Result<Json<MemberOrderView>, AppError> {
    let row = own_order(&state, &headers, &order_id).await?;
    Ok(Json(row.member_view()))
}

/// Tombol "Saya sudah bayar": verifikasi + grant (atau laporkan status).
/// Order yang sudah granted/dll dikembalikan apa adanya (idempoten).
pub async fn check_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(order_id): axum::extract::Path<String>,
) -> Result<Json<MemberOrderView>, AppError> {
    let row = own_order(&state, &headers, &order_id).await?;
    let id =
        uuid::Uuid::parse_str(&row.id).map_err(|_| AppError::internal("ID order tidak valid"))?;
    let (view, _) = qris::verify_and_grant(&state.store, &state.config, id).await?;
    Ok(Json(view))
}

/// Batalkan order waiting. Bila Cutiezy ternyata sudah lunas, batal
/// DIBATALKAN dan verify_and_grant dijalankan (uang member tidak hilang).
pub async fn cancel_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(order_id): axum::extract::Path<String>,
) -> Result<Json<MemberOrderView>, AppError> {
    let row = own_order(&state, &headers, &order_id).await?;
    if row.status != "waiting_payment" {
        return Ok(Json(row.member_view()));
    }
    let pool = pool_or_unavailable(&state)?;
    let settings = qris::load_qris_settings(&pool).await?;
    let Some(ciphertext) = settings.api_key_ciphertext else {
        return Err(AppError::service_unavailable(
            "Pembayaran belum dikonfigurasi admin.",
        ));
    };
    let cipher = crate::provider_config::CredentialCipher::new(
        state.config.api_key_encryption_key.as_deref(),
    );
    let api_key = cipher
        .decrypt(&ciphertext)
        .map_err(|_| AppError::service_unavailable("Pembayaran belum dikonfigurasi admin."))?;
    let token = row
        .qris_token
        .clone()
        .ok_or_else(|| AppError::internal("Order tanpa token QRIS"))?;
    let client = QrisClient::new(&state.config.qris_base_url)?;
    match client.cancel(&api_key, &token).await {
        Ok(()) => {
            // K35: hasil CAS dicek EKSPLISIT, lalu re-read menjadi
            // otoritas hasil akhir (hasil akhir TIDAK berubah dari
            // perilaku lama — re-read sudah menyelamatkannya — tapi
            // polanya kini tertulis, bukan kebetulan). CAS 0 baris
            // berarti sweep/verify sudah mengubah status di antara
            // cancel Cutiezy dan UPDATE ini (mis. sudah ter-grant):
            // member melihat status benar itu, bukan `canceled` palsu.
            let changed = sqlx::query(
                "UPDATE package_orders SET status = 'canceled', updated_at = UTC_TIMESTAMP(6) \
                 WHERE id = ? AND status = 'waiting_payment'",
            )
            .bind(&row.id)
            .execute(&pool)
            .await
            .map_err(|_| AppError::internal("Order tidak dapat dibatalkan"))?;
            if changed.rows_affected() != 1 {
                tracing::debug!(order_id = %row.id, "Cancel lokal kalah CAS; status hasil re-read yang dipakai");
            }
            let updated = qris::get_order(
                &pool,
                &uuid::Uuid::parse_str(&row.id)
                    .map_err(|_| AppError::internal("ID order tidak valid"))?,
            )
            .await?
            .unwrap_or(row);
            Ok(Json(updated.member_view()))
        }
        Err(qris::QrisError::AlreadyPaid) => {
            let id = uuid::Uuid::parse_str(&row.id)
                .map_err(|_| AppError::internal("ID order tidak valid"))?;
            let (view, _) = qris::verify_and_grant(&state.store, &state.config, id).await?;
            Ok(Json(view))
        }
        Err(error) => {
            tracing::warn!(?error, "Cancel QRIS gagal");
            Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "qris_provider_error",
                "Pembatalan belum bisa diproses. Coba lagi.",
            ))
        }
    }
}

/// Proxy gambar QR: token/URL Cutiezy tidak pernah sampai ke browser
/// member; server yang mengunduh dan meneruskan bytes-nya.
pub async fn order_qr(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(order_id): axum::extract::Path<String>,
) -> Result<Response, AppError> {
    let row = own_order(&state, &headers, &order_id).await?;
    if row.status != "waiting_payment" {
        return Err(AppError::not_found("QR tidak tersedia untuk order ini"));
    }
    let image_url = row
        .qris_image_url
        .clone()
        .ok_or_else(|| AppError::not_found("QR tidak tersedia untuk order ini"))?;
    let client = QrisClient::new(&state.config.qris_base_url)?;
    let (bytes, content_type) = client.fetch_qr_png(&image_url).await.map_err(|error| {
        tracing::warn!(?error, "Proxy QR gagal");
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "qris_qr_unavailable",
            "Gambar QR tidak dapat dimuat. Coba lagi.",
        )
    })?;
    let mut response = Response::new(axum::body::Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("image/png")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

#[cfg(test)]
mod session_binding_tests {
    use super::session_key_binding_matches;

    #[test]
    fn matching_prefix_resolves() {
        assert!(session_key_binding_matches(
            "rv_live_ab12",
            Some("rv_live_ab12")
        ));
    }

    #[test]
    fn regenerated_prefix_rejects_old_session() {
        assert!(!session_key_binding_matches(
            "rv_live_ab12",
            Some("rv_live_cd34")
        ));
    }

    #[test]
    fn legacy_unbound_session_with_live_key_rejects() {
        // Pre-binding session, member still has a key: one re-login.
        assert!(!session_key_binding_matches("", Some("rv_live_ab12")));
    }

    #[test]
    fn unbound_session_with_no_current_key_passes_binding() {
        // Nothing to mismatch; the caller still fails closed on the
        // missing key itself, and re-login provisions + binds a session.
        assert!(session_key_binding_matches("", None));
    }

    #[test]
    fn bound_session_with_no_current_key_rejects() {
        assert!(!session_key_binding_matches("rv_live_ab12", None));
    }
}

#[cfg(test)]
mod member_history_product_filter_tests {
    use super::*;

    #[test]
    fn member_history_filter_accepts_pln_like_admin() {
        assert_eq!(
            parse_member_history_product(Some("pln")).expect("pln accepted"),
            Some(ValidationProduct::Pln)
        );
        assert_eq!(
            parse_member_history_product(Some(" pln ")).expect("pln trimmed"),
            Some(ValidationProduct::Pln)
        );
        assert_eq!(
            parse_member_history_product(None).expect("absent ok"),
            None
        );
        assert_eq!(
            parse_member_history_product(Some("")).expect("empty ok"),
            None
        );
        assert!(parse_member_history_product(Some("tidak_dikenal")).is_err());
    }

    #[test]
    fn usage_aggregation_fills_pln_column_and_keeps_total_consistent() {
        let mut day = UsageDay {
            date: "2026-10-26".to_owned(),
            bank_account: 0,
            ewallet: 0,
            whatsapp: 0,
            pln: 0,
            total: 0,
        };
        add_usage_entry(&mut day, "bank_account", 3);
        add_usage_entry(&mut day, "ewallet", 2);
        add_usage_entry(&mut day, "whatsapp", 1);
        add_usage_entry(&mut day, "pln", 5);
        add_usage_entry(&mut day, "tidak_dikenal", 7);
        assert_eq!(day.bank_account, 3);
        assert_eq!(day.ewallet, 2);
        assert_eq!(day.whatsapp, 1);
        assert_eq!(day.pln, 5);
        assert_eq!(day.total, 18);
        assert_eq!(
            day.bank_account + day.ewallet + day.whatsapp + day.pln + 7,
            day.total
        );
    }
}

#[cfg(test)]
mod member_history_no_raw_fields_tests {
    use super::*;


    #[test]
    fn member_history_response_serialization_omits_raw_target_and_name() {
        // Bukti ujung-ke-ujung di level struct respons member: item yang
        // membawa target_raw + account_name tetap terserialisasi TANPA
        // keduanya saat dibungkus HistoryResponse.
        let item = crate::models::ValidationHistoryItem {
            request_id: "R9".to_owned(),
            api_key_prefix: "rv_live_x".to_owned(),
            member_code: Some("RC000001".to_owned()),
            product: ValidationProduct::BankAccount,
            outcome: "valid".to_owned(),
            target_masked: "***7890".to_owned(),
            target_raw: Some("1234567890".to_owned()),
            account_name: Some("Andrias Se****an Su****o".to_owned()),
            provider_endpoint_name: Some("Endpoint Uji".to_owned()),
            provider_reference: None,
            provider_latency_ms: 10,
            rajacek_processing_ms: None,
            total_latency_ms: None,
            attempts: None,
            occurred_at: Utc::now(),
            channel: "api".to_owned(),
        };
        let response = HistoryResponse {
            items: vec![item],
            total: 1,
            limit: 15,
            offset: 0,
            source: "database",
            stats: HistoryStats {
                hits_last_60s: 0,
                hits_last_3600s: 0,
            },
        };
        let serialized = serde_json::to_string(&response).expect("serialize");
        assert!(!serialized.contains("target_raw"));
        assert!(!serialized.contains("account_name"));
        assert!(!serialized.contains("member_code"));
        assert!(!serialized.contains("provider_endpoint_name"));
        assert!(!serialized.contains("Endpoint Uji"));
        assert!(!serialized.contains("1234567890"));
        assert!(!serialized.contains("Andrias Se****an Su****o"));
        assert!(!serialized.contains("RC000001"));
        assert!(serialized.contains("\"target_masked\":\"***7890\""));
    }

    #[test]
    fn member_profile_serialization_omits_member_code() {
        // Profil member (SessionResponse / OverviewResponse) dibangun
        // dari MemberProfileView yang hand-built — field member_code
        // tidak ada di struct itu, jadi tidak mungkin terserialisasi
        // walau akun internalnya berkode.
        let account = MemberAccount {
            id: uuid::Uuid::now_v7(),
            member_code: Some("RC000001".to_owned()),
            google_sub: "sub-tes".to_owned(),
            email: "member-tes@example.test".to_owned(),
            name: Some("Member Tes".to_owned()),
            picture_url: None,
            plan_kind: "trial".to_owned(),
            status: "active".to_owned(),
            created_at: Utc::now(),
            last_login_at: None,
        };
        let profile = MemberProfileView::from(&account);
        let serialized = serde_json::to_string(&profile).expect("serialize");
        assert!(!serialized.contains("member_code"));
        assert!(!serialized.contains("RC000001"));
        assert!(serialized.contains("member-tes@example.test"));
    }
}

#[cfg(test)]
mod resolve_session_and_reveal_audit_tests {
    use super::*;
    use crate::api::AppState;
    use crate::models::{CreateApiKeyRequest, MemberAccount};

    async fn test_app_state() -> AppState {
        let config = std::sync::Arc::new(crate::config::AppConfig {
            environment: crate::config::Environment::Test,
            bind_address: "127.0.0.1:0".to_owned(),
            database_url: None,
            redis_url: None,
            provider_mode: crate::config::ProviderMode::Demo,
            provider_base_url: None,
            provider_api_key: None,
            provider_credential_key: None,
            api_key_encryption_key: None,
            provider_allowed_hosts: Vec::new(),
            request_timeout_seconds: 8,
            default_rate_limit_per_minute: 60,
            provider_max_concurrency_per_product: 16,
            provider_queue_wait_ms: 2_000,
            provider_breaker_failure_threshold: 5,
            provider_breaker_cooldown_seconds: 30,
            event_stream_name: "validation-events".to_owned(),
            idempotency_ttl_seconds: 86_400,
            dashboard_session_secret: Some("test-dashboard-secret-untuk-tes".to_owned()),
            data_fingerprint_secret: Some("test-fingerprint-secret".to_owned()),
            google_client_id: None,
            google_client_secret: None,
            google_redirect_uri: None,
            google_member_redirect_uri: None,
            admin_google_emails: std::collections::HashSet::new(),
            development_admin_token: None,
            demo_api_key: None,
            allowed_dashboard_origin: None,
            qris_base_url: "https://example.invalid".to_owned(),
        });
        let provider_configs = crate::provider_config::ProviderConfigStore::build(&config)
            .await
            .expect("provider configs tanpa DB");
        let store = std::sync::Arc::new(
            crate::store::AdminStore::new(None, 60).expect("admin store demo"),
        );
        let guard_arc = std::sync::Arc::new(crate::provider_guard::ProviderGuard::new(
            crate::provider_guard::ProviderGuardConfig::default(),
        ));
        let provider =
            crate::provider::build_provider(&config, provider_configs.clone(), guard_arc);
        AppState {
            config: config.clone(),
            store,
            rate_limiter: crate::rate_limit::build_rate_limiter(None, 60)
                .await
                .expect("rate limiter lokal"),
            idempotency: crate::idempotency::build_idempotency_coordinator(
                None,
                std::time::Duration::from_secs(86_400),
            )
            .await
            .expect("idempotensi lokal"),
            provider,
            provider_configs,
            provider_guard: None,
            event_sink: crate::events::build_usage_event_sink(
                None,
                "validation-events".to_owned(),
            )
            .await
            .expect("event sink lokal"),
            oauth_states: std::sync::Arc::new(crate::auth::OAuthStateStore::new()),
            webhook_secret_cache: std::sync::Arc::new(std::sync::RwLock::new(None)),
            session_revocation: std::sync::Arc::new(
                crate::session_revocation::SessionRevocation::new(None).await,
            ),
        }
    }

    fn member_fixture() -> MemberAccount {
        MemberAccount {
            id: uuid::Uuid::now_v7(),
            member_code: None,
            google_sub: "google-sub-tes".to_owned(),
            email: "member-tes@example.test".to_owned(),
            name: Some("Member Tes".to_owned()),
            picture_url: None,
            plan_kind: "manual".to_owned(),
            status: "active".to_owned(),
            created_at: Utc::now(),
            last_login_at: None,
        }
    }

    fn headers_with_member_cookie(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{MEMBER_SESSION_COOKIE}={token}"))
                .expect("cookie tes"),
        );
        headers
    }

    // ---- B17: reveal satu-kali meninggalkan baris audit prefix-only ----

    #[tokio::test]
    async fn one_time_reveal_leaves_prefix_only_audit_row() {
        let state = test_app_state().await;
        let member = member_fixture();
        let session = MemberSession {
            member: Some(member.clone()),
            prefix: "rv_live_ab12".to_owned(),
        };
        record_one_time_reveal_activity(&state, &session).await;
        let (entries, total) = state
            .store
            .list_admin_audit(10, 0, Some("satu-kali"), None, None, None)
            .await;
        assert!(total >= 1);
        let entry = entries
            .into_iter()
            .find(|entry| entry.action.contains("satu-kali"))
            .expect("baris audit reveal satu-kali");
        assert_eq!(entry.actor, member.email);
        // Hanya prefix — tidak ada plaintext apa pun di detail.
        assert_eq!(entry.detail, "Kunci rv_live_ab12");
    }

    // ---- K29: prefix dengan member_id hilang -> 401, sama seperti UUID ----

    #[tokio::test]
    async fn prefix_session_with_missing_member_row_fails_closed() {
        let state = test_app_state().await;
        let member = member_fixture();
        let created = state
            .store
            .create_member_api_key(&member, 100, None, 60)
            .await
            .expect("kunci fixture terbit");
        drop(created.plaintext_key);
        assert!(created.key.member_id.is_some());
        // Tanpa pool DB, member_by_id mengembalikan None: persis kondisi
        // baris member hilang yang dimaksud K29.
        assert!(state
            .store
            .member_by_id(member.id)
            .await
            .expect("baca member")
            .is_none());
        let token = issue_member_session(
            &state,
            &created.key.prefix,
            "api_key",
            &created.key.prefix,
        )
        .expect("sesi prefix");
        let error = resolve_session(&state, &headers_with_member_cookie(&token))
            .await
            .expect_err("sesi prefix yatim harus ditolak");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.message, "Sesi member tidak valid");
    }

    #[tokio::test]
    async fn uuid_session_with_missing_member_row_fails_closed_the_same_way() {
        // Paritas yang dituntut K29: cabang UUID sudah fail-closed dengan
        // pesan yang sama; tes ini mengunci paritas itu.
        let state = test_app_state().await;
        let orphan = uuid::Uuid::now_v7();
        let token = issue_member_session(&state, &orphan.to_string(), "api_key", "")
            .expect("sesi uuid");
        let error = resolve_session(&state, &headers_with_member_cookie(&token))
            .await
            .expect_err("sesi uuid yatim harus ditolak");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.message, "Sesi member tidak valid");
    }

    #[tokio::test]
    async fn prefix_session_without_member_still_resolves() {
        // Regresi penjaga: kunci mandiri (member_id None) TIDAK ikut
        // ditolak oleh perbaikan K29 — ia tetap resolve ke member None.
        let state = test_app_state().await;
        let created = state
            .store
            .create_api_key(CreateApiKeyRequest {
                name: "Kunci tes".to_owned(),
                scopes: vec!["validate:*".to_owned()],
                rate_limit_per_minute: Some(60),
            })
            .await
            .expect("kunci mandiri terbit");
        drop(created.plaintext_key);
        assert!(created.key.member_id.is_none());
        let token = issue_member_session(
            &state,
            &created.key.prefix,
            "api_key",
            &created.key.prefix,
        )
        .expect("sesi prefix");
        let session = resolve_session(&state, &headers_with_member_cookie(&token))
            .await
            .expect("kunci mandiri tetap lolos");
        assert!(session.member.is_none());
        assert_eq!(session.prefix, created.key.prefix);
    }
}


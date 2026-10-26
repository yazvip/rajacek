use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    services::{ServeDir, ServeFile},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    admin_roles::{self, Role},
    auth::{self, AdminPrincipal, OAuthStateStore},
    bank_codes,
    config::AppConfig,
    error::AppError,
    events::UsageEventSink,
    idempotency::{IdempotencyCoordinator, IdempotencyDecision},
    models::{
        ActivityItem, AdminAuditEntry, AdminPackage, AdminProduct, AdminProviderTesterRequest,
        AdminProviderTesterResponse, AdminValidationHistoryItem, BankAccountValidationRequest,
        CreateApiKeyRequest,
        CreatePackageRequest, CreateRateLimitPolicyRequest, EwalletValidationRequest,
        GoogleCallbackQuery, HealthResponse, LocalLoginRequest, ProviderEndpoint,
        ProviderEndpointTestResponse, ProviderValidationRequest, UpdatePackageRequest,
        UpdateProductRequest, UpdateProviderEndpointRequest, UpdateRateLimitPolicyRequest,
        UsageEvent, ValidationHistoryFilters, ValidationHistoryItem, ValidationMeta,
        ValidationProduct, ValidationResponse, ValidationStatus, WhatsappValidationRequest,
    },
    provider::ProviderAdapter,
    provider_config::ProviderConfigStore,
    provider_guard::{GuardProductStatus, ProviderGuard, ProviderGuardConfig},
    rate_limit::RateLimiter,
    store::AdminStore,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub store: Arc<AdminStore>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub idempotency: Arc<dyn IdempotencyCoordinator>,
    pub provider: Arc<dyn ProviderAdapter>,
    pub provider_configs: Arc<ProviderConfigStore>,
    pub provider_guard: Option<Arc<ProviderGuard>>,
    pub event_sink: Arc<dyn UsageEventSink>,
    pub oauth_states: Arc<OAuthStateStore>,
    pub session_revocation: Arc<crate::session_revocation::SessionRevocation>,
}

pub fn build_router(state: AppState) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");

    let api = Router::new()
        .route("/health/live", get(live_health))
        .route("/health/ready", get(readiness_health))
        .route("/status", get(public_status_page))
        .route("/v1/status", get(public_status_json))
        .route(
            "/v1/admin/site-settings",
            get(get_site_settings).put(update_site_settings),
        )
        .route("/openapi/openapi.yaml", get(openapi_spec))
        .route("/openapi/openapi.json", get(openapi_json_spec))
        .route("/openapi.json", get(openapi_json_spec))
        .route("/docs", get(public_docs))
        .route("/v1/banks", get(list_bank_codes))
        .route("/v1/admin/banks", get(list_bank_codes_admin))
        .route("/v1/auth/session", get(auth_session))
        .route("/v1/auth/local/login", post(local_login))
        .route("/v1/auth/google/start", get(google_login_start))
        .route("/v1/auth/google/callback", get(google_login_callback))
        .route("/v1/auth/logout", post(logout))
        .route(
            "/v1/auth/google/member/start",
            get(crate::member::google_start),
        )
        .route(
            "/v1/auth/google/member/callback",
            get(crate::member::google_callback),
        )
        .route("/v1/member/login", post(crate::member::login))
        .route("/v1/member/reveal-key", get(crate::member::reveal_key))
        // K31: reveal is a POST, not a GET, so it falls under the
        // global CSRF origin check (which only inspects POST/PUT/
        // PATCH/DELETE). The one-time /v1/member/reveal-key stays a
        // GET by design: it needs a single-use token, not just the
        // session cookie, and a cross-site trigger could at most burn
        // the token, never read the key (same-origin response).
        .route(
            "/v1/member/api-key/reveal",
            post(crate::member::reveal_own_key),
        )
        .route("/v1/member/check", post(crate::member::sandbox_check))
        .route("/v1/member/banks", get(crate::member::banks))
        .route("/v1/member/ewallets", get(crate::member::ewallets))
        .route("/v1/member/session", get(crate::member::session))
        .route("/v1/member/logout", post(crate::member::logout))
        .route("/v1/member/overview", get(crate::member::overview))
        .route("/v1/member/history", get(crate::member::history))
        .route("/v1/member/usage", get(crate::member::usage))
        .route("/v1/validate/bank-account", post(validate_bank_account))
        .route("/v1/validate/ewallet", post(validate_ewallet))
        .route("/v1/validate/whatsapp", post(validate_whatsapp))
        .route("/v1/admin/overview", get(admin_overview))
        .route("/v1/admin/analytics", get(admin_analytics))
        .route("/v1/admin/providers/health", get(admin_providers_health))
        .route("/v1/admin/activity", get(list_admin_activity))
        .route(
            "/v1/admin/admins",
            get(list_admin_accounts).post(create_admin_account),
        )
        .route(
            "/v1/admin/admins/:id",
            patch(update_admin_account).delete(delete_admin_account),
        )
        .route(
            "/v1/admin/validation-history",
            get(admin_validation_history),
        )
        .route(
            "/v1/admin/rate-limit-default",
            get(get_rate_limit_default).put(update_rate_limit_default),
        )
        .route("/v1/admin/products", get(list_products))
        .route("/v1/admin/products/:id", patch(update_product))
        .route(
            "/v1/admin/provider-endpoints",
            get(list_provider_endpoints).post(create_provider_endpoint),
        )
        .route(
            "/v1/admin/provider-endpoints/:id",
            axum::routing::put(update_provider_endpoint).delete(delete_provider_endpoint),
        )
        .route(
            "/v1/admin/provider-endpoints/:id/active",
            patch(set_provider_endpoint_active),
        )
        .route(
            "/v1/admin/provider-endpoints/:id/test",
            post(test_provider_endpoint),
        )
        .route("/v1/admin/provider-tester", post(admin_provider_tester))
        .route(
            "/v1/admin/provider-guard",
            get(get_provider_guard).put(update_provider_guard),
        )
        .route(
            "/v1/admin/packages",
            get(list_packages).post(create_package),
        )
        .route(
            "/v1/admin/packages/:id",
            patch(update_package).delete(delete_package),
        )
        .route(
            "/v1/admin/rate-limits",
            get(list_rate_limits).post(create_rate_limit),
        )
        .route(
            "/v1/admin/rate-limits/:id",
            patch(update_rate_limit).delete(delete_rate_limit),
        )
        .route(
            "/v1/admin/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route("/v1/admin/api-keys/:id", delete(revoke_api_key))
        .route("/v1/admin/members", get(list_members))
        .route(
            "/v1/admin/members/:id/assign-package",
            post(assign_member_package),
        )
        .route(
            "/v1/admin/members/:id/rate-limit",
            post(set_member_rate_limit),
        )
        .route("/v1/admin/members/:id/status", post(set_member_status))
        .route(
            "/v1/admin/members/:id/api-key/reveal",
            post(reveal_member_key),
        )
        .route(
            "/v1/admin/members/:id/regenerate-key",
            post(regenerate_member_key),
        )
        .route("/v1/admin/members/:id/detail", get(get_member_detail))
        .route(
            "/v1/admin/members/:id/keys/:key_id/adjust",
            post(adjust_member_key_quota),
        )
        .route(
            "/v1/admin/trial-settings",
            get(get_trial_settings).put(update_trial_settings),
        )
        .route("/v1/member/packages", get(crate::member::purchase_packages))
        .route(
            "/v1/member/orders/preview",
            post(crate::member::purchase_preview),
        )
        .route(
            "/v1/member/orders",
            get(crate::member::list_orders).post(crate::member::create_order),
        )
        .route(
            "/v1/member/orders/:id",
            get(crate::member::get_order_detail),
        )
        .route(
            "/v1/member/orders/:id/check",
            post(crate::member::check_order),
        )
        .route(
            "/v1/member/orders/:id/cancel",
            post(crate::member::cancel_order),
        )
        .route("/v1/member/orders/:id/qr", get(crate::member::order_qr))
        .route("/v1/payments/qris/webhook", post(qris_webhook))
        .route(
            "/v1/admin/qris/settings",
            get(get_qris_settings).put(update_qris_settings),
        )
        .route("/v1/admin/orders", get(list_admin_orders))
        .route("/v1/admin/export/:kind", get(export_admin_csv))
        .route(
            "/v1/admin/orders/reconciliation",
            get(get_orders_reconciliation),
        )
        .route("/v1/admin/orders/:id", get(get_admin_order))
        .route(
            "/v1/admin/orders/:id/resolve",
            post(resolve_admin_order),
        )
        .route(
            "/v1/admin/orders/:id/refund-record",
            post(create_refund_record),
        )
        .route(
            "/v1/admin/orders/:id/refunds",
            get(list_order_refunds),
        )
        .route("/v1/admin/alerts/status", get(get_alert_status))
        .route("/", get(public_landing))
        .with_state(state.clone());

    let router = Router::new()
        .merge(api)
        .route("/member", get(member_page))
        .route_service("/admin", ServeFile::new("web/index.html"))
        .fallback(fallback_handler)
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(redirect_to_www))
                .layer(middleware::from_fn(stamp_request_start))
                .layer(CompressionLayer::new())
                .layer(TraceLayer::new_for_http())
                .layer(SetRequestIdLayer::new(
                    request_id_header.clone(),
                    MakeShortRequestId,
                ))
                .layer(PropagateRequestIdLayer::new(request_id_header))
                .layer(middleware::from_fn(security_headers))
                .layer(middleware::from_fn(csrf_origin_check))
                // Keep the status-producing timeout closest to the router so it sees Axum's
                // defaultable response body before tracing and compression wrap that body.
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(20),
                )),
        );

    match state.config.allowed_dashboard_origin.as_deref() {
        Some(origin) => match HeaderValue::from_str(origin) {
            Ok(origin) => router.layer(
                CorsLayer::new()
                    .allow_origin(origin)
                    .allow_methods([
                        Method::GET,
                        Method::POST,
                        Method::PUT,
                        Method::PATCH,
                        Method::DELETE,
                    ])
                    .allow_headers([
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                        HeaderName::from_static("x-api-key"),
                        HeaderName::from_static("x-admin-token"),
                        HeaderName::from_static("idempotency-key"),
                    ])
                    .expose_headers([HeaderName::from_static("idempotency-key")]),
            ),
            Err(_) => {
                tracing::warn!("ALLOWED_DASHBOARD_ORIGIN tidak valid; CORS tidak diaktifkan");
                router
            }
        },
        None => router,
    }
}

async fn member_page() -> Response {
    // Portal member bersifat dinamis & per sesi: jangan biarkan peramban
    // menyajikan HTML basi dari cache (pernah membuat desain baru tak
    // tampak di layar user). no-cache = selalu revalidasi ke server.
    let mut res = Html(include_str!("../web/member.html")).into_response();
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    res
}

async fn public_landing(State(state): State<AppState>) -> Html<String> {
    // K23: the landing renders the live package-validity window from
    // qris_settings (same source the member portal's purchase list uses),
    // never a hardcoded day count; without a database it falls back to
    // the historical 30 days. Zero-price (promo 100%) cards are filtered
    // here exactly like the member purchase list — an unbuyable package
    // must not appear as a buy card.
    let now = Utc::now();
    let valid_days = match state.store.pool() {
        Some(pool) => match crate::qris::load_qris_settings(&pool).await {
            Ok(settings) => settings.valid_days,
            Err(_) => 30,
        },
        None => 30,
    };
    let packages: Vec<crate::models::AdminPackage> = state
        .store
        .list_packages()
        .await
        .into_iter()
        .filter(|package| package.active && crate::models::effective_price(package, now) > 0)
        .collect();
    Html(render_landing(&packages, valid_days))
}

/// The landing page template carries placeholders for the pricing cards and
/// the JSON-LD offer range; both are rendered from the live package catalog
/// (the same data the admin panel edits) so the public page can never drift
/// from the admin settings.
/// Tanggal WIB "30 Okt 2026" untuk label promo (tanpa jam).
fn format_id_date(moment: chrono::DateTime<Utc>) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des",
    ];
    let wib = moment + chrono::Duration::hours(7);
    format!(
        "{} {} {}",
        wib.day(),
        MONTHS[wib.month0() as usize],
        wib.year()
    )
}

fn render_landing(packages: &[crate::models::AdminPackage], valid_days: i64) -> String {
    let now = Utc::now();
    let mut cards = String::new();
    for package in packages {
        let popular = if package.highlighted {
            " price-popular"
        } else {
            ""
        };
        let badge = if package.highlighted {
            "<p class=\"price-badge\">Paling dipilih</p>"
        } else {
            ""
        };
        let promo_on = crate::models::promo_active(package, now);
        let effective = crate::models::effective_price(package, now);
        let promo_badge = if promo_on {
            format!(
                "<p class=\"price-promo-badge\">PROMO −{}%</p>",
                package.promo_percent
            )
        } else {
            String::new()
        };
        // Harga asli dicoret di elemennya sendiri; tanggal berakhir di
        // elemen terpisah TANPA coretan (sebelumnya satu <p class="price-old">
        // sehingga tanggal ikut tercoret — bug 2026-10-25).
        let promo_old = if promo_on {
            format!(
                "<p class=\"price-old\">Rp{}</p><p class=\"price-promo-ends\">Berakhir {}</p>",
                format_id_number(package.price_idr),
                format_id_date(package.promo_ends_at.unwrap_or(now))
            )
        } else {
            String::new()
        };
        cards.push_str(&format!(
            "<article class=\"product-card price-card{popular}\">{badge}<h3>{name}</h3>{promo_badge}<p class=\"price-amount\">Rp{price}</p>{promo_old}<p class=\"price-per\">per paket · masa aktif {valid_days} hari</p><ul class=\"price-features\"><li><span>✓</span> {hits} hit</li><li><span>✓</span> {rate} hit/menit</li><li><span>✓</span> {products}</li></ul><a class=\"price-cta\" href=\"/member\">Masuk &amp; coba gratis <span aria-hidden=\"true\">→</span></a></article>",
            name = html_escape(&package.name),
            price = format_id_number(effective),
            hits = format_id_number(package.included_hits),
            rate = package.rate_limit_per_minute,
            products = package_products_label(&package.products),
            valid_days = valid_days,
        ));
    }
    let low = packages
        .iter()
        .map(|package| crate::models::effective_price(package, now))
        .min()
        .unwrap_or(0);
    let high = packages
        .iter()
        .map(|package| crate::models::effective_price(package, now))
        .max()
        .unwrap_or(0);
    include_str!("../web/landing.html")
        .replace("<!--PRICING_CARDS-->", &cards)
        .replace("{{LOW_PRICE}}", &low.to_string())
        .replace("{{HIGH_PRICE}}", &high.to_string())
        .replace("{{OFFER_COUNT}}", &packages.len().to_string())
        // K23: the footer note carries the same live validity window, so
        // it cannot drift from the cards (or from qris_settings) when an
        // admin changes the package validity.
        .replace(
            "Semua paket berlaku <strong>30 hari</strong>",
            &format!("Semua paket berlaku <strong>{valid_days} hari</strong>"),
        )
}

/// Indonesian thousand grouping: 10000 -> "10.000".
fn format_id_number(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push('.');
        }
        out.push(ch);
    }
    out
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(crate) fn package_products_label(products: &[ValidationProduct]) -> String {
    let has = |wanted: ValidationProduct| products.contains(&wanted);
    match (
        has(ValidationProduct::BankAccount),
        has(ValidationProduct::Ewallet),
        has(ValidationProduct::Whatsapp),
    ) {
        (true, true, true) => "Rekening bank + e-wallet + WhatsApp".to_owned(),
        (true, true, false) => "Rekening bank + e-wallet".to_owned(),
        (true, false, true) => "Rekening bank + WhatsApp".to_owned(),
        (false, true, true) => "E-wallet + WhatsApp".to_owned(),
        (true, false, false) => "Rekening bank".to_owned(),
        (false, true, false) => "E-wallet".to_owned(),
        (false, false, true) => "WhatsApp".to_owned(),
        (false, false, false) => "Semua produk".to_owned(),
    }
}

async fn public_docs() -> Html<&'static str> {
    Html(include_str!("../web/docs.html"))
}

/// Canonical host: browser-facing GET requests on the bare domain are
/// redirected permanently to www. API and health paths are never redirected,
/// so existing integrations on the bare domain keep working unchanged.
async fn redirect_to_www(req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let bare = host == "rajacek.com" || host == "rajacek.com:443" || host == "rajacek.com:80";
    let path = req.uri().path();
    let api_path = path.starts_with("/v1/") || path.starts_with("/health/");
    if bare && req.method() == Method::GET && !api_path {
        let suffix = req
            .uri()
            .path_and_query()
            .map(|path_query| path_query.as_str())
            .unwrap_or("/");
        return Redirect::permanent(&format!("https://www.rajacek.com{suffix}")).into_response();
    }
    next.run(req).await
}

/// Static files still come from web/; anything else becomes the branded
/// 404 page (JSON for API paths). The 404 keeps its status code so search
/// engines do not index missing URLs.
async fn fallback_handler(method: Method, uri: Uri) -> Response {
    if method == Method::GET || method == Method::HEAD {
        if let Some(response) = serve_static_file(&method, uri.path()).await {
            return response;
        }
    }
    let path = uri.path();
    if path.starts_with("/v1/") || path.starts_with("/health/") {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "not_found",
                "message": "Endpoint tidak ditemukan",
            })),
        )
            .into_response();
    }
    not_found_page()
}

/// Serves an existing file from web/ (CSS, JS, images, sitemap, robots).
/// Paths are confined to that directory; anything missing falls through.
async fn serve_static_file(method: &Method, raw_path: &str) -> Option<Response> {
    let decoded = percent_decode(raw_path);
    let relative = decoded.trim_start_matches('/');
    if relative.is_empty()
        || relative
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
    {
        return None;
    }
    let mut path = std::path::PathBuf::from("web");
    path.push(relative);
    if path.is_dir() {
        path.push("index.html");
    }
    let bytes = tokio::fs::read(&path).await.ok()?;
    let content_type = match path.extension().and_then(|extension| extension.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("xml") => "application/xml",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };
    let body = if *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    Some((StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response())
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn not_found_page() -> Response {
    let html = r#"<!doctype html>
<html lang="id">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>404 — Halaman tidak ditemukan | Rajacek</title>
    <meta name="robots" content="noindex" />
    <meta http-equiv="refresh" content="5;url=/" />
    <style>
      * { box-sizing:border-box; }
      body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; font-family:"Manrope",Aptos,"Segoe UI",sans-serif; background:linear-gradient(160deg,#071225,#0b2a5b); color:#10213d; }
      .card { background:#fff; border-radius:22px; padding:40px 36px; max-width:480px; width:100%; text-align:center; box-shadow:0 30px 60px rgba(0,0,0,.35); }
      .mark { width:56px; height:56px; margin:0 auto 16px; border-radius:14px; background:#2563eb; color:#fff; font-size:30px; font-weight:800; line-height:56px; }
      h1 { font-size:64px; margin:0 0 4px; color:#071225; letter-spacing:-.03em; }
      h2 { font-size:20px; margin:0 0 12px; color:#071225; }
      p { color:#60718c; line-height:1.65; margin:0 0 12px; font-size:15px; }
      .btn { display:inline-block; margin-top:10px; background:#2563eb; color:#fff; text-decoration:none; font-weight:700; padding:12px 22px; border-radius:999px; }
      .btn:hover { background:#1d4ed8; }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="mark">R</div>
      <h1>404</h1>
      <h2>Halaman tidak ditemukan</h2>
      <p>Halaman yang Anda cari tidak ada atau sudah dipindahkan.</p>
      <p>Anda akan diarahkan ke <a href="/">beranda Rajacek</a> dalam <strong id="count">5</strong> detik.</p>
      <a class="btn" href="/">Ke beranda sekarang →</a>
    </main>
    <script>
      var n = 5, el = document.getElementById('count');
      setInterval(function () {
        n -= 1;
        if (n <= 0) { location.href = '/'; } else { el.textContent = n; }
      }, 1000);
    </script>
  </body>
</html>"#;
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

/// Member/public-only OpenAPI contract (no admin surface). The full internal
/// spec stays in openapi.yaml; this JSON is what the public docs link to and
/// what members import into Postman/Insomnia/code generators.
async fn openapi_json_spec() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../openapi/openapi.json"),
    )
        .into_response()
}

/// When the application first received the request, stamped by middleware
/// before any routing or handler work. Validation latency is measured from
/// here, so `total_latency_ms` covers the full in-application handling —
/// authentication, limit checks, provider queueing and attempts, event
/// enqueue — up to the moment the response is ready to send. (Time spent in
/// the network before the request reaches this process is not measurable
/// from inside it.)
#[derive(Clone, Copy)]
struct RequestStart(Instant);

async fn stamp_request_start(mut request: Request, next: Next) -> Response {
    request
        .extensions_mut()
        .insert(RequestStart(Instant::now()));
    next.run(request).await
}

/// Defense-in-depth CSRF check (audit 2026-10-25, A8). SameSite=Lax
/// already blocks cross-site cookie sends for state-changing requests, but
/// an explicit Origin/Referer host check closes the gap for same-site
/// tricks and for any future GET mutation. Browsers always send Origin on
/// POST; non-browser clients (curl, servers, webhooks) send none and are
/// allowed through — they cannot carry a victim's cookies anyway. A
/// present-but-unparseable Origin is also allowed (only a definite host
/// mismatch is rejected), so exotic clients are not broken.
async fn csrf_origin_check(request: Request, next: Next) -> Result<Response, AppError> {
    if matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let origin_host = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .and_then(|origin| url::Url::parse(origin).ok())
            .and_then(|url| url.host_str().map(str::to_owned));
        let referer_host = request
            .headers()
            .get(header::REFERER)
            .and_then(|value| value.to_str().ok())
            .and_then(|referer| url::Url::parse(referer).ok())
            .and_then(|url| url.host_str().map(str::to_owned));
        if let Some(declared) = origin_host.or(referer_host) {
            if declared.to_ascii_lowercase() != host {
                return Err(AppError::forbidden("Origin permintaan tidak sesuai host"));
            }
        }
    }
    Ok(next.run(request).await)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers
        .entry("x-content-type-options")
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry("x-frame-options")
        .or_insert(HeaderValue::from_static("DENY"));
    headers
        .entry("referrer-policy")
        .or_insert(HeaderValue::from_static("no-referrer"));
    headers
        .entry("permissions-policy")
        .or_insert(HeaderValue::from_static(
            "camera=(), geolocation=(), microphone=()",
        ));
    response
}

async fn openapi_spec() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/yaml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../openapi/openapi.yaml"),
    )
        .into_response()
}

async fn live_health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "rajacek-api",
        timestamp: Utc::now(),
        provider_mode: provider_mode_label(&state.config),
    })
}

async fn readiness_health(State(state): State<AppState>) -> Result<Json<HealthResponse>, AppError> {
    if state.config.environment.is_production()
        && (state.config.database_url.is_none() || state.config.redis_url.is_none())
    {
        return Err(AppError::service_unavailable(
            "Dependensi wajib belum dikonfigurasi untuk mode production",
        ));
    }

    Ok(Json(HealthResponse {
        status: "ready",
        service: "rajacek-api",
        timestamp: Utc::now(),
        provider_mode: provider_mode_label(&state.config),
    }))
}

/// AREA 6 — halaman status publik, pengumuman, dan mode maintenance.
///
/// Permukaan ini SENGAJA tidak menyebut nama, URL, atau kode provider
/// upstream apa pun: hanya label produk member-facing
/// ("Validasi Rekening" / "Validasi E-Wallet" / "Validasi WhatsApp")
/// dan status agregat "operational" / "degraded". Teks banner berasal
/// dari admin (runtime_settings) dan selalu dirender escaped — di
/// halaman HTML lewat `html_escape`, di portal/landing lewat
/// `textContent` (bukan innerHTML).
///
/// Catatan skema: tabel `runtime_settings` SUDAH ADA sejak migrasi
/// 0005 dengan kolom `setting_key` / `setting_value` (bukan `key` /
/// `value` seperti spesifikasi awal area ini), jadi migrasi 0020
/// hanya menambahkan kolom `updated_by` secara aditif, melebarkan
/// `setting_value` menjadi TEXT (agar teks banner tidak terpotong
/// di batas VARCHAR 255), dan men-seed lima kunci area ini. Kode di
/// sini memakai nama kolom yang sudah ada agar tidak memecahkan
/// pemakai lama tabel ini (mis. provider guard, trial settings).
const SITE_SETTING_ANNOUNCEMENT_TEXT: &str = "announcement_text";
const SITE_SETTING_ANNOUNCEMENT_ACTIVE: &str = "announcement_active";
const SITE_SETTING_MAINTENANCE_BANNER_TEXT: &str = "maintenance_banner_text";
const SITE_SETTING_MAINTENANCE_BANNER_ACTIVE: &str = "maintenance_banner_active";
const SITE_SETTING_MAINTENANCE_BLOCK_VALIDATIONS: &str = "maintenance_block_validations";
/// Pesan yang dikembalikan endpoint validasi saat sakelar blokir aktif.
const MAINTENANCE_MESSAGE: &str = "Layanan sedang dalam pemeliharaan";
/// Batas teks banner/pengumuman yang diterima endpoint admin.
const SITE_SETTING_TEXT_MAX_LEN: usize = 2000;

/// Pengaturan situs apa adanya (dipakai endpoint admin). Nilai aktif
/// disimpan sebagai "0"/"1" di runtime_settings; default semuanya
/// nonaktif dan teks kosong.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SiteSettings {
    announcement_text: String,
    announcement_active: bool,
    maintenance_banner_text: String,
    maintenance_banner_active: bool,
    maintenance_block_validations: bool,
}

#[derive(Clone, Debug, Serialize)]
struct PublicProductStatus {
    /// Kode produk stabil untuk klien: bank_account | ewallet | whatsapp.
    product: &'static str,
    /// Label member-facing, sama dengan `ValidationProduct::label_id`.
    label: &'static str,
    /// "operational" | "degraded".
    status: &'static str,
}

/// Label produk persis seperti spesifikasi area ini (kapitalisasi
/// disengaja berbeda dari `ValidationProduct::label_id`, yang memakai
/// "Validasi rekening" / "Validasi e-wallet" di permukaan lain — label
/// global itu TIDAK diubah agar tidak menggeser permukaan lain).
fn public_product_label(product: ValidationProduct) -> &'static str {
    match product {
        ValidationProduct::BankAccount => "Validasi Rekening",
        ValidationProduct::Ewallet => "Validasi E-Wallet",
        ValidationProduct::Whatsapp => "Validasi WhatsApp",
    }
}

/// Payload GET /v1/status — dan data yang sama dirender GET /status.
/// Tidak ada field apa pun yang membawa nama/URL/kode provider.
#[derive(Clone, Debug, Serialize)]
struct PublicStatus {
    overall: &'static str,
    products: Vec<PublicProductStatus>,
    /// Teks pengumuman aktif, atau None bila tidak ada yang aktif.
    announcement: Option<String>,
    /// Teks banner maintenance aktif, atau None bila tidak ada yang aktif.
    maintenance_banner: Option<String>,
    /// Sakelar blokir validasi (default false).
    maintenance_blocks_validations: bool,
}

/// "1" (tepat) berarti aktif; nilai lain — termasuk kunci yang hilang
/// — berarti nonaktif. Fail-closed ke arah TIDAK memblokir.
fn parse_active_flag(value: Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| value == "1")
}

/// Agregasi status satu produk dari circuit breaker in-memory.
/// "open" (semua server produk tertutup) dan "half_open" (sebagian
/// server terganggu) sama-sama "degraded"; "closed" dan tidak adanya
/// data guard sama sekali berarti "operational" — jangan mengarang
/// gangguan dari ketiadaan data.
fn product_status_from_circuit(circuit: &str) -> &'static str {
    match circuit {
        "open" | "half_open" => "degraded",
        _ => "operational",
    }
}

/// Perakit murni status publik dari snapshot guard + pengaturan situs,
/// agar bisa diuji tanpa database maupun guard.
fn build_public_status(
    guard_statuses: Option<Vec<GuardProductStatus>>,
    settings: &SiteSettings,
) -> PublicStatus {
    let mut products = Vec::with_capacity(3);
    for product in [
        ValidationProduct::BankAccount,
        ValidationProduct::Ewallet,
        ValidationProduct::Whatsapp,
    ] {
        let status = match &guard_statuses {
            Some(statuses) => statuses
                .iter()
                .find(|entry| entry.product == product)
                .map(|entry| product_status_from_circuit(entry.circuit))
                .unwrap_or("operational"),
            None => "operational",
        };
        products.push(PublicProductStatus {
            product: product.as_str(),
            label: public_product_label(product),
            status,
        });
    }
    let overall = if products.iter().any(|entry| entry.status == "degraded") {
        "degraded"
    } else {
        "operational"
    };
    PublicStatus {
        overall,
        products,
        announcement: if settings.announcement_active
            && !settings.announcement_text.trim().is_empty()
        {
            Some(settings.announcement_text.clone())
        } else {
            None
        },
        maintenance_banner: if settings.maintenance_banner_active
            && !settings.maintenance_banner_text.trim().is_empty()
        {
            Some(settings.maintenance_banner_text.clone())
        } else {
            None
        },
        maintenance_blocks_validations: settings.maintenance_block_validations,
    }
}

async fn load_site_settings(state: &AppState) -> SiteSettings {
    let store = &state.provider_configs;
    SiteSettings {
        announcement_text: store
            .load_runtime_setting(SITE_SETTING_ANNOUNCEMENT_TEXT)
            .await
            .unwrap_or_default(),
        announcement_active: parse_active_flag(
            store
                .load_runtime_setting(SITE_SETTING_ANNOUNCEMENT_ACTIVE)
                .await,
        ),
        maintenance_banner_text: store
            .load_runtime_setting(SITE_SETTING_MAINTENANCE_BANNER_TEXT)
            .await
            .unwrap_or_default(),
        maintenance_banner_active: parse_active_flag(
            store
                .load_runtime_setting(SITE_SETTING_MAINTENANCE_BANNER_ACTIVE)
                .await,
        ),
        maintenance_block_validations: parse_active_flag(
            store
                .load_runtime_setting(SITE_SETTING_MAINTENANCE_BLOCK_VALIDATIONS)
                .await,
        ),
    }
}

async fn load_public_status(state: &AppState) -> PublicStatus {
    let guard_statuses = match &state.provider_guard {
        Some(guard) => Some(guard.status().await),
        None => None,
    };
    let settings = load_site_settings(state).await;
    build_public_status(guard_statuses, &settings)
}

/// GET /v1/status — publik, tanpa login, hanya agregat aman.
async fn public_status_json(State(state): State<AppState>) -> Response {
    let mut response = Json(load_public_status(&state).await).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    response
}

/// GET /status — halaman HTML dengan data yang sama dengan /v1/status.
/// Teks banner dirender lewat `html_escape` (bukan mentah), sehingga
/// karakter `<`, `>`, `&` dari teks admin tidak pernah menjadi markup.
async fn public_status_page(State(state): State<AppState>) -> Response {
    let status = load_public_status(&state).await;
    let mut response = Html(render_public_status_page(&status)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    response
}

/// Perender murni halaman /status (dipakai handler + tes escaping).
fn render_public_status_page(status: &PublicStatus) -> String {
    let mut rows = String::new();
    for product in &status.products {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            html_escape(product.label),
            html_escape(product.status),
        ));
    }
    let announcement = match &status.announcement {
        Some(text) => format!(
            "<div class=\"banner announcement\" role=\"note\">{}</div>",
            html_escape(text)
        ),
        None => String::new(),
    };
    let maintenance = match &status.maintenance_banner {
        Some(text) => format!(
            "<div class=\"banner maintenance\" role=\"note\">{}</div>",
            html_escape(text)
        ),
        None => String::new(),
    };
    let blocking = if status.maintenance_blocks_validations {
        "<p>Validasi sedang ditangguhkan sementara karena pemeliharaan.</p>"
    } else {
        ""
    };
    format!(
        "<!doctype html><html lang=\"id\"><head><meta charset=\"utf-8\" />\
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\
        <title>Status Layanan — Rajacek</title>\
        <style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 20px;color:#0f172a}}table{{width:100%;border-collapse:collapse}}td{{padding:10px 0;border-top:1px solid #e2e8f0}}.banner{{padding:12px 16px;border-radius:12px;margin:16px 0}}.announcement{{background:#ecfdf5;border:1px solid #a7f3d0}}.maintenance{{background:#fffbeb;border:1px solid #fde68a}}</style>\
        </head><body><h1>Status Layanan</h1>\
        <p>Status keseluruhan: <strong>{}</strong></p>\
        {}{}<table><tbody>{}</tbody></table>{}\
        <p><a href=\"/\">Kembali ke beranda</a></p></body></html>",
        html_escape(status.overall),
        announcement,
        maintenance,
        rows,
        blocking,
    )
}

/// Sakelar blokir validasi saja (satu kunci, satu query berindeks).
/// Tanpa database atau kunci hilang: false — validasi berjalan normal.
async fn maintenance_blocks_validations(state: &AppState) -> bool {
    parse_active_flag(
        state
            .provider_configs
            .load_runtime_setting(SITE_SETTING_MAINTENANCE_BLOCK_VALIDATIONS)
            .await,
    )
}

/// Menyimpan satu kunci runtime_settings beserta `updated_by` (email
/// admin). Mengembalikan false bila database tidak terpasang atau
/// tulis gagal — pemanggil memutuskan apakah itu fatal.
async fn save_site_setting(
    state: &AppState,
    key: &str,
    value: &str,
    updated_by: &str,
) -> bool {
    let Some(pool) = state.store.pool() else {
        return false;
    };
    sqlx::query(
        "INSERT INTO runtime_settings (setting_key, setting_value, updated_by) \
         VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), \
         updated_by = VALUES(updated_by)",
    )
    .bind(key)
    .bind(value)
    .bind(updated_by)
    .execute(&pool)
    .await
    .is_ok()
}

// AUTHZ-ROLE: Manager
async fn get_site_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SiteSettings>, AppError> {
    require_admin_role(&state, &headers, Role::Manager).await?;
    Ok(Json(load_site_settings(&state).await))
}

// AUTHZ-ROLE: Manager
async fn update_site_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SiteSettings>,
) -> Result<Json<SiteSettings>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    if input.announcement_text.chars().count() > SITE_SETTING_TEXT_MAX_LEN
        || input.maintenance_banner_text.chars().count() > SITE_SETTING_TEXT_MAX_LEN
    {
        return Err(AppError::bad_request(
            "Teks pengumuman dan banner maintenance maks 2000 karakter",
        ));
    }
    if state.store.pool().is_none() {
        return Err(AppError::service_unavailable(
            "Pengaturan situs belum tersedia (database tidak terpasang).",
        ));
    }
    let previous = load_site_settings(&state).await;
    let block_changed =
        previous.maintenance_block_validations != input.maintenance_block_validations;
    let email = principal.email.clone();
    let entries = [
        (
            SITE_SETTING_ANNOUNCEMENT_TEXT,
            input.announcement_text.as_str(),
        ),
        (
            SITE_SETTING_ANNOUNCEMENT_ACTIVE,
            if input.announcement_active { "1" } else { "0" },
        ),
        (
            SITE_SETTING_MAINTENANCE_BANNER_TEXT,
            input.maintenance_banner_text.as_str(),
        ),
        (
            SITE_SETTING_MAINTENANCE_BANNER_ACTIVE,
            if input.maintenance_banner_active {
                "1"
            } else {
                "0"
            },
        ),
        (
            SITE_SETTING_MAINTENANCE_BLOCK_VALIDATIONS,
            if input.maintenance_block_validations {
                "1"
            } else {
                "0"
            },
        ),
    ];
    for (key, value) in entries {
        if !save_site_setting(&state, key, value, &email).await {
            return Err(AppError::service_unavailable(
                "Pengaturan situs gagal disimpan.",
            ));
        }
    }
    // Sakelar blokir WAJIB tercatat di audit; perubahan nilainya
    // mendapat judul sendiri agar mudah dicari di jejak audit.
    // Teks banner dipotong di detail audit (bukan isi penuh).
    let truncate = |text: &str| -> String {
        let mut clipped: String = text.chars().take(120).collect();
        if text.chars().count() > 120 {
            clipped.push('…');
        }
        clipped
    };
    let (title, detail) = if block_changed {
        (
            "Blokir validasi maintenance diubah",
            format!(
                "Blokir validasi maintenance: {} → {}. Pengumuman: {}. Banner maintenance: {}.",
                if previous.maintenance_block_validations {
                    "aktif"
                } else {
                    "nonaktif"
                },
                if input.maintenance_block_validations {
                    "aktif"
                } else {
                    "nonaktif"
                },
                if input.announcement_active {
                    format!("aktif ({})", truncate(&input.announcement_text))
                } else {
                    "nonaktif".to_owned()
                },
                if input.maintenance_banner_active {
                    format!("aktif ({})", truncate(&input.maintenance_banner_text))
                } else {
                    "nonaktif".to_owned()
                },
            ),
        )
    } else {
        (
            "Pengaturan pengumuman & maintenance diperbarui",
            format!(
                "Pengumuman: {}. Banner maintenance: {}. Blokir validasi: {}.",
                if input.announcement_active {
                    format!("aktif ({})", truncate(&input.announcement_text))
                } else {
                    "nonaktif".to_owned()
                },
                if input.maintenance_banner_active {
                    format!("aktif ({})", truncate(&input.maintenance_banner_text))
                } else {
                    "nonaktif".to_owned()
                },
                if input.maintenance_block_validations {
                    "aktif"
                } else {
                    "nonaktif"
                },
            ),
        )
    };
    record_admin_activity(&state, &principal, title, detail).await;
    Ok(Json(load_site_settings(&state).await))
}

async fn auth_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<crate::models::AuthSessionResponse> {
    Json(
        auth::auth_session_response_checked(&state.config, &headers, &state.session_revocation)
            .await,
    )
}

async fn list_bank_codes() -> Json<Vec<crate::bank_codes::PublicBankCode>> {
    Json(bank_codes::public_list())
}

/// Admin-only full catalog (includes the upstream mapping codes the
/// provider tester needs). The public endpoint never exposes them.
async fn list_bank_codes_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<&'static [crate::bank_codes::BankCode]>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(bank_codes::list()))
}

async fn local_login(
    State(state): State<AppState>,
    Json(input): Json<LocalLoginRequest>,
) -> Result<Response, AppError> {
    // Audit 2026-10-25, B12: admin login/logout (success AND failure)
    // go to the durable audit log. Auth logic itself is untouched —
    // only the outcome is recorded. Member-role local logins are not
    // admin actions, so only the admin address is recorded as a login;
    // failures are recorded for any attempted address (forensics).
    let email = input.email.trim().to_ascii_lowercase();
    match auth::local_login_response(&state.config, input) {
        Ok(response) => {
            if auth::is_local_admin_email(&email) {
                record_admin_activity(
                    &state,
                    &audit_principal(&email),
                    "Login admin lokal berhasil",
                    format!("Login lokal admin {email} berhasil."),
                )
                .await;
            }
            Ok(response)
        }
        Err(error) => {
            record_admin_activity(
                &state,
                &audit_principal(&email),
                "Login lokal gagal",
                format!("Percobaan login lokal {email} gagal."),
            )
            .await;
            Err(error)
        }
    }
}

async fn google_login_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    if !state.config.google_login_is_configured() {
        return Err(AppError::service_unavailable(
            "Login Google belum dikonfigurasi. Lengkapi GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, DATABASE_URL, REDIS_URL, dan DASHBOARD_SESSION_SECRET.",
        ));
    }
    // Light per-IP throttle (audit flow K18), mirroring the member
    // start endpoint; cap + TTL in the state store are unchanged.
    let ip = effective_client_ip(&headers, address.ip()).to_string();
    if !auth::oauth_start_allowed(&ip) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Terlalu banyak percobaan masuk. Coba lagi dalam beberapa menit.",
        ));
    }
    Ok(auth::google_login_start(state.config, state.oauth_states)
        .await?
        .into_response())
}

async fn google_login_callback(
    State(state): State<AppState>,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<Response, AppError> {
    // B12, same pattern as local login: the auth flow in auth.rs is
    // unchanged; only its outcome is recorded, with the verified admin
    // email on success (the callback now returns it alongside the
    // redirect). On failure the email is not reliably known, so the
    // actor is "unknown" rather than a guess.
    match auth::google_login_callback(state.config.clone(), state.oauth_states.clone(), query)
        .await
    {
        Ok((response, email)) => {
            record_admin_activity(
                &state,
                &audit_principal(&email),
                "Login admin Google berhasil",
                format!("Login Google admin {email} berhasil."),
            )
            .await;
            Ok(response)
        }
        Err(error) => {
            record_admin_activity(
                &state,
                &audit_principal("unknown"),
                "Login admin Google gagal",
                "Percobaan login Google admin gagal (akun ditolak, state tidak valid, atau Google menolak kode).".to_owned(),
            )
            .await;
            Err(error)
        }
    }
}

#[derive(Serialize)]
struct AdminLogoutResponse {
    revoked: bool,
    warning: Option<String>,
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Honest logout (audit flow B5): the cookies are cleared either
    // way, but a failed server-side revoke is reported in the body
    // instead of a silent 204. B12: the logout is recorded when the
    // session identifies an admin; a logout with no valid admin
    // session has no actor worth recording. An already-revoked or
    // expired token (or no token at all) counts as revoked — there
    // is nothing left to revoke.
    let principal = auth::session_from_headers(&state.config, &headers);
    let mut revoked = true;
    if let Some((jti, exp)) = auth::session_token_from_headers(&state.config, &headers) {
        let ttl = exp.saturating_sub(chrono::Utc::now().timestamp() as usize);
        revoked = state
            .session_revocation
            .revoke(&jti, std::time::Duration::from_secs(ttl as u64))
            .await;
    }
    if let Some(principal) = &principal {
        let detail = if revoked {
            format!("Admin {} keluar.", principal.email)
        } else {
            format!("Admin {} keluar (peringatan: revocasi sesi gagal).", principal.email)
        };
        record_admin_activity(&state, principal, "Logout admin", detail).await;
    }
    let warning = if revoked {
        None
    } else {
        Some(
            "Sesi server tidak berhasil dicabut (Redis tidak terjangkau). Cookie browser sudah dihapus, tetapi token lama masih bisa berlaku sampai kedaluwarsa."
                .to_owned(),
        )
    };
    let mut response = Json(AdminLogoutResponse { revoked, warning }).into_response();
    // Reuse the cookie-clearing headers from the shared logout
    // response (domain + host-only variants, with Secure as configured).
    let clears = auth::logout_response(&state.config);
    for (name, value) in clears.headers() {
        if name.as_str() == "set-cookie" {
            response.headers_mut().append(name.clone(), value.clone());
        }
    }
    response
}

async fn validate_bank_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Extension(RequestStart(request_started)): Extension<RequestStart>,
    Json(input): Json<BankAccountValidationRequest>,
) -> Result<Response, AppError> {
    let request = normalize_bank_request(input)?;
    validate(state, headers, address, request, request_started).await
}

async fn validate_ewallet(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Extension(RequestStart(request_started)): Extension<RequestStart>,
    Json(input): Json<EwalletValidationRequest>,
) -> Result<Response, AppError> {
    let request = normalize_ewallet_request(input)?;
    validate(state, headers, address, request, request_started).await
}

async fn validate_whatsapp(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Extension(RequestStart(request_started)): Extension<RequestStart>,
    Json(input): Json<WhatsappValidationRequest>,
) -> Result<Response, AppError> {
    let request = normalize_whatsapp_request(input)?;
    validate(state, headers, address, request, request_started).await
}

/// Client IP for rate limiting. The TCP peer is authoritative, except when the
/// peer is loopback (the local reverse proxy): then a proxy header wins.
/// Remote peers can never spoof a header into the limiter, because for
/// them every header is ignored entirely.
/// Header trust order for loopback peers (audit flow K14): Cloudflare
/// overwrites `CF-Connecting-IP` (it does not append to it), so the
/// client cannot forge it the way it can forge the FIRST entry of an
/// appended `X-Forwarded-For` chain — prefer it when present and
/// parseable, and fall back to the old first-XFF behavior otherwise.
/// Limitation, kept deliberately: when CF-Connecting-IP is absent, the
/// first XFF entry is still spoofable (a client can rotate throttle /
/// per-IP buckets at will); the per-API-key bucket is unaffected, and
/// this only ever applies to loopback peers, i.e. requests that came
/// through the local nginx proxy.
pub(crate) fn effective_client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if !peer.is_loopback() {
        return peer;
    }
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|first| first.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

async fn validate(
    state: AppState,
    headers: HeaderMap,
    address: SocketAddr,
    request: ProviderValidationRequest,
    request_started: Instant,
) -> Result<Response, AppError> {
    let request_id = request_id(&headers);
    let raw_api_key = api_key_from_headers(&headers)
        .ok_or_else(|| AppError::unauthorized("Header API key tidak ditemukan"))?;
    let api_key = state
        .store
        .authenticate_api_key(raw_api_key)
        .await
        .map_err(|error| error.with_request_id(request_id.clone()))?;
    let (raw_idempotency_key, idempotency_generated) = idempotency_key_or_generate(&headers)
        .map_err(|error| error.with_request_id(request_id.clone()))?;
    let client_ip = effective_client_ip(&headers, address.ip());
    let mut response = execute_validation(
        state,
        api_key,
        client_ip,
        raw_idempotency_key.clone(),
        request,
        request_started,
        request_id,
        "api",
    )
    .await?;
    if idempotency_generated {
        if let Ok(value) = HeaderValue::from_str(&raw_idempotency_key) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("idempotency-key"), value);
        }
    }
    Ok(response)
}

/// The shared validation pipeline (scope, idempotency, rate limit, quota,
/// provider, ledger event) used by the public API and by the member
/// portal's live-check sandbox. `channel` marks where the check came from
/// ("api" | "portal") and is stored with the history record.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_validation(
    state: AppState,
    api_key: crate::models::ApiKeyContext,
    client_ip: std::net::IpAddr,
    raw_idempotency_key: String,
    request: ProviderValidationRequest,
    request_started: Instant,
    request_id: String,
    channel: &'static str,
) -> Result<Response, AppError> {
    // AREA 6 — sakelar maintenance: bila aktif, SEMUA jalur validasi
    // (API /v1/validate/* maupun portal "Coba Cek Live", karena keduanya
    // lewat fungsi ini) ditolak 503 SEBELUM scope, idempotensi, maupun
    // kuota tersentuh, sehingga tidak ada hit yang terpotong. Health,
    // login, portal, dan endpoint lain tidak lewat sini dan tidak
    // diblokir. Default (kunci hilang / tanpa database): tidak memblokir.
    if maintenance_blocks_validations(&state).await {
        return Err(AppError::service_unavailable(MAINTENANCE_MESSAGE)
            .with_request_id(request_id));
    }
    if !has_scope(&api_key.scopes, request.product) {
        return Err(
            AppError::forbidden("API key tidak memiliki scope untuk produk ini")
                .with_request_id(request_id),
        );
    }

    // Idempotency is resolved BEFORE rate limiting: a replay is not new work, so it must
    // not consume rate-limit budget, and a malformed Idempotency-Key is rejected
    // before it can burn any admission quota (a missing one was generated upstream).
    let idempotency_key = format!("{}:{}", api_key.prefix, raw_idempotency_key);
    let fingerprint = target_fingerprint(
        &state.config,
        request.product,
        &request.target,
        request.provider_hint.as_deref().unwrap_or(""),
    );

    match state
        .idempotency
        .begin(&idempotency_key, &fingerprint)
        .await
        .map_err(|error| error.with_request_id(request_id.clone()))?
    {
        IdempotencyDecision::Replay(mut replay) => {
            replay.request_id = request_id.clone();
            replay.meta.cached = true;
            replay.meta.total_latency_ms = request_started.elapsed().as_millis() as u64;
            // A replay performs no provider work, and the stored quota
            // figure is stale by the time it is served: report zero
            // processing and refresh the quota from live state
            // (audit 2026-10-25, K10).
            replay.meta.rajacek_processing_ms = 0;
            if let Some(current) = state.store.quota_remaining(&api_key.prefix).await {
                replay.meta.remaining_quota = current;
            }
            return Ok(validation_response(replay, None, true));
        }
        IdempotencyDecision::Execute => {}
    }

    // K8, accepted trade-off (documented, not changed): the provider
    // guard (breaker-open / semaphore-full / pacer-shed) is only consulted
    // inside provider.validate(), AFTER this admission and the quota
    // reserve below. A breaker-open rejection therefore refunds the quota
    // but still spends one rate-limit slot. Moving a breaker peek before
    // admit was rejected deliberately: it would be racy (a breaker can
    // open, or its cooldown can expire, between peek and acquire, causing
    // false rejections of requests that would have succeeded), it cannot
    // cover semaphore-full or pacer-shed rejections anyway (those are
    // only meaningful at dispatch time), and it would duplicate the
    // guard's admission logic in a second place. Quota-refund behavior
    // is unchanged: guard rejections always refund exactly once.
    let admission = match state
        .rate_limiter
        .admit(
            &api_key.prefix,
            &client_ip.to_string(),
            api_key.rate_limit_per_minute,
        )
        .await
    {
        Ok(admission) => admission,
        Err(error) => {
            state
                .idempotency
                .abandon(&idempotency_key, &fingerprint)
                .await;
            return Err(error.with_request_id(request_id));
        }
    };
    if !admission.allowed {
        state
            .idempotency
            .abandon(&idempotency_key, &fingerprint)
            .await;
        return Err(AppError::too_many_requests(
            "Batas permintaan tercapai. Silakan coba kembali setelah jeda yang ditentukan.",
            admission.retry_after_seconds,
        )
        .with_request_id(request_id));
    }

    // Bucket yang dipotong dicatat agar setiap refund di bawah ini
    // mengembalikan hit ke bucket yang SAMA (bukan bucket FIFO-pertama
    // saat itu, yang bisa berbeda bila grant/assign mendarat di tengah).
    let (remaining_quota, reserved_bucket) =
        match state.store.reserve_quota(&api_key.prefix).await {
            Ok((remaining, bucket_id)) => (remaining, bucket_id),
            Err(error) => {
                state
                    .idempotency
                    .abandon(&idempotency_key, &fingerprint)
                    .await;
                return Err(error.with_request_id(request_id));
            }
        };

    let outcome = match state.provider.validate(request.clone()).await {
        Ok(outcome) => outcome,
        Err(error) => {
            state.store.refund_quota(&api_key.prefix, reserved_bucket).await;
            state
                .idempotency
                .abandon(&idempotency_key, &fingerprint)
                .await;
            return Err(error.with_request_id(request_id));
        }
    };

    // Billing decision (rule 2026-10-25). The 1-hit reserve above is KEPT
    // deliberately: a zero-balance key still fails with 402 BEFORE
    // validation (reserve_quota), so the free pool is only usable while
    // the balance is above zero. Do not restructure this into
    // validate-then-charge.
    //
    // - Valid / NotKyc: always charged (reserve stands).
    // - Invalid / NotFound: free while the per-key per-WIB-day pool
    //   (100) still has room — claim the slot, then refund in full
    //   (net 0). Once exhausted, the reserve stands like any charge.
    // - Pending / ProviderError / RateLimited / QuotaExhausted: never
    //   charged, never draw from the pool (refund in full).
    // Idempotent replays return before this point and never reach a claim.
    let wib_day = crate::models::wib_date(Utc::now());
    let mut charged = outcome.status.is_billable();
    let mut free_invalid = false;
    if outcome.status.is_invalid_pool() {
        if state
            .store
            .claim_invalid_free_slot(&api_key.prefix, wib_day)
            .await
        {
            free_invalid = true;
            charged = false;
            state.store.refund_quota(&api_key.prefix, reserved_bucket).await;
        }
    } else if !outcome.status.is_billable() {
        state.store.refund_quota(&api_key.prefix, reserved_bucket).await;
    }

    let total_latency_ms = request_started.elapsed().as_millis() as u64;
    let rajacek_processing_ms = total_latency_ms.saturating_sub(outcome.provider_latency_ms);
    let response = ValidationResponse {
        request_id: request_id.clone(),
        status: outcome.status,
        valid: outcome.status.is_success(),
        product: request.product,
        message: outcome.message,
        result: outcome.result.clone(),
        meta: ValidationMeta {
            // Public responses never identify the upstream provider: the
            // configured endpoint name stays visible only in the admin
            // tester. Members always see the platform's own label.
            provider: "Rajacek".to_owned(),
            provider_latency_ms: outcome.provider_latency_ms,
            attempts: outcome.attempts,
            rajacek_processing_ms,
            total_latency_ms,
            cached: false,
            // Uncharged outcomes are refunded above; re-read the live
            // figure instead of guessing reserve+1, which overstates the
            // quota under concurrency (audit 2026-10-25, K2). This covers
            // both never-billable outcomes and free-pool invalid results.
            remaining_quota: if charged {
                remaining_quota
            } else {
                state
                    .store
                    .quota_remaining(&api_key.prefix)
                    .await
                    .unwrap_or_else(|| remaining_quota.saturating_add(1))
            },
        },
    };

    // Admin history only (migration 0024): the raw target as submitted
    // and the holder name exactly as returned upstream. The name is taken
    // from `outcome` BEFORE the reference move below, and is deliberately
    // NOT uppercased here — validation_response uppercases its own copy
    // for the member JSON, while history keeps the upstream form. For
    // e-wallet NotKyc the provider logic already set account_name to None.
    let history_account_name = outcome
        .result
        .as_ref()
        .and_then(|result| result.account_name.clone());
    let usage_event = UsageEvent {
        event_id: Uuid::now_v7(),
        request_id: request_id.clone(),
        idempotency_key: Some(raw_idempotency_key),
        api_key_prefix: api_key.prefix.clone(),
        product: request.product,
        status: outcome.status,
        charged,
        price_snapshot_id: None,
        occurred_at: Utc::now(),
        target_fingerprint: fingerprint.clone(),
        target_masked: mask_target(request.product, &request.target),
        target_raw: Some(request.target.clone()),
        account_name: history_account_name,
        provider_reference: outcome.result.and_then(|result| result.reference),
        provider_latency_ms: outcome.provider_latency_ms,
        rajacek_processing_ms,
        total_latency_ms,
        attempts: outcome.attempts,
        channel: channel.to_owned(),
    };

    let history_item = ValidationHistoryItem {
        request_id: usage_event.request_id.clone(),
        api_key_prefix: usage_event.api_key_prefix.clone(),
        product: usage_event.product,
        outcome: usage_event.status.as_str().to_owned(),
        target_masked: usage_event.target_masked.clone(),
        target_raw: usage_event.target_raw.clone(),
        account_name: usage_event.account_name.clone(),
        provider_reference: usage_event.provider_reference.clone(),
        provider_latency_ms: usage_event.provider_latency_ms,
        rajacek_processing_ms: Some(usage_event.rajacek_processing_ms),
        total_latency_ms: Some(usage_event.total_latency_ms),
        attempts: Some(usage_event.attempts),
        occurred_at: usage_event.occurred_at,
        channel: usage_event.channel.clone(),
    };

    if let Err(error) = state.event_sink.enqueue(usage_event).await {
        // No ledger event = no delivery: reverse the charge, or return a
        // free-pool slot the member never got a result for.
        if charged {
            state.store.refund_quota(&api_key.prefix, reserved_bucket).await;
        } else if free_invalid {
            state
                .store
                .release_invalid_free_slot(&api_key.prefix, wib_day)
                .await;
        }
        state
            .idempotency
            .abandon(&idempotency_key, &fingerprint)
            .await;
        return Err(error.with_request_id(request_id));
    }

    // Mirror into the in-memory fallback history (used when MySQL is absent).
    state.store.push_validation_history(history_item).await;

    if let Err(error) = state
        .idempotency
        .complete(&idempotency_key, &fingerprint, response.clone())
        .await
    {
        // The usage event is already durably queued, so the ledger WILL record this
        // validation. Failing the request here would lie to the client (an error for a
        // charged, completed validation) and a retry could not replay anyway. Log loudly
        // and still return the completed response; the in-flight entry expires on its own.
        //
        // K11(a) (audit 2026-10-25) — ACCEPTED TRADE-OFF, documented, no
        // recovery queue built (out of scope for this fix): if complete()
        // fails here AND the response is lost in transit AND the client
        // retries with the same key AFTER the 300-second in-flight TTL, the
        // retry will Execute again and charge a second time for one logical
        // request. All three conditions must coincide (Redis failing at
        // exactly complete(), plus a lost response, plus a retry delayed
        // past the TTL), so the chain is rare; a durable recovery queue
        // for failed completions would be the full fix if this is ever
        // judged material.
        tracing::error!(
            request_id = %request_id,
            error = ?error,
            "Respons tidak dapat disimpan untuk replay idempotensi; event penggunaan sudah terantre sehingga respons tetap dikembalikan"
        );
    }

    // Dashboard activity is non-critical telemetry. It must never delay the member-facing
    // response; durable billing/audit recovery is handled by the queued usage event above.
    let activity_store = state.store.clone();
    let activity = ActivityItem {
        id: Uuid::now_v7(),
        title: format!("{} diproses", request.product.label_id()),
        detail: format!(
            "{} • {} • {} ms",
            mask_target(request.product, &request.target),
            outcome.provider_name,
            outcome.provider_latency_ms
        ),
        product: Some(request.product),
        status: outcome.status.as_str().to_owned(),
        occurred_at: Utc::now(),
        provider_latency_ms: Some(outcome.provider_latency_ms),
    };
    tokio::spawn(async move {
        activity_store.append_activity(activity).await;
    });

    Ok(validation_response(response, Some(&admission), false))
}

async fn admin_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::models::DashboardOverview>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(
        state
            .store
            .dashboard_overview(
                format!("{:?}", state.config.environment).to_ascii_lowercase(),
                state.config.is_demo_mode(),
            )
            .await,
    ))
}

#[derive(Deserialize)]
struct AnalyticsQuery {
    days: Option<i64>,
}

// AUTHZ-ROLE: Viewer
// Analitik riil (AREA 1): pendapatan dari package_orders (hanya status
// `paid`/`granted`, lihat analytics::REVENUE_STATUSES), hit harian per
// produk + success rate per produk dari validation_requests. Rentang
// di-clamp (default 30, maks 90 hari) dan respons di-cache 60 detik di
// AdminStore. Tanpa database: respons kosong (angka nol = tidak
// diketahui), bukan error. Penegakan peran Viewer aktif
// (require_admin_role, ditegakkan server-side).
async fn admin_analytics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<crate::analytics::AnalyticsResponse>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let days = crate::analytics::clamp_analytics_days(query.days);
    if let Some(cached) = state.store.cached_analytics(days) {
        return Ok(Json(cached));
    }
    let Some(pool) = state.store.pool() else {
        return Ok(Json(crate::analytics::AnalyticsResponse::empty(days)));
    };
    let response = crate::analytics::analytics_from_db(&pool, days)
        .await
        .ok_or_else(|| AppError::internal("Analitik gagal dibaca dari database"))?;
    state.store.store_cached_analytics(days, response.clone());
    Ok(Json(response))
}

// AUTHZ-ROLE: Viewer
// Monitor kesehatan rute (AREA 2): per rute = status circuit breaker
// dari guard in-memory + flag aktif dari katalog (latensi/success per
// rute TIDAK tersedia — ledger tidak menyimpan id rute, nilainya null);
// per produk = latensi rata-rata/p95 + success rate + jumlah error
// 24 jam terakhir dari validation_requests. Failover manual TIDAK
// dibuat baru di sini: PATCH /v1/admin/provider-endpoints/:id/active
// SUDAH ADA dan SUDAH mencatat audit (record_admin_activity) — panel
// memakai endpoint itu. Penegakan peran Viewer aktif
// (require_admin_role, ditegakkan server-side).
async fn admin_providers_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::analytics::ProvidersHealthResponse>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let endpoints = state.provider_configs.list().await;
    let guard_snapshot = match &state.provider_guard {
        Some(guard) => Some(guard.endpoint_snapshot().await),
        None => None,
    };
    let pool = state.store.pool();
    Ok(Json(
        crate::analytics::providers_health(pool.as_ref(), &endpoints, guard_snapshot).await,
    ))
}

async fn list_products(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminProduct>>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(state.store.list_products().await))
}

async fn update_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateProductRequest>,
) -> Result<Json<AdminProduct>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let product = state.store.update_product(id, input).await?;
    record_admin_activity(
        &state,
        &principal,
        "Produk diperbarui",
        format!("{} diperbarui dari dashboard admin.", product.name),
    )
    .await;
    Ok(Json(product))
}

async fn list_provider_endpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProviderEndpoint>>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(state.provider_configs.list().await))
}

/// Switching a server ON in the admin panel is an explicit operator
/// decision: it force-closes that server's circuit breaker (failure history
/// forgotten) so the server serves again immediately instead of waiting
/// out the automatic cooldown.
async fn reset_breaker_if_active(state: &AppState, endpoint: &ProviderEndpoint) {
    if endpoint.active {
        if let Some(guard) = &state.provider_guard {
            guard.reset_endpoint(&endpoint.id.to_string()).await;
        }
    }
}

async fn create_provider_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<crate::models::CreateProviderEndpointRequest>,
) -> Result<(StatusCode, Json<ProviderEndpoint>), AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let product = input.product;
    let endpoint = state.provider_configs.create(input).await?;
    reset_breaker_if_active(&state, &endpoint).await;
    record_admin_activity(
        &state,
        &principal,
        "Server provider ditambahkan",
        format!(
            "Server {} untuk {} ditambahkan; kredensial tetap dimasking.",
            endpoint.name,
            product.label_id()
        ),
    )
    .await;
    Ok((StatusCode::CREATED, Json(endpoint)))
}

async fn update_provider_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateProviderEndpointRequest>,
) -> Result<Json<ProviderEndpoint>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let endpoint = state.provider_configs.update_by_id(id, input).await?;
    reset_breaker_if_active(&state, &endpoint).await;
    record_admin_activity(
        &state,
        &principal,
        "Endpoint provider diperbarui",
        format!(
            "Server {} ({}) diperbarui; kredensial tetap dimasking.",
            endpoint.name,
            endpoint.product.label_id()
        ),
    )
    .await;
    Ok(Json(endpoint))
}

#[derive(Deserialize)]
struct SetEndpointActiveInput {
    active: bool,
}

async fn set_provider_endpoint_active(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SetEndpointActiveInput>,
) -> Result<Json<ProviderEndpoint>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let endpoint = state.provider_configs.set_active(id, input.active).await?;
    reset_breaker_if_active(&state, &endpoint).await;
    record_admin_activity(
        &state,
        &principal,
        if input.active {
            "Server provider diaktifkan"
        } else {
            "Server provider dinonaktifkan"
        },
        format!(
            "Server {} ({}) kini {}.",
            endpoint.name,
            endpoint.product.label_id(),
            if input.active { "aktif" } else { "nonaktif" }
        ),
    )
    .await;
    Ok(Json(endpoint))
}

async fn delete_provider_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    // Resolve first so the audit row can name the endpoint (B12: no
    // generic "one server deleted" rows); delete() itself returns ().
    let endpoint = state
        .provider_configs
        .resolve_by_id(id)
        .await
        .ok_or_else(|| AppError::not_found("Endpoint provider tidak ditemukan"))?;
    state.provider_configs.delete(id).await?;
    record_admin_activity(
        &state,
        &principal,
        "Server provider dihapus",
        format!(
            "Server {} ({}, {}) dihapus dari konfigurasi.",
            endpoint.name,
            id,
            endpoint.product.label_id()
        ),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_provider_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ProviderEndpointTestResponse>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let endpoint = state
        .provider_configs
        .resolve_by_id(id)
        .await
        .ok_or_else(|| AppError::not_found("Endpoint provider tidak ditemukan"))?;
    let started = tokio::time::Instant::now();
    state
        .provider_configs
        .verify_destination(&endpoint.base_url)
        .await?;
    // The tester sends real validations, so its use is logged like any
    // other sensitive admin action (audit 2026-10-25, A4). No target, URL,
    // or upstream payload is recorded — only which endpoint was tested.
    record_admin_activity(
        &state,
        &principal,
        "Tes endpoint provider",
        format!(
            "Endpoint {} ({}) diverifikasi.",
            endpoint.name,
            endpoint.product.label_id()
        ),
    )
    .await;
    Ok(Json(ProviderEndpointTestResponse {
        reachable: true,
        provider: endpoint.name,
        latency_ms: started.elapsed().as_millis() as u64,
        message: "URL, host, DNS, dan kebijakan jaringan endpoint berhasil diverifikasi. Payload bisnis tidak dikirim pada tes ini.".to_owned(),
    }))
}

#[derive(Serialize)]
struct RateLimitDefaultResponse {
    default_per_minute: u32,
    /// Derived buckets the default drives: per-IP = default * 3, global = default * 100 (min 1000).
    ip_limit_per_minute: u32,
    global_limit_per_minute: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    persisted: Option<bool>,
}

#[derive(Deserialize)]
struct RateLimitDefaultInput {
    default_per_minute: u32,
}

fn rate_limit_default_response(
    state: &AppState,
    persisted: Option<bool>,
) -> RateLimitDefaultResponse {
    let default = state.rate_limiter.default_limit_per_minute();
    RateLimitDefaultResponse {
        default_per_minute: default,
        ip_limit_per_minute: default.saturating_mul(3),
        global_limit_per_minute: default.saturating_mul(100).max(1_000),
        persisted,
    }
}

async fn get_rate_limit_default(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RateLimitDefaultResponse>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(rate_limit_default_response(&state, None)))
}

async fn update_rate_limit_default(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RateLimitDefaultInput>,
) -> Result<Json<RateLimitDefaultResponse>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    if !(1..=100_000).contains(&input.default_per_minute) {
        return Err(AppError::bad_request(
            "Rate limit bawaan harus antara 1 dan 100000 per menit",
        ));
    }
    state
        .rate_limiter
        .set_default_limit_per_minute(input.default_per_minute);
    state
        .store
        .set_default_rate_limit_per_minute(input.default_per_minute);
    let persisted = state
        .provider_configs
        .save_runtime_setting(
            "rate_limit.default_per_minute",
            &input.default_per_minute.to_string(),
        )
        .await;
    record_admin_activity(
        &state,
        &principal,
        "Rate limit bawaan diperbarui",
        format!(
            "Menjadi {} request/menit per kunci (IP {}, global {}){}",
            input.default_per_minute,
            input.default_per_minute.saturating_mul(3),
            input.default_per_minute.saturating_mul(100).max(1_000),
            if persisted {
                ""
            } else {
                " (hanya di memori proses; database tidak terhubung)"
            }
        ),
    )
    .await;
    Ok(Json(rate_limit_default_response(&state, Some(persisted))))
}

#[derive(Deserialize)]
struct ValidationHistoryQuery {
    limit: Option<u32>,
    offset: Option<u32>,
    product: Option<String>,
    outcome: Option<String>,
    api_key_prefix: Option<String>,
    // AREA 5: parameter pencarian/filter baru (opsional; respons lama
    // tanpa parameter ini tidak berubah bentuk). `status` adalah alias
    // untuk `outcome`; bila keduanya diisi dan berbeda -> 400.
    q: Option<String>,
    status: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Serialize)]
struct ValidationHistoryResponse {
    // Admin-only shape: carries target_raw + account_name (migration
    // 0024). The member endpoint returns ValidationHistoryItem directly
    // and therefore never serializes those fields.
    items: Vec<AdminValidationHistoryItem>,
    total: u64,
    limit: u32,
    offset: u32,
    /// "database" = durable MySQL history; "memory" = this process only, since startup.
    source: &'static str,
    /// Hit counts over rolling windows (same filters as the listing), for the
    /// admin recap cards: average hits per second / per minute.
    stats: ValidationHistoryStats,
}

#[derive(Serialize)]
struct ValidationHistoryStats {
    hits_last_60s: u64,
    hits_last_3600s: u64,
}

async fn admin_validation_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ValidationHistoryQuery>,
) -> Result<Json<ValidationHistoryResponse>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let limit = query.limit.unwrap_or(25).clamp(1, 100);
    let offset = query.offset.unwrap_or(0);
    let product = match query.product.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("bank_account") => Some(ValidationProduct::BankAccount),
        Some("ewallet") => Some(ValidationProduct::Ewallet),
        Some("whatsapp") => Some(ValidationProduct::Whatsapp),
        Some(other) => {
            return Err(AppError::bad_request(format!(
                "Produk tidak dikenal: {other}"
            )))
        }
    };
    let clean = |value: Option<String>| {
        value
            .map(|text| text.trim().to_lowercase())
            .filter(|text| !text.is_empty())
    };
    // AREA 5: `status` adalah alias `outcome` (bukan filter kedua).
    let outcome = match (clean(query.outcome), clean(query.status)) {
        (Some(outcome), Some(status)) if outcome != status => {
            return Err(AppError::bad_request(
                "Parameter outcome dan status berbeda; isi salah satu saja",
            ))
        }
        (Some(outcome), _) => Some(outcome),
        (None, status) => status,
    };
    let list_filters = parse_admin_list_filters(query.q, None, query.from, query.to)?;
    let filters = ValidationHistoryFilters {
        product,
        outcome,
        api_key_prefix: clean(query.api_key_prefix),
        api_key_prefixes: None,
        q: list_filters.q,
        from: list_filters.from.map(|naive| naive.and_utc()),
        to_exclusive: list_filters.to_exclusive.map(|naive| naive.and_utc()),
    };
    let page = fetch_validation_history(&state, &filters, limit, offset).await;
    Ok(Json(ValidationHistoryResponse {
        items: page
            .items
            .iter()
            .map(AdminValidationHistoryItem::from)
            .collect(),
        total: page.total,
        limit,
        offset,
        source: page.source,
        stats: ValidationHistoryStats {
            hits_last_60s: page.hits_last_60s,
            hits_last_3600s: page.hits_last_3600s,
        },
    }))
}

#[derive(Serialize)]
struct ProviderGuardResponse {
    settings: ProviderGuardConfig,
    products: Vec<GuardProductStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    persisted: Option<bool>,
}

fn require_provider_guard(state: &AppState) -> Result<&Arc<ProviderGuard>, AppError> {
    state.provider_guard.as_ref().ok_or_else(|| {
        AppError::service_unavailable(
            "Provider guard hanya aktif pada mode provider HTTP, bukan mode demo",
        )
    })
}

async fn get_provider_guard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProviderGuardResponse>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let guard = require_provider_guard(&state)?;
    Ok(Json(ProviderGuardResponse {
        settings: guard.config(),
        products: guard.status().await,
        persisted: None,
    }))
}

async fn update_provider_guard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ProviderGuardConfig>,
) -> Result<Json<ProviderGuardResponse>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let guard = require_provider_guard(&state)?;
    input.validate_for_admin()?;
    guard.update_config(input);
    let persisted = state.provider_configs.save_guard_config(&input).await;
    record_admin_activity(
        &state,
        &principal,
        "Pengaturan provider guard diperbarui",
        format!(
            "Konkurensi {}/produk, tunggu {} ms, ambang {}, cooldown {} dtk{}",
            input.max_concurrency_per_product,
            input.queue_wait_ms,
            input.failure_threshold,
            input.cooldown_seconds,
            if persisted {
                ""
            } else {
                " (hanya di memori proses; database tidak terhubung)"
            }
        ),
    )
    .await;
    Ok(Json(ProviderGuardResponse {
        settings: guard.config(),
        products: guard.status().await,
        persisted: Some(persisted),
    }))
}

async fn admin_provider_tester(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AdminProviderTesterRequest>,
) -> Result<Json<AdminProviderTesterResponse>, AppError> {
    let request_started = tokio::time::Instant::now();
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    if state.config.is_demo_mode() {
        return Err(AppError::service_unavailable(
            "Tester admin tidak mengizinkan provider demo. Aktifkan PROVIDER_MODE=http dan konfigurasi endpoint pihak ketiga terlebih dahulu.",
        ));
    }
    let endpoint_id = input.endpoint_id;
    let request = normalize_admin_tester_request(input)?;
    let (outcome, upstream_response) = match endpoint_id {
        Some(endpoint_id) => {
            state
                .provider
                .validate_for_admin_at(endpoint_id, request.clone())
                .await?
        }
        None => state.provider.validate_for_admin(request.clone()).await?,
    };
    let total_latency_ms = request_started.elapsed().as_millis() as u64;
    // The tester sends real validations and returns raw upstream payloads,
    // so its use is logged like any other sensitive admin action (audit
    // 2026-10-25, A4). No target or payload is recorded — only the product,
    // endpoint scope, and outcome.
    record_admin_activity(
        &state,
        &principal,
        "Tes validasi provider",
        format!(
            "Tester {} (endpoint {}) menghasilkan {}.",
            request.product.as_str(),
            endpoint_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "otomatis".to_owned()),
            outcome.status.as_str()
        ),
    )
    .await;
    Ok(Json(AdminProviderTesterResponse {
        status: outcome.status,
        valid: outcome.status.is_success(),
        product: request.product,
        message: outcome.message,
        result: outcome.result,
        provider: outcome.provider_name,
        provider_latency_ms: outcome.provider_latency_ms,
        rajacek_processing_ms: total_latency_ms.saturating_sub(outcome.provider_latency_ms),
        total_latency_ms,
        attempts: outcome.attempts,
        upstream_response,
    }))
}

fn normalize_admin_tester_request(
    input: AdminProviderTesterRequest,
) -> Result<ProviderValidationRequest, AppError> {
    match input.product {
        ValidationProduct::BankAccount => normalize_bank_request(BankAccountValidationRequest {
            bank_code: input
                .bank_code
                .ok_or_else(|| AppError::bad_request("code_bank wajib dipilih untuk tes bank"))?,
            account_number: input.target,
        }),
        ValidationProduct::Ewallet => normalize_ewallet_request(EwalletValidationRequest {
            provider: input.ewallet_provider.ok_or_else(|| {
                AppError::bad_request("Provider e-wallet wajib dipilih untuk tes e-wallet")
            })?,
            account_number: input.target,
        }),
        ValidationProduct::Whatsapp => normalize_whatsapp_request(WhatsappValidationRequest {
            phone_number: input.target,
        }),
    }
}

async fn list_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminPackage>>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(state.store.list_packages().await))
}

async fn create_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreatePackageRequest>,
) -> Result<(StatusCode, Json<AdminPackage>), AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let package = state.store.create_package(input).await?;
    record_admin_activity(
        &state,
        &principal,
        "Paket baru dibuat",
        format!("Paket {} berhasil diterbitkan.", package.name),
    )
    .await;
    Ok((StatusCode::CREATED, Json(package)))
}

async fn update_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdatePackageRequest>,
) -> Result<Json<AdminPackage>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let package = state.store.update_package(id, input).await?;
    record_admin_activity(
        &state,
        &principal,
        "Paket diperbarui",
        format!("Paket {} diperbarui.", package.name),
    )
    .await;
    Ok(Json(package))
}

async fn delete_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    // DB-first inside the store (B13): a database failure now fails
    // this handler instead of reporting a delete that resurrects on
    // restart. The returned detach count (K30) goes into the audit row.
    let deleted = state.store.delete_package(id).await?;
    record_admin_activity(
        &state,
        &principal,
        "Paket dihapus",
        format!(
            "Paket {} ({}) dihapus; {} kunci dilepas dari paket (kuota member dipertahankan).",
            deleted.name, id, deleted.keys_detached
        ),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_rate_limits(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::models::RateLimitPolicy>>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(state.store.list_rate_limit_policies().await))
}

async fn create_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateRateLimitPolicyRequest>,
) -> Result<(StatusCode, Json<crate::models::RateLimitPolicy>), AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let policy = state.store.create_rate_limit_policy(input).await?;
    record_admin_activity(
        &state,
        &principal,
        "Kebijakan rate limit dibuat",
        format!("{} aktif untuk scope {}.", policy.name, policy.scope),
    )
    .await;
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn update_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateRateLimitPolicyRequest>,
) -> Result<Json<crate::models::RateLimitPolicy>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let policy = state.store.update_rate_limit_policy(id, input).await?;
    record_admin_activity(
        &state,
        &principal,
        "Kebijakan rate limit diperbarui",
        format!("{} diperbarui.", policy.name),
    )
    .await;
    Ok(Json(policy))
}

async fn delete_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let policy = state.store.delete_rate_limit_policy(id).await?;
    record_admin_activity(
        &state,
        &principal,
        "Kebijakan rate limit dihapus",
        format!("Kebijakan {} ({}) dihapus.", policy.name, id),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Admin key list row (audit 2026-10-25, K32): the existing summary,
/// plus the owning member's email when the key belongs to one.
/// Purely additive — no existing summary field changes shape. When
/// the member directory is unavailable (no database), `owner_email`
/// is None and the panel falls back to "Member" for `member_id` keys
/// and "standalone" otherwise.
#[derive(Serialize)]
struct AdminApiKeyView {
    #[serde(flatten)]
    summary: crate::models::AdminApiKeySummary,
    owner_email: Option<String>,
    /// Final invalid results consumed from today's free pool (WIB) for
    /// this key; billing rule 2026-10-25 (100/day/key).
    invalid_free_used_today: u32,
}

async fn list_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminApiKeyView>>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let members = state.store.list_members().await;
    let wib_day = crate::models::wib_date(Utc::now());
    let mut views = Vec::new();
    for summary in state.store.list_api_keys().await {
        let owner_email = summary.member_id.and_then(|member_id| {
            members
                .iter()
                .find(|member| member.id == member_id)
                .map(|member| member.email.clone())
        });
        let invalid_free_used_today = state
            .store
            .invalid_free_used_today(&summary.prefix, wib_day)
            .await;
        views.push(AdminApiKeyView {
            summary,
            owner_email,
            invalid_free_used_today,
        });
    }
    Ok(Json(views))
}

async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<crate::models::CreatedApiKey>), AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let created = state.store.create_api_key(input).await?;
    record_admin_activity(
        &state,
        &principal,
        "Kunci API dibuat",
        format!(
            "{} diterbitkan dan hanya ditampilkan sekali.",
            created.key.name
        ),
    )
    .await;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let summary = state.store.revoke_api_key(id).await?;
    // Name the key and, for member keys, the owner (B12/K32): a bare
    // "one key revoked" row is useless forensics for a paid member key.
    let owner = match summary.member_id {
        Some(member_id) => state
            .store
            .member_by_id(member_id)
            .await
            .ok()
            .flatten()
            .map(|member| format!("milik member {}", member.email))
            .unwrap_or_else(|| format!("milik member {member_id}")),
        None => "standalone".to_owned(),
    };
    record_admin_activity(
        &state,
        &principal,
        "Kunci API dicabut",
        format!(
            "Kunci {} ({}, {}) dicabut; tidak lagi dapat melakukan validasi.",
            summary.prefix, summary.name, owner
        ),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Admin: member accounts (Google sign-ups)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AdminMemberView {
    #[serde(flatten)]
    member: crate::models::MemberAccount,
    key_prefix: Option<String>,
    key_status: Option<String>,
    quota_total: Option<u64>,
    quota_remaining: Option<u64>,
    expires_at: Option<chrono::DateTime<Utc>>,
    rate_limit_per_minute: Option<u32>,
    package_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct MemberListQuery {
    // AREA 5: parameter pencarian/filter baru (opsional). Respons lama
    // (array AdminMemberView tanpa parameter) tidak berubah bentuk.
    q: Option<String>,
    status: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

async fn list_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MemberListQuery>,
) -> Result<Json<Vec<AdminMemberView>>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let filters = parse_admin_list_filters(query.q, query.status, query.from, query.to)?;
    let mut views = Vec::new();
    for member in state
        .store
        .list_members()
        .await
        .into_iter()
        .filter(|member| member_matches_admin_filters(member, &filters))
    {
        let key = state.store.member_key(member.id).await;
        views.push(AdminMemberView {
            key_prefix: key.as_ref().map(|(summary, _)| summary.prefix.clone()),
            key_status: key.as_ref().map(|(summary, _)| summary.status.clone()),
            quota_total: key.as_ref().map(|(summary, _)| summary.quota_total),
            quota_remaining: key.as_ref().map(|(_, remaining)| *remaining),
            expires_at: key.as_ref().and_then(|(summary, _)| summary.expires_at),
            rate_limit_per_minute: key
                .as_ref()
                .map(|(summary, _)| summary.rate_limit_per_minute),
            package_id: key.as_ref().and_then(|(summary, _)| summary.package_id),
            member,
        });
    }
    Ok(Json(views))
}

#[derive(Deserialize)]
struct AssignMemberPackageInput {
    package_id: Option<Uuid>,
    quota_hits: Option<u64>,
    valid_days: Option<i64>,
    rate_limit_per_minute: Option<u32>,
    mode: Option<String>,
}

async fn assign_member_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<AssignMemberPackageInput>,
) -> Result<Json<AdminMemberView>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Support).await?;
    let member = state
        .store
        .member_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("Member tidak ditemukan"))?;
    // Audit flow K16: assigning a package to a disabled member used to
    // succeed silently (quota + plan_kind changed while the account
    // stayed disabled, confusing everyone on re-enable). Reject
    // explicitly with 409 instead of pretending the assign landed.
    if member.status != "active" {
        return Err(AppError::conflict(
            "Member dinonaktifkan; aktifkan dulu sebelum assign paket",
        ));
    }
    let valid_days = input.valid_days.unwrap_or(30);
    if !(1..=3650).contains(&valid_days) {
        return Err(AppError::bad_request("Masa aktif harus 1–3650 hari"));
    }
    let mode = input.mode.as_deref().unwrap_or("replace");
    if mode != "add" && mode != "replace" {
        return Err(AppError::bad_request("Mode harus 'add' atau 'replace'"));
    }
    let (quota_hits, rate_limit, package_id, plan_kind) = if let Some(package_id) = input.package_id
    {
        let package = state
            .store
            .list_packages()
            .await
            .into_iter()
            .find(|package| package.id == package_id)
            .ok_or_else(|| AppError::not_found("Paket tidak ditemukan"))?;
        (
            package.included_hits,
            input
                .rate_limit_per_minute
                .or(Some(package.rate_limit_per_minute)),
            Some(package_id),
            "package",
        )
    } else {
        let hits = input
            .quota_hits
            .filter(|hits| *hits > 0)
            .ok_or_else(|| AppError::bad_request("Jumlah hit paket manual wajib diisi"))?;
        (hits, input.rate_limit_per_minute, None, "manual")
    };
    if let Some(rate) = rate_limit {
        if rate == 0 || rate > 100_000 {
            return Err(AppError::bad_request(
                "Rate limit harus antara 1 dan 100000 per menit",
            ));
        }
    }
    let (summary, remaining) = state
        .store
        .assign_plan_to_member_key(
            id, quota_hits, valid_days, mode, rate_limit, package_id, plan_kind,
        )
        .await?;
    record_admin_activity(
        &state,
        &principal,
        "Paket member diatur",
        format!(
            "{}: {} hit, {} hari, mode {}, sisa {}",
            member.email, quota_hits, valid_days, mode, remaining
        ),
    )
    .await;
    Ok(Json(AdminMemberView {
        key_prefix: Some(summary.prefix.clone()),
        key_status: Some(summary.status.clone()),
        quota_total: Some(summary.quota_total),
        quota_remaining: Some(remaining),
        expires_at: summary.expires_at,
        rate_limit_per_minute: Some(summary.rate_limit_per_minute),
        package_id: summary.package_id,
        member: crate::models::MemberAccount {
            plan_kind: plan_kind.to_owned(),
            ..member
        },
    }))
}

#[derive(Deserialize)]
struct MemberRateLimitInput {
    rate_limit_per_minute: u32,
}

async fn set_member_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<MemberRateLimitInput>,
) -> Result<Json<crate::models::AdminApiKeySummary>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Support).await?;
    if input.rate_limit_per_minute == 0 || input.rate_limit_per_minute > 100_000 {
        return Err(AppError::bad_request(
            "Rate limit harus antara 1 dan 100000 per menit",
        ));
    }
    let summary = state
        .store
        .set_member_key_rate_limit(id, input.rate_limit_per_minute)
        .await?;
    record_admin_activity(
        &state,
        &principal,
        "Rate limit member diatur",
        format!(
            "Kunci {} menjadi {} request/menit",
            summary.prefix, input.rate_limit_per_minute
        ),
    )
    .await;
    Ok(Json(summary))
}

#[derive(Deserialize)]
struct MemberStatusInput {
    active: bool,
}

async fn set_member_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<MemberStatusInput>,
) -> Result<StatusCode, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Support).await?;
    let member = state
        .store
        .member_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("Member tidak ditemukan"))?;
    state.store.set_member_status(id, input.active).await?;
    record_admin_activity(
        &state,
        &principal,
        if input.active {
            "Member diaktifkan"
        } else {
            "Member dinonaktifkan"
        },
        format!("Akun {}", member.email),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct AdminKeyRevealResponse {
    api_key: String,
    prefix: String,
}

/// An admin views a member's full API key (the panel's eye button). The
/// view is written to the admin activity log. Keys issued before key
/// encryption existed have no stored ciphertext and answer 404.
///
/// Deliberate exception (audit flow K17, kept — NOT a gate to add):
/// unlike the member self-reveal, the admin reveal has no key-status
/// gate, so an admin can still view a revoked/disabled/expired key for
/// forensics and support. Admins are trusted parties; the protection
/// here is the audit record (every successful reveal is logged above
/// via record_admin_activity), not a status block. Blocking admin
/// reveal would hinder support with no access-control gain, since the
/// admin already controls revocation and regeneration.
async fn reveal_member_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminKeyRevealResponse>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let member = state
        .store
        .member_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("Member tidak ditemukan"))?;
    let (summary, _) = state
        .store
        .member_key(id)
        .await
        .ok_or_else(|| AppError::not_found("Member belum memiliki kunci API"))?;
    let plaintext = state
        .store
        .reveal_api_key(&summary.prefix)
        .await
        .ok_or_else(|| {
            AppError::not_found(
                "Kunci ini dibuat sebelum fitur lihat kunci tersedia, jadi tidak dapat ditampilkan. Regenerasi kunci untuk membuatnya dapat dilihat.",
            )
        })?;
    record_admin_activity(
        &state,
        &principal,
        "API key member dilihat",
        format!("Kunci {} milik {}", summary.prefix, member.email),
    )
    .await;
    Ok(Json(AdminKeyRevealResponse {
        api_key: plaintext,
        prefix: summary.prefix,
    }))
}

async fn regenerate_member_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::CreatedApiKey>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let member = state
        .store
        .member_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("Member tidak ditemukan"))?;
    let created = state.store.regenerate_member_key(&member).await?;
    record_admin_activity(
        &state,
        &principal,
        "Kunci member diregenerasi",
        format!("Kunci baru untuk {}", member.email),
    )
    .await;
    Ok(Json(created))
}

// ---------------------------------------------------------------------------
// Admin: detail member lengkap + adjust kuota manual (Area 4, 2026-10-25)
// ---------------------------------------------------------------------------

/// Satu kunci di halaman detail member. Sengaja HANYA ringkasan +
/// sisa kuota: tipe ini secara fisik tidak punya field hash,
/// ciphertext, atau plaintext, jadi respons detail TIDAK BISA memuat
/// nilai kunci apa pun (prefix saja yang tampil, seperti di daftar).
#[derive(Serialize)]
struct MemberDetailKeyView {
    #[serde(flatten)]
    summary: crate::models::AdminApiKeySummary,
    quota_remaining: u64,
    invalid_free_used_today: u32,
    /// Bucket FIFO kunci ini (urutan expiry terdekat dulu; nama paket
    /// di-resolve, null bila paket sudah dihapus/manual).
    buckets: Vec<crate::models::QuotaBucketView>,
}

#[derive(Serialize)]
struct MemberDailyUsageView {
    date: String,
    charged_hits: i64,
}

#[derive(Serialize)]
struct MemberDetailResponse {
    member: crate::models::MemberAccount,
    keys: Vec<MemberDetailKeyView>,
    orders: Vec<crate::qris::MemberOrderView>,
    orders_limit: i64,
    orders_offset: i64,
    /// Konvensi paginasi yang sama dengan daftar order admin (K27):
    /// halaman penuh berarti kemungkinan masih ada halaman berikut.
    orders_has_more: bool,
    /// Pemakaian tertagih per hari WIB dari usage_ledger (lihat
    /// store::MemberDailyUsage): hari tanpa hit tetap dikirim dengan
    /// nilai 0 agar grafik panel kontinu.
    usage: Vec<MemberDailyUsageView>,
    usage_days: u32,
    usage_total_charged: i64,
    /// "ledger" bila database terpasang, "none" bila tidak (mode
    /// in-memory tidak punya ledger dan tidak berpura-pura punya).
    usage_source: &'static str,
}

#[derive(Deserialize)]
struct MemberDetailQuery {
    days: Option<u32>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Isi hari-hari kosong dengan 0 (naik tanggal WIB), agar grafik panel
/// selalu sepanjang `days` hari dan total tidak bergantung pada hari
/// yang kebetulan punya baris ledger.
fn fill_usage_days(
    today: chrono::NaiveDate,
    days: u32,
    sparse: &[crate::store::MemberDailyUsage],
) -> Vec<MemberDailyUsageView> {
    let days = days.clamp(1, 90);
    let by_date: std::collections::HashMap<&str, i64> = sparse
        .iter()
        .map(|entry| (entry.date.as_str(), entry.charged_hits))
        .collect();
    (0..days)
        .map(|index| {
            let date = today - chrono::Duration::days(i64::from(days - 1 - index));
            let key = date.format("%Y-%m-%d").to_string();
            MemberDailyUsageView {
                charged_hits: by_date.get(key.as_str()).copied().unwrap_or(0),
                date: key,
            }
        })
        .collect()
}

// AUTHZ-ROLE: Viewer
//
// Detail member read-only: profil, SEMUA kunci (semua status, terbaru
// dulu — regenerasi tidak menghilangkan riwayat), order member
// (ringkas, berpaginasi; memakai MemberOrderView yang memang tidak
// membawa token/QR string provider), dan pemakaian tertagih per hari
// dari usage_ledger (rentang default 30 hari, maks 90).
// Member tak ada -> 404. Tidak ada plaintext kunci di respons mana pun.
async fn get_member_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<MemberDetailQuery>,
) -> Result<Json<MemberDetailResponse>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let member = state
        .store
        .member_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("Member tidak ditemukan"))?;
    let days = query.days.unwrap_or(30).clamp(1, 90);
    let (limit, offset) = clamp_admin_page(query.limit, query.offset, 20);
    let wib_day = crate::models::wib_date(Utc::now());
    let mut keys = Vec::new();
    for (summary, remaining) in state.store.list_member_keys(id).await {
        let invalid_free_used_today = state
            .store
            .invalid_free_used_today(&summary.prefix, wib_day)
            .await;
        let buckets = state.store.key_buckets(&summary.prefix).await;
        keys.push(MemberDetailKeyView {
            summary,
            quota_remaining: remaining,
            invalid_free_used_today,
            buckets,
        });
    }
    let (orders, usage_source) = match state.store.pool() {
        Some(pool) => (
            crate::qris::list_orders_for_member_paged(&pool, &id, limit, offset)
                .await?
                .into_iter()
                .map(|row| row.member_view())
                .collect::<Vec<_>>(),
            "ledger",
        ),
        None => (Vec::new(), "none"),
    };
    let orders_has_more = orders.len() as i64 == limit;
    let sparse = state
        .store
        .member_daily_usage_from_ledger(id, days)
        .await;
    let usage = fill_usage_days(wib_day, days, &sparse);
    let usage_total_charged = usage.iter().map(|day| day.charged_hits).sum();
    Ok(Json(MemberDetailResponse {
        member,
        keys,
        orders,
        orders_limit: limit,
        orders_offset: offset,
        orders_has_more,
        usage,
        usage_days: days,
        usage_total_charged,
        usage_source,
    }))
}

#[derive(Deserialize)]
struct AdjustMemberKeyInput {
    delta: Option<i64>,
    reason: Option<String>,
}

#[derive(Serialize)]
struct AdjustMemberKeyResponse {
    member_id: Uuid,
    key_id: Uuid,
    prefix: String,
    delta: i64,
    quota_total_before: u64,
    quota_total_after: u64,
    quota_remaining_before: u64,
    quota_remaining_after: u64,
    reason: String,
}

/// Validasi input adjust di sisi server (ditegakkan di handler sebelum
/// store disentuh; store memvalidasi ulang delta). Alasan di-trim dan
/// dihitung per karakter (bukan byte) agar alasan multi-byte tidak
/// lolos/tertolak karena hitungan byte.
fn validate_quota_adjust_input(
    delta: Option<i64>,
    reason: Option<&str>,
) -> Result<(i64, String), AppError> {
    let delta = delta.ok_or_else(|| AppError::bad_request("Delta kuota wajib diisi"))?;
    if delta == 0 {
        return Err(AppError::bad_request("Delta kuota tidak boleh 0"));
    }
    if delta < -crate::store::MAX_QUOTA_ADJUST_DELTA
        || delta > crate::store::MAX_QUOTA_ADJUST_DELTA
    {
        return Err(AppError::bad_request(
            "Delta kuota melebihi batas 10.000.000 per penyesuaian",
        ));
    }
    let reason = reason.unwrap_or("").trim().to_owned();
    if reason.chars().count() < 5 {
        return Err(AppError::bad_request(
            "Alasan adjust wajib diisi, minimal 5 karakter",
        ));
    }
    if reason.chars().count() > 500 {
        return Err(AppError::bad_request("Alasan adjust maksimal 500 karakter"));
    }
    Ok((delta, reason))
}

/// Gerbang status member untuk adjust (Area 4): member disabled atau
/// terhapus (baris tidak ada -> 404 di handler) tidak boleh menerima
/// adjust. Dipisah sebagai fungsi murni agar bisa dites tanpa database.
fn ensure_member_active_for_adjust(
    member: &crate::models::MemberAccount,
) -> Result<(), AppError> {
    if member.status != "active" {
        return Err(AppError::conflict(
            "Member dinonaktifkan; aktifkan dulu sebelum adjust kuota",
        ));
    }
    Ok(())
}

/// Satu baris detail audit adjust: member, prefix kunci, delta, sisa
/// sebelum/sesudah, total sebelum/sesudah, alasan, dan admin pelaksana
/// (ditambahkan `record_admin_activity` sebagai "oleh <email>").
/// TIDAK PERNAH memuat nilai kunci: inputnya hanya prefix + angka.
fn quota_adjust_audit_detail(
    email: &str,
    outcome: &crate::store::QuotaAdjustment,
    reason: &str,
) -> String {
    format!(
        "Member {email}: kunci {} delta {:+} (sisa {} → {}, total {} → {}); alasan: {reason}",
        outcome.prefix,
        outcome.delta,
        outcome.quota_remaining_before,
        outcome.quota_remaining_after,
        outcome.quota_total_before,
        outcome.quota_total_after
    )
}

// AUTHZ-ROLE: Manager
//
// Adjust kuota manual: jalur BARU yang tidak mengubah aturan potong
// (billing) yang sudah ada — adjust tidak menyentuh ledger, tidak
// mengubah hit tertagih, dan tidak mengubah status/rate limit kunci.
// Penegakan peran Manager aktif (require_admin_role, ditegakkan
// server-side). Setiap adjust yang lolos WAJIB menulis baris audit
// persisten via `record_admin_activity` (tabel admin_audit_log +
// mirror in-memory); tanpa baris itu adjust tidak dianggap selesai.
async fn adjust_member_key_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
    Json(input): Json<AdjustMemberKeyInput>,
) -> Result<Json<AdjustMemberKeyResponse>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let member = state
        .store
        .member_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("Member tidak ditemukan"))?;
    ensure_member_active_for_adjust(&member)?;
    let (delta, reason) = validate_quota_adjust_input(input.delta, input.reason.as_deref())?;
    let outcome = state
        .store
        .adjust_member_key_quota(id, key_id, delta)
        .await?;
    record_admin_activity(
        &state,
        &principal,
        "Kuota member disesuaikan",
        quota_adjust_audit_detail(&member.email, &outcome, &reason),
    )
    .await;
    Ok(Json(AdjustMemberKeyResponse {
        member_id: id,
        key_id,
        prefix: outcome.prefix,
        delta: outcome.delta,
        quota_total_before: outcome.quota_total_before,
        quota_total_after: outcome.quota_total_after,
        quota_remaining_before: outcome.quota_remaining_before,
        quota_remaining_after: outcome.quota_remaining_after,
        reason,
    }))
}

#[derive(Serialize, Deserialize)]
struct TrialSettings {
    quota_hits: u64,
    valid_days: i64,
}

async fn load_trial_settings(state: &AppState) -> TrialSettings {
    let quota_hits = state
        .provider_configs
        .load_runtime_setting("trial.quota_hits")
        .await
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=100_000).contains(value))
        .unwrap_or(10);
    let valid_days = state
        .provider_configs
        .load_runtime_setting("trial.valid_days")
        .await
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (1..=90).contains(value))
        .unwrap_or(7);
    TrialSettings {
        quota_hits,
        valid_days,
    }
}

async fn get_trial_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TrialSettings>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(load_trial_settings(&state).await))
}

async fn update_trial_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TrialSettings>,
) -> Result<Json<TrialSettings>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    if !(1..=100_000).contains(&input.quota_hits) || !(1..=90).contains(&input.valid_days) {
        return Err(AppError::bad_request(
            "Trial harus 1–100000 hit dan 1–90 hari",
        ));
    }
    state
        .provider_configs
        .save_runtime_setting("trial.quota_hits", &input.quota_hits.to_string())
        .await;
    state
        .provider_configs
        .save_runtime_setting("trial.valid_days", &input.valid_days.to_string())
        .await;
    record_admin_activity(
        &state,
        &principal,
        "Pengaturan trial diperbarui",
        format!(
            "Trial menjadi {} hit / {} hari",
            input.quota_hits, input.valid_days
        ),
    )
    .await;
    Ok(Json(load_trial_settings(&state).await))
}

async fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<AdminPrincipal, AppError> {
    let principal = auth::require_admin(&state.config, headers)?;
    // Server-side revocation (audit 2026-10-25, B8): a logged-out token is
    // rejected even before its expiry. The dev-token principal carries no
    // JWT id and skips this check (it only exists outside production).
    if !principal.jti.is_empty() && state.session_revocation.is_revoked(&principal.jti).await {
        return Err(AppError::unauthorized("Sesi admin tidak valid"));
    }
    Ok(principal)
}

/// Gerbang admin + peran (area 7+8). Urutan cek: sesi sah (termasuk
/// revocation) dulu, baru peran — jadi 401 untuk sesi tak valid dan
/// 403 untuk peran kurang, tidak tercampur. Mengembalikan principal
/// (bukan peran) agar handler yang sudah ada tidak berubah bentuk;
/// peran teresolusi tersedia lewat `admin_roles::require_role` bila
/// koordinator membutuhkannya. Akun dinonaktifkan ditolak di sini
/// (403, dari `resolve_admin_role`), termasuk untuk GET read-only.
async fn require_admin_role(
    state: &AppState,
    headers: &HeaderMap,
    min_role: Role,
) -> Result<AdminPrincipal, AppError> {
    let principal = require_admin(state, headers).await?;
    admin_roles::require_role(&state.store, &principal, min_role).await?;
    Ok(principal)
}

/// Shared admin-activity recorder. Signature intentionally unchanged
/// (audit 2026-10-25, B12 coordination): other areas call this for
/// self-reveal and admin login/logout, so it stays
/// `(state, principal, title, detail)`. It writes TWO records:
/// (1) the in-memory mirror via `append_activity` — kept because it is
/// cheap and is the only record in memory-only mode, and because the
/// overview feed still renders from it; (2) the DURABLE row in
/// `admin_audit_log` via `persist_admin_audit`, which never fails the
/// caller (a failed insert only warns). The durable row keeps the raw
/// detail with the actor in its own column; the mirror appends
/// " • oleh <email>" for display, as before.
pub(crate) async fn record_admin_activity(
    state: &AppState,
    principal: &AdminPrincipal,
    title: &str,
    detail: String,
) {
    state
        .store
        .persist_admin_audit(&principal.email, title, &detail, None, None)
        .await;
    state
        .store
        .append_activity(ActivityItem {
            id: Uuid::now_v7(),
            title: title.to_owned(),
            detail: format!("{} • oleh {}", detail, principal.email),
            product: None,
            status: "info".to_owned(),
            occurred_at: Utc::now(),
            provider_latency_ms: None,
        })
        .await;
}

/// Convenience principal for audit rows that are not tied to a verified
/// admin session (failed logins): the actor is the attempted address,
/// or "unknown" when even that is unavailable.
fn audit_principal(email: &str) -> AdminPrincipal {
    AdminPrincipal {
        email: email.to_owned(),
        name: String::new(),
        source: "auth",
        jti: String::new(),
    }
}

#[derive(Deserialize)]
struct AdminActivityQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    action: Option<String>,
    actor: Option<String>,
    /// Alias baru untuk `actor` (spesifikasi area 7+8): substring email
    /// admin. Bila keduanya diisi, `admin` menang (kompatibel mundur:
    /// panel lama masih mengirim `actor`).
    admin: Option<String>,
    /// Rentang tanggal: "YYYY-MM-DD" (UTC) atau datetime RFC3339.
    /// `from` tanggal polos = 00:00:00 UTC; `to` tanggal polos =
    /// akhir hari itu (23:59:59.999999 UTC) agar satu hari penuh ikut.
    from: Option<String>,
    to: Option<String>,
}

#[derive(Serialize)]
struct AdminActivityPage {
    items: Vec<AdminAuditEntry>,
    total: u64,
    limit: i64,
    offset: i64,
}

/// Shared pagination clamp for the admin list endpoints (B12/K27):
/// defaults differ per endpoint, the 200-row ceiling and the
/// non-negative offset do not.
fn clamp_admin_page(limit: Option<i64>, offset: Option<i64>, default_limit: i64) -> (i64, i64) {
    (
        limit.unwrap_or(default_limit).clamp(1, 200),
        offset.unwrap_or(0).max(0),
    )
}

/// Persistent admin audit feed (audit 2026-10-25, B12). This is a
/// DIFFERENT feed from the overview's `recent_activities`, which shows
/// validation history; this one shows admin actions (grants, revokes,
/// package/settings changes, logins) and survives restarts.
/// Parse satu batas rentang aktivitas. Menerima "YYYY-MM-DD" atau
/// datetime RFC3339; yang lain -> 400 (validasi server-side, bukan
/// diam-diam diabaikan). `end_of_day` true hanya untuk `to` tanggal
/// polos, sehingga filter satu hari mencakup hari itu penuh.
fn parse_activity_bound(
    value: &str,
    end_of_day: bool,
) -> Result<chrono::DateTime<Utc>, AppError> {
    use chrono::{NaiveDate, NaiveTime, TimeZone as _};
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::bad_request("Rentang tanggal aktivitas kosong"));
    }
    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let time = if end_of_day {
            NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999)
                .unwrap_or_else(|| NaiveTime::from_hms_opt(23, 59, 59).unwrap())
        } else {
            NaiveTime::from_hms_opt(0, 0, 0).unwrap()
        };
        return Ok(Utc.from_utc_datetime(&date.and_time(time)));
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map(|moment| moment.with_timezone(&Utc))
        .map_err(|_| {
            AppError::bad_request(
                "Tanggal aktivitas tidak valid (pakai YYYY-MM-DD atau RFC3339)",
            )
        })
}

async fn list_admin_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminActivityQuery>,
) -> Result<Json<AdminActivityPage>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let (limit, offset) = clamp_admin_page(query.limit, query.offset, 50);
    let action = query.action.as_deref().filter(|value| !value.is_empty());
    // `admin` (baru) menang atas `actor` (lama) bila keduanya ada.
    let actor = query
        .admin
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| query.actor.as_deref().filter(|value| !value.is_empty()));
    let from = query
        .from
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_activity_bound(value, false))
        .transpose()?;
    let to = query
        .to
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_activity_bound(value, true))
        .transpose()?;
    if let (Some(from), Some(to)) = (from, to) {
        if from > to {
            return Err(AppError::bad_request(
                "Rentang tanggal aktivitas tidak valid (from melewati to)",
            ));
        }
    }
    let (items, total) = state
        .store
        .list_admin_audit(limit, offset, action, actor, from, to)
        .await;
    Ok(Json(AdminActivityPage {
        items,
        total,
        limit,
        offset,
    }))
}

// ---------------------------------------------------------------
// Kelola admin (area 7+8, owner saja). Guard bersama:
// * tanpa database -> 503 dari store (bukan 500);
// * diri sendiri tidak boleh dinonaktifkan/didemot/dihapus, agar
//   owner tidak mengunci dirinya sendiri lewat satu klik;
// * owner aktif terakhir tidak boleh dinonaktifkan/didemot/dihapus,
//   agar selalu ada yang bisa mengelola admin.
// Semua perubahan dicatat lewat record_admin_activity.
// ---------------------------------------------------------------

#[derive(Deserialize)]
struct CreateAdminAccountRequest {
    email: String,
    role: String,
}

#[derive(Deserialize)]
struct UpdateAdminAccountRequest {
    role: Option<String>,
    active: Option<bool>,
}

async fn list_admin_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<admin_roles::AdminAccount>>, AppError> {
    require_admin_role(&state, &headers, Role::Owner).await?;
    if state.store.pool().is_none() {
        return Err(AppError::service_unavailable(
            "Kelola admin membutuhkan database.",
        ));
    }
    Ok(Json(state.store.list_admin_accounts().await))
}

async fn create_admin_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateAdminAccountRequest>,
) -> Result<(StatusCode, Json<admin_roles::AdminAccount>), AppError> {
    let principal = require_admin_role(&state, &headers, Role::Owner).await?;
    let email = admin_roles::validate_admin_email(&input.email)?;
    let role = input
        .role
        .parse::<Role>()
        .map_err(|_| AppError::bad_request("Peran admin tidak valid (viewer/support/manager/owner)"))?;
    let account = state
        .store
        .create_admin_account(&email, role, &principal.email)
        .await?;
    record_admin_activity(
        &state,
        &principal,
        "Admin ditambahkan",
        format!(
            "Admin {} ditambahkan dengan peran {} oleh {}.",
            email,
            role.as_str(),
            principal.email
        ),
    )
    .await;
    Ok((StatusCode::CREATED, Json(account)))
}

async fn update_admin_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateAdminAccountRequest>,
) -> Result<Json<admin_roles::AdminAccount>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Owner).await?;
    if state.store.pool().is_none() {
        return Err(AppError::service_unavailable(
            "Kelola admin membutuhkan database.",
        ));
    }
    let role = input
        .role
        .as_deref()
        .map(|value| {
            value.parse::<Role>().map_err(|_| {
                AppError::bad_request("Peran admin tidak valid (viewer/support/manager/owner)")
            })
        })
        .transpose()?;
    let current = state
        .store
        .list_admin_accounts()
        .await
        .into_iter()
        .find(|account| account.id == id)
        .ok_or_else(|| AppError::not_found("Admin tidak ditemukan"))?;
    let self_email =
        admin_roles::normalize_admin_email(&principal.email) == current.email;
    // Guard diri sendiri + owner terakhir (lihat header bagian ini).
    if self_email && input.active == Some(false) {
        return Err(AppError::bad_request(
            "Akun sendiri tidak dapat dinonaktifkan.",
        ));
    }
    // Owner terakhir (diri sendiri atau bukan) tidak boleh hilang:
    // demot/nonaktifkan owner aktif saat hanya tersisa satu owner
    // aktif akan mengunci pengelolaan admin sepenuhnya.
    if current.role == Role::Owner
        && current.active
        && (input.active == Some(false)
            || matches!(
                role,
                Some(Role::Viewer | Role::Support | Role::Manager)
            ))
        && state.store.count_active_owners().await <= 1
    {
        return Err(AppError::conflict(
            "Owner aktif terakhir tidak dapat dinonaktifkan atau didemot.",
        ));
    }
    let updated = state
        .store
        .update_admin_account(id, role, input.active)
        .await?
        .ok_or_else(|| AppError::not_found("Admin tidak ditemukan"))?;
    let mut changes = Vec::new();
    if let Some(role) = role {
        changes.push(format!("peran menjadi {}", role.as_str()));
    }
    if let Some(active) = input.active {
        changes.push(if active {
            "diaktifkan".to_owned()
        } else {
            "dinonaktifkan".to_owned()
        });
    }
    record_admin_activity(
        &state,
        &principal,
        "Admin diubah",
        format!(
            "Admin {} {} oleh {}.",
            updated.email,
            if changes.is_empty() {
                "diperbarui".to_owned()
            } else {
                changes.join(", ")
            },
            principal.email
        ),
    )
    .await;
    Ok(Json(updated))
}

async fn delete_admin_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Owner).await?;
    if state.store.pool().is_none() {
        return Err(AppError::service_unavailable(
            "Kelola admin membutuhkan database.",
        ));
    }
    let current = state
        .store
        .list_admin_accounts()
        .await
        .into_iter()
        .find(|account| account.id == id)
        .ok_or_else(|| AppError::not_found("Admin tidak ditemukan"))?;
    if admin_roles::normalize_admin_email(&principal.email) == current.email {
        return Err(AppError::bad_request("Akun sendiri tidak dapat dihapus."));
    }
    if current.role == Role::Owner
        && current.active
        && state.store.count_active_owners().await <= 1
    {
        return Err(AppError::conflict(
            "Owner aktif terakhir tidak dapat dihapus.",
        ));
    }
    if !state.store.delete_admin_account(id).await? {
        return Err(AppError::not_found("Admin tidak ditemukan"));
    }
    record_admin_activity(
        &state,
        &principal,
        "Admin dihapus",
        format!("Admin {} dihapus oleh {}.", current.email, principal.email),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Nama pemilik di JSON member selalu huruf besar semua — berlaku untuk
/// nama penuh dari provider maupun nama tersamar, dan untuk respons live
/// maupun replay idempotensi (keduanya lewat fungsi ini). Tester admin
/// tidak lewat sini sehingga payload mentah vendor tetap apa adanya.
fn uppercase_account_name(result: &mut Option<crate::models::ValidationResultData>) {
    if let Some(data) = result.as_mut() {
        if let Some(name) = data.account_name.take() {
            data.account_name = Some(name.to_uppercase());
        }
    }
}

fn validation_response(
    mut response: ValidationResponse,
    admission: Option<&crate::models::RateLimitAdmission>,
    idempotent_replay: bool,
) -> Response {
    uppercase_account_name(&mut response.result);
    let status = match response.status {
        ValidationStatus::ProviderError => StatusCode::BAD_GATEWAY,
        ValidationStatus::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ValidationStatus::QuotaExhausted => StatusCode::PAYMENT_REQUIRED,
        _ => StatusCode::OK,
    };
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "x-request-id", &response.request_id);
    // Replays never passed admission, so they carry no rate-limit headers instead of
    // presenting a fabricated remaining budget.
    if let Some(admission) = admission {
        insert_header(
            &mut headers,
            "x-ratelimit-remaining",
            &admission.remaining.to_string(),
        );
        insert_header(
            &mut headers,
            "x-ratelimit-reset",
            &admission.retry_after_seconds.to_string(),
        );
    }
    insert_header(&mut headers, header::CACHE_CONTROL.as_str(), "no-store");
    if idempotent_replay {
        insert_header(&mut headers, "x-idempotent-replay", "true");
    }
    (status, headers, Json(response)).into_response()
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(name, value);
    }
}

/// Short public request ID: exactly 10 characters from [A-Za-z0-9]
/// (62^10 ≈ 8.4e17 combinations), drawn from the OS RNG with rejection
/// sampling so every character is uniform. Used in API responses, member
/// history, and support lookups instead of a 36-character UUID.
fn short_request_id() -> String {
    use rand::RngCore;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rngs::OsRng;
    let mut id = String::with_capacity(10);
    let mut buf = [0u8; 16];
    while id.len() < 10 {
        rng.fill_bytes(&mut buf);
        for &byte in &buf {
            if byte < 248 {
                id.push(ALPHABET[(byte % 62) as usize] as char);
                if id.len() == 10 {
                    break;
                }
            }
        }
    }
    id
}

#[derive(Clone, Copy, Default)]
struct MakeShortRequestId;

impl MakeRequestId for MakeShortRequestId {
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        HeaderValue::from_str(&short_request_id())
            .ok()
            .map(RequestId::new)
    }
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
        .unwrap_or_else(short_request_id)
}

fn api_key_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
        })
        .map(str::trim)
        .filter(|key| !key.is_empty())
}

/// Reads the client-supplied Idempotency-Key, or generates one when the
/// header is absent/empty so the request can still proceed. The boolean
/// reports whether the key was generated server-side (the caller echoes it
/// back in the response headers so the client can learn and reuse it). A
/// key the client DID supply is still validated strictly.
fn idempotency_key_or_generate(headers: &HeaderMap) -> Result<(String, bool), AppError> {
    let supplied = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match supplied {
        Some(key) => {
            if !(8..=200).contains(&key.len())
                || !key.chars().all(|character| character.is_ascii_graphic())
            {
                return Err(AppError::bad_request(
                    "Idempotency-Key harus 8-200 karakter ASCII tanpa spasi",
                ));
            }
            Ok((key.to_owned(), false))
        }
        None => Ok((Uuid::now_v7().to_string(), true)),
    }
}

fn has_scope(scopes: &[String], product: ValidationProduct) -> bool {
    scopes
        .iter()
        .any(|scope| scope == "validate:*" || scope == &format!("validate:{}", product.as_str()))
}

fn provider_product_from_path(value: &str) -> Result<ValidationProduct, AppError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "bank_account" => Ok(ValidationProduct::BankAccount),
        "ewallet" => Ok(ValidationProduct::Ewallet),
        "whatsapp" => Ok(ValidationProduct::Whatsapp),
        _ => Err(AppError::bad_request("Produk provider tidak dikenal")),
    }
}

pub(crate) fn normalize_bank_request(
    input: BankAccountValidationRequest,
) -> Result<ProviderValidationRequest, AppError> {
    let bank_code = input.bank_code.trim();
    if bank_code.len() != 3
        || !bank_code
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return Err(AppError::bad_request(
            "code_bank wajib berupa tepat tiga digit, misalnya 002 untuk BRI",
        ));
    }
    bank_codes::validate_public_code(bank_code)?;
    let bank_code = bank_code.to_owned();
    let account_number = normalize_numeric(&input.account_number, 6, 32, "Nomor rekening")?;
    Ok(ProviderValidationRequest {
        product: ValidationProduct::BankAccount,
        provider_hint: Some(bank_code),
        target: account_number,
    })
}

pub(crate) fn normalize_ewallet_request(
    input: EwalletValidationRequest,
) -> Result<ProviderValidationRequest, AppError> {
    let provider = input.provider.trim().to_ascii_lowercase();
    if !(2..=48).contains(&provider.len())
        || !provider.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-')
        })
    {
        return Err(AppError::bad_request("Provider e-wallet tidak valid"));
    }
    let account_number = normalize_numeric(&input.account_number, 6, 32, "Nomor akun e-wallet")?;
    Ok(ProviderValidationRequest {
        product: ValidationProduct::Ewallet,
        provider_hint: Some(provider),
        target: account_number,
    })
}

pub(crate) fn normalize_whatsapp_request(
    input: WhatsappValidationRequest,
) -> Result<ProviderValidationRequest, AppError> {
    let original = input.phone_number.trim();
    if original.len() > 32 {
        return Err(AppError::bad_request("Nomor WhatsApp terlalu panjang"));
    }
    let mut phone = original
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect::<String>();
    if phone.starts_with('0') {
        phone = format!("62{}", phone.trim_start_matches('0'));
    }
    if !(10..=16).contains(&phone.len()) || !phone.starts_with("62") {
        return Err(AppError::bad_request(
            "Nomor WhatsApp harus menggunakan format Indonesia, misalnya +628123456789",
        ));
    }
    Ok(ProviderValidationRequest {
        product: ValidationProduct::Whatsapp,
        provider_hint: None,
        target: phone,
    })
}

fn normalize_numeric(
    input: &str,
    min_length: usize,
    max_length: usize,
    label: &str,
) -> Result<String, AppError> {
    let normalized = input.trim().replace([' ', '-'], "");
    if !(min_length..=max_length).contains(&normalized.len())
        || !normalized
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return Err(AppError::bad_request(format!("{label} tidak valid")));
    }
    Ok(normalized)
}

fn target_fingerprint(
    config: &AppConfig,
    product: ValidationProduct,
    target: &str,
    provider_hint: &str,
) -> String {
    let secret = config
        .data_fingerprint_secret
        .as_deref()
        .or(config.dashboard_session_secret.as_deref())
        .unwrap_or("development-only-fingerprint-secret");
    fingerprint_hash(&secret, product, target, provider_hint)
}

fn fingerprint_hash(
    secret: &str,
    product: ValidationProduct,
    target: &str,
    provider_hint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update([0]);
    hasher.update(product.as_str().as_bytes());
    hasher.update([0]);
    // The bank code / e-wallet slug MUST participate: without it, the same
    // account number checked against a different bank replays the first
    // bank's result for free (audit 2026-10-25, B1).
    hasher.update(provider_hint.as_bytes());
    hasher.update([0]);
    hasher.update(target.as_bytes());
    hex::encode(hasher.finalize())
}

fn mask_target(product: ValidationProduct, target: &str) -> String {
    let visible = match product {
        ValidationProduct::BankAccount | ValidationProduct::Ewallet => 4,
        ValidationProduct::Whatsapp => 3,
    };
    let suffix = target
        .chars()
        .rev()
        .take(visible)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    let prefix = match product {
        ValidationProduct::Whatsapp => "+62••••••",
        _ => "••••••",
    };
    format!("{prefix}{suffix}")
}

fn provider_mode_label(config: &AppConfig) -> &'static str {
    if config.is_demo_mode() {
        "demo"
    } else {
        "http"
    }
}

// ---------------------------------------------------------------------------
// Pembelian paket QRIS: pengaturan + order admin + webhook Cutiezy
// ---------------------------------------------------------------------------

async fn qris_pool(state: &AppState) -> Result<sqlx::MySqlPool, AppError> {
    state.store.pool().ok_or_else(|| {
        AppError::service_unavailable("Pembayaran belum tersedia (database tidak terpasang).")
    })
}

async fn get_qris_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::qris::QrisSettingsView>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let pool = qris_pool(&state).await?;
    Ok(Json(crate::qris::load_qris_settings(&pool).await?.view()))
}

async fn update_qris_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<crate::qris::QrisSettingsInput>,
) -> Result<Json<crate::qris::QrisSettingsView>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Manager).await?;
    let pool = qris_pool(&state).await?;
    let cipher = crate::provider_config::CredentialCipher::new(
        state.config.api_key_encryption_key.as_deref(),
    );
    // Audit flow B6: never encrypt a NEW QRIS secret under the fallback
    // development key. Saves that carry no new secret (toggles, expiry,
    // valid_days, source_id) are still allowed — they touch no
    // ciphertext, so blocking them would also block the kill switch
    // (disabling QRIS) exactly when it is most needed. Production
    // startup validation (config.rs) additionally refuses to start
    // without a real API_KEY_ENCRYPTION_KEY, so in production this
    // guard is a second layer, not the only one. Decrypt-only paths
    // (webhook secret, cancel) are untouched: they must keep reading
    // secrets that were encrypted earlier.
    let carries_new_secret = input
        .api_key
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || input
            .webhook_secret
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    if carries_new_secret && cipher.is_fallback() {
        return Err(AppError::service_unavailable(
            "API_KEY_ENCRYPTION_KEY belum dikonfigurasi; secret QRIS baru tidak disimpan agar tidak terenkripsi dengan kunci fallback.",
        ));
    }
    let view = crate::qris::save_qris_settings(&pool, input, &cipher).await?;
    record_admin_activity(
        &state,
        &principal,
        "Pengaturan QRIS diperbarui",
        format!(
            "QRIS {} (expiry {} mnt, valid {} hari)",
            if view.enabled { "aktif" } else { "nonaktif" },
            view.expiry_minutes,
            view.valid_days,
        ),
    )
    .await;
    Ok(Json(view))
}

// =====================================================================
// AREA 5 — Export CSV + pencarian/filter list admin (2026-10-25).
//
// Kontrak yang dijaga di sini:
// * Semua endpoint di bawah ini admin-only dan memakai `require_admin`
//   yang sudah ada (cek sesi admin). Komentar `// AUTHZ-ROLE: Viewer`
//   di tiap handler baru menandai bahwa koordinator integrasi-lah yang
//   me-wire cek peran sungguhan; salinan ini TIDAK mengklaim penegakan
//   peran sudah live.
// * Parameter baru (q/status/from/to) selalu opsional: respons lama
//   tanpa parameter tidak berubah bentuk.
// * TIDAK ADA kolom CSV yang memuat plaintext kunci, hash kunci, secret,
//   atau token apa pun. Export order sengaja TIDAK memakai kolom
//   qris_token / key_id / mutation_ref / last_error dari AdminOrderView
//   (token pembayaran hanya hidup di detail order admin, bukan di CSV).
//   Export member tidak memuat prefix kunci sekalipun; export pemakaian
//   hanya memuat prefix kunci (yang memang sudah tampil di panel).
// * Permukaan member/publik tidak disentuh: tidak ada nama/URL/kode
//   provider upstream di sini.
// * TANPA migrasi baru untuk area ini.
// =====================================================================

/// Batas panjang kata kunci pencarian (karakter, bukan byte) — lebih
/// dari ini -> 400, bukan pemotongan diam-diam.
const ADMIN_SEARCH_MAX_CHARS: usize = 100;
/// Batas panjang nilai status (karakter). Status tak dikenal TIDAK
/// ditolak (list lama mengembalikan kosong untuk status tak dikenal);
/// yang ditolak hanya nilai yang terlalu panjang / tanggal tak valid.
const ADMIN_STATUS_MAX_CHARS: usize = 64;
/// Cap export CSV: MAKSIMAL 10.000 baris data per respons. Perilaku cap
/// yang dipilih: POTONG + PENANDA (bukan 400). Bila sumber punya lebih
/// dari 10.000 baris yang cocok, respons berisi 10.000 baris pertama
/// (urutan sama dengan list: terbaru dulu) dan header
/// `x-export-truncated: true` + `x-export-rows` memberitahu jumlahnya.
/// Admin yang butuh sisanya mempersempit filter (status/rentang tanggal).
const EXPORT_MAX_ROWS: usize = 10_000;

/// Filter list admin yang dipakai bersama oleh order, member, riwayat
/// pemakaian, dan export CSV. `from` inklusif, `to_exclusive` eksklusif,
/// keduanya NaiveDateTime UTC (kolom database disimpan UTC).
#[derive(Clone, Debug, Default)]
struct AdminListFilters {
    q: Option<String>,
    status: Option<String>,
    from: Option<chrono::NaiveDateTime>,
    to_exclusive: Option<chrono::NaiveDateTime>,
}

fn clean_admin_search(value: Option<String>) -> Result<Option<String>, AppError> {
    let cleaned = value.map(|text| text.trim().to_owned()).filter(|text| !text.is_empty());
    if let Some(text) = &cleaned {
        if text.chars().count() > ADMIN_SEARCH_MAX_CHARS {
            return Err(AppError::bad_request(
                "Kata kunci pencarian maksimal 100 karakter",
            ));
        }
    }
    Ok(cleaned)
}

fn clean_admin_status(value: Option<String>) -> Result<Option<String>, AppError> {
    let cleaned = value.map(|text| text.trim().to_owned()).filter(|text| !text.is_empty());
    if let Some(text) = &cleaned {
        if text.chars().count() > ADMIN_STATUS_MAX_CHARS {
            return Err(AppError::bad_request("Nilai status terlalu panjang"));
        }
    }
    Ok(cleaned)
}

/// Satu batas tanggal. Menerima `YYYY-MM-DD` (tanggal kalender) atau
/// RFC 3339 lengkap (`2026-10-25T10:00:00Z`). Untuk `to`, tanggal
/// kalender berarti "sampai akhir hari itu", jadi dikembalikan sebagai
/// 00:00 hari berikutnya (batas eksklusif); untuk `from`, tanggal
/// kalender berarti 00:00 hari itu. Format lain -> 400 (bukan 500).
fn parse_admin_date_bound(value: &str, is_to: bool) -> Result<chrono::NaiveDateTime, AppError> {
    let text = value.trim();
    if text.is_empty() {
        return Err(AppError::bad_request("Tanggal filter tidak boleh kosong"));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        let start = date.and_hms_opt(0, 0, 0).ok_or_else(|| {
            AppError::bad_request(format!("Tanggal tidak valid: {text}"))
        })?;
        if is_to {
            return Ok(start + chrono::Duration::days(1));
        }
        return Ok(start);
    }
    if let Ok(moment) = chrono::DateTime::parse_from_rfc3339(text) {
        return Ok(moment.with_timezone(&Utc).naive_utc());
    }
    Err(AppError::bad_request(format!(
        "Tanggal tidak valid (gunakan YYYY-MM-DD atau RFC 3339): {text}"
    )))
}

fn parse_admin_list_filters(
    q: Option<String>,
    status: Option<String>,
    from: Option<String>,
    to: Option<String>,
) -> Result<AdminListFilters, AppError> {
    let q = clean_admin_search(q)?;
    let status = clean_admin_status(status)?;
    let from = match from {
        None => None,
        Some(value) => Some(parse_admin_date_bound(&value, false)?),
    };
    let to_exclusive = match to {
        None => None,
        Some(value) => Some(parse_admin_date_bound(&value, true)?),
    };
    if let (Some(from), Some(to)) = (from, to_exclusive) {
        if from >= to {
            return Err(AppError::bad_request(
                "Rentang tanggal tidak valid: tanggal awal harus sebelum tanggal akhir",
            ));
        }
    }
    Ok(AdminListFilters {
        q,
        status,
        from,
        to_exclusive,
    })
}

/// Substring tak peka huruf besar/kecil ke satu atau beberapa kolom.
/// None (tanpa q) selalu cocok.
fn admin_q_matches(q: Option<&str>, haystacks: &[&str]) -> bool {
    match q {
        None => true,
        Some(needle) => {
            let needle = needle.to_lowercase();
            haystacks
                .iter()
                .any(|haystack| haystack.to_lowercase().contains(&needle))
        }
    }
}

fn admin_moment_in_range(moment: chrono::DateTime<Utc>, filters: &AdminListFilters) -> bool {
    let naive = moment.naive_utc();
    filters.from.is_none_or(|from| naive >= from)
        && filters
            .to_exclusive
            .is_none_or(|to| naive < to)
}

/// Filter member di memori (list member memang sudah dimuat penuh dari
/// store; responsnya tetap array yang sama, hanya dipersempit).
/// q -> email / nama / id; status -> status member (tak peka huruf);
/// from/to -> created_at.
fn member_matches_admin_filters(
    member: &crate::models::MemberAccount,
    filters: &AdminListFilters,
) -> bool {
    let status_ok = match filters.status.as_deref() {
        None => true,
        Some(status) => member.status.eq_ignore_ascii_case(status),
    };
    status_ok
        && admin_q_matches(
            filters.q.as_deref(),
            &[
                &member.email,
                member.name.as_deref().unwrap_or(""),
                &member.id.to_string(),
            ],
        )
        && admin_moment_in_range(member.created_at, filters)
}

/// Satu halaman riwayat validasi dari sumber mana pun yang tersedia
/// (database dulu, memori proses sebagai fallback — sama seperti list
/// riwayat admin). Dipakai bersama oleh list riwayat dan export usage.
struct ValidationHistoryPage {
    items: Vec<crate::models::ValidationHistoryItem>,
    total: u64,
    source: &'static str,
    hits_last_60s: u64,
    hits_last_3600s: u64,
}

async fn fetch_validation_history(
    state: &AppState,
    filters: &crate::models::ValidationHistoryFilters,
    limit: u32,
    offset: u32,
) -> ValidationHistoryPage {
    if let Some((items, total, hits_last_60s, hits_last_3600s)) = state
        .provider_configs
        .validation_history_from_db(filters, limit, offset)
        .await
    {
        return ValidationHistoryPage {
            items,
            total,
            source: "database",
            hits_last_60s,
            hits_last_3600s,
        };
    }
    let (items, total, (hits_last_60s, hits_last_3600s)) = state
        .store
        .validation_history(filters, limit as usize, offset as usize)
        .await;
    ValidationHistoryPage {
        items,
        total: total as u64,
        source: "memory",
        hits_last_60s: hits_last_60s as u64,
        hits_last_3600s: hits_last_3600s as u64,
    }
}

// ---- CSV (tanpa dependensi baru: escaping ditulis sendiri) ----

/// Escaping RFC 4180: field yang mengandung koma, kutip ganda, atau
/// newline dibungkus kutip ganda dan kutip ganda di dalamnya digandakan.
/// Field lain dibiarkan apa adanya (nilai tidak diubah).
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        let mut escaped = String::with_capacity(value.len() + 2);
        escaped.push('"');
        for character in value.chars() {
            if character == '"' {
                escaped.push('"');
            }
            escaped.push(character);
        }
        escaped.push('"');
        escaped
    } else {
        value.to_owned()
    }
}

/// Satu baris CSV (diakhiri newline). Dipanggil per baris oleh writer
/// di bawah — tidak ada buffering tak berbatas di luar cap export.
fn csv_row(fields: &[String]) -> String {
    let mut line = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            line.push(',');
        }
        line.push_str(&csv_field(field));
    }
    line.push('\n');
    line
}

fn csv_document(header: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut document = csv_row(
        &header
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<String>>(),
    );
    for row in rows {
        document.push_str(&csv_row(&row));
    }
    document
}

fn format_csv_naive(moment: chrono::NaiveDateTime) -> String {
    moment
        .and_utc()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn format_csv_optional_naive(moment: Option<chrono::NaiveDateTime>) -> String {
    moment.map(format_csv_naive).unwrap_or_default()
}

/// Baris CSV order. SENGAJA hanya kolom yang tercantum di spesifikasi;
/// qris_token, key_id, mutation_ref, dan last_error dari AdminOrderView
/// tidak pernah dibaca di sini (lihat header blok AREA 5).
fn order_csv_row(order: &crate::qris::AdminOrderView) -> Vec<String> {
    vec![
        order.id.clone(),
        order.member_email.clone().unwrap_or_default(),
        order.package_name.clone(),
        order.amount_idr.to_string(),
        order.status.clone(),
        format_csv_naive(order.created_at),
        format_csv_optional_naive(order.paid_at),
        format_csv_optional_naive(order.granted_at),
    ]
}

/// Baris CSV member. Tidak memuat prefix kunci maupun data kunci apa pun.
fn member_csv_row(member: &crate::models::MemberAccount) -> Vec<String> {
    vec![
        member.id.to_string(),
        member.email.clone(),
        member.status.clone(),
        member.plan_kind.clone(),
        member.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    ]
}

/// Label kolom `charged` export pemakaian.
/// * Sumber database: eksak — `ya` bila ada baris `charge` di
///   `usage_ledger` untuk request_id itu, `tidak` bila tidak ada. Baris
///   ledger adalah satu-satunya bukti penagihan per permintaan; kolom
///   `validation_requests` sendiri tidak menyimpan flag charged, dan
///   aturan jatah gratis 100/hari untuk Invalid/NotFound membuat
///   derivasi dari outcome saja TIDAK BENAR (baris Invalid ke-101
///   tetap ditagih, 100 pertama gratis).
/// * Sumber memori / ledger gagal dibaca: fallback derivasi — Valid dan
///   NotKyc selalu ditagih (`ya`), hasil lain `tidak`. Fallback ini
///   didokumentasikan karena mode memori hanya ada sejak proses start
///   dan tidak punya ledger; di produksi (database) jalur eksak yang
///   dipakai.
fn usage_charged_label(
    item: &crate::models::ValidationHistoryItem,
    charged_set: Option<&std::collections::HashSet<String>>,
) -> &'static str {
    if let Some(charged) = charged_set {
        if charged.contains(&item.request_id) {
            return "ya";
        }
        return "tidak";
    }
    match item.outcome.as_str() {
        "valid" | "not_kyc" => "ya",
        _ => "tidak",
    }
}

fn usage_csv_row(
    item: &crate::models::ValidationHistoryItem,
    charged_set: Option<&std::collections::HashSet<String>>,
) -> Vec<String> {
    vec![
        item.occurred_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        item.api_key_prefix.clone(),
        item.product.as_str().to_owned(),
        item.outcome.clone(),
        usage_charged_label(item, charged_set).to_owned(),
    ]
}

/// Himpunan request_id yang punya baris `charge` di usage_ledger.
/// Gagal baca -> None (pemanggil memakai fallback derivasi, export
/// tidak digagalkan oleh kegagalan baca sekunder ini).
async fn charged_request_ids(
    pool: &sqlx::MySqlPool,
    request_ids: &[String],
) -> Option<std::collections::HashSet<String>> {
    let mut charged = std::collections::HashSet::new();
    for chunk in request_ids.chunks(500) {
        let mut builder = sqlx::QueryBuilder::new(
            "SELECT request_id FROM usage_ledger WHERE operation = 'charge' AND request_id IN (",
        );
        let mut separated = builder.separated(", ");
        for request_id in chunk {
            separated.push_bind(request_id.clone());
        }
        separated.push_unseparated(")");
        let rows: Vec<(String,)> = match builder.build_query_as().fetch_all(pool).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(?error, "Baca usage_ledger untuk export gagal; pakai fallback charged");
                return None;
            }
        };
        for (request_id,) in rows {
            charged.insert(request_id);
        }
    }
    Some(charged)
}

/// Ringkasan filter untuk baris audit (tanpa nilai sensitif: q adalah
/// kata kunci pencarian admin sendiri dan sudah dibatasi 100 karakter;
/// tidak ada token/kunci/hash yang pernah ditulis ke audit di sini).
fn export_audit_detail(
    kind: &str,
    rows: usize,
    truncated: bool,
    filters: &AdminListFilters,
    extra: &str,
) -> String {
    format!(
        "Export CSV {kind}: {rows} baris{}; filter: status={}, q={}, from={}, to={}{}",
        if truncated {
            " (dipotong pada cap 10000)"
        } else {
            ""
        },
        filters.status.as_deref().unwrap_or("-"),
        filters.q.as_deref().unwrap_or("-"),
        filters
            .from
            .map(format_csv_naive)
            .unwrap_or_else(|| "-".to_owned()),
        filters
            .to_exclusive
            .map(format_csv_naive)
            .unwrap_or_else(|| "-".to_owned()),
        extra,
    )
}

#[derive(Deserialize)]
struct AdminExportQuery {
    status: Option<String>,
    outcome: Option<String>,
    q: Option<String>,
    from: Option<String>,
    to: Option<String>,
    // Khusus usage: produk + prefix (sama seperti list riwayat).
    product: Option<String>,
    api_key_prefix: Option<String>,
}

// AUTHZ-ROLE: Viewer
async fn export_admin_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(kind): Path<String>,
    Query(query): Query<AdminExportQuery>,
) -> Result<Response, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Viewer).await?;
    // Validasi filter DULU (400) sebelum menyentuh database/audit.
    let filters = parse_admin_list_filters(
        query.q,
        query.status,
        query.from,
        query.to,
    )?;
    let kind = kind.trim().to_lowercase();
    let (csv, rows, truncated, audit_extra) = match kind.as_str() {
        "orders" => {
            let pool = qris_pool(&state).await?;
            let order_filters = crate::qris::AdminOrderFilters {
                status: filters.status.clone(),
                q: filters.q.clone(),
                from: filters.from,
                to_exclusive: filters.to_exclusive,
            };
            // Ambil satu baris ekstra untuk mendeteksi pemotongan tanpa
            // COUNT terpisah; baris ekstra dibuang, bukan dikirim.
            let mut orders = crate::qris::list_orders_admin_filtered(
                &pool,
                &order_filters,
                EXPORT_MAX_ROWS as i64 + 1,
                0,
            )
            .await?;
            let truncated = orders.len() > EXPORT_MAX_ROWS;
            orders.truncate(EXPORT_MAX_ROWS);
            let count = orders.len();
            let document = csv_document(
                &[
                    "id",
                    "member_email",
                    "paket",
                    "nominal",
                    "status",
                    "dibuat",
                    "dibayar",
                    "granted",
                ],
                orders.iter().map(order_csv_row).collect(),
            );
            (document, count, truncated, String::new())
        }
        "members" => {
            let mut members = state
                .store
                .list_members()
                .await
                .into_iter()
                .filter(|member| member_matches_admin_filters(member, &filters))
                .collect::<Vec<_>>();
            let truncated = members.len() > EXPORT_MAX_ROWS;
            members.truncate(EXPORT_MAX_ROWS);
            let count = members.len();
            let document = csv_document(
                &["id", "email", "status", "plan", "dibuat"],
                members.iter().map(member_csv_row).collect(),
            );
            (document, count, truncated, String::new())
        }
        "usage" => {
            let product = match query.product.as_deref().map(str::trim) {
                None | Some("") => None,
                Some("bank_account") => Some(crate::models::ValidationProduct::BankAccount),
                Some("ewallet") => Some(crate::models::ValidationProduct::Ewallet),
                Some("whatsapp") => Some(crate::models::ValidationProduct::Whatsapp),
                Some(other) => {
                    return Err(AppError::bad_request(format!(
                        "Produk tidak dikenal: {other}"
                    )))
                }
            };
            let outcome = match (
                query.outcome.as_deref().map(str::trim).filter(|text| !text.is_empty()),
                filters.status.clone(),
            ) {
                (Some(outcome), Some(status))
                    if outcome.to_lowercase() != status.to_lowercase() =>
                {
                    return Err(AppError::bad_request(
                        "Parameter outcome dan status berbeda; isi salah satu saja",
                    ))
                }
                (Some(outcome), _) => Some(outcome.to_lowercase()),
                (None, status) => status.map(|text| text.to_lowercase()),
            };
            let prefix = query
                .api_key_prefix
                .as_deref()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(|text| text.to_lowercase());
            let history_filters = crate::models::ValidationHistoryFilters {
                product,
                outcome,
                api_key_prefix: prefix,
                api_key_prefixes: None,
                q: filters.q.clone(),
                from: filters.from.map(|naive| naive.and_utc()),
                to_exclusive: filters.to_exclusive.map(|naive| naive.and_utc()),
            };
            let page = fetch_validation_history(
                &state,
                &history_filters,
                EXPORT_MAX_ROWS as u32 + 1,
                0,
            )
            .await;
            let mut items = page.items;
            let truncated = items.len() > EXPORT_MAX_ROWS;
            items.truncate(EXPORT_MAX_ROWS);
            // Jalur eksak charged hanya untuk sumber database; mode
            // memori memakai fallback derivasi (lihat usage_charged_label).
            let charged_set = if page.source == "database" {
                match state.store.pool() {
                    Some(pool) => {
                        let request_ids = items
                            .iter()
                            .map(|item| item.request_id.clone())
                            .collect::<Vec<String>>();
                        charged_request_ids(&pool, &request_ids).await
                    }
                    None => None,
                }
            } else {
                None
            };
            let count = items.len();
            let document = csv_document(
                &["tanggal", "prefix_kunci", "produk", "status_hasil", "charged"],
                items
                    .iter()
                    .map(|item| usage_csv_row(item, charged_set.as_ref()))
                    .collect(),
            );
            (
                document,
                count,
                truncated,
                format!("; sumber={}", page.source),
            )
        }
        _ => {
            return Err(AppError::bad_request(
                "Jenis export tidak dikenal: gunakan orders, usage, atau members",
            ))
        }
    };
    record_admin_activity(
        &state,
        &principal,
        "Export CSV admin",
        export_audit_detail(&kind, rows, truncated, &filters, &audit_extra),
    )
    .await;
    // Pilihan streaming (didokumentasikan): writer CSV di atas menulis
    // per baris ke satu String yang DIBATASI cap 10.000 baris, jadi
    // memori respons tidak pernah tak berbatas; tidak ada dependensi
    // streaming baru yang ditambahkan (menghindari churn Cargo.lock).
    // Bila koordinator menginginkan body stream sejati, ganti Body di
    // bawah dengan stream per-baris — cap yang sama tetap berlaku.
    let filename = format!(
        "rajacek-export-{kind}-{}.csv",
        Utc::now().format("%Y%m%d")
    );
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    response_headers.insert(
        HeaderName::from_static("x-export-rows"),
        HeaderValue::from_str(&rows.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    response_headers.insert(
        HeaderName::from_static("x-export-truncated"),
        HeaderValue::from_static(if truncated { "true" } else { "false" }),
    );
    response_headers.insert(
        HeaderName::from_static("x-export-cap"),
        HeaderValue::from_static("10000"),
    );
    Ok((response_headers, csv).into_response())
}

#[derive(Deserialize)]
struct AdminOrdersQuery {
    status: Option<String>,
    // AREA 5: parameter pencarian/filter baru (opsional). Respons lama
    // (array AdminOrderView, default limit 100) tidak berubah bentuk.
    q: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

// Peran: Viewer (ditegakkan server-side via require_admin_role).
async fn list_admin_orders(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminOrdersQuery>,
) -> Result<Json<Vec<crate::qris::AdminOrderView>>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let pool = qris_pool(&state).await?;
    // AREA 3: filter status + rentang tanggal dengan validasi
    // server-side (status tak dikenal -> 400; rentang tak lengkap /
    // terbalik / > 366 hari -> 400). Bentuk respons TIDAK berubah
    // (array) agar pemanggil lama tetap jalan.
    let status = crate::qris::normalize_order_status_filter(query.status.as_deref())?;
    let range = crate::qris::validate_order_date_range(query.from.as_deref(), query.to.as_deref())?;
    // AREA 5: kata kunci q dibersihkan (maks 100 karakter -> 400);
    // validasi tanggal tetap memakai aturan AREA 3 yang lebih ketat
    // (berpasangan, maks 366 hari) agar perilaku list lama tidak bergeser.
    let q = clean_admin_search(query.q.clone())?;
    let (from, to_exclusive) = match range {
        Some((from_date, to_date)) => (
            Some(from_date.and_hms_opt(0, 0, 0).unwrap_or_default()),
            Some(
                (to_date + chrono::Duration::days(1))
                    .and_hms_opt(0, 0, 0)
                    .unwrap_or_default(),
            ),
        ),
        None => (None, None),
    };
    let order_filters = crate::qris::AdminOrderFilters {
        status: status.map(str::to_owned),
        q,
        from,
        to_exclusive,
    };
    // Audit 2026-10-25, K27: paginated, but the old hardcoded limit
    // 100 stays the default so existing callers are unaffected.
    let (limit, offset) = clamp_admin_page(query.limit, query.offset, 100);
    Ok(Json(
        crate::qris::list_orders_admin_filtered(&pool, &order_filters, limit, offset).await?,
    ))
}

#[derive(Deserialize)]
struct ReconciliationQuery {
    from: Option<String>,
    to: Option<String>,
}

#[derive(Serialize)]
struct ReconciliationResponse {
    from: String,
    to: String,
    summary: crate::qris::ReconciliationSummary,
}

// Peran: Viewer (ditegakkan server-side via require_admin_role).
// Ringkasan rekonsiliasi untuk SATU rentang tanggal yang wajib diisi
// (from + to, maks 366 hari — aturan yang sama dengan filter daftar).
// Filter status TIDAK diterapkan di sini: ringkasan memecah SEMUA
// status dalam rentang itu, sehingga total per status dapat dicocokkan
// dengan jumlah baris daftar pada rentang yang sama.
async fn get_orders_reconciliation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReconciliationQuery>,
) -> Result<Json<ReconciliationResponse>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let pool = qris_pool(&state).await?;
    let (from, to) = match crate::qris::validate_order_date_range(
        query.from.as_deref(),
        query.to.as_deref(),
    )? {
        Some(range) => range,
        None => {
            return Err(AppError::bad_request(
                "Rekonsiliasi wajib memakai rentang tanggal (from dan to)",
            ));
        }
    };
    let summary = crate::qris::reconciliation_summary(&pool, from, to).await?;
    Ok(Json(ReconciliationResponse {
        from: from.to_string(),
        to: to.to_string(),
        summary,
    }))
}

#[derive(Deserialize)]
struct RefundRecordRequest {
    amount_idr: u64,
    reason: String,
    external_ref: Option<String>,
    compensation_note: Option<String>,
}

// Peran: Support (ditegakkan server-side via require_admin_role).
// PENCATATAN refund admin — BUKAN pergerakan uang dan BUKAN
// kompensasi kuota (lihat komentar modul refund di qris.rs):
// admin mengembalikan uang lewat dashboard provider secara manual,
// lalu mencatatnya di sini. Endpoint ini tidak memanggil provider,
// tidak mengubah status order, dan tidak mengubah kuota.
async fn create_refund_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
    Json(input): Json<RefundRecordRequest>,
) -> Result<Json<crate::qris::RefundRecordView>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Support).await?;
    let pool = qris_pool(&state).await?;
    let id =
        Uuid::parse_str(&order_id).map_err(|_| AppError::bad_request("ID order tidak valid"))?;
    let record = crate::qris::record_refund(
        &pool,
        &id,
        input.amount_idr,
        &input.reason,
        input.external_ref.as_deref(),
        input.compensation_note.as_deref(),
        &principal.email,
    )
    .await?;
    record_admin_activity(
        &state,
        &principal,
        "Refund dicatat",
        format!(
            "Refund Rp{} dicatat untuk order {} (alasan: {})",
            record.amount_idr, order_id, record.reason
        ),
    )
    .await;
    Ok(Json(record))
}

// Peran: Support (ditegakkan server-side via require_admin_role).
async fn list_order_refunds(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
) -> Result<Json<Vec<crate::qris::RefundRecordView>>, AppError> {
    require_admin_role(&state, &headers, Role::Support).await?;
    let pool = qris_pool(&state).await?;
    let id =
        Uuid::parse_str(&order_id).map_err(|_| AppError::bad_request("ID order tidak valid"))?;
    Ok(Json(
        crate::qris::list_refunds_for_order(&pool, &id).await?,
    ))
}

// Peran: Viewer (ditegakkan server-side via require_admin_role).
// Status alert: aktif hanya bila env Telegram ter-set. Respons ini
// TIDAK PERNAH memuat nilai env apa pun, hanya boolean.
async fn get_alert_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::alerts::AlertStatus>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    Ok(Json(crate::alerts::alert_status()))
}

async fn get_admin_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
) -> Result<Json<crate::qris::AdminOrderView>, AppError> {
    require_admin_role(&state, &headers, Role::Viewer).await?;
    let pool = qris_pool(&state).await?;
    let id =
        Uuid::parse_str(&order_id).map_err(|_| AppError::bad_request("ID order tidak valid"))?;
    Ok(Json(
        crate::qris::get_order_admin(&pool, &id)
            .await?
            .ok_or_else(|| AppError::not_found("Order tidak ditemukan"))?,
    ))
}

/// Admin resolve untuk order tertahan (audit 2026-10-25, B7+B10+K2).
/// Menerima order `needs_review`, `expired`, dan `canceled` — grant
/// HANYA bila terbukti lunas (lihat qris::resolve_needs_review_order).
/// Responsnya adalah SEMUA field MemberOrderView (kompatibel mundur:
/// panel lama yang hanya membaca `status` dkk. tetap jalan) DITAMBAH
/// field `outcome` eksplisit, sehingga konsumen API tidak perlu
/// menebak dari status HTTP 200 semata.
#[derive(Serialize)]
struct ResolveOrderResponse {
    /// "granted" | "already_granted" | "needs_review" | "rejected"
    /// (lihat VerifyOutcome). "rejected" = check-status membuktikan
    /// order belum lunas — kuota TIDAK di-grant, status order tidak
    /// berubah. "needs_review" = grant ditahan (kunci/member tidak
    /// aktif saat grant) — juga TIDAK di-grant.
    outcome: crate::qris::VerifyOutcome,
    #[serde(flatten)]
    view: crate::qris::MemberOrderView,
}

/// Whether a resolve outcome means quota actually landed (K2/B12):
/// only Granted and AlreadyGranted did. Every other outcome — the
/// order is still waiting, expired, canceled, or held for review —
/// must be logged and displayed as "ditahan", never as a grant.
/// (The handler below logs each outcome with its own detail text;
/// this predicate is the single rule behind that distinction, and
/// is covered by `only_granted_outcomes_count_as_landed`.)
#[cfg(test)]
pub(crate) fn resolve_grant_landed(outcome: &crate::qris::VerifyOutcome) -> bool {
    matches!(
        outcome,
        crate::qris::VerifyOutcome::Granted | crate::qris::VerifyOutcome::AlreadyGranted
    )
}

async fn resolve_admin_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
) -> Result<Json<ResolveOrderResponse>, AppError> {
    let principal = require_admin_role(&state, &headers, Role::Support).await?;
    let id =
        Uuid::parse_str(&order_id).map_err(|_| AppError::bad_request("ID order tidak valid"))?;
    let (view, outcome) =
        crate::qris::resolve_needs_review_order(&state.store, &state.config, id).await?;
    // K2: teks log membedakan granted vs ditahan vs ditolak — jangan
    // pernah lagi mencatat NeedsReview/Rejected seolah grant terjadi.
    let detail = match outcome {
        crate::qris::VerifyOutcome::Granted => {
            format!("Order {id} di-grant oleh admin.")
        }
        crate::qris::VerifyOutcome::AlreadyGranted => {
            format!("Order {id} sudah ter-grant sebelumnya (resolve admin).")
        }
        crate::qris::VerifyOutcome::NeedsReview => {
            format!("Order {id} DITAHAN admin (needs_review) — grant belum terjadi.")
        }
        crate::qris::VerifyOutcome::Rejected => {
            format!("Order {id} DITOLAK admin — belum terbukti lunas, kuota tidak di-grant.")
        }
        other => {
            format!("Order {id} di-resolve admin (hasil: {other:?}).")
        }
    };
    record_admin_activity(&state, &principal, "Resolve order pembayaran", detail).await;
    Ok(Json(ResolveOrderResponse { outcome, view }))
}

/// Payload webhook mutasi Cutiezy (docs /docs/webhook): event +
/// data.reference (RRN bank) + data.amount + data.status. TIDAK ADA
/// token order QR dinamis di payload ini — jadi webhook tidak pernah
/// dipakai untuk mencocokkan satu order.
#[derive(Deserialize)]
struct QrisWebhookPayload {
    event: Option<String>,
    data: Option<QrisWebhookPaymentData>,
}

#[derive(Deserialize)]
struct QrisWebhookPaymentData {
    reference: Option<String>,
    amount: Option<u64>,
    status: Option<String>,
}

#[derive(Serialize)]
struct QrisWebhookAck {
    received: bool,
}

/// Webhook Cutiezy sebagai PEMICU sweep, bukan bukti bayar:
/// 1. Signature HMAC diverifikasi dulu (fail closed: tanpa secret
///    terkonfigurasi -> 503, signature salah -> 401).
/// 2. Event pembayaran (`qris.payment`, plus `qris.payment.success`
///    dari halaman QRIS yang penamaannya berbeda) hanya membangunkan
///    sweep order terbuka di background — grant tetap diputuskan
///    verify_and_grant lewat check-status + cocok nominal.
/// 3. Balas 200 `{"received": true}` SEGERA (docs menuntut <= 5 detik);
///    kegagalan transient di dalam sweep ditanggung sweep rutin tiap
///    menit, bukan retry Cutiezy.
/// Sengaja TIDAK memeriksa qris_enabled: kill switch mematikan
/// pembelian baru, tapi order yang sudah dibayar harus tetap bisa
/// grant — sama seperti janji sweep rutin.
async fn qris_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<QrisWebhookAck>, AppError> {
    let pool = qris_pool(&state).await?;
    let settings = crate::qris::load_qris_settings(&pool).await?;
    let cipher = crate::provider_config::CredentialCipher::new(
        state.config.api_key_encryption_key.as_deref(),
    );
    let secret = settings
        .webhook_secret_ciphertext
        .as_deref()
        .and_then(|ciphertext| cipher.decrypt(ciphertext).ok())
        .ok_or_else(|| AppError::service_unavailable("Webhook QRIS belum dikonfigurasi."))?;
    let signature = headers
        .get("x-cutiezy-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("Signature webhook tidak ada"))?;
    if !crate::qris::verify_webhook_signature(&secret, &body, signature) {
        tracing::warn!("Signature webhook QRIS tidak valid");
        return Err(AppError::unauthorized("Signature webhook tidak valid"));
    }
    let payload: QrisWebhookPayload = serde_json::from_slice(&body).unwrap_or(QrisWebhookPayload {
        event: None,
        data: None,
    });
    if crate::qris::is_payment_event(payload.event.as_deref()) {
        if let Some(data) = &payload.data {
            tracing::info!(
                reference = data.reference.as_deref().unwrap_or("-"),
                amount = data.amount.unwrap_or(0),
                status = data.status.as_deref().unwrap_or("-"),
                "Webhook pembayaran QRIS diterima; memicu sweep order terbuka",
            );
        }
        // K25: spawn sweep ter-dedup (maks satu berjalan); banjir
        // webhook tidak menumpuk sweep bersamaan. Sweep rutin tiap
        // 60 detik tetap menjadi backstop dan tidak ikut dedup ini.
        crate::qris::spawn_webhook_sweep(state.store.clone(), state.config.clone());
    }
    Ok(Json(QrisWebhookAck { received: true }))
}

#[cfg(test)]
mod account_name_tests {
    use super::*;

    fn result_with(name: Option<&str>) -> Option<crate::models::ValidationResultData> {
        Some(crate::models::ValidationResultData {
            account_number: None,
            phone_number: None,
            service_code: None,
            bank_name: None,
            account_name: name.map(str::to_owned),
            provider: None,
            registered: None,
            reference: None,
        })
    }

    #[test]
    fn mixed_case_and_masked_names_become_uppercase() {
        let mut result = result_with(Some("Andrias Setiawan"));
        uppercase_account_name(&mut result);
        assert_eq!(
            result.unwrap().account_name.as_deref(),
            Some("ANDRIAS SETIAWAN")
        );
        let mut result = result_with(Some("Andrias Se****an Su****o"));
        uppercase_account_name(&mut result);
        assert_eq!(
            result.unwrap().account_name.as_deref(),
            Some("ANDRIAS SE****AN SU****O")
        );
    }

    #[test]
    fn missing_name_stays_missing() {
        let mut result = result_with(None);
        uppercase_account_name(&mut result);
        assert!(result.unwrap().account_name.is_none());
        let mut result: Option<crate::models::ValidationResultData> = None;
        uppercase_account_name(&mut result);
        assert!(result.is_none());
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn hint_participates_in_fingerprint() {
        let base = fingerprint_hash(
            "test-secret",
            ValidationProduct::BankAccount,
            "1234567890",
            "014",
        );
        // Same account, different bank: MUST differ (audit 2026-10-25, B1).
        let other_bank = fingerprint_hash(
            "test-secret",
            ValidationProduct::BankAccount,
            "1234567890",
            "002",
        );
        assert_ne!(base, other_bank);
        // Same inputs: stable.
        let again = fingerprint_hash(
            "test-secret",
            ValidationProduct::BankAccount,
            "1234567890",
            "014",
        );
        assert_eq!(base, again);
        // Empty hint differs from a real hint.
        let no_hint = fingerprint_hash(
            "test-secret",
            ValidationProduct::BankAccount,
            "1234567890",
            "",
        );
        assert_ne!(base, no_hint);
    }
}

#[cfg(test)]
mod admin_audit_tests {
    use super::*;

    #[test]
    fn page_params_keep_defaults_and_clamp() {
        // Activity default 50, orders default 100 (K27 compatibility).
        assert_eq!(clamp_admin_page(None, None, 50), (50, 0));
        assert_eq!(clamp_admin_page(None, None, 100), (100, 0));
        assert_eq!(clamp_admin_page(Some(0), Some(-5), 50), (1, 0));
        assert_eq!(clamp_admin_page(Some(999), Some(40), 100), (200, 40));
        assert_eq!(clamp_admin_page(Some(25), Some(50), 50), (25, 50));
    }

    #[test]
    fn activity_date_bounds_parse_and_reject() {
        // Tanggal polos: from = awal hari, to = akhir hari.
        let from = parse_activity_bound("2026-10-20", false).expect("from valid");
        let to = parse_activity_bound("2026-10-20", true).expect("to valid");
        assert!(from < to);
        assert_eq!(from.to_rfc3339(), "2026-10-20T00:00:00+00:00");
        assert!(to.to_rfc3339().starts_with("2026-10-20T23:59:59"));
        // RFC3339 dipertahankan apa adanya (dikonversi ke UTC).
        let moment =
            parse_activity_bound("2026-10-21T10:30:00+07:00", false).expect("rfc3339 valid");
        assert_eq!(moment.to_rfc3339(), "2026-10-21T03:30:00+00:00");
        // Input sampah ditolak 400, bukan diam-diam diabaikan.
        assert!(parse_activity_bound("kemarin", false).is_err());
        assert!(parse_activity_bound("2026-13-40", false).is_err());
        assert!(parse_activity_bound("2026-10-20T25:00:00Z", false).is_err());
        assert_eq!(
            parse_activity_bound("kemarin", false).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn only_granted_outcomes_count_as_landed() {
        use crate::qris::VerifyOutcome;
        assert!(resolve_grant_landed(&VerifyOutcome::Granted));
        assert!(resolve_grant_landed(&VerifyOutcome::AlreadyGranted));
        assert!(!resolve_grant_landed(&VerifyOutcome::Waiting));
        assert!(!resolve_grant_landed(&VerifyOutcome::Expired));
        assert!(!resolve_grant_landed(&VerifyOutcome::Canceled));
        assert!(!resolve_grant_landed(&VerifyOutcome::NeedsReview));
    }
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("nama header valid"),
                HeaderValue::from_str(value).expect("nilai header valid"),
            );
        }
        headers
    }

    #[test]
    fn cf_connecting_ip_wins_over_first_xff_on_loopback() {
        let headers = headers_with(&[
            ("cf-connecting-ip", "203.0.113.7"),
            ("x-forwarded-for", "198.51.100.9, 10.0.0.1"),
        ]);
        assert_eq!(
            effective_client_ip(&headers, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn unparseable_cf_falls_back_to_first_xff() {
        let headers = headers_with(&[
            ("cf-connecting-ip", "bukan-ip"),
            ("x-forwarded-for", "198.51.100.9, 10.0.0.1"),
        ]);
        assert_eq!(
            effective_client_ip(&headers, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))
        );
    }

    #[test]
    fn loopback_without_headers_keeps_peer() {
        let headers = HeaderMap::new();
        assert_eq!(
            effective_client_ip(&headers, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn non_loopback_peer_ignores_all_headers() {
        let headers = headers_with(&[
            ("cf-connecting-ip", "203.0.113.7"),
            ("x-forwarded-for", "198.51.100.9"),
        ]);
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55));
        assert_eq!(effective_client_ip(&headers, peer), peer);
    }
}

#[cfg(test)]
mod member_detail_adjust_tests {
    use super::*;
    use crate::models::AdminApiKeySummary;

    fn member_fixture(status: &str) -> crate::models::MemberAccount {
        crate::models::MemberAccount {
            id: Uuid::now_v7(),
            google_sub: "google-sub-tes".to_owned(),
            email: "member-tes@example.test".to_owned(),
            name: Some("Member Tes".to_owned()),
            picture_url: None,
            plan_kind: "manual".to_owned(),
            status: status.to_owned(),
            created_at: Utc::now(),
            last_login_at: None,
        }
    }

    #[test]
    fn adjust_input_validation() {
        assert_eq!(
            validate_quota_adjust_input(Some(250), Some("  koreksi paket  ")).unwrap(),
            (250, "koreksi paket".to_owned())
        );
        assert_eq!(
            validate_quota_adjust_input(Some(-50), Some("pengembalian")).unwrap().0,
            -50
        );
        // Delta wajib, tidak boleh 0, dan dibatasi per panggilan.
        assert!(validate_quota_adjust_input(None, Some("alasan sah")).is_err());
        assert!(validate_quota_adjust_input(Some(0), Some("alasan sah")).is_err());
        assert!(validate_quota_adjust_input(
            Some(crate::store::MAX_QUOTA_ADJUST_DELTA + 1),
            Some("alasan sah")
        )
        .is_err());
        assert!(validate_quota_adjust_input(
            Some(-crate::store::MAX_QUOTA_ADJUST_DELTA - 1),
            Some("alasan sah")
        )
        .is_err());
        assert!(validate_quota_adjust_input(
            Some(crate::store::MAX_QUOTA_ADJUST_DELTA),
            Some("alasan sah")
        )
        .is_ok());
        // Alasan wajib, minimal 5 karakter (dihitung per karakter),
        // dan dibatasi 500 karakter.
        assert!(validate_quota_adjust_input(Some(10), None).is_err());
        assert!(validate_quota_adjust_input(Some(10), Some("")).is_err());
        assert!(validate_quota_adjust_input(Some(10), Some("   ")).is_err());
        assert!(validate_quota_adjust_input(Some(10), Some("abcd")).is_err());
        assert!(validate_quota_adjust_input(Some(10), Some("abcde")).is_ok());
        assert!(validate_quota_adjust_input(Some(10), Some(&"a".repeat(501))).is_err());
    }

    #[test]
    fn disabled_member_rejected_for_adjust() {
        assert!(ensure_member_active_for_adjust(&member_fixture("active")).is_ok());
        let error = ensure_member_active_for_adjust(&member_fixture("disabled"))
            .expect_err("member disabled harus ditolak");
        assert_eq!(error.status, StatusCode::CONFLICT);
    }

    #[test]
    fn usage_days_fill_zero_days_in_order() {
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 25).expect("tanggal tes valid");
        let sparse = vec![crate::store::MemberDailyUsage {
            date: "2026-10-24".to_owned(),
            charged_hits: 5,
        }];
        let filled = fill_usage_days(today, 3, &sparse);
        assert_eq!(
            filled
                .iter()
                .map(|day| day.date.as_str())
                .collect::<Vec<_>>(),
            vec!["2026-10-23", "2026-10-24", "2026-10-25"]
        );
        assert_eq!(
            filled
                .iter()
                .map(|day| day.charged_hits)
                .collect::<Vec<_>>(),
            vec![0, 5, 0]
        );
        // Rentang di-clamp 1..=90.
        assert_eq!(fill_usage_days(today, 0, &sparse).len(), 1);
        assert_eq!(fill_usage_days(today, 999, &sparse).len(), 90);
    }

    #[test]
    fn adjust_audit_detail_carries_before_and_after() {
        let outcome = crate::store::QuotaAdjustment {
            key_id: Uuid::now_v7(),
            prefix: "rk_live_ab12".to_owned(),
            delta: 250,
            quota_total_before: 1000,
            quota_total_after: 1250,
            quota_remaining_before: 900,
            quota_remaining_after: 1150,
        };
        let detail =
            quota_adjust_audit_detail("member-tes@example.test", &outcome, "koreksi paket");
        assert!(detail.contains("member-tes@example.test"));
        assert!(detail.contains("rk_live_ab12"));
        assert!(detail.contains("+250"));
        assert!(detail.contains("900 → 1150"));
        assert!(detail.contains("1000 → 1250"));
        assert!(detail.contains("koreksi paket"));
    }

    #[test]
    fn detail_key_view_serialization_has_no_secret_fields() {
        // Tipe view detail TIDAK PUNYA field rahasia: serialisasi apa pun
        // dari tipe ini tidak bisa membocorkan plaintext/hash/ciphertext.
        let summary = AdminApiKeySummary {
            id: Uuid::now_v7(),
            name: "Kunci member".to_owned(),
            prefix: "rk_live_ab12".to_owned(),
            scopes: vec!["validate:*".to_owned()],
            status: "active".to_owned(),
            last_used_at: None,
            rate_limit_per_minute: 60,
            quota_total: 1000,
            expires_at: None,
            package_id: None,
            member_id: Some(Uuid::now_v7()),
            created_at: Utc::now(),
        };
        let view = MemberDetailKeyView {
            summary,
            quota_remaining: 900,
            invalid_free_used_today: 3,
            buckets: Vec::new(),
        };
        let serialized = serde_json::to_string(&view).expect("serialisasi view detail");
        assert!(serialized.contains("rk_live_ab12"));
        assert!(serialized.contains("\"quota_remaining\":900"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("ciphertext"));
        assert!(!serialized.contains("plaintext"));
    }
}

#[cfg(test)]
mod site_status_tests {
    use super::*;
    use std::collections::HashSet;

    /// Kata yang dilarang muncul di permukaan publik/member: nama
    /// provider upstream, host-nya, header khasnya, dan contoh kode
    /// mapping upstream (bukan kode bank publik).
    const FORBIDDEN_PROVIDER_WORDS: &[&str] = &[
        "tukangcek",
        "cutiezy",
        "xiongdi",
        "api.cutiezy.id",
        "tukangcek.id",
        "bric1id",
        "bcac1id",
        "x-cutiezy",
    ];

    fn assert_no_provider_words(body: &str) {
        let lowered = body.to_ascii_lowercase();
        for word in FORBIDDEN_PROVIDER_WORDS {
            assert!(
                !lowered.contains(word),
                "permukaan publik tidak boleh menyebut {word}; body: {body}"
            );
        }
    }

    fn test_settings() -> SiteSettings {
        SiteSettings {
            announcement_text: String::new(),
            announcement_active: false,
            maintenance_banner_text: String::new(),
            maintenance_banner_active: false,
            maintenance_block_validations: false,
        }
    }

    #[test]
    fn only_exact_one_activates_a_flag() {
        assert!(parse_active_flag(Some("1".to_owned())));
        assert!(!parse_active_flag(Some("0".to_owned())));
        assert!(!parse_active_flag(None));
        assert!(!parse_active_flag(Some(String::new())));
        assert!(!parse_active_flag(Some("true".to_owned())));
        assert!(!parse_active_flag(Some("yes".to_owned())));
    }

    #[test]
    fn guard_circuit_maps_to_product_status() {
        assert_eq!(product_status_from_circuit("closed"), "operational");
        assert_eq!(product_status_from_circuit("open"), "degraded");
        assert_eq!(product_status_from_circuit("half_open"), "degraded");
        assert_eq!(product_status_from_circuit("tidak-dikenal"), "operational");
    }

    #[test]
    fn no_guard_means_operational_not_invented_outage() {
        let status = build_public_status(None, &test_settings());
        assert_eq!(status.overall, "operational");
        assert_eq!(status.products.len(), 3);
        assert!(status
            .products
            .iter()
            .all(|entry| entry.status == "operational"));
        assert_eq!(status.products[0].product, "bank_account");
        assert_eq!(status.products[0].label, "Validasi Rekening");
        assert_eq!(status.products[1].product, "ewallet");
        assert_eq!(status.products[1].label, "Validasi E-Wallet");
        assert_eq!(status.products[2].product, "whatsapp");
        assert_eq!(status.products[2].label, "Validasi WhatsApp");
        assert!(status.announcement.is_none());
        assert!(status.maintenance_banner.is_none());
        assert!(!status.maintenance_blocks_validations);
    }

    #[test]
    fn open_circuit_degrades_only_that_product_and_overall() {
        let guard_statuses = vec![
            GuardProductStatus {
                product: ValidationProduct::BankAccount,
                circuit: "closed",
                consecutive_failures: 0,
                in_flight: 0,
                max_concurrency: 16,
            },
            GuardProductStatus {
                product: ValidationProduct::Ewallet,
                circuit: "open",
                consecutive_failures: 5,
                in_flight: 0,
                max_concurrency: 16,
            },
            GuardProductStatus {
                product: ValidationProduct::Whatsapp,
                circuit: "half_open",
                consecutive_failures: 2,
                in_flight: 0,
                max_concurrency: 16,
            },
        ];
        let status = build_public_status(Some(guard_statuses), &test_settings());
        assert_eq!(status.overall, "degraded");
        assert_eq!(status.products[0].status, "operational");
        assert_eq!(status.products[1].status, "degraded");
        assert_eq!(status.products[2].status, "degraded");
    }

    #[test]
    fn banners_appear_only_when_active_and_nonempty() {
        let mut settings = test_settings();
        settings.announcement_text = "Info penting".to_owned();
        settings.announcement_active = false;
        settings.maintenance_banner_text = "   ".to_owned();
        settings.maintenance_banner_active = true;
        let status = build_public_status(None, &settings);
        assert!(status.announcement.is_none());
        assert!(status.maintenance_banner.is_none());

        settings.announcement_active = true;
        settings.maintenance_banner_text = "Pemeliharaan terjadwal".to_owned();
        settings.maintenance_block_validations = true;
        let status = build_public_status(None, &settings);
        assert_eq!(status.announcement.as_deref(), Some("Info penting"));
        assert_eq!(
            status.maintenance_banner.as_deref(),
            Some("Pemeliharaan terjadwal")
        );
        assert!(status.maintenance_blocks_validations);
    }

    #[test]
    fn banner_html_is_escaped_not_executed() {
        let mut settings = test_settings();
        settings.announcement_text =
            "<script>alert(1)</script> & \"promo\" <b>tebal</b>".to_owned();
        settings.announcement_active = true;
        let status = build_public_status(None, &settings);
        let page = render_public_status_page(&status);
        assert!(!page.contains("<script>alert(1)</script>"));
        assert!(!page.contains("<b>tebal</b>"));
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("&amp;"));
        assert!(page.contains("&lt;b&gt;tebal&lt;/b&gt;"));
        assert_no_provider_words(&page);
    }

    #[test]
    fn public_status_json_hides_provider_words() {
        let status = build_public_status(None, &test_settings());
        let json = serde_json::to_string(&status).expect("serialisasi status");
        assert_no_provider_words(&json);
        assert!(json.contains("Validasi Rekening"));
        assert!(json.contains("operational"));
    }

    #[test]
    fn maintenance_message_is_the_spec_message() {
        assert_eq!(MAINTENANCE_MESSAGE, "Layanan sedang dalam pemeliharaan");
    }

    async fn test_app_state(
        guard: Option<Arc<ProviderGuard>>,
    ) -> AppState {
        let config = Arc::new(crate::config::AppConfig {
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
            dashboard_session_secret: Some("test-dashboard-secret".to_owned()),
            data_fingerprint_secret: Some("test-fingerprint-secret".to_owned()),
            google_client_id: None,
            google_client_secret: None,
            google_redirect_uri: None,
            google_member_redirect_uri: None,
            admin_google_emails: HashSet::new(),
            development_admin_token: None,
            demo_api_key: Some(
                "rv_demo_0123456789abcdef0123456789abcdef".to_owned(),
            ),
            allowed_dashboard_origin: None,
            qris_base_url: "https://example.invalid".to_owned(),
        });
        let provider_configs = crate::provider_config::ProviderConfigStore::build(&config)
            .await
            .expect("provider configs tanpa DB");
        let store = Arc::new(
            crate::store::AdminStore::new(config.demo_api_key.as_deref(), 60)
                .expect("admin store demo"),
        );
        let guard_arc = Arc::new(ProviderGuard::new(ProviderGuardConfig::default()));
        let provider = crate::provider::build_provider(&config, provider_configs.clone(), guard_arc);
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
            provider_guard: guard,
            event_sink: crate::events::build_usage_event_sink(
                None,
                "validation-events".to_owned(),
            )
            .await
            .expect("event sink lokal"),
            oauth_states: Arc::new(crate::auth::OAuthStateStore::new()),
            session_revocation: Arc::new(
                crate::session_revocation::SessionRevocation::new(None).await,
            ),
        }
    }

    async fn serve_test_app(state: AppState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind localhost");
        let address = listener.local_addr().expect("alamat listener");
        let router = build_router(state);
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn public_status_and_health_need_no_login() {
        let base = serve_test_app(test_app_state(None).await).await;
        let client = reqwest::Client::new();

        let health = client
            .get(format!("{base}/health/live"))
            .send()
            .await
            .expect("health/live");
        assert_eq!(health.status(), 200);

        let json = client
            .get(format!("{base}/v1/status"))
            .send()
            .await
            .expect("/v1/status");
        assert_eq!(json.status(), 200);
        let body = json.text().await.expect("body /v1/status");
        assert!(body.contains("Validasi Rekening"));
        assert!(body.contains("Validasi E-Wallet"));
        assert!(body.contains("Validasi WhatsApp"));
        assert!(body.contains("\"overall\":\"operational\""));
        assert_no_provider_words(&body);

        let page = client
            .get(format!("{base}/status"))
            .send()
            .await
            .expect("/status");
        assert_eq!(page.status(), 200);
        let page_body = page.text().await.expect("body /status");
        assert!(page_body.contains("Status Layanan"));
        assert!(page_body.contains("Validasi Rekening"));
        assert_no_provider_words(&page_body);
    }

    #[tokio::test]
    async fn open_guard_circuit_shows_degraded_over_http() {
        let guard = ProviderGuard::new(ProviderGuardConfig {
            failure_threshold: 1,
            ..ProviderGuardConfig::default()
        });
        let ticket = guard
            .acquire(ValidationProduct::Ewallet, "srv-ewallet-uji")
            .await
            .expect("circuit tertutup menerima");
        guard.record_failure(&ticket).await;
        let base = serve_test_app(test_app_state(Some(Arc::new(guard))).await).await;
        let body = reqwest::Client::new()
            .get(format!("{base}/v1/status"))
            .send()
            .await
            .expect("/v1/status")
            .text()
            .await
            .expect("body");
        let value: serde_json::Value =
            serde_json::from_str(&body).expect("JSON status valid");
        assert_eq!(value["overall"], "degraded");
        let products = value["products"].as_array().expect("array produk");
        let ewallet = products
            .iter()
            .find(|entry| entry["product"] == "ewallet")
            .expect("produk ewallet");
        assert_eq!(ewallet["status"], "degraded");
        let bank = products
            .iter()
            .find(|entry| entry["product"] == "bank_account")
            .expect("produk bank");
        assert_eq!(bank["status"], "operational");
        assert_no_provider_words(&body);
    }

    #[tokio::test]
    async fn validation_runs_normally_when_no_block_flag_exists() {
        // Tanpa database, kunci maintenance_block_validations tidak ada:
        // default HARUS tidak memblokir (validasi demo berjalan normal,
        // bukan 503). Cabang "1" tidak bisa diuji tanpa MySQL — lihat
        // laporan: verifikasi itu diserahkan ke integrasi dengan DB.
        let base = serve_test_app(test_app_state(None).await).await;
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/validate/bank-account"))
            .header("X-API-Key", "rv_demo_0123456789abcdef0123456789abcdef")
            .json(&serde_json::json!({
                "bank_code": "002",
                "account_number": "1234567890",
            }))
            .send()
            .await
            .expect("validasi demo");
        assert_ne!(
            response.status().as_u16(),
            503,
            "tanpa flag blokir, validasi tidak boleh 503"
        );
        let body = response.text().await.expect("body validasi");
        assert!(!body.contains(MAINTENANCE_MESSAGE));
    }

    #[tokio::test]
    async fn site_settings_endpoints_require_admin_session() {
        let base = serve_test_app(test_app_state(None).await).await;
        let client = reqwest::Client::new();
        let get = client
            .get(format!("{base}/v1/admin/site-settings"))
            .send()
            .await
            .expect("GET site-settings");
        assert_eq!(get.status(), 401);
        let put = client
            .put(format!("{base}/v1/admin/site-settings"))
            .json(&serde_json::json!({
                "announcement_text": "Uji",
                "announcement_active": true,
                "maintenance_banner_text": "",
                "maintenance_banner_active": false,
                "maintenance_block_validations": false,
            }))
            .send()
            .await
            .expect("PUT site-settings");
        assert_eq!(put.status(), 401);
    }
}

#[cfg(test)]
mod admin_export_tests {
    use super::*;

    fn naive_at(day: u32) -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 10, day)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap()
    }

    fn member_fixture(email: &str, name: Option<&str>, status: &str, day: u32) -> crate::models::MemberAccount {
        crate::models::MemberAccount {
            id: Uuid::parse_str("0199a5a5-0000-7000-8000-000000000001").unwrap(),
            google_sub: "sub-fixture".to_owned(),
            email: email.to_owned(),
            name: name.map(str::to_owned),
            picture_url: None,
            plan_kind: "trial".to_owned(),
            status: status.to_owned(),
            created_at: naive_at(day).and_utc(),
            last_login_at: None,
        }
    }

    fn history_fixture(prefix: &str, outcome: &str, request_id: &str) -> crate::models::ValidationHistoryItem {
        crate::models::ValidationHistoryItem {
            request_id: request_id.to_owned(),
            api_key_prefix: prefix.to_owned(),
            product: crate::models::ValidationProduct::BankAccount,
            outcome: outcome.to_owned(),
            target_masked: "***1234".to_owned(),
            target_raw: None,
            account_name: None,
            provider_reference: None,
            provider_latency_ms: 10,
            rajacek_processing_ms: None,
            total_latency_ms: None,
            attempts: None,
            occurred_at: naive_at(20).and_utc(),
            channel: "api".to_owned(),
        }
    }

    #[test]
    fn csv_escaping_quotes_commas_and_newlines() {
        assert_eq!(csv_field("sederhana"), "sederhana");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("kata \"kutip\""), "\"kata \"\"kutip\"\"\"");
        assert_eq!(csv_field("baris1\nbaris2"), "\"baris1\nbaris2\"");
        let row = csv_row(&[
            "a,b".to_owned(),
            "kata \"x\"".to_owned(),
            "normal".to_owned(),
        ]);
        assert_eq!(row, "\"a,b\",\"kata \"\"x\"\"\",normal\n");
    }

    #[test]
    fn order_csv_row_never_carries_payment_token_or_key_material() {
        // Nilai tiruan yang menyerupai secret — HANYA untuk membuktikan
        // kolom-kolom itu tidak pernah disalin ke CSV.
        let fake_token = "FAKE-TOKEN-VALUE-12345";
        let fake_key_id = "FAKE-KEY-ID-67890";
        let order = crate::qris::AdminOrderView {
            id: "0199a5a5-0000-7000-8000-000000000099".to_owned(),
            member_id: "0199a5a5-0000-7000-8000-000000000001".to_owned(),
            member_email: Some("member, \"test\"@contoh.id".to_owned()),
            key_id: Some(fake_key_id.to_owned()),
            package_id: "pkg-1".to_owned(),
            package_name: "Paket, Premium".to_owned(),
            price_idr: 50000,
            quota_hits: 1000,
            rate_limit_per_minute: 60,
            valid_days: 30,
            amount_idr: 50000,
            status: "granted".to_owned(),
            qris_token: Some(fake_token.to_owned()),
            qris_expires_at: None,
            paid_at: Some(naive_at(21)),
            granted_at: Some(naive_at(22)),
            granted_quota: Some(1000),
            granted_expires_at: None,
            mutation_ref: Some("FAKE-MUTATION-REF".to_owned()),
            last_error: Some("FAKE-PROVIDER-ERROR".to_owned()),
            created_at: naive_at(20),
            updated_at: naive_at(22),
        };
        let document = csv_document(
            &["id", "member_email", "paket", "nominal", "status", "dibuat", "dibayar", "granted"],
            vec![order_csv_row(&order)],
        );
        assert!(!document.contains(fake_token), "token pembayaran bocor ke CSV");
        assert!(!document.contains(fake_key_id), "key_id bocor ke CSV");
        assert!(!document.contains("FAKE-MUTATION-REF"));
        assert!(!document.contains("FAKE-PROVIDER-ERROR"));
        assert!(document.contains("0199a5a5-0000-7000-8000-000000000099"));
        assert!(document.contains("\"member, \"\"test\"\"@contoh.id\""));
        assert!(document.contains("\"Paket, Premium\""));
        assert_eq!(document.lines().count(), 2, "header + 1 baris data");
    }

    #[test]
    fn member_csv_row_has_exactly_the_specified_columns() {
        let member = member_fixture("a@contoh.id", Some("Ani"), "active", 20);
        let row = member_csv_row(&member);
        assert_eq!(row.len(), 5);
        assert_eq!(row[1], "a@contoh.id");
        assert_eq!(row[2], "active");
        assert_eq!(row[3], "trial");
        assert!(row[4].starts_with("2026-10-20T10:00:00"));
        // Tidak ada prefix kunci / data kunci di baris member.
        assert!(!row.iter().any(|field| field.contains("rv_live")));
    }

    #[test]
    fn usage_charged_prefers_ledger_over_outcome_derivation() {
        let item = history_fixture("rv_live_ab12", "invalid", "req-1");
        let mut charged = std::collections::HashSet::new();
        charged.insert("req-1".to_owned());
        // Invalid yang ADA di ledger = ditagih (melewati jatah gratis).
        assert_eq!(usage_charged_label(&item, Some(&charged)), "ya");
        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        assert_eq!(usage_charged_label(&item, Some(&empty)), "tidak");
        // Fallback (tanpa ledger): valid/not_kyc selalu ya, lainnya tidak.
        assert_eq!(usage_charged_label(&history_fixture("p", "valid", "r2"), None), "ya");
        assert_eq!(usage_charged_label(&history_fixture("p", "not_kyc", "r3"), None), "ya");
        assert_eq!(usage_charged_label(&history_fixture("p", "pending", "r4"), None), "tidak");
        let row = usage_csv_row(&item, Some(&charged));
        assert_eq!(row.len(), 5);
        assert_eq!(row[1], "rv_live_ab12");
        assert_eq!(row[4], "ya");
    }

    #[test]
    fn export_cap_truncates_at_10000_rows() {
        assert_eq!(EXPORT_MAX_ROWS, 10_000);
        let mut rows: Vec<u32> = (0..10_001).collect();
        let truncated = rows.len() > EXPORT_MAX_ROWS;
        rows.truncate(EXPORT_MAX_ROWS);
        assert!(truncated);
        assert_eq!(rows.len(), 10_000);
    }

    #[test]
    fn filter_validation_rejects_bad_input_with_400_not_500() {
        assert!(parse_admin_list_filters(None, None, Some("bukan-tanggal".to_owned()), None).is_err());
        assert!(parse_admin_list_filters(None, None, Some("2026-02-30".to_owned()), None).is_err());
        assert!(parse_admin_list_filters(
            None,
            None,
            Some("2026-10-25".to_owned()),
            Some("2026-10-20".to_owned()),
        )
        .is_err());
        assert!(parse_admin_list_filters(Some("x".repeat(101)), None, None, None).is_err());
        let filters = parse_admin_list_filters(
            Some("  Ani@Contoh.ID ".to_owned()),
            Some("active".to_owned()),
            Some("2026-10-20".to_owned()),
            Some("2026-10-25".to_owned()),
        )
        .expect("filter valid harus lolos");
        assert_eq!(filters.q.as_deref(), Some("Ani@Contoh.ID"));
        assert_eq!(filters.from, Some(naive_at(20).date().and_hms_opt(0, 0, 0).unwrap()));
        // `to` tanggal kalender = eksklusif 00:00 hari berikutnya.
        assert_eq!(
            filters.to_exclusive,
            Some(naive_at(25).date().and_hms_opt(0, 0, 0).unwrap() + chrono::Duration::days(1))
        );
        for error in [
            parse_admin_list_filters(None, None, Some("bukan-tanggal".to_owned()), None).unwrap_err(),
            parse_admin_list_filters(None, None, Some("2026-10-25".to_owned()), Some("2026-10-20".to_owned())).unwrap_err(),
        ] {
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn member_filters_narrow_results_correctly() {
        let base = parse_admin_list_filters(None, None, None, None).unwrap();
        let member = member_fixture("ani@contoh.id", Some("Ani Wijaya"), "active", 20);
        assert!(member_matches_admin_filters(&member, &base));

        let by_email = parse_admin_list_filters(Some("ANI@contoh".to_owned()), None, None, None).unwrap();
        assert!(member_matches_admin_filters(&member, &by_email));
        let by_name = parse_admin_list_filters(Some("wijaya".to_owned()), None, None, None).unwrap();
        assert!(member_matches_admin_filters(&member, &by_name));
        let by_id = parse_admin_list_filters(Some("0199a5a5".to_owned()), None, None, None).unwrap();
        assert!(member_matches_admin_filters(&member, &by_id));
        let miss = parse_admin_list_filters(Some("budi".to_owned()), None, None, None).unwrap();
        assert!(!member_matches_admin_filters(&member, &miss));

        let by_status = parse_admin_list_filters(None, Some("DISABLED".to_owned()), None, None).unwrap();
        assert!(!member_matches_admin_filters(&member, &by_status));
        let active = parse_admin_list_filters(None, Some("active".to_owned()), None, None).unwrap();
        assert!(member_matches_admin_filters(&member, &active));

        let in_range = parse_admin_list_filters(None, None, Some("2026-10-20".to_owned()), Some("2026-10-21".to_owned())).unwrap();
        assert!(member_matches_admin_filters(&member, &in_range));
        let out_range = parse_admin_list_filters(None, None, Some("2026-10-21".to_owned()), Some("2026-10-22".to_owned())).unwrap();
        assert!(!member_matches_admin_filters(&member, &out_range));
    }

    #[test]
    fn history_filter_matches_q_and_date_range() {
        let filters = crate::models::ValidationHistoryFilters {
            product: None,
            outcome: None,
            api_key_prefix: None,
            api_key_prefixes: None,
            q: Some("rv_live_ab".to_owned()),
            from: None,
            to_exclusive: None,
        };
        assert!(filters.matches(&history_fixture("rv_live_ab12", "valid", "req-1")));
        assert!(!filters.matches(&history_fixture("rv_live_zz99", "valid", "req-2")));
        let dated = crate::models::ValidationHistoryFilters {
            product: None,
            outcome: None,
            api_key_prefix: None,
            api_key_prefixes: None,
            q: None,
            from: Some(naive_at(20).and_utc()),
            to_exclusive: Some(naive_at(21).and_utc()),
        };
        assert!(dated.matches(&history_fixture("rv_live_ab12", "valid", "req-1")));
    }

    #[test]
    fn admin_gate_without_session_is_unauthorized() {
        // Gerbang yang dipakai export_admin_csv sebagai baris pertama
        // (lewat require_admin lokal): tanpa sesi/token -> 401.
        let config = crate::config::AppConfig {
            environment: crate::config::Environment::Production,
            bind_address: "127.0.0.1:0".to_owned(),
            database_url: Some(String::new()),
            redis_url: None,
            provider_mode: crate::config::ProviderMode::Demo,
            provider_base_url: None,
            provider_api_key: None,
            provider_credential_key: None,
            api_key_encryption_key: None,
            provider_allowed_hosts: Vec::new(),
            request_timeout_seconds: 10,
            default_rate_limit_per_minute: 60,
            provider_max_concurrency_per_product: 4,
            provider_queue_wait_ms: 100,
            provider_breaker_failure_threshold: 5,
            provider_breaker_cooldown_seconds: 30,
            event_stream_name: "test".to_owned(),
            idempotency_ttl_seconds: 3600,
            dashboard_session_secret: Some("test-secret".to_owned()),
            data_fingerprint_secret: Some("test-secret".to_owned()),
            google_client_id: None,
            google_client_secret: None,
            google_redirect_uri: None,
            google_member_redirect_uri: None,
            admin_google_emails: std::collections::HashSet::new(),
            development_admin_token: None,
            demo_api_key: None,
            allowed_dashboard_origin: None,
            qris_base_url: "https://example.invalid".to_owned(),
        };
        let error = crate::auth::require_admin(&config, &HeaderMap::new()).unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn admin_history_response_contains_raw_fields_member_shape_does_not() {
        // Respons admin (ValidationHistoryResponse) memakai bentuk admin;
        // bentuk member untuk item yang sama tetap tanpa field baru
        // (dibuktikan juga di models/member; di sini di level respons).
        let mut item = history_fixture("rv_live_x", "valid", "R9");
        item.target_raw = Some("1234567890".to_owned());
        item.account_name = Some("Andrias Se****an Su****o".to_owned());
        let admin_response = ValidationHistoryResponse {
            items: vec![crate::models::AdminValidationHistoryItem::from(&item)],
            total: 1,
            limit: 25,
            offset: 0,
            source: "database",
            stats: ValidationHistoryStats {
                hits_last_60s: 0,
                hits_last_3600s: 0,
            },
        };
        let serialized = serde_json::to_string(&admin_response).expect("serialize");
        assert!(serialized.contains("\"target_raw\":\"1234567890\""));
        assert!(serialized.contains("\"account_name\":\"Andrias Se****an Su****o\""));
        assert!(serialized.contains("\"target_masked\":\"***1234\""));
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub timestamp: DateTime<Utc>,
    pub provider_mode: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProduct {
    BankAccount,
    Ewallet,
    Whatsapp,
}

impl ValidationProduct {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BankAccount => "bank_account",
            Self::Ewallet => "ewallet",
            Self::Whatsapp => "whatsapp",
        }
    }

    pub const fn label_id(self) -> &'static str {
        match self {
            Self::BankAccount => "Validasi rekening",
            Self::Ewallet => "Validasi e-wallet",
            Self::Whatsapp => "Validasi WhatsApp",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Valid,
    Invalid,
    NotFound,
    /// E-wallet only: the upstream answer carried a "not KYC" marker instead
    /// of a real holder name (a "Belum Premium" placeholder, or the checked
    /// number echoed back as the name). Never a Valid: a placeholder/echo is
    /// not evidence that the account is registered under a real name.
    /// HTTP 200, like NotFound (see `validation_response`).
    NotKyc,
    Pending,
    ProviderError,
    RateLimited,
    QuotaExhausted,
}

impl ValidationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::NotFound => "not_found",
            Self::NotKyc => "not_kyc",
            Self::Pending => "pending",
            Self::ProviderError => "provider_error",
            Self::RateLimited => "rate_limited",
            Self::QuotaExhausted => "quota_exhausted",
        }
    }

    // Billing for NotKyc deliberately mirrors NotFound (verified from this
    // function: Valid | Invalid | NotFound are billable). The check was
    // genuinely performed and answered by the upstream; only the
    // interpretation changed (placeholder/echo name instead of a holder
    // name), so the member is charged exactly as for a NotFound answer.
    //
    // NOTE (billing rule 2026-10-25): `is_billable` means "potentially
    // charged". Invalid/NotFound are actually charged only once the daily
    // free pool (100 final invalid results per key per WIB day) is
    // exhausted; the API decides that per validation in api.rs and records
    // it on `UsageEvent.charged`, which is what the ledger gates on.
    pub const fn is_billable(self) -> bool {
        matches!(
            self,
            Self::Valid | Self::Invalid | Self::NotFound | Self::NotKyc
        )
    }

    /// Final invalid outcomes (Invalid + NotFound) share ONE free pool:
    /// the first 100 per key per WIB day are free, the rest cost 1 hit.
    /// Valid and NotKyc never draw from this pool; every other outcome
    /// never charges and never draws from it either.
    pub const fn is_invalid_pool(self) -> bool {
        matches!(self, Self::Invalid | Self::NotFound)
    }

    pub const fn is_success(self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct BankAccountValidationRequest {
    pub bank_code: String,
    pub account_number: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EwalletValidationRequest {
    pub provider: String,
    pub account_number: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WhatsappValidationRequest {
    pub phone_number: String,
}

#[derive(Clone, Debug)]
pub struct ProviderValidationRequest {
    pub product: ValidationProduct,
    pub provider_hint: Option<String>,
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationResponse {
    pub request_id: String,
    pub status: ValidationStatus,
    pub valid: bool,
    pub product: ValidationProduct,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ValidationResultData>,
    pub meta: ValidationMeta,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationResultData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

fn default_attempts() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationMeta {
    pub provider: String,
    pub provider_latency_ms: u64,
    /// Which provider attempt produced the result (1 = no retry happened).
    /// Defaults to 1 so idempotency-stored responses from before this field
    /// existed still deserialize.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    #[serde(default)]
    pub rajacek_processing_ms: u64,
    #[serde(default)]
    pub total_latency_ms: u64,
    pub cached: bool,
    pub remaining_quota: u64,
}

fn default_channel() -> String {
    "api".to_owned()
}

/// Events queued by binaries predating the `charged` field were charged
/// exactly when `is_billable()` held, so the old-behavior default is true.
/// New code always sets `charged` explicitly; the worker gates the ledger
/// on `status.is_billable() && event.charged`.
fn default_charged() -> bool {
    true
}

/// WIB calendar date for a UTC moment. Asia/Jakarta is UTC+7 year-round
/// (no DST), so a fixed +7h shift is exact — never CONVERT_TZ (which
/// needs MySQL timezone tables) and never the server's local zone.
pub fn wib_date(moment: DateTime<Utc>) -> chrono::NaiveDate {
    (moment + chrono::Duration::hours(7)).date_naive()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageEvent {
    pub event_id: Uuid,
    pub request_id: String,
    pub idempotency_key: Option<String>,
    pub api_key_prefix: String,
    pub product: ValidationProduct,
    pub status: ValidationStatus,
    /// Whether this validation actually cost 1 hit, decided by the API at
    /// commit time (billing rule 2026-10-25): Valid/NotKyc always true;
    /// Invalid/NotFound true only after the daily free pool is exhausted;
    /// all other outcomes false. Defaulted to true for old events (see
    /// `default_charged`).
    #[serde(default = "default_charged")]
    pub charged: bool,
    pub price_snapshot_id: Option<Uuid>,
    pub occurred_at: DateTime<Utc>,
    pub target_fingerprint: String,
    pub target_masked: String,
    pub provider_reference: Option<String>,
    pub provider_latency_ms: u64,
    /// Internal processing time and end-to-end total for this check, plus how
    /// many provider attempts it took. Defaulted so events queued by older
    /// binaries still deserialize.
    #[serde(default)]
    pub rajacek_processing_ms: u64,
    #[serde(default)]
    pub total_latency_ms: u64,
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    /// Where the check originated: "api" (public API) or "portal" (member
    /// sandbox). Defaults to "api" for events queued before this field.
    #[serde(default = "default_channel")]
    pub channel: String,
}

/// One recorded member validation, as shown in the admin history view. Mirrors
/// the durable `validation_requests` table written by the worker; the target is
/// always the masked form, never the raw account number.
#[derive(Clone, Debug, Serialize)]
pub struct ValidationHistoryItem {
    pub request_id: String,
    pub api_key_prefix: String,
    pub product: ValidationProduct,
    pub outcome: String,
    pub target_masked: String,
    pub provider_reference: Option<String>,
    pub provider_latency_ms: u64,
    /// Latency breakdown for the admin history view; None for rows recorded
    /// before the breakdown existed (migration 0012).
    pub rajacek_processing_ms: Option<u64>,
    pub total_latency_ms: Option<u64>,
    pub attempts: Option<u32>,
    pub occurred_at: DateTime<Utc>,
    /// "api" | "portal" — where the check was made (default "api").
    #[serde(default = "default_channel")]
    pub channel: String,
}

/// Aggregated member-portal usage, computed either from MySQL
/// `validation_requests` or from the in-memory history fallback.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MemberUsageData {
    pub checks_today: i64,
    pub checks_last_30_days: i64,
    pub daily: Vec<MemberDailyCount>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberDailyCount {
    /// WIB calendar date, `YYYY-MM-DD`.
    pub date: String,
    /// Product code (`bank_account`/`ewallet`/`whatsapp`).
    pub product: String,
    pub count: i64,
}

pub struct ValidationHistoryFilters {
    pub product: Option<ValidationProduct>,
    pub outcome: Option<String>,
    pub api_key_prefix: Option<String>,
    /// When set, history matches any of these prefixes exactly (member-wide
    /// view across key regenerations). Takes precedence over
    /// `api_key_prefix` when both are present.
    pub api_key_prefixes: Option<Vec<String>>,
    /// AREA 5 (export + pencarian/filter, 2026-10-25): kata kunci admin
    /// untuk riwayat pemakaian — dicocokkan (substring, tak peka huruf
    /// besar/kecil) ke prefix kunci, request_id, dan target tersamar.
    /// None = tanpa filter kata kunci.
    pub q: Option<String>,
    /// AREA 5: batas bawah waktu kejadian (inklusif, UTC) dan batas atas
    /// (eksklusif, UTC). Tanggal `YYYY-MM-DD` dari panel diubah pemanggil
    /// menjadi rentang [00:00, 00:00 hari berikutnya).
    pub from: Option<DateTime<Utc>>,
    pub to_exclusive: Option<DateTime<Utc>>,
}

impl ValidationHistoryFilters {
    pub fn matches(&self, item: &ValidationHistoryItem) -> bool {
        let q_matches = match self.q.as_deref() {
            None => true,
            Some(q) => {
                let needle = q.to_lowercase();
                item.api_key_prefix.to_lowercase().contains(&needle)
                    || item.request_id.to_lowercase().contains(&needle)
                    || item.target_masked.to_lowercase().contains(&needle)
            }
        };
        let from_matches = self.from.is_none_or(|from| item.occurred_at >= from);
        let to_matches = self
            .to_exclusive
            .is_none_or(|to| item.occurred_at < to);
        self.product.is_none_or(|product| product == item.product)
            && self
                .outcome
                .as_deref()
                .is_none_or(|outcome| outcome == item.outcome)
            && match (&self.api_key_prefixes, &self.api_key_prefix) {
                (Some(prefixes), _) => prefixes.iter().any(|prefix| prefix == &item.api_key_prefix),
                (None, Some(prefix)) => item.api_key_prefix.starts_with(prefix),
                (None, None) => true,
            }
            && q_matches
            && from_matches
            && to_matches
    }
}

/// Escape LIKE wildcards so a prefix filter can never match more than the
/// intended prefix (audit 2026-10-25, F15: `_` in a prefix acted as a
/// single-character wildcard).
pub fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiKeyContext {
    pub key_id: Uuid,
    pub prefix: String,
    pub owner_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub remaining_quota: u64,
    pub rate_limit_per_minute: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct RateLimitAdmission {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DashboardOverview {
    pub generated_at: DateTime<Utc>,
    pub environment: String,
    pub demo_mode: bool,
    pub metrics: DashboardMetrics,
    pub traffic: Vec<TrafficPoint>,
    pub services: Vec<ServiceStatus>,
    pub recent_activities: Vec<ActivityItem>,
    pub alerts: Vec<DashboardAlert>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DashboardMetrics {
    pub total_requests_today: u64,
    pub request_change_percent: f32,
    pub success_rate: f32,
    pub success_rate_change_percent: f32,
    pub average_latency_ms: u64,
    pub average_latency_change_percent: f32,
    pub estimated_revenue: u64,
    pub revenue_change_percent: f32,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrafficPoint {
    pub label: String,
    pub requests: u64,
    pub successful: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceStatus {
    pub name: String,
    pub label: String,
    pub status: String,
    pub latency_ms: Option<u64>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivityItem {
    pub id: Uuid,
    pub title: String,
    pub detail: String,
    pub product: Option<ValidationProduct>,
    pub status: String,
    pub occurred_at: DateTime<Utc>,
    pub provider_latency_ms: Option<u64>,
}

/// One durable admin-audit row (audit 2026-10-25, B12). Unlike
/// `ActivityItem` — which also carries validation telemetry and lives
/// only in process memory — this row is written to `admin_audit_log`
/// and survives restarts. `entity_type`/`entity_id` are advisory
/// (e.g. "package"/uuid); the human-readable `detail` always carries
/// the object's name or id as well, so a row stays useful on its own.
#[derive(Clone, Debug, Serialize)]
pub struct AdminAuditEntry {
    pub id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub detail: String,
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DashboardAlert {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminProduct {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub active: bool,
    pub provider_route: String,
    pub base_price_idr: u64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateProductRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub active: Option<bool>,
    pub provider_route: Option<String>,
    pub base_price_idr: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRequestMode {
    Generic,
    Tukangcek,
    Cutiezy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderResponseMapping {
    pub status_path: String,
    #[serde(default)]
    pub valid_values: Vec<String>,
    #[serde(default)]
    pub invalid_values: Vec<String>,
    #[serde(default)]
    pub not_found_values: Vec<String>,
    #[serde(default)]
    pub pending_values: Vec<String>,
    pub message_path: Option<String>,
    pub account_name_path: Option<String>,
    pub provider_path: Option<String>,
    pub registered_path: Option<String>,
    pub reference_path: Option<String>,
}

impl ProviderResponseMapping {
    pub fn default_for(product: ValidationProduct) -> Self {
        Self {
            status_path: "status".to_owned(),
            valid_values: vec![
                "valid".to_owned(),
                "success".to_owned(),
                "registered".to_owned(),
            ],
            invalid_values: vec!["invalid".to_owned(), "unregistered".to_owned()],
            not_found_values: vec!["not_found".to_owned(), "not found".to_owned()],
            pending_values: vec!["pending".to_owned(), "processing".to_owned()],
            message_path: Some("message".to_owned()),
            account_name_path: matches!(product, ValidationProduct::BankAccount)
                .then(|| "result.account_name".to_owned()),
            provider_path: Some("result.provider".to_owned()),
            registered_path: (!matches!(product, ValidationProduct::BankAccount))
                .then(|| "result.registered".to_owned()),
            reference_path: Some("result.reference".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderEndpoint {
    pub id: Uuid,
    pub product: ValidationProduct,
    pub name: String,
    pub base_url: String,
    pub timeout_ms: u32,
    pub request_mode: ProviderRequestMode,
    pub auth_header: String,
    pub active: bool,
    pub api_key_configured: bool,
    pub response_mapping: ProviderResponseMapping,
    #[serde(default)]
    pub service_code_mapping: HashMap<String, String>,
    /// GET or POST; only honored for request_mode='generic', other modes
    /// keep their fixed dispatch. Defaults to POST for pre-migration rows.
    #[serde(default = "default_http_method")]
    pub http_method: String,
    /// Query param name carrying the translated service code (Generic GET).
    #[serde(default = "default_code_param")]
    pub code_param: String,
    /// Query param name carrying the account number / phone (Generic GET).
    #[serde(default = "default_number_param")]
    pub number_param: String,
    /// Optional query param name carrying the API key (Generic GET);
    /// None means the key travels only in the configured auth header.
    #[serde(default)]
    pub key_param: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateProviderEndpointRequest {
    pub name: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout_ms: u32,
    pub request_mode: ProviderRequestMode,
    pub auth_header: String,
    pub response_mapping: ProviderResponseMapping,
    #[serde(default)]
    pub service_code_mapping: HashMap<String, String>,
    #[serde(default = "default_http_method")]
    pub http_method: String,
    #[serde(default = "default_code_param")]
    pub code_param: String,
    #[serde(default = "default_number_param")]
    pub number_param: String,
    #[serde(default)]
    pub key_param: Option<String>,
    #[serde(default = "default_active")]
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AdminProviderTesterRequest {
    pub product: ValidationProduct,
    pub target: String,
    pub bank_code: Option<String>,
    pub ewallet_provider: Option<String>,
    /// Test one specific server instead of racing every active endpoint.
    #[serde(default)]
    pub endpoint_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateProviderEndpointRequest {
    pub product: ValidationProduct,
    pub name: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout_ms: u32,
    pub request_mode: ProviderRequestMode,
    pub auth_header: String,
    pub response_mapping: ProviderResponseMapping,
    #[serde(default)]
    pub service_code_mapping: HashMap<String, String>,
    #[serde(default = "default_http_method")]
    pub http_method: String,
    #[serde(default = "default_code_param")]
    pub code_param: String,
    #[serde(default = "default_number_param")]
    pub number_param: String,
    #[serde(default)]
    pub key_param: Option<String>,
    #[serde(default = "default_active")]
    pub active: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminProviderTesterResponse {
    pub status: ValidationStatus,
    pub valid: bool,
    pub product: ValidationProduct,
    pub message: String,
    pub result: Option<ValidationResultData>,
    pub provider: String,
    pub provider_latency_ms: u64,
    pub rajacek_processing_ms: u64,
    pub total_latency_ms: u64,
    /// Which provider attempt produced this result (1 = no retry happened).
    pub attempts: u32,
    pub upstream_response: crate::provider::RawProviderResponse,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderEndpointTestResponse {
    pub reachable: bool,
    pub provider: String,
    pub latency_ms: u64,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminPackage {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: String,
    pub price_idr: u64,
    pub included_hits: u64,
    pub active: bool,
    pub highlighted: bool,
    pub products: Vec<ValidationProduct>,
    pub rate_limit_per_minute: u32,
    /// Persen potongan promo (0 = tidak ada promo).
    pub promo_percent: u8,
    /// Promo hanya aktif sampai tanggal ini (wajib bila persen > 0).
    pub promo_ends_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Promo aktif bila persen 1–100 dan tanggal berakhir ada dan masih di
/// masa depan. Tanpa tanggal berakhir, promo dianggap tidak aktif.
pub(crate) fn promo_active(package: &AdminPackage, now: DateTime<Utc>) -> bool {
    package.promo_percent > 0
        && package.promo_percent <= 100
        && package.promo_ends_at.map(|ends| ends > now).unwrap_or(false)
}

/// Harga yang benar-benar ditagih: harga katalog dipotong promo aktif
/// (dibulatkan ke rupiah terdekat). Satu-satunya sumber harga bayar —
/// dipakai daftar paket member, pratinjau, order, dan landing, agar
/// harga yang tampil selalu sama dengan harga yang ditagih.
pub(crate) fn effective_price(package: &AdminPackage, now: DateTime<Utc>) -> u64 {
    if promo_active(package, now) {
        (package.price_idr * u64::from(100 - package.promo_percent) + 50) / 100
    } else {
        package.price_idr
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreatePackageRequest {
    pub name: String,
    pub slug: String,
    pub description: String,
    pub price_idr: u64,
    pub included_hits: u64,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub highlighted: bool,
    pub products: Vec<ValidationProduct>,
    pub rate_limit_per_minute: u32,
    #[serde(default)]
    pub promo_percent: u8,
    #[serde(default)]
    pub promo_ends_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdatePackageRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price_idr: Option<u64>,
    pub included_hits: Option<u64>,
    pub active: Option<bool>,
    pub highlighted: Option<bool>,
    pub products: Option<Vec<ValidationProduct>>,
    pub rate_limit_per_minute: Option<u32>,
    pub promo_percent: Option<u8>,
    /// Some(None) = hapus tanggal berakhir; None = tidak diubah.
    #[serde(default)]
    pub promo_ends_at: Option<Option<DateTime<Utc>>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RateLimitPolicy {
    pub id: Uuid,
    pub name: String,
    pub scope: String,
    pub target: String,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub concurrency_limit: u32,
    pub active: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateRateLimitPolicyRequest {
    pub name: String,
    pub scope: String,
    pub target: String,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub concurrency_limit: u32,
    #[serde(default = "default_active")]
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateRateLimitPolicyRequest {
    pub name: Option<String>,
    pub target: Option<String>,
    pub requests_per_minute: Option<u32>,
    pub burst: Option<u32>,
    pub concurrency_limit: Option<u32>,
    pub active: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminApiKeySummary {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub status: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub rate_limit_per_minute: u32,
    /// Total quota granted to this key (its remaining balance is reported
    /// separately by the account view).
    pub quota_total: u64,
    /// When the key stops working (package/trial end); None = no expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Package this key's quota/limit came from, when assigned from one.
    pub package_id: Option<Uuid>,
    /// Owning member account (Google sign-up), when the key belongs to one.
    pub member_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// A self-serve member account created via Google sign-in. Owns one
/// `admin_api_keys` row (via member_id) whose quota/expiry carry the plan.
#[derive(Clone, Debug, Serialize)]
pub struct MemberAccount {
    pub id: Uuid,
    pub google_sub: String,
    pub email: String,
    pub name: Option<String>,
    pub picture_url: Option<String>,
    /// 'trial' | 'package' | 'manual' — how the current plan was granted.
    pub plan_kind: String,
    /// 'active' | 'disabled'
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub rate_limit_per_minute: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreatedApiKey {
    pub key: AdminApiKeySummary,
    pub plaintext_key: String,
    pub warning: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthSessionResponse {
    pub authenticated: bool,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: Option<String>,
    pub google_login_configured: bool,
    pub development_access_available: bool,
    pub local_login_available: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LocalLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GoogleCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
    /// Token id for server-side revocation (audit 2026-10-25, B8).
    /// Tokens minted before this field existed decode it as empty.
    #[serde(default)]
    pub jti: String,
    /// How the session was minted: "google" | "local" (dev).
    /// Tokens minted before this field existed decode it as empty.
    #[serde(default)]
    pub source: String,
}

fn default_active() -> bool {
    true
}

fn default_http_method() -> String {
    "POST".to_owned()
}

fn default_code_param() -> String {
    "code".to_owned()
}

fn default_number_param() -> String {
    "target".to_owned()
}

/// Hasil grant pembelian paket ke kunci member: mode "add" (kuota menumpuk,
/// masa aktif diperpanjang dari expiry lama bila masih future) + rate
/// tertinggi (membeli paket murah tidak pernah menurunkan rate member).
/// Dipakai store::grant_package_order; diuji di bawah tanpa database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantEffect {
    pub new_total: u64,
    pub new_remaining: u64,
    pub new_expires_at: DateTime<Utc>,
    pub new_rate_limit_per_minute: u32,
}

pub fn compute_grant_effect(
    current_total: u64,
    current_remaining: u64,
    current_expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    package_hits: u64,
    valid_days: i64,
    current_rate: u32,
    package_rate: u32,
) -> GrantEffect {
    let base = current_expires_at
        .filter(|expiry| *expiry > now)
        .unwrap_or(now);
    GrantEffect {
        new_total: current_total.saturating_add(package_hits),
        new_remaining: current_remaining.saturating_add(package_hits),
        new_expires_at: base + chrono::Duration::days(valid_days),
        new_rate_limit_per_minute: current_rate.max(package_rate),
    }
}

/// Hasil grant_package_order: Granted berarti transaksi atomik berhasil,
/// AlreadyGranted berarti order sudah berstatus granted (grant ganda
/// dicegah; pemanggil boleh menganggapnya sukses idempoten).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantOutcome {
    Granted {
        new_total: u64,
        new_remaining: u64,
        new_rate_limit_per_minute: u32,
    },
    AlreadyGranted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bank_request_ignores_retired_hint_field() {
        // Field account_holder_hint dihapus dari kontrak, tapi pengirim
        // lama yang masih menyertakannya harus tetap lolos parse
        // (tidak ada deny_unknown_fields di struct ini).
        let parsed: BankAccountValidationRequest = serde_json::from_str(
            r#"{"bank_code":"014","account_number":"123456","account_holder_hint":"BUDI SANTOSO"}"#,
        )
        .expect("request lama yang masih mengirim hint harus tetap lolos parse");
        assert_eq!(parsed.bank_code, "014");
        assert_eq!(parsed.account_number, "123456");
    }

    fn dt(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn grant_stacks_and_extends_from_active_expiry() {
        let effect = compute_grant_effect(
            1000,
            200,
            Some(dt("2026-11-01T00:00:00Z")),
            dt("2026-10-25T00:00:00Z"),
            500,
            30,
            30,
            120,
        );
        assert_eq!(effect.new_total, 1500);
        assert_eq!(effect.new_remaining, 700);
        assert_eq!(effect.new_expires_at, dt("2026-12-01T00:00:00Z"));
        assert_eq!(effect.new_rate_limit_per_minute, 120);
    }

    #[test]
    fn grant_extends_from_now_when_expired_or_missing() {
        let now = dt("2026-10-25T00:00:00Z");
        let expired = compute_grant_effect(
            0,
            0,
            Some(dt("2026-10-01T00:00:00Z")),
            now,
            100,
            30,
            120,
            120,
        );
        assert_eq!(expired.new_expires_at, dt("2026-11-24T00:00:00Z"));
        let missing = compute_grant_effect(0, 0, None, now, 100, 30, 120, 120);
        assert_eq!(missing.new_expires_at, dt("2026-11-24T00:00:00Z"));
    }

    #[test]
    fn grant_never_downgrades_rate_and_saturates() {
        let effect =
            compute_grant_effect(100, 100, None, dt("2026-10-25T00:00:00Z"), 50, 30, 120, 30);
        assert_eq!(effect.new_rate_limit_per_minute, 120);
        let saturated = compute_grant_effect(
            u64::MAX,
            u64::MAX,
            None,
            dt("2026-10-25T00:00:00Z"),
            1,
            30,
            1,
            1,
        );
        assert_eq!(saturated.new_total, u64::MAX);
        assert_eq!(saturated.new_remaining, u64::MAX);
    }
}

#[cfg(test)]
mod promo_price_tests {
    use super::*;

    fn package(price: u64, percent: u8, ends: Option<DateTime<Utc>>) -> AdminPackage {
        AdminPackage {
            id: Uuid::now_v7(),
            name: "Tes".to_owned(),
            slug: "tes".to_owned(),
            description: String::new(),
            price_idr: price,
            included_hits: 1000,
            active: true,
            highlighted: false,
            products: vec![],
            rate_limit_per_minute: 60,
            promo_percent: percent,
            promo_ends_at: ends,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn no_promo_pays_catalog_price() {
        let now = Utc::now();
        assert_eq!(effective_price(&package(99_000, 0, None), now), 99_000);
    }

    #[test]
    fn active_promo_discounts_and_rounds() {
        let now = Utc::now();
        let ends = now + chrono::Duration::days(3);
        assert_eq!(effective_price(&package(99_000, 20, Some(ends)), now), 79_200);
        assert_eq!(effective_price(&package(399_000, 25, Some(ends)), now), 299_250);
    }

    #[test]
    fn expired_or_dateless_promo_is_inactive() {
        let now = Utc::now();
        assert!(!promo_active(
            &package(99_000, 20, Some(now - chrono::Duration::hours(1))),
            now
        ));
        assert!(!promo_active(&package(99_000, 20, None), now));
        assert_eq!(
            effective_price(
                &package(99_000, 20, Some(now - chrono::Duration::hours(1))),
                now
            ),
            99_000
        );
    }

    #[test]
    fn full_discount_is_zero_and_percent_over_100_inactive() {
        let now = Utc::now();
        let ends = now + chrono::Duration::days(1);
        assert_eq!(effective_price(&package(99_000, 100, Some(ends)), now), 0);
        assert!(!promo_active(&package(99_000, 101, Some(ends)), now));
    }
}

#[cfg(test)]
mod history_filter_tests {
    use super::*;

    fn item(prefix: &str) -> ValidationHistoryItem {
        ValidationHistoryItem {
            request_id: "test".to_owned(),
            api_key_prefix: prefix.to_owned(),
            product: ValidationProduct::BankAccount,
            outcome: "valid".to_owned(),
            target_masked: String::new(),
            provider_reference: None,
            provider_latency_ms: 0,
            rajacek_processing_ms: None,
            total_latency_ms: None,
            attempts: None,
            occurred_at: Utc::now(),
            channel: "api".to_owned(),
        }
    }

    #[test]
    fn like_wildcards_are_escaped() {
        // Every wildcard is escaped, including the underscores in rv_live_.
        assert_eq!(escape_like("rv_live_ab_c%"), "rv\\_live\\_ab\\_c\\%");
        assert_eq!(escape_like("plain"), "plain");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
    }

    // Local helper (the `tests` module's own `dt` is not visible here).
    fn dt(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    // Billing rule 2026-10-25: classification table for every outcome.
    // Valid + NotKyc always charge; Invalid + NotFound share one free
    // pool (charged only after exhaustion); everything else never charges
    // and never draws from the pool.
    #[test]
    fn billing_classification_table() {
        use ValidationStatus::*;
        // (status, is_billable, is_invalid_pool)
        let table = [
            (Valid, true, false),
            (NotKyc, true, false),
            (Invalid, true, true),
            (NotFound, true, true),
            (Pending, false, false),
            (ProviderError, false, false),
            (RateLimited, false, false),
            (QuotaExhausted, false, false),
        ];
        for (status, billable, pool) in table {
            assert_eq!(status.is_billable(), billable, "{status:?}");
            assert_eq!(status.is_invalid_pool(), pool, "{status:?}");
        }
    }

    // WIB boundary: 23:59 WIB and 00:01 WIB the next day are different
    // free-pool days (UTC 16:59Z vs 17:01Z).
    #[test]
    fn wib_date_boundary() {
        assert_eq!(
            wib_date(dt("2026-10-25T16:59:00Z")).to_string(),
            "2026-10-25"
        );
        assert_eq!(
            wib_date(dt("2026-10-25T17:01:00Z")).to_string(),
            "2026-10-26"
        );
        // Noon UTC is evening WIB, same calendar day.
        assert_eq!(
            wib_date(dt("2026-10-25T12:00:00Z")).to_string(),
            "2026-10-25"
        );
    }

    // Events queued by pre-`charged` binaries deserialize with charged=true,
    // preserving the old ledger behavior (insert iff is_billable).
    #[test]
    fn usage_event_charged_defaults_true_for_old_events() {
        let event: UsageEvent = serde_json::from_str(
            r#"{"event_id":"0199a5a5-0000-7000-8000-000000000001","request_id":"R1","idempotency_key":null,"api_key_prefix":"rv_live_x","product":"bank_account","status":"valid","price_snapshot_id":null,"occurred_at":"2026-10-25T00:00:00Z","target_fingerprint":"f","target_masked":"***","provider_reference":null,"provider_latency_ms":10,"channel":"api"}"#,
        )
        .expect("event lama tanpa charged harus ter-parse");
        assert!(event.charged);
        let event: UsageEvent = serde_json::from_str(
            r#"{"event_id":"0199a5a5-0000-7000-8000-000000000002","request_id":"R2","idempotency_key":null,"api_key_prefix":"rv_live_x","product":"bank_account","status":"invalid","price_snapshot_id":null,"occurred_at":"2026-10-25T00:00:00Z","target_fingerprint":"f","target_masked":"***","provider_reference":null,"provider_latency_ms":10,"channel":"api","charged":false}"#,
        )
        .expect("event baru dengan charged=false harus ter-parse");
        assert!(!event.charged);
    }

    #[test]
    fn prefix_list_matches_any_exact_prefix() {
        let filters = ValidationHistoryFilters {
            product: None,
            outcome: None,
            api_key_prefix: None,
            api_key_prefixes: Some(vec![
                "rv_live_old".to_owned(),
                "rv_live_new".to_owned(),
            ]),
            q: None,
            from: None,
            to_exclusive: None,
        };
        assert!(filters.matches(&item("rv_live_old")));
        assert!(filters.matches(&item("rv_live_new")));
        assert!(!filters.matches(&item("rv_live_other")));
        // Exact, not prefix-based: a longer string sharing the prefix fails.
        assert!(!filters.matches(&item("rv_live_old_extra")));
    }
}

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
    Pln,
}

impl ValidationProduct {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BankAccount => "bank_account",
            Self::Ewallet => "ewallet",
            Self::Whatsapp => "whatsapp",
            Self::Pln => "pln",
        }
    }

    pub const fn label_id(self) -> &'static str {
        match self {
            Self::BankAccount => "Validasi rekening",
            Self::Ewallet => "Validasi e-wallet",
            Self::Whatsapp => "Validasi WhatsApp",
            Self::Pln => "Validasi PLN",
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

#[derive(Clone, Debug, Deserialize)]
pub struct PlnValidationRequest {
    pub customer_id: String,
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
    /// PLN only: tariff and power parsed from the trailing
    /// " - TARIF/DAYA" suffix of the upstream holder name (e.g. the name
    /// suffix " - R1/1300" yields tarif "R1", daya "1300"). None for every
    /// other product and whenever the name carries no matching suffix, so
    /// other products' serialized responses are byte-identical to before.
    /// The holder name itself is never stripped of its suffix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tarif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daya: Option<String>,
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
    /// Masa aktif agregat kunci ini, definisi SAMA PERSIS dengan overview
    /// member (live_view → bucket_aggregate): expiry bucket aktif
    /// terdekat; None = kunci tidak pernah kedaluwarsa. Diserialisasi
    /// eksplisit sebagai null saat None (tanpa skip_serializing_if),
    /// konsisten dengan overview. Default None agar JSON idempotensi lama
    /// yang belum memuat field ini tetap lolos parse.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
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
    /// Raw target exactly as submitted (account number / phone). Stored
    /// only for the admin history view — never serialized into member
    /// responses. Defaulted so events queued by older binaries still
    /// deserialize.
    #[serde(default)]
    pub target_raw: Option<String>,
    /// Holder name exactly as returned upstream (provider-masked for
    /// Tukangcek, verbatim nickname/accountname for Cutiezy, None for
    /// WhatsApp and for e-wallet NotKyc). NOT uppercased here: the member
    /// response uppercases its own copy in validation_response, while the
    /// stored history keeps the upstream form. Defaulted like target_raw.
    #[serde(default)]
    pub account_name: Option<String>,
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
///
/// The raw target and holder name live on this struct for internal use
/// (admin view, CSV-adjacent logic) but are NEVER serialized from it:
/// the member history endpoint returns this struct verbatim, so the new
/// fields carry `skip_serializing` and the admin endpoint converts to
/// [`AdminValidationHistoryItem`] instead. Adding a field here without
/// `skip_serializing` would leak raw targets/names to members.
#[derive(Clone, Debug, Serialize)]
pub struct ValidationHistoryItem {
    pub request_id: String,
    pub api_key_prefix: String,
    pub product: ValidationProduct,
    pub outcome: String,
    pub target_masked: String,
    /// Admin-only member code ("RC000001", ...) resolved from the key
    /// prefix (migration 0025: admin_api_keys.prefix -> members.member_code).
    /// None when the key is not linked to a member (env seed / deleted key)
    /// or when the item comes from the in-memory fallback history, which has
    /// no member map. Never serialized from this struct: the member history
    /// endpoint returns this struct verbatim, so the admin endpoint converts
    /// to [`AdminValidationHistoryItem`] instead — same pattern as
    /// `target_raw` / `account_name` below.
    #[serde(skip_serializing)]
    pub member_code: Option<String>,
    /// Raw target, admin history only. None for rows recorded before
    /// migration 0024.
    #[serde(skip_serializing)]
    pub target_raw: Option<String>,
    /// Holder name as returned upstream, admin history only. None for rows
    /// recorded before migration 0024, for WhatsApp, and for e-wallet
    /// NotKyc (the provider logic already strips the name there).
    #[serde(skip_serializing)]
    pub account_name: Option<String>,
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

/// Admin-only serialization of [`ValidationHistoryItem`]: identical
/// fields plus the raw target and holder name from migration 0024.
/// This is the ONLY shape that serializes those two fields; the member
/// history endpoint keeps returning `ValidationHistoryItem` directly.
#[derive(Clone, Debug, Serialize)]
pub struct AdminValidationHistoryItem {
    pub request_id: String,
    pub api_key_prefix: String,
    /// Admin-only member code resolved via the key prefix (see
    /// `ValidationHistoryItem::member_code`); null when unresolvable.
    pub member_code: Option<String>,
    pub product: ValidationProduct,
    pub outcome: String,
    pub target_masked: String,
    pub target_raw: Option<String>,
    pub account_name: Option<String>,
    pub provider_reference: Option<String>,
    pub provider_latency_ms: u64,
    pub rajacek_processing_ms: Option<u64>,
    pub total_latency_ms: Option<u64>,
    pub attempts: Option<u32>,
    pub occurred_at: DateTime<Utc>,
    pub channel: String,
}

impl From<&ValidationHistoryItem> for AdminValidationHistoryItem {
    fn from(item: &ValidationHistoryItem) -> Self {
        Self {
            request_id: item.request_id.clone(),
            api_key_prefix: item.api_key_prefix.clone(),
            member_code: item.member_code.clone(),
            product: item.product,
            outcome: item.outcome.clone(),
            target_masked: item.target_masked.clone(),
            target_raw: item.target_raw.clone(),
            account_name: item.account_name.clone(),
            provider_reference: item.provider_reference.clone(),
            provider_latency_ms: item.provider_latency_ms,
            rajacek_processing_ms: item.rajacek_processing_ms,
            total_latency_ms: item.total_latency_ms,
            attempts: item.attempts,
            occurred_at: item.occurred_at,
            channel: item.channel.clone(),
        }
    }
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
///
/// HARD BOUNDARY (migration 0025): `member_code` is admin-only. It is
/// deliberately NOT serialized from this struct: no member-facing endpoint
/// serializes `MemberAccount` directly (member endpoints use hand-built
/// views such as `MemberProfileView`, exactly like `google_sub` above,
/// which is likewise admin-serialization-only in practice). Admin
/// responses carry the code through explicit admin-only views instead
/// (`AdminMemberView::member_code`, `MemberDetailMemberView::member_code`
/// in api.rs), so a future member endpoint can never leak it by
/// serializing this struct by accident.
#[derive(Clone, Debug, Serialize)]
pub struct MemberAccount {
    pub id: Uuid,
    /// Admin-only member code ("RC000001", ...; migration 0025).
    /// None for rows created before the migration ran or read by a
    /// binary predating it; never serialized (see the struct doc).
    #[serde(skip_serializing)]
    pub member_code: Option<String>,
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

/// Bucket FIFO kuota (2026-10-26): menggantikan semantik stacking-expiry
/// lama (compute_grant_effect, dihapus — grant/assign kini membuat bucket
/// baru dengan expiry beli + valid_days, dan agregat dihitung dari bucket).
/// Rate grant tetap max (membeli paket murah tidak pernah menurunkan rate
/// member); logika itu kini inline di store::grant_package_order.
/// Satu bucket kuota FIFO: satu pembelian (grant/assign-add), satu
/// penyesuaian manual yang butuh bucket baru, atau satu bucket backfill
/// dari agregat kunci lama. Bucket dimiliki KEY (bukan member): saat
/// regenerasi, bucket pindah ke kunci pengganti bersama saldonya.
/// Pemotongan selalu dari bucket paling cepat kedaluwarsa dulu (FIFO);
/// bucket tanpa expiry dikonsumsi TERAKHIR dan tidak pernah kedaluwarsa.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaBucket {
    pub id: Uuid,
    pub key_id: Uuid,
    pub member_id: Option<Uuid>,
    /// Order pembelian yang melahirkan bucket ini; NULL untuk bucket
    /// backfill, assign admin, dan adjust manual.
    pub order_id: Option<Uuid>,
    pub package_id: Option<Uuid>,
    pub total_hits: u64,
    pub remaining_hits: u64,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Bentuk bucket di respons API (kontrak tampilan): nama paket di-resolve
/// dari package_id saat dibaca, jadi rename paket ikut terlihat dan paket
/// yang sudah dihapus tampil sebagai null — bukan snapshot nama beku.
#[derive(Clone, Debug, Serialize)]
pub struct QuotaBucketView {
    pub id: Uuid,
    pub order_id: Option<Uuid>,
    pub package_name: Option<String>,
    pub total_hits: u64,
    pub remaining_hits: u64,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Bucket masih berlaku pada `now`: tanpa expiry, atau expiry-nya future.
/// Bucket kedaluwarsa dilewati pemotongan (sisanya mati), bukan dihapus.
pub fn bucket_is_active(bucket: &QuotaBucket, now: DateTime<Utc>) -> bool {
    bucket.expires_at.map_or(true, |expiry| expiry > now)
}

/// Urutan FIFO: expiry paling awal dulu; bucket tanpa expiry TERAKHIR;
/// seri dipecah created_at lalu id agar urutannya deterministik.
fn fifo_key(bucket: &QuotaBucket) -> (bool, DateTime<Utc>, DateTime<Utc>, Uuid) {
    (
        bucket.expires_at.is_none(),
        bucket.expires_at.unwrap_or(DateTime::<Utc>::MAX_UTC),
        bucket.created_at,
        bucket.id,
    )
}

pub fn sort_buckets_fifo(buckets: &mut [QuotaBucket]) {
    buckets.sort_by_key(fifo_key);
}

/// Indeks bucket dalam urutan FIFO tanpa mengurut ulang vec aslinya.
fn fifo_indices(buckets: &[QuotaBucket]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..buckets.len()).collect();
    indices.sort_by_key(|&index| fifo_key(&buckets[index]));
    indices
}

/// Agregat tampilan dari bucket (satu-satunya definisi agregat untuk kunci
/// ber-bucket):
/// - total = jumlah total_hits SEMUA bucket (termasuk kedaluwarsa/habis);
/// - sisa = jumlah remaining_hits bucket AKTIF saja (sisa bucket
///   kedaluwarsa sudah mati dan tidak dihitung);
/// - expiry agregat = expiry bucket aktif terdekat yang masih bersisa;
///   NULL bila yang bersisa hanya bucket tanpa expiry. Bila TIDAK ADA
///   bucket aktif bersisa sama sekali (semua habis/kedaluwarsa), expiry
///   = NULL (keputusan D6 audit 2026-10-26, K14): saldo habis BUKAN
///   kedaluwarsa — menampilkan tanggal bucket pertama dulu menyesatkan
///   (member membaca "sudah kedaluwarsa" padahal masalahnya saldo 0).
///   Sinyal saldo habis sudah ada di remaining_quota = 0, dan kunci
///   legacy tanpa bucket tidak berubah (tetap memakai nilai tersimpan).
pub fn bucket_aggregate(
    buckets: &[QuotaBucket],
    now: DateTime<Utc>,
) -> (u64, u64, Option<DateTime<Utc>>) {
    let total = buckets
        .iter()
        .fold(0u64, |sum, bucket| sum.saturating_add(bucket.total_hits));
    let mut active_remaining = 0u64;
    let mut nearest_dated: Option<DateTime<Utc>> = None;
    let mut has_active_undated_with_remaining = false;
    for bucket in buckets {
        if !bucket_is_active(bucket, now) {
            continue;
        }
        active_remaining = active_remaining.saturating_add(bucket.remaining_hits);
        if bucket.remaining_hits > 0 {
            match bucket.expires_at {
                Some(expiry) => {
                    nearest_dated = Some(match nearest_dated {
                        Some(current) => current.min(expiry),
                        None => expiry,
                    });
                }
                None => has_active_undated_with_remaining = true,
            }
        }
    }
    let expiry = if let Some(expiry) = nearest_dated {
        Some(expiry)
    } else if has_active_undated_with_remaining {
        None
    } else {
        // D6/K14: tidak ada bucket aktif bersisa -> NULL, bukan tanggal
        // bucket pertama. Fallback MIN lama menampilkan tanggal lampau
        // (atau tanggal bucket pertama) saat saldo habis, padahal kunci
        // belum tentu kedaluwarsa. Cabang ini juga mencakup "semua bucket
        // lewat expiry" dan "tidak ada bucket sama sekali".
        None
    };
    (total, active_remaining, expiry)
}

/// Bucket baru dari satu pembelian: total = sisa = hit paket, expiry =
/// saat beli + valid_days (TIDAK menumpuk dari expiry lama — itulah inti
/// bucket: pembelian lama dan baru kedaluwarsa masing-masing).
/// Prasyarat: valid_days >= 1 (ditegakkan validasi settings QRIS dan
/// handler assign; bucket dengan valid_days <= 0 akan langsung mati).
pub fn new_purchase_bucket(
    key_id: Uuid,
    member_id: Option<Uuid>,
    order_id: Option<Uuid>,
    package_id: Option<Uuid>,
    hits: u64,
    valid_days: i64,
    now: DateTime<Utc>,
) -> QuotaBucket {
    QuotaBucket {
        id: Uuid::now_v7(),
        key_id,
        member_id,
        order_id,
        package_id,
        total_hits: hits,
        remaining_hits: hits,
        expires_at: Some(now + chrono::Duration::days(valid_days)),
        created_at: now,
    }
}

/// Bucket backfill satu kunci lama (cerminan persis migrasi 0023):
/// satu bucket dari agregat kunci saat migrasi. Dipakai tes + safety net
/// load (kunci non-revoked tanpa baris bucket mendapat bucket ini).
pub fn backfill_bucket_for_key(
    key_id: Uuid,
    member_id: Option<Uuid>,
    package_id: Option<Uuid>,
    quota_total: u64,
    quota_remaining: u64,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> QuotaBucket {
    QuotaBucket {
        id: Uuid::now_v7(),
        key_id,
        member_id,
        order_id: None,
        package_id,
        total_hits: quota_total,
        remaining_hits: quota_remaining,
        expires_at,
        created_at: now,
    }
}

/// Konsumsi FIFO `hits` dari bucket aktif bersisa, paling cepat
/// kedaluwarsa dulu. GAGAL (None, tanpa mutasi apa pun) bila total sisa
/// aktif < hits — pemanggil reserve memakai ini untuk 402. Sukses
/// mengembalikan daftar (bucket_id, sisa baru) yang tersentuh, dalam
/// urutan konsumsi, untuk persist berurutan.
pub fn consume_buckets_fifo(
    buckets: &mut [QuotaBucket],
    now: DateTime<Utc>,
    hits: u64,
) -> Option<Vec<(Uuid, u64)>> {
    let active_remaining: u64 = buckets
        .iter()
        .filter(|bucket| bucket_is_active(bucket, now))
        .fold(0u64, |sum, bucket| sum.saturating_add(bucket.remaining_hits));
    if active_remaining < hits {
        return None;
    }
    let mut left = hits;
    let mut touched = Vec::new();
    for index in fifo_indices(buckets) {
        if left == 0 {
            break;
        }
        let bucket = &mut buckets[index];
        if !bucket_is_active(bucket, now) || bucket.remaining_hits == 0 {
            continue;
        }
        let take = left.min(bucket.remaining_hits);
        bucket.remaining_hits -= take;
        left -= take;
        touched.push((bucket.id, bucket.remaining_hits));
    }
    debug_assert_eq!(left, 0);
    Some(touched)
}

/// Kembalikan 1 hit ke satu bucket, dibatasi total bucket itu (refund
/// tidak pernah mencetak hit). Aturan pendaratan (audit flow K1/K13):
/// 1. bucket asal (`bucket_id`) bila masih AKTIF dan masih punya ruang
///    (sisa < total);
/// 2. bila tidak, bucket aktif FIFO-pertama yang masih punya ruang;
/// 3. bila tidak ada bucket aktif yang punya ruang sama sekali, kembalikan
///    None — refund DICATAT HILANG oleh pemanggil (log), bukan dikreditkan
///    ke bucket kedaluwarsa (hitnya takkan pernah bisa dipakai lagi) dan
///    bukan dikreditkan melewati cap total bucket lain (menggelembungkan
///    total). None juga bila tidak ada bucket sama sekali (pemanggil
///    memakai jalur agregat lama).
pub fn refund_bucket(
    buckets: &mut [QuotaBucket],
    now: DateTime<Utc>,
    bucket_id: Option<Uuid>,
) -> Option<(Uuid, u64)> {
    let has_room = |bucket: &QuotaBucket| bucket.remaining_hits < bucket.total_hits;
    let target = bucket_id
        .and_then(|id| buckets.iter().position(|bucket| bucket.id == id))
        .filter(|&index| bucket_is_active(&buckets[index], now) && has_room(&buckets[index]))
        .or_else(|| {
            fifo_indices(buckets).into_iter().find(|&index| {
                bucket_is_active(&buckets[index], now) && has_room(&buckets[index])
            })
        });
    let index = target?;
    let bucket = &mut buckets[index];
    bucket.remaining_hits = bucket.remaining_hits.saturating_add(1).min(bucket.total_hits);
    Some((bucket.id, bucket.remaining_hits))
}

/// Tambah positif adjust ke bucket: isi dulu headroom (total - sisa)
/// bucket aktif urutan FIFO — "mengisi kembali" pemakaian lama TANPA
/// menaikkan total, persis aturan compute_adjusted_quota lama. Bila
/// semua headroom aktif penuh, sisa delta menaikkan total+sisa bucket
/// aktif FIFO-pertama (total baru = sisa baru, seperti aturan lama).
/// Mengembalikan sisa delta yang TIDAK tertampung — itu hanya terjadi
/// bila tidak ada bucket aktif sama sekali, dan pemanggil wajib membuat
/// bucket baru dari sisa tersebut (expiry/paket dari kunci).
pub fn add_hits_to_buckets(
    buckets: &mut [QuotaBucket],
    now: DateTime<Utc>,
    delta: u64,
) -> u64 {
    let mut left = delta;
    for index in fifo_indices(buckets) {
        if left == 0 {
            break;
        }
        let bucket = &mut buckets[index];
        if !bucket_is_active(bucket, now) {
            continue;
        }
        let headroom = bucket.total_hits.saturating_sub(bucket.remaining_hits);
        let take = left.min(headroom);
        bucket.remaining_hits += take;
        left -= take;
    }
    if left > 0 {
        if let Some(index) = fifo_indices(buckets)
            .into_iter()
            .find(|&index| bucket_is_active(&buckets[index], now))
        {
            let bucket = &mut buckets[index];
            bucket.total_hits = bucket.total_hits.saturating_add(left);
            bucket.remaining_hits = bucket.remaining_hits.saturating_add(left);
            left = 0;
        }
    }
    left
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

    #[test]
    fn pln_product_code_parses_and_labels() {
        assert_eq!(ValidationProduct::Pln.as_str(), "pln");
        assert_eq!(ValidationProduct::Pln.label_id(), "Validasi PLN");
        let parsed: ValidationProduct =
            serde_json::from_str("\"pln\"").expect("pln parses like other products");
        assert_eq!(parsed, ValidationProduct::Pln);
        assert_eq!(
            serde_json::to_string(&ValidationProduct::Pln).expect("serialize"),
            "\"pln\""
        );
    }

    fn dt(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn validation_meta_expires_at_serializes_and_defaults() {
        let meta = ValidationMeta {
            provider: "Rajacek".to_owned(),
            provider_latency_ms: 120,
            attempts: 1,
            rajacek_processing_ms: 5,
            total_latency_ms: 125,
            cached: false,
            remaining_quota: 42,
            expires_at: Some(dt("2026-11-25T10:00:00Z")),
        };
        let json = serde_json::to_value(&meta).expect("serialize");
        assert_eq!(json["expires_at"], "2026-11-25T10:00:00Z");
        // None diserialisasi eksplisit sebagai null, bukan dihilangkan.
        let meta_null = ValidationMeta {
            expires_at: None,
            ..meta
        };
        let json_null = serde_json::to_value(&meta_null).expect("serialize");
        assert!(
            json_null.get("expires_at").is_some(),
            "null harus eksplisit, bukan hilang"
        );
        assert!(json_null["expires_at"].is_null());
        // JSON lama (idempotensi tersimpan sebelum field ini ada) tetap
        // lolos parse, dengan default None.
        let legacy: ValidationMeta = serde_json::from_str(
            r#"{"provider":"Rajacek","provider_latency_ms":120,"attempts":1,"rajacek_processing_ms":5,"total_latency_ms":125,"cached":false,"remaining_quota":42}"#,
        )
        .expect("meta lama tanpa expires_at harus tetap lolos parse");
        assert_eq!(legacy.expires_at, None);
    }

    // Tes-tes grant lama di bawah ini DIGANTI eksplisit (2026-10-26):
    // compute_grant_effect dihapus bersama semantik stacking-expiry-nya
    // (expiry baru = expiry lama + valid_days). Penggantinya: grant
    // membuat bucket baru (expiry = beli + valid_days) dan agregat
    // dihitung dari bucket. Rate-max tetap ditegakkan di grant (bukan
    // lagi lewat fungsi ini) dan saturasi diuji lewat agregat.
    fn bucket(
        total: u64,
        remaining: u64,
        expires_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) -> QuotaBucket {
        QuotaBucket {
            id: Uuid::now_v7(),
            key_id: Uuid::now_v7(),
            member_id: None,
            order_id: None,
            package_id: None,
            total_hits: total,
            remaining_hits: remaining,
            expires_at,
            created_at,
        }
    }

    #[test]
    fn grant_bucket_expires_from_purchase_not_from_old_expiry() {
        // Kunci lama: bucket 1000 total / 200 sisa, expiry 1 Nov.
        // Beli 500 hit, 30 hari, pada 25 Okt: bucket BARU expiry
        // 24 Nov (beli + 30 hari) — BUKAN 1 Des (stacking lama).
        let now = dt("2026-10-25T00:00:00Z");
        let key_id = Uuid::now_v7();
        let mut buckets = vec![bucket(
            1000,
            200,
            Some(dt("2026-11-01T00:00:00Z")),
            now,
        )];
        buckets[0].key_id = key_id;
        let new_bucket = new_purchase_bucket(key_id, None, None, None, 500, 30, now);
        assert_eq!(new_bucket.total_hits, 500);
        assert_eq!(new_bucket.remaining_hits, 500);
        assert_eq!(new_bucket.expires_at, Some(dt("2026-11-24T00:00:00Z")));
        buckets.push(new_bucket);
        let (total, remaining, expiry) = bucket_aggregate(&buckets, now);
        assert_eq!(total, 1500);
        assert_eq!(remaining, 700);
        // Agregat = bucket aktif terdekat bersisa = bucket lama (1 Nov).
        assert_eq!(expiry, Some(dt("2026-11-01T00:00:00Z")));
    }

    #[test]
    fn fifo_consumes_earliest_expiry_and_skips_expired() {
        let now = dt("2026-10-25T00:00:00Z");
        let mut buckets = vec![
            bucket(100, 100, Some(dt("2026-12-01T00:00:00Z")), now),
            bucket(50, 50, Some(dt("2026-10-01T00:00:00Z")), now),
            bucket(70, 70, None, now),
            bucket(30, 30, Some(dt("2026-11-01T00:00:00Z")), now),
        ];
        // Konsumsi 40: lewati bucket kedaluwarsa (1 Okt), habiskan 30 dari
        // bucket 1 Nov dulu, lalu 10 dari bucket 1 Des. Bucket tanpa
        // expiry tidak tersentuh.
        let touched = consume_buckets_fifo(&mut buckets, now, 40).expect("sisa cukup");
        assert_eq!(touched.len(), 2);
        let by_id: std::collections::HashMap<Uuid, u64> = touched.into_iter().collect();
        let nov = buckets
            .iter()
            .find(|b| b.expires_at == Some(dt("2026-11-01T00:00:00Z")))
            .unwrap();
        let dec = buckets
            .iter()
            .find(|b| b.expires_at == Some(dt("2026-12-01T00:00:00Z")))
            .unwrap();
        assert_eq!(nov.remaining_hits, 0);
        assert_eq!(dec.remaining_hits, 90);
        assert_eq!(by_id[&nov.id], 0);
        assert_eq!(by_id[&dec.id], 90);
        // Agregat: total semua bucket (250), sisa aktif saja (kedaluwarsa
        // 50 tidak dihitung): 0 + 90 + 70 = 160.
        let (total, remaining, expiry) = bucket_aggregate(&buckets, now);
        assert_eq!(total, 250);
        assert_eq!(remaining, 160);
        assert_eq!(expiry, Some(dt("2026-12-01T00:00:00Z")));
    }

    #[test]
    fn fifo_empty_active_remaining_consumes_nothing() {
        let now = dt("2026-10-25T00:00:00Z");
        let mut buckets = vec![
            bucket(100, 0, Some(dt("2026-12-01T00:00:00Z")), now),
            bucket(50, 50, Some(dt("2026-10-01T00:00:00Z")), now),
        ];
        // Habis = sisa aktif 0 (satu habis, satu kedaluwarsa): konsumsi
        // gagal TANPA mutasi — pemanggil mengubahnya menjadi 402.
        assert!(consume_buckets_fifo(&mut buckets, now, 1).is_none());
        assert_eq!(buckets[0].remaining_hits, 0);
        assert_eq!(buckets[1].remaining_hits, 50);
        let (_, remaining, _) = bucket_aggregate(&buckets, now);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn refund_returns_to_same_bucket_capped_at_its_total() {
        let now = dt("2026-10-25T00:00:00Z");
        let mut buckets = vec![
            bucket(10, 9, Some(dt("2026-11-01T00:00:00Z")), now),
            bucket(20, 20, Some(dt("2026-12-01T00:00:00Z")), now),
        ];
        let first_id = buckets[0].id;
        let (id, remaining) = refund_bucket(&mut buckets, now, Some(first_id)).unwrap();
        assert_eq!(id, first_id);
        assert_eq!(remaining, 10);
        // Refund kedua tidak mencetak hit dan tidak menggelembungkan
        // bucket lain: kedua bucket sudah penuh → refund hilang (None),
        // pemanggil wajib mencatatnya di log, bukan mengkredit diam-diam.
        assert!(refund_bucket(&mut buckets, now, Some(first_id)).is_none());
        // Bucket tak dikenal jatuh ke FIFO-pertama aktif yang punya ruang.
        let mut buckets = vec![
            bucket(10, 10, Some(dt("2026-11-01T00:00:00Z")), now),
            bucket(20, 19, Some(dt("2026-12-01T00:00:00Z")), now),
        ];
        let second_id = buckets[1].id;
        let (id, remaining) =
            refund_bucket(&mut buckets, now, Some(Uuid::now_v7())).unwrap();
        assert_eq!(id, second_id);
        assert_eq!(remaining, 20);
    }

    #[test]
    fn refund_never_lands_in_expired_bucket() {
        let now = dt("2026-10-25T00:00:00Z");
        // Asal kedaluwarsa (sisa 9/10) + satu bucket aktif punya ruang:
        // refund pindah ke bucket aktif, bukan ke bucket mati.
        let mut buckets = vec![
            bucket(10, 9, Some(dt("2026-10-01T00:00:00Z")), now),
            bucket(20, 19, Some(dt("2026-12-01T00:00:00Z")), now),
        ];
        let expired_id = buckets[0].id;
        let active_id = buckets[1].id;
        let (id, remaining) =
            refund_bucket(&mut buckets, now, Some(expired_id)).unwrap();
        assert_eq!(id, active_id);
        assert_eq!(remaining, 20);
        assert_eq!(buckets[0].remaining_hits, 9);
        // Asal kedaluwarsa dan TIDAK ADA bucket aktif sama sekali:
        // refund hilang (None), bukan dikreditkan ke bucket mati.
        let mut buckets = vec![bucket(10, 9, Some(dt("2026-10-01T00:00:00Z")), now)];
        assert!(refund_bucket(&mut buckets, now, Some(expired_id)).is_none());
        assert_eq!(buckets[0].remaining_hits, 9);
    }

    #[test]
    fn aggregate_uses_nearest_active_expiry_and_null_only_case() {
        let now = dt("2026-10-25T00:00:00Z");
        let dated = bucket(100, 40, Some(dt("2026-12-01T00:00:00Z")), now);
        let undated = bucket(50, 50, None, now);
        let (_, _, expiry) = bucket_aggregate(&[dated, undated.clone()], now);
        assert_eq!(expiry, Some(dt("2026-12-01T00:00:00Z")));
        let (_, _, expiry) = bucket_aggregate(&[undated], now);
        assert_eq!(expiry, None);
    }

    #[test]
    fn aggregate_expired_balance_is_null_not_first_bucket_date() {
        // K14/D6: saldo habis -> meta.expires_at = null, bukan tanggal
        // bucket pertama (dulu MIN semua bucket).
        let now = dt("2026-10-25T00:00:00Z");
        // Bucket aktif bersisa -> tanggal terdekat tetap dipakai.
        let active = bucket(100, 40, Some(dt("2026-12-01T00:00:00Z")), now);
        let (_, remaining, expiry) = bucket_aggregate(&[active], now);
        assert_eq!((remaining, expiry), (40, Some(dt("2026-12-01T00:00:00Z"))));
        // Hanya bucket tanpa tanggal bersisa -> null (tidak berubah).
        let undated = bucket(50, 50, None, now);
        let (_, _, expiry) = bucket_aggregate(&[undated], now);
        assert_eq!(expiry, None);
        // Semua bucket habis/lewat -> null (dulu tanggal bucket pertama).
        let spent = bucket(100, 0, Some(dt("2026-12-01T00:00:00Z")), now);
        let expired = bucket(100, 9, Some(dt("2026-10-01T00:00:00Z")), now);
        let (_, remaining, expiry) = bucket_aggregate(&[spent, expired], now);
        assert_eq!(remaining, 0);
        assert_eq!(expiry, None);
        // Kunci legacy tanpa bucket tidak berubah: (0, 0, None).
        let (total, remaining, expiry) = bucket_aggregate(&[], now);
        assert_eq!((total, remaining, expiry), (0, 0, None));
    }

    #[test]
    fn aggregate_saturates_instead_of_overflowing() {
        let now = dt("2026-10-25T00:00:00Z");
        let buckets = vec![
            bucket(u64::MAX, u64::MAX, None, now),
            bucket(1, 1, None, now),
        ];
        let (total, remaining, _) = bucket_aggregate(&buckets, now);
        assert_eq!(total, u64::MAX);
        assert_eq!(remaining, u64::MAX);
    }

    #[test]
    fn add_hits_refills_headroom_before_raising_total() {
        let now = dt("2026-10-25T00:00:00Z");
        let mut buckets = vec![bucket(1000, 500, None, now)];
        // +100 mengisi pemakaian lama: total tetap 1000, sisa 600.
        assert_eq!(add_hits_to_buckets(&mut buckets, now, 100), 0);
        assert_eq!(buckets[0].total_hits, 1000);
        assert_eq!(buckets[0].remaining_hits, 600);
        // +500 lagi: 400 headroom + 100 overflow menaikkan total 1100.
        assert_eq!(add_hits_to_buckets(&mut buckets, now, 500), 0);
        assert_eq!(buckets[0].total_hits, 1100);
        assert_eq!(buckets[0].remaining_hits, 1100);
    }

    #[test]
    fn backfill_mirrors_key_aggregates() {
        let now = dt("2026-10-25T00:00:00Z");
        let key_id = Uuid::now_v7();
        let member_id = Uuid::now_v7();
        let package_id = Uuid::now_v7();
        let bucket = backfill_bucket_for_key(
            key_id,
            Some(member_id),
            Some(package_id),
            5000,
            1234,
            Some(dt("2026-12-01T00:00:00Z")),
            now,
        );
        assert_eq!(bucket.key_id, key_id);
        assert_eq!(bucket.member_id, Some(member_id));
        assert_eq!(bucket.package_id, Some(package_id));
        assert_eq!(bucket.order_id, None);
        assert_eq!(bucket.total_hits, 5000);
        assert_eq!(bucket.remaining_hits, 1234);
        assert_eq!(bucket.expires_at, Some(dt("2026-12-01T00:00:00Z")));
        let (total, remaining, expiry) = bucket_aggregate(&[bucket], now);
        assert_eq!((total, remaining), (5000, 1234));
        assert_eq!(expiry, Some(dt("2026-12-01T00:00:00Z")));
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
            member_code: None,
            product: ValidationProduct::BankAccount,
            outcome: "valid".to_owned(),
            target_masked: String::new(),
            target_raw: None,
            account_name: None,
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

#[cfg(test)]
mod admin_history_fields_tests {
    use super::*;

    fn history_item_with_raw() -> ValidationHistoryItem {
        ValidationHistoryItem {
            request_id: "R9".to_owned(),
            api_key_prefix: "rv_live_x".to_owned(),
            member_code: Some("RC000042".to_owned()),
            product: ValidationProduct::BankAccount,
            outcome: "valid".to_owned(),
            target_masked: "***7890".to_owned(),
            target_raw: Some("1234567890".to_owned()),
            account_name: Some("Andrias Se****an Su****o".to_owned()),
            provider_reference: None,
            provider_latency_ms: 10,
            rajacek_processing_ms: None,
            total_latency_ms: None,
            attempts: None,
            occurred_at: Utc::now(),
            channel: "api".to_owned(),
        }
    }

    #[test]
    fn usage_event_new_fields_roundtrip() {
        let event: UsageEvent = serde_json::from_str(
            r#"{"event_id":"0199a5a5-0000-7000-8000-000000000009","request_id":"R9","idempotency_key":null,"api_key_prefix":"rv_live_x","product":"bank_account","status":"valid","price_snapshot_id":null,"occurred_at":"2026-10-25T00:00:00Z","target_fingerprint":"f","target_masked":"***7890","target_raw":"1234567890","account_name":"Andrias Se****an Su****o","provider_reference":null,"provider_latency_ms":10,"channel":"api"}"#,
        )
        .expect("event dengan field baru harus ter-parse");
        assert_eq!(event.target_raw.as_deref(), Some("1234567890"));
        assert_eq!(
            event.account_name.as_deref(),
            Some("Andrias Se****an Su****o")
        );
        let serialized = serde_json::to_string(&event).expect("serialize");
        assert!(serialized.contains("\"target_raw\":\"1234567890\""));
        assert!(serialized.contains("Andrias Se****an Su****o"));
    }

    #[test]
    fn usage_event_old_events_without_new_fields_default_to_none() {
        // Event dari binary lama (sebelum migrasi 0024) yang masih antre
        // di Redis harus tetap ter-deserialisasi; field baru = None.
        let event: UsageEvent = serde_json::from_str(
            r#"{"event_id":"0199a5a5-0000-7000-8000-000000000001","request_id":"R1","idempotency_key":null,"api_key_prefix":"rv_live_x","product":"bank_account","status":"valid","price_snapshot_id":null,"occurred_at":"2026-10-25T00:00:00Z","target_fingerprint":"f","target_masked":"***","provider_reference":null,"provider_latency_ms":10,"channel":"api"}"#,
        )
        .expect("event lama tanpa field baru harus ter-parse");
        assert_eq!(event.target_raw, None);
        assert_eq!(event.account_name, None);
    }

    #[test]
    fn member_item_serialization_never_contains_raw_fields() {
        // Batas keras: ValidationHistoryItem adalah bentuk yang dipakai
        // endpoint riwayat member (member::HistoryResponse), jadi
        // serialisasinya tidak boleh memuat target utuh / nama / kode
        // member apa pun — walau item internalnya membawa ketiganya.
        let serialized = serde_json::to_string(&history_item_with_raw()).expect("serialize");
        assert!(!serialized.contains("target_raw"));
        assert!(!serialized.contains("account_name"));
        assert!(!serialized.contains("member_code"));
        assert!(!serialized.contains("1234567890"));
        assert!(!serialized.contains("Andrias Se****an Su****o"));
        assert!(!serialized.contains("RC000042"));
        assert!(serialized.contains("\"target_masked\":\"***7890\""));
    }

    #[test]
    fn admin_item_serialization_contains_raw_fields() {
        let item = history_item_with_raw();
        let admin = AdminValidationHistoryItem::from(&item);
        let serialized = serde_json::to_string(&admin).expect("serialize");
        assert!(serialized.contains("\"target_raw\":\"1234567890\""));
        assert!(serialized.contains("\"account_name\":\"Andrias Se****an Su****o\""));
        assert!(serialized.contains("\"target_masked\":\"***7890\""));
    }

    #[test]
    fn admin_history_item_carries_member_code_and_null_is_preserved() {
        // (d) level serialisasi: prefix ter-resolve -> kode ikut;
        // lookup gagal (item tanpa kode) -> admin tetap dapat null,
        // bukan error — konversi From tidak pernah gagal.
        let resolved = AdminValidationHistoryItem::from(&history_item_with_raw());
        assert_eq!(resolved.member_code.as_deref(), Some("RC000042"));
        let serialized = serde_json::to_string(&resolved).expect("serialize");
        assert!(serialized.contains("\"member_code\":\"RC000042\""));
        assert!(serialized.contains("\"api_key_prefix\":\"rv_live_x\""));

        let mut unresolved = history_item_with_raw();
        unresolved.member_code = None;
        let admin = AdminValidationHistoryItem::from(&unresolved);
        assert_eq!(admin.member_code, None);
        let serialized = serde_json::to_string(&admin).expect("serialize");
        assert!(serialized.contains("\"member_code\":null"));
        assert!(serialized.contains("\"api_key_prefix\":\"rv_live_x\""));
    }

    #[test]
    fn member_account_serialization_never_contains_member_code() {
        // Batas keras kedua: MemberAccount sendiri skip_serializing
        // member_code, jadi serialisasi langsung struct ini pun tidak
        // membocorkan kode — view admin membawanya lewat field eksplisit
        // (AdminMemberView / MemberDetailResponse di api.rs).
        let account = MemberAccount {
            id: Uuid::now_v7(),
            member_code: Some("RC000042".to_owned()),
            google_sub: "sub-tes".to_owned(),
            email: "member-tes@example.test".to_owned(),
            name: None,
            picture_url: None,
            plan_kind: "trial".to_owned(),
            status: "active".to_owned(),
            created_at: Utc::now(),
            last_login_at: None,
        };
        let serialized = serde_json::to_string(&account).expect("serialize");
        assert!(!serialized.contains("member_code"));
        assert!(!serialized.contains("RC000042"));
        assert!(serialized.contains("member-tes@example.test"));
    }
}

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    admin_roles::{AdminAccount, Role},
    error::AppError,
    models::{
        ActivityItem, AdminApiKeySummary, AdminAuditEntry, AdminPackage, AdminProduct, ApiKeyContext,
        CreateApiKeyRequest, CreatePackageRequest, CreateRateLimitPolicyRequest, CreatedApiKey,
        DashboardAlert, DashboardMetrics, DashboardOverview, GrantOutcome, RateLimitPolicy,
        ServiceStatus, TrafficPoint, UpdatePackageRequest, UpdateProductRequest,
        UpdateRateLimitPolicyRequest, ValidationHistoryFilters, ValidationHistoryItem,
        ValidationProduct,
    },
};

const MAX_RECENT_ACTIVITIES: usize = 16;

#[derive(Clone)]
struct ApiKeyRecord {
    summary: AdminApiKeySummary,
    secret_hash: String,
    /// AES-256-GCM ciphertext (nonce ‖ ciphertext) of the full plaintext
    /// key, present only for keys issued while a key-encryption secret was
    /// configured. Lets the member (portal) and admin (panel) view the key
    /// again; verification always uses the hash, never this value. Keys
    /// issued before the feature stay hash-only (None).
    secret_ciphertext: Option<Vec<u8>>,
    remaining_quota: u64,
    /// Total quota granted (mirrors summary.quota_total; kept here so the
    /// record is self-contained for persistence).
    quota_total: u64,
    expires_at: Option<chrono::DateTime<Utc>>,
    package_id: Option<Uuid>,
    member_id: Option<Uuid>,
}

struct StoreData {
    products: HashMap<Uuid, AdminProduct>,
    packages: HashMap<Uuid, AdminPackage>,
    policies: HashMap<Uuid, RateLimitPolicy>,
    api_keys: HashMap<String, ApiKeyRecord>,
    activities: Vec<ActivityItem>,
    stats: ValidationStats,
    history: VecDeque<ValidationHistoryItem>,
}

/// How many recent validations the in-memory history fallback retains. The
/// durable, unbounded history lives in MySQL `validation_requests`.
const HISTORY_MEMORY_CAP: usize = 500;

/// Real counters for validation traffic processed by THIS process since startup.
/// They replace the previously hard-coded overview numbers; durable cross-restart
/// aggregates belong to the MySQL `validation_requests`/`usage_ledger` tables that
/// the worker maintains.
#[derive(Default)]
struct ValidationStats {
    total: u64,
    successful: u64,
    provider_latency_total_ms: u64,
}

/// Development-compatible administration storage.
///
/// This store deliberately implements the same semantics expected from the persistent MySQL
/// repository: generated external IDs, immutable API-key hashes, and append-only activity
/// feed updates. The production repository can replace this implementation without changing
/// the HTTP contract.
pub struct AdminStore {
    data: RwLock<StoreData>,
    default_rate_limit_per_minute: std::sync::atomic::AtomicU32,
    /// Optional MySQL pool (attached at startup when a database is
    /// configured). When present, packages, policies, and API keys —
    /// including quota counters — are persisted and reloaded on boot, so
    /// restarts no longer reset them. Without it the store is purely
    /// in-memory (development/demo behavior).
    pool: std::sync::RwLock<Option<sqlx::MySqlPool>>,
    /// Cipher for storing newly issued API keys recoverably (see
    /// `ApiKeyRecord::secret_ciphertext`). Attached at startup from
    /// API_KEY_ENCRYPTION_KEY; absent = hash-only issuance.
    key_cipher: std::sync::RwLock<Option<crate::provider_config::CredentialCipher>>,
    /// Ordered background writer for quota snapshots (started by the API
    /// binary). Sends are FIFO, so the reserve/refund write order that used
    /// to require holding the data lock across a MySQL UPDATE is preserved
    /// by the channel instead.
    quota_tx: std::sync::RwLock<Option<tokio::sync::mpsc::Sender<QuotaWrite>>>,
    quota_writer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// One serialization lock per member for key provisioning
    /// (regeneration + first-sign-in trial issuance, audit flow B4/K15).
    /// Entries are never removed: the map is bounded by the member
    /// count, the same order as the `api_keys` map itself.
    key_locks: std::sync::Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    /// Fallback counters for the daily invalid free pool, used only when no
    /// MySQL pool is attached (development/tests). Production always has a
    /// pool, so restarts never reset the pool there. The mutex is held
    /// only for the get-or-increment, never across an await.
    invalid_free_fallback:
        std::sync::Mutex<HashMap<(String, chrono::NaiveDate), u32>>,
    /// Short-lived analytics cache (AREA 1, 60 detik, keyed by `days`):
    /// the analytics endpoint aggregates `validation_requests` on every
    /// call, and the dashboard polls often enough for that to matter.
    /// Health is intentionally NOT cached (breaker state must stay live).
    analytics_cache: std::sync::Mutex<
        Option<(
            std::time::Instant,
            i64,
            crate::analytics::AnalyticsResponse,
        )>,
    >,
}

/// Daily free pool for final invalid outcomes (billing rule 2026-10-25):
/// the first 100 Invalid/NotFound results per API key per WIB calendar day
/// are free; further invalid results cost 1 hit like any other charged
/// outcome. One pool shared by Invalid and NotFound.
pub const INVALID_FREE_DAILY_LIMIT: u32 = 100;

/// One quota snapshot for the background writer. Values are absolute, so a
/// later snapshot always supersedes an earlier one for the same key.
struct QuotaWrite {
    prefix: String,
    remaining: u64,
    at: chrono::DateTime<Utc>,
}

/// Durable dashboard aggregates computed from `validation_requests`.
struct DbOverview {
    metrics: DashboardMetrics,
    traffic: Vec<TrafficPoint>,
    activities: Vec<ActivityItem>,
}

/// Outcome of a package delete, for the audit log: the package name
/// plus how many key rows were detached from it (K30).
pub struct DeletedPackage {
    pub name: String,
    pub keys_detached: usize,
}

/// Batas adjust kuota manual per panggilan (Area 4, 2026-10-25).
/// Batas ini ditegakkan di handler DAN di store (defense in depth).
pub const MAX_QUOTA_ADJUST_DELTA: i64 = 10_000_000;

/// Hasil satu adjust kuota manual: sebelum/sesudah untuk sisa DAN total.
/// Handler menulis nilai-nilai ini verbatim ke baris audit persisten,
/// sehingga jejak adjust selalu bisa direkonsiliasi tanpa menebak.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaAdjustment {
    pub key_id: Uuid,
    pub prefix: String,
    pub delta: i64,
    pub quota_total_before: u64,
    pub quota_total_after: u64,
    pub quota_remaining_before: u64,
    pub quota_remaining_after: u64,
}

/// Pemakaian tertagih satu hari WIB dari `usage_ledger` (hanya baris
/// `operation = 'charge'`, satu baris = 1 hit tertagih). Hit gratis dari
/// pool invalid (billing 2026-10-25) TIDAK masuk ledger, jadi angka ini
/// adalah hit yang memotong kuota — bukan jumlah cek mentah.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberDailyUsage {
    pub date: String,
    pub charged_hits: i64,
}

/// Aturan total untuk adjust kuota manual (Area 4) — dirumuskan di sini
/// agar handler, store, dan tes membaca aturan yang sama:
///
/// - Delta positif: remaining += delta. Bila remaining baru MELEBIHI
///   total, total ikut naik sebesar selisihnya (total baru =
///   remaining baru). Bila remaining baru masih <= total, total TIDAK
///   berubah: sisa yang dulu terpakai "diisi kembali" tanpa menaikkan
///   pagu.
/// - Delta negatif: remaining -= |delta|. Total TIDAK berubah: pagu
///   tetap, hanya sisa yang berkurang.
/// - Remaining hasil tidak boleh < 0 (ditolak, tanpa perubahan).
/// - TIDAK PERNAH set absolut dari input: delta hanya dijumlahkan
///   (SQL: `quota_remaining = quota_remaining + delta` untuk positif,
///   `quota_remaining = quota_remaining - |delta|` untuk negatif).
///   Nilai absolut di sisi database hanya dipakai untuk kolom total
///   yang dihitung server dari aturan di atas, bukan dari input.
pub(crate) fn compute_adjusted_quota(
    quota_total: u64,
    quota_remaining: u64,
    delta: i64,
) -> Result<(u64, u64), AppError> {
    if delta == 0 {
        return Err(AppError::bad_request("Delta kuota tidak boleh 0"));
    }
    if delta < -MAX_QUOTA_ADJUST_DELTA || delta > MAX_QUOTA_ADJUST_DELTA {
        return Err(AppError::bad_request(
            "Delta kuota melebihi batas 10.000.000 per penyesuaian",
        ));
    }
    let new_remaining = if delta > 0 {
        quota_remaining.saturating_add(delta as u64)
    } else {
        quota_remaining
            .checked_sub(delta.unsigned_abs())
            .ok_or_else(|| {
                AppError::bad_request("Penyesuaian membuat sisa kuota negatif")
            })?
    };
    let new_total = if delta > 0 && new_remaining > quota_total {
        new_remaining
    } else {
        quota_total
    };
    Ok((new_total, new_remaining))
}

impl AdminStore {
    pub fn new(
        demo_api_key: Option<&str>,
        default_rate_limit_per_minute: u32,
    ) -> Result<Self, AppError> {
        let now = Utc::now();
        let products = sample_products(now)
            .into_iter()
            .map(|product| (product.id, product))
            .collect();
        let packages = sample_packages(now)
            .into_iter()
            .map(|package| (package.id, package))
            .collect();
        let policies = sample_policies(now)
            .into_iter()
            .map(|policy| (policy.id, policy))
            .collect();

        let mut api_keys = HashMap::new();
        if let Some(raw_key) = demo_api_key {
            let (prefix, secret) = split_api_key(raw_key).ok_or_else(|| {
                AppError::internal("Format DEMO_API_KEY tidak sesuai dengan format kunci API")
            })?;
            let secret_hash = hash_secret(&secret)?;
            let summary = AdminApiKeySummary {
                id: Uuid::now_v7(),
                name: "Kunci demo pengembangan".to_owned(),
                prefix: prefix.clone(),
                scopes: vec!["validate:*".to_owned()],
                status: "active".to_owned(),
                last_used_at: None,
                rate_limit_per_minute: default_rate_limit_per_minute,
                quota_total: 50_000,
                expires_at: None,
                package_id: None,
                member_id: None,
                created_at: now,
            };
            api_keys.insert(
                prefix,
                ApiKeyRecord {
                    summary,
                    secret_hash,
                    secret_ciphertext: None,
                    remaining_quota: 50_000,
                    quota_total: 50_000,
                    expires_at: None,
                    package_id: None,
                    member_id: None,
                },
            );
        }

        Ok(Self {
            pool: std::sync::RwLock::new(None),
            key_cipher: std::sync::RwLock::new(None),
            quota_tx: std::sync::RwLock::new(None),
            quota_writer: std::sync::Mutex::new(None),
            key_locks: std::sync::Mutex::new(HashMap::new()),
            invalid_free_fallback: std::sync::Mutex::new(HashMap::new()),
            analytics_cache: std::sync::Mutex::new(None),
            default_rate_limit_per_minute: std::sync::atomic::AtomicU32::new(
                default_rate_limit_per_minute.max(1),
            ),
            data: RwLock::new(StoreData {
                products,
                packages,
                policies,
                api_keys,
                activities: Vec::new(),
                stats: ValidationStats::default(),
                history: VecDeque::new(),
            }),
        })
    }

    /// Fallback rate limit for newly created API keys without an explicit
    /// value. Adjustable live by admin; existing keys keep their own limit.
    /// The serialization lock for one member's key provisioning.
    /// Deadlock argument (audit flow B4): this lock is always acquired
    /// OUTERMOST — before any `data` lock or database await — by both
    /// of its holders (`regenerate_member_key` and the Google-callback
    /// provisioning block), and the map mutex is held only for the
    /// get-or-insert, never across an await. No code path acquires a
    /// provisioning lock while holding `data`, so the ordering
    /// (provision lock -> data lock) can never invert. Holding it
    /// across awaits is the point: the whole check-then-issue sequence
    /// must be atomic per member, or two concurrent regenerations (or
    /// first sign-ins) can each mint a live key from the same balance.
    /// A single global lock would also be correct but would serialize
    /// unrelated members; per-member locks keep that cost per account.
    pub(crate) fn member_key_lock(&self, member_id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.key_locks.lock().expect("key locks map");
        locks
            .entry(member_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub fn default_rate_limit_per_minute(&self) -> u32 {
        self.default_rate_limit_per_minute
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_default_rate_limit_per_minute(&self, limit: u32) {
        self.default_rate_limit_per_minute
            .store(limit.max(1), std::sync::atomic::Ordering::Relaxed);
    }

    // ---- MySQL persistence (write-through) --------------------------------
    //
    // The in-memory maps stay the runtime read model (fast auth path); every
    // structural mutation is also written to MySQL, and quota movements are
    // persisted fire-and-forget. On boot, `load_persisted` replaces the
    // seeded state with the database state so restarts preserve packages,
    // keys, and remaining quota.

    pub fn attach_pool(&self, pool: sqlx::MySqlPool) {
        *self.pool.write().expect("pool lock") = Some(pool);
    }

    /// Attach the API-key encryption cipher (from API_KEY_ENCRYPTION_KEY).
    /// Without it, new keys are stored hash-only and cannot be revealed.
    pub fn attach_key_cipher(&self, secret: Option<&str>) {
        *self.key_cipher.write().expect("key cipher lock") =
            secret.map(|value| crate::provider_config::CredentialCipher::new(Some(value)));
    }

    fn key_cipher(&self) -> Option<crate::provider_config::CredentialCipher> {
        self.key_cipher.read().expect("key cipher lock").clone()
    }

    /// Decrypt a stored key's plaintext for an authorized reveal (the
    /// member viewing their own key, or an admin viewing a member's key).
    pub async fn reveal_api_key(&self, prefix: &str) -> Option<String> {
        let ciphertext = {
            let data = self.data.read().await;
            data.api_keys
                .get(prefix)
                .and_then(|record| record.secret_ciphertext.clone())
        }?;
        self.key_cipher()?.decrypt(&ciphertext).ok()
    }

    /// Whether the key with this prefix can be revealed (has ciphertext).
    pub async fn key_revealable(&self, prefix: &str) -> bool {
        let data = self.data.read().await;
        data.api_keys
            .get(prefix)
            .is_some_and(|record| record.secret_ciphertext.is_some())
    }

    pub(crate) fn pool(&self) -> Option<sqlx::MySqlPool> {
        self.pool.read().expect("pool lock").clone()
    }

    /// Cached analytics response for this `days` window, if fresh
    /// (AREA 1, TTL 60 detik). The returned copy is marked `cached`.
    pub(crate) fn cached_analytics(
        &self,
        days: i64,
    ) -> Option<crate::analytics::AnalyticsResponse> {
        let guard = self.analytics_cache.lock().expect("analytics cache lock");
        let (stored_at, stored_days, response) = guard.as_ref()?;
        if *stored_days != days
            || stored_at.elapsed().as_secs() >= crate::analytics::ANALYTICS_CACHE_TTL_SECS
        {
            return None;
        }
        let mut response = response.clone();
        response.cached = true;
        Some(response)
    }

    /// Store a fresh analytics response for this `days` window.
    pub(crate) fn store_cached_analytics(
        &self,
        days: i64,
        response: crate::analytics::AnalyticsResponse,
    ) {
        let mut guard = self.analytics_cache.lock().expect("analytics cache lock");
        *guard = Some((std::time::Instant::now(), days, response));
    }

    /// Member pemilik sebuah kunci berdasarkan prefix, tanpa memeriksa
    /// status/kedaluwarsa kunci. Dipakai jalur pembelian: member yang
    /// kuncinya kedaluwarsa justru harus bisa membeli perpanjangan.
    pub(crate) async fn key_member_id_by_prefix(&self, prefix: &str) -> Option<Uuid> {
        let data = self.data.read().await;
        data.api_keys
            .get(prefix)
            .and_then(|record| record.member_id)
    }

    pub async fn load_persisted(&self) {
        let Some(pool) = self.pool() else {
            return;
        };
        // Packages: DB rows replace the samples; an empty table receives the
        // current in-memory set as its initial content.
        match sqlx::query_as::<_, PackageRow>("SELECT id, name, slug, description, price_idr, included_hits, active, highlighted, products, rate_limit_per_minute, promo_percent, promo_ends_at, created_at, updated_at FROM admin_packages")
            .fetch_all(&pool)
            .await
        {
            Ok(rows) if !rows.is_empty() => {
                let mut data = self.data.write().await;
                data.packages = rows
                    .into_iter()
                    .filter_map(|row| row.into_package().ok())
                    .map(|package| (package.id, package))
                    .collect();
                tracing::info!("Paket dimuat dari database");
            }
            Ok(_) => {
                for package in self.list_packages().await {
                    self.persist_package(&package).await;
                }
            }
            Err(error) => tracing::warn!(?error, "Gagal memuat paket dari database"),
        }
        // Rate-limit policies: same treatment.
        match sqlx::query_as::<_, PolicyRow>("SELECT id, name, scope, target, requests_per_minute, burst, concurrency_limit, active, updated_at FROM rate_limit_policies")
            .fetch_all(&pool)
            .await
        {
            Ok(rows) if !rows.is_empty() => {
                let mut data = self.data.write().await;
                data.policies = rows
                    .into_iter()
                    .filter_map(|row| row.into_policy().ok())
                    .map(|policy| (policy.id, policy))
                    .collect();
                tracing::info!("Kebijakan rate limit dimuat dari database");
            }
            Ok(_) => {
                for policy in self.list_rate_limit_policies().await {
                    self.persist_policy(&policy).await;
                }
            }
            Err(error) => tracing::warn!(?error, "Gagal memuat kebijakan rate limit dari database"),
        }
        // API keys: DB wins per prefix; in-memory-only keys (the env seed)
        // are written to the DB so they survive the next restart too.
        match sqlx::query_as::<_, ApiKeyRow>("SELECT id, prefix, name, secret_hash, secret_ciphertext, scopes, status, rate_limit_per_minute, quota_total, quota_remaining, expires_at, package_id, member_id, last_used_at, created_at FROM admin_api_keys")
            .fetch_all(&pool)
            .await
        {
            Ok(rows) => {
                let db_prefixes: std::collections::HashSet<String> =
                    rows.iter().map(|row| row.prefix.clone()).collect();
                {
                    let mut data = self.data.write().await;
                    for row in rows {
                        match row.into_record() {
                            Ok(record) => {
                                data.api_keys
                                    .insert(record.summary.prefix.clone(), record);
                            }
                            Err(error) => {
                                tracing::warn!(?error, "Baris kunci API dilewati saat muat")
                            }
                        }
                    }
                }
                let seeds: Vec<ApiKeyRecord> = {
                    let data = self.data.read().await;
                    data.api_keys
                        .values()
                        .filter(|record| !db_prefixes.contains(&record.summary.prefix))
                        .cloned()
                        .collect()
                };
                for record in &seeds {
                    // Deliberate exception to fail-closed persists: a seed
                    // that cannot be written is recreated on the next boot.
                    if let Err(error) = self.persist_key(record).await {
                        tracing::warn!(?error, "Gagal menyimpan kunci seed");
                    }
                }
                tracing::info!("Kunci API dimuat dari database");
            }
            Err(error) => tracing::warn!(?error, "Gagal memuat kunci API dari database"),
        }
    }

    async fn persist_package(&self, package: &AdminPackage) {
        let Some(pool) = self.pool() else { return };
        let products = serde_json::to_string(&package.products).unwrap_or_else(|_| "[]".into());
        if let Err(error) = sqlx::query(
            "INSERT INTO admin_packages (id, name, slug, description, price_idr, included_hits, active, highlighted, products, rate_limit_per_minute, promo_percent, promo_ends_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE name = VALUES(name), slug = VALUES(slug), description = VALUES(description), price_idr = VALUES(price_idr), included_hits = VALUES(included_hits), active = VALUES(active), highlighted = VALUES(highlighted), products = VALUES(products), rate_limit_per_minute = VALUES(rate_limit_per_minute), promo_percent = VALUES(promo_percent), promo_ends_at = VALUES(promo_ends_at), updated_at = VALUES(updated_at)",
        )
        .bind(package.id.to_string())
        .bind(&package.name)
        .bind(&package.slug)
        .bind(&package.description)
        .bind(package.price_idr)
        .bind(package.included_hits)
        .bind(package.active)
        .bind(package.highlighted)
        .bind(products)
        .bind(package.rate_limit_per_minute)
        .bind(package.promo_percent)
        .bind(package.promo_ends_at)
        .bind(package.created_at)
        .bind(package.updated_at)
        .execute(&pool)
        .await
        {
            tracing::warn!(?error, package_id = %package.id, "Gagal menyimpan paket ke database");
        }
    }

    /// Delete a package row inside the caller's transaction, FAILING on
    /// database error (audit 2026-10-25, B13): the old warn-only
    /// behavior let the handler report success while the row survived,
    /// so the package "came back" on restart. Taking the transaction
    /// (rather than the pool) is what lets `delete_package` run this
    /// DELETE atomically with the K30 key detach. A 0-row delete is
    /// Ok: the desired end state (row gone) already holds.
    async fn delete_package_row(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        id: Uuid,
    ) -> Result<(), AppError> {
        if let Err(error) = sqlx::query("DELETE FROM admin_packages WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut **tx)
            .await
        {
            tracing::warn!(?error, package_id = %id, "Gagal menghapus paket dari database");
            return Err(AppError::internal("Paket tidak dapat dihapus dari database"));
        }
        Ok(())
    }

    async fn persist_policy(&self, policy: &RateLimitPolicy) {
        let Some(pool) = self.pool() else { return };
        if let Err(error) = sqlx::query(
            "INSERT INTO rate_limit_policies (id, name, scope, target, requests_per_minute, burst, concurrency_limit, active, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE name = VALUES(name), scope = VALUES(scope), target = VALUES(target), requests_per_minute = VALUES(requests_per_minute), burst = VALUES(burst), concurrency_limit = VALUES(concurrency_limit), active = VALUES(active), updated_at = VALUES(updated_at)",
        )
        .bind(policy.id)
        .bind(&policy.name)
        .bind(&policy.scope)
        .bind(&policy.target)
        .bind(policy.requests_per_minute)
        .bind(policy.burst)
        .bind(policy.concurrency_limit)
        .bind(policy.active)
        .bind(policy.updated_at)
        .execute(&pool)
        .await
        {
            tracing::warn!(?error, policy_id = %policy.id, "Gagal menyimpan kebijakan rate limit");
        }
    }

    /// Same fail-on-error contract as `delete_package_row` (audit
    /// 2026-10-25, B13, which notes the identical warn-only pattern
    /// here): the caller deletes the row first, then memory.
    async fn delete_policy_row(&self, id: Uuid) -> Result<(), AppError> {
        let Some(pool) = self.pool() else { return Ok(()) };
        if let Err(error) = sqlx::query("DELETE FROM rate_limit_policies WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
        {
            tracing::warn!(?error, policy_id = %id, "Gagal menghapus kebijakan rate limit");
            return Err(AppError::internal(
                "Kebijakan rate limit tidak dapat dihapus dari database",
            ));
        }
        Ok(())
    }

    /// Upsert a key record. Failures are RETURNED (audit 2026-10-25, B5):
    /// the old warn-only behavior let memory and the database diverge
    /// silently, so an assign or a disable could vanish on restart. The
    /// single deliberate exception is the startup seed loop, which logs
    /// and continues instead of failing the boot.
    async fn persist_key(&self, record: &ApiKeyRecord) -> Result<(), AppError> {
        let Some(pool) = self.pool() else { return Ok(()) };
        let scopes = serde_json::to_string(&record.summary.scopes).unwrap_or_else(|_| "[]".into());
        if let Err(error) = sqlx::query(
            "INSERT INTO admin_api_keys (id, prefix, name, secret_hash, secret_ciphertext, scopes, status, rate_limit_per_minute, quota_total, quota_remaining, expires_at, package_id, member_id, last_used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE name = VALUES(name), secret_hash = VALUES(secret_hash), secret_ciphertext = VALUES(secret_ciphertext), scopes = VALUES(scopes), status = VALUES(status), rate_limit_per_minute = VALUES(rate_limit_per_minute), quota_total = VALUES(quota_total), quota_remaining = VALUES(quota_remaining), expires_at = VALUES(expires_at), package_id = VALUES(package_id), member_id = VALUES(member_id), last_used_at = VALUES(last_used_at)",
        )
        .bind(record.summary.id.to_string())
        .bind(&record.summary.prefix)
        .bind(&record.summary.name)
        .bind(&record.secret_hash)
        .bind(&record.secret_ciphertext)
        .bind(scopes)
        .bind(&record.summary.status)
        .bind(record.summary.rate_limit_per_minute)
        .bind(record.quota_total)
        .bind(record.remaining_quota)
        .bind(record.expires_at)
        .bind(record.package_id.map(|id| id.to_string()))
        .bind(record.member_id.map(|id| id.to_string()))
        .bind(record.summary.last_used_at)
        .bind(record.summary.created_at)
        .execute(&pool)
        .await
        {
            tracing::warn!(?error, prefix = %record.summary.prefix, "Gagal menyimpan kunci API ke database");
            return Err(AppError::internal("Kunci API tidak dapat disimpan"));
        }
        Ok(())
    }

    /// Insert a newly issued key. Unlike `persist_key` (upsert, used for
    /// updates to existing records) this FAILS on a duplicate prefix so a
    /// collision can never silently overwrite another key's row: the
    /// caller retries issuance with a fresh prefix instead.
    async fn persist_new_key(&self, record: &ApiKeyRecord) -> Result<(), AppError> {
        let Some(pool) = self.pool() else { return Ok(()) };
        let scopes = serde_json::to_string(&record.summary.scopes).unwrap_or_else(|_| "[]".into());
        if let Err(error) = sqlx::query(
            "INSERT INTO admin_api_keys (id, prefix, name, secret_hash, secret_ciphertext, scopes, status, rate_limit_per_minute, quota_total, quota_remaining, expires_at, package_id, member_id, last_used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(record.summary.id.to_string())
        .bind(&record.summary.prefix)
        .bind(&record.summary.name)
        .bind(&record.secret_hash)
        .bind(&record.secret_ciphertext)
        .bind(scopes)
        .bind(&record.summary.status)
        .bind(record.summary.rate_limit_per_minute)
        .bind(record.quota_total)
        .bind(record.remaining_quota)
        .bind(record.expires_at)
        .bind(record.package_id.map(|id| id.to_string()))
        .bind(record.member_id.map(|id| id.to_string()))
        .bind(record.summary.last_used_at)
        .bind(record.summary.created_at)
        .execute(&pool)
        .await
        {
            if is_duplicate_key_error(&error) {
                return Err(AppError::new(
                    axum::http::StatusCode::CONFLICT,
                    "duplicate_key_prefix",
                    "Prefix kunci sudah dipakai; penerbitan diulang",
                ));
            }
            tracing::warn!(?error, prefix = %record.summary.prefix, "Gagal menyimpan kunci API baru ke database");
            return Err(AppError::internal("Kunci API tidak dapat disimpan"));
        }
        Ok(())
    }

    /// Start the ordered background quota writer (API binary only). The
    /// single consumer executes the same UPDATE the callers used to await
    /// inline, in the exact FIFO order the snapshots were produced under
    /// the data lock — so a reserve can never be overtaken by its refund —
    /// while the validation response no longer waits on MySQL.
    pub fn start_quota_writer(&self) {
        let Some(pool) = self.pool() else { return };
        let mut slot = self.quota_tx.write().expect("quota writer lock");
        if slot.is_some() {
            return;
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<QuotaWrite>(8192);
        let handle = tokio::spawn(async move {
            // recv() yields every buffered snapshot before returning None
            // once all senders drop, so shutdown drains the queue in order.
            // A failed write is RETRIED with backoff, never dropped
            // (audit 2026-10-25, B6): dropping it let the database overstate
            // the remaining quota after a restart (free hits).
            while let Some(write) = rx.recv().await {
                let mut delay = std::time::Duration::from_secs(1);
                loop {
                    match sqlx::query(
                        "UPDATE admin_api_keys SET quota_remaining = ?, last_used_at = ? WHERE prefix = ?",
                    )
                    .bind(write.remaining)
                    .bind(write.at)
                    .bind(&write.prefix)
                    .execute(&pool)
                    .await
                    {
                        Ok(result) => {
                            // Audit 2026-10-25, K34: a 0-row update means
                            // the key row is gone from the database (only
                            // reachable via manual DB intervention — the
                            // app never DELETEs key rows), so the snapshot
                            // is silently lost. Warn loudly; retrying
                            // would loop forever on a missing row, and the
                            // retry/backpressure behavior stays unchanged.
                            if result.rows_affected() == 0 {
                                tracing::warn!(prefix = %write.prefix, "Snapshot kuota tidak menemukan baris kunci di database (0 baris diubah); snapshot hilang");
                            }
                            break;
                        }
                        Err(error) => {
                            tracing::warn!(?error, prefix = %write.prefix, "Gagal menyimpan sisa kuota ke database (writer); percobaan ulang");
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(std::time::Duration::from_secs(30));
                        }
                    }
                }
            }
        });
        *slot = Some(tx);
        *self.quota_writer.lock().expect("quota writer handle lock") = Some(handle);
    }

    /// Close the quota writer channel and wait (bounded) for it to drain.
    pub async fn stop_quota_writer(&self) {
        let tx = self.quota_tx.write().expect("quota writer lock").take();
        drop(tx);
        let handle = self
            .quota_writer
            .lock()
            .expect("quota writer handle lock")
            .take();
        if let Some(handle) = handle {
            // Generous drain bound (systemd's default stop timeout is 90 s):
            // a 5 s bound could still strand queued snapshots on shutdown
            // (audit 2026-10-25, K8). SIGKILL mid-validation remains an
            // inherent window (reserve without refund/event) — it cannot be
            // closed from inside the process.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), handle).await;
        }
    }

    /// Persist a quota movement. With the background writer running this is
    /// a FIFO channel hand-off (microseconds); absolute snapshots make a
    /// rare dropped write self-healing on the next movement. Without a
    /// writer (worker binary, tests) the UPDATE runs inline as before.
    async fn persist_key_quota(&self, prefix: &str, remaining_quota: u64) {
        let tx = self.quota_tx.read().expect("quota writer lock").clone();
        if let Some(tx) = tx {
            let write = QuotaWrite {
                prefix: prefix.to_owned(),
                remaining: remaining_quota,
                at: Utc::now(),
            };
            match tx.try_send(write) {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TrySendError::Full(write)) => {
                    // Backpressure, NOT a direct write (audit 2026-10-25,
                    // B6): writing the newest snapshot directly and then
                    // letting the writer drain older ones over it regressed
                    // the database to a stale value. Waiting preserves FIFO
                    // order; callers already hold the data lock here, so a
                    // stalled database stalls (rather than corrupts) quota
                    // accounting.
                    if tx.send(write).await.is_ok() {
                        return;
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
        self.persist_key_quota_direct(prefix, remaining_quota, Utc::now())
            .await;
    }

    async fn persist_key_quota_direct(
        &self,
        prefix: &str,
        remaining_quota: u64,
        at: chrono::DateTime<Utc>,
    ) {
        let Some(pool) = self.pool() else { return };
        match sqlx::query(
            "UPDATE admin_api_keys SET quota_remaining = ?, last_used_at = ? WHERE prefix = ?",
        )
        .bind(remaining_quota)
        .bind(at)
        .bind(prefix)
        .execute(&pool)
        .await
        {
            Ok(result) => {
                // Same K34 warning as the background writer (see above).
                if result.rows_affected() == 0 {
                    tracing::warn!(prefix, "Snapshot kuota tidak menemukan baris kunci di database (0 baris diubah); snapshot hilang");
                }
            }
            Err(error) => {
                tracing::warn!(?error, prefix, "Gagal menyimpan sisa kuota ke database");
            }
        }
    }

    pub async fn dashboard_overview(
        &self,
        environment: String,
        demo_mode: bool,
    ) -> DashboardOverview {
        // Durable aggregates first: the in-memory counters die with the
        // process, so the summary page went blank after every restart even
        // though validation_requests holds the real history. MySQL is the
        // source of truth whenever it is connected; the in-memory values
        // remain only as the no-database fallback.
        let db_overview = match self.pool() {
            Some(pool) => self.overview_from_db(&pool).await,
            None => None,
        };
        let data = self.data.read().await;
        let (metrics, traffic, recent_activities) = if let Some(db) = db_overview {
            (db.metrics, db.traffic, db.activities)
        } else {
            let total_requests_today = data.stats.total;
            let successful = data.stats.successful;
            let success_rate = if total_requests_today > 0 {
                (successful as f64 / total_requests_today as f64 * 100.0) as f32
            } else {
                0.0
            };
            let average_latency_ms = if total_requests_today > 0 {
                data.stats.provider_latency_total_ms / total_requests_today
            } else {
                0
            };
            (
                DashboardMetrics {
                    total_requests_today,
                    request_change_percent: 0.0,
                    success_rate,
                    success_rate_change_percent: 0.0,
                    average_latency_ms,
                    average_latency_change_percent: 0.0,
                    // Tanpa database tidak ada sumber pendapatan: 0 di sini
                    // berarti "tidak diketahui", bukan "tidak ada penjualan".
                    estimated_revenue: 0,
                    revenue_change_percent: 0.0,
                },
                if total_requests_today > 0 {
                    vec![TrafficPoint {
                        label: "Sejak API dimulai".to_owned(),
                        requests: total_requests_today,
                        successful,
                    }]
                } else {
                    Vec::new()
                },
                data.activities.iter().take(8).cloned().collect(),
            )
        };

        DashboardOverview {
            generated_at: Utc::now(),
            environment,
            demo_mode,
            metrics,
            traffic,
            services: vec![
                ServiceStatus {
                    name: "api".to_owned(),
                    label: "API Gateway".to_owned(),
                    status: "operational".to_owned(),
                    latency_ms: None,
                    detail: "Semua rute menerima trafik normal".to_owned(),
                },
                ServiceStatus {
                    name: "redis".to_owned(),
                    label: "Redis / Rate Limit".to_owned(),
                    status: if demo_mode { "demo" } else { "unknown" }.to_owned(),
                    latency_ms: None,
                    detail: if demo_mode {
                        "Mode demo menggunakan limiter memori".to_owned()
                    } else {
                        "Token bucket dan idempotensi aktif; kesehatan tidak diprobe".to_owned()
                    },
                },
                ServiceStatus {
                    name: "provider".to_owned(),
                    label: "Provider Validasi".to_owned(),
                    status: if demo_mode { "demo" } else { "unknown" }.to_owned(),
                    latency_ms: None,
                    detail: if demo_mode {
                        "Respons simulasi aman untuk pengembangan".to_owned()
                    } else {
                        "Rute provider terkonfigurasi; kesehatan tidak diprobe".to_owned()
                    },
                },
                ServiceStatus {
                    name: "worker".to_owned(),
                    label: "Worker Ledger".to_owned(),
                    status: "unknown".to_owned(),
                    latency_ms: None,
                    detail: "Event penggunaan diproses asinkron; kesehatan worker tidak diprobe"
                        .to_owned(),
                },
            ],
            recent_activities,
            alerts: vec![
                DashboardAlert {
                    id: "provider-contract".to_owned(),
                    severity: "info".to_owned(),
                    title: "Konfigurasi provider perlu ditinjau".to_owned(),
                    detail:
                        "Pastikan SLA, batas hit, dan kredensial provider produksi telah disetujui."
                            .to_owned(),
                },
                DashboardAlert {
                    id: "pii-guard".to_owned(),
                    severity: "success".to_owned(),
                    title: "Penjagaan data sensitif aktif".to_owned(),
                    detail:
                        "Identifier rekening dan nomor telepon dimasking di aktivitas dashboard."
                            .to_owned(),
                },
            ],
        }
    }

    /// Aggregates for the dashboard overview from `validation_requests`
    /// (WIB calendar days). Returns None on any query problem so the caller
    /// falls back to the in-memory counters.
    async fn overview_from_db(&self, pool: &sqlx::MySqlPool) -> Option<DbOverview> {
        use chrono::Datelike;
        let wib = chrono::FixedOffset::east_opt(7 * 3600)?;
        let today_wib = Utc::now().with_timezone(&wib).date_naive();
        let yesterday_wib = today_wib - chrono::Duration::days(1);

        async fn day_stats(
            pool: &sqlx::MySqlPool,
            day: chrono::NaiveDate,
        ) -> Option<(i64, i64, f64)> {
            match sqlx::query_as::<_, (i64, i64, f64)>(
                "SELECT COUNT(*), CAST(COALESCE(SUM(outcome = 'valid'), 0) AS SIGNED), \
                 CAST(COALESCE(AVG(provider_latency_ms), 0) AS DOUBLE) \
                 FROM validation_requests \
                 WHERE DATE(CONVERT_TZ(occurred_at, '+00:00', '+07:00')) = ?",
            )
            .bind(day.format("%Y-%m-%d").to_string())
            .fetch_one(pool)
            .await
            {
                Ok(stats) => Some(stats),
                Err(error) => {
                    tracing::warn!(?error, "Statistik ringkasan dari database gagal");
                    None
                }
            }
        }
        let (today_total, today_valid, today_latency) = day_stats(pool, today_wib).await?;
        let (yday_total, yday_valid, yday_latency) = day_stats(pool, yesterday_wib).await?;
        let pct_change = |today: f64, yesterday: f64| -> f32 {
            if yesterday <= 0.0 {
                0.0
            } else {
                ((today - yesterday) / yesterday * 100.0) as f32
            }
        };
        let success_rate = |valid: i64, total: i64| -> f64 {
            if total > 0 {
                valid as f64 / total as f64 * 100.0
            } else {
                0.0
            }
        };
        // AREA 1: estimated_revenue nyata (sebelumnya hardcoded 0).
        // Total = SEMUA order lunas/ter-grant sepanjang masa; perubahan =
        // pendapatan hari WIB ini vs kemarin (tanggal paid_at, fallback
        // created_at untuk baris warisan). Status lain (menunggu bayar,
        // kedaluwarsa, dibatalkan, perlu tinjauan) TIDAK dihitung — lihat
        // definisi di analytics::REVENUE_STATUSES. Kegagalan query TIDAK
        // boleh menjatuhkan overview: kembali ke 0 dengan peringatan.
        async fn revenue_on_day(
            pool: &sqlx::MySqlPool,
            day: chrono::NaiveDate,
        ) -> i64 {
            match sqlx::query_scalar::<_, i64>(
                "SELECT CAST(COALESCE(SUM(amount_idr), 0) AS SIGNED) FROM package_orders \
                 WHERE status IN ('paid', 'granted') \
                 AND DATE(CONVERT_TZ(COALESCE(paid_at, created_at), '+00:00', '+07:00')) = ?",
            )
            .bind(day.format("%Y-%m-%d").to_string())
            .fetch_one(pool)
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(?error, "Pendapatan harian dashboard gagal dibaca");
                    0
                }
            }
        }
        let revenue_total: i64 = match sqlx::query_scalar::<_, i64>(
            "SELECT CAST(COALESCE(SUM(amount_idr), 0) AS SIGNED) FROM package_orders \
             WHERE status IN ('paid', 'granted')",
        )
        .fetch_one(pool)
        .await
        {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(?error, "Total pendapatan dashboard gagal dibaca");
                0
            }
        };
        let revenue_today = revenue_on_day(pool, today_wib).await;
        let revenue_yesterday = revenue_on_day(pool, yesterday_wib).await;
        let metrics = DashboardMetrics {
            total_requests_today: today_total.max(0) as u64,
            request_change_percent: pct_change(today_total as f64, yday_total as f64),
            success_rate: success_rate(today_valid, today_total) as f32,
            success_rate_change_percent: pct_change(
                success_rate(today_valid, today_total),
                success_rate(yday_valid, yday_total),
            ),
            average_latency_ms: today_latency.max(0.0) as u64,
            average_latency_change_percent: pct_change(today_latency, yday_latency),
            estimated_revenue: revenue_total.max(0) as u64,
            revenue_change_percent: pct_change(
                revenue_today as f64,
                revenue_yesterday as f64,
            ),
        };

        // Traffic: one point per WIB day for the last 14 days, zero-filled.
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT DATE_FORMAT(CONVERT_TZ(occurred_at, '+00:00', '+07:00'), '%Y-%m-%d') AS day, \
             COUNT(*), CAST(COALESCE(SUM(outcome = 'valid'), 0) AS SIGNED) FROM validation_requests \
             WHERE occurred_at >= UTC_TIMESTAMP() - INTERVAL 14 DAY \
             GROUP BY day ORDER BY day",
        )
        .fetch_all(pool)
        .await
        .ok()?;
        let by_day: std::collections::HashMap<String, (i64, i64)> = rows
            .into_iter()
            .map(|(day, total, valid)| (day, (total, valid)))
            .collect();
        const MONTH_ID: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des",
        ];
        let mut traffic = Vec::with_capacity(14);
        for offset in (0..14).rev() {
            let day = today_wib - chrono::Duration::days(offset);
            let (total, valid) = by_day
                .get(&day.format("%Y-%m-%d").to_string())
                .copied()
                .unwrap_or((0, 0));
            traffic.push(TrafficPoint {
                label: format!("{} {}", day.day(), MONTH_ID[(day.month() - 1) as usize]),
                requests: total.max(0) as u64,
                successful: valid.max(0) as u64,
            });
        }

        // Recent activities: the latest validations, newest first.
        let recent: Vec<(String, String, String, String, u64, chrono::NaiveDateTime)> =
            sqlx::query_as(
                "SELECT request_id, product_code, outcome, target_masked, provider_latency_ms, occurred_at \
                 FROM validation_requests ORDER BY occurred_at DESC LIMIT 8",
            )
            .fetch_all(pool)
            .await
            .ok()?;
        let outcome_label = |outcome: &str| -> &str {
            match outcome {
                "valid" => "Valid",
                "invalid" => "Tidak valid",
                "not_found" => "Tidak ditemukan",
                "provider_error" => "Error provider",
                "pending" => "Menunggu",
                "rate_limited" => "Kena rate limit",
                "quota_exhausted" => "Kuota habis",
                _ => "Diproses",
            }
        };
        let activities = recent
            .into_iter()
            .filter_map(
                |(
                    request_id,
                    product_code,
                    outcome,
                    target_masked,
                    provider_latency_ms,
                    occurred_at,
                )| {
                    let product = match product_code.as_str() {
                        "bank_account" => ValidationProduct::BankAccount,
                        "ewallet" => ValidationProduct::Ewallet,
                        "whatsapp" => ValidationProduct::Whatsapp,
                        _ => return None,
                    };
                    let title = match product {
                        ValidationProduct::BankAccount => "Validasi rekening bank",
                        ValidationProduct::Ewallet => "Validasi e-wallet",
                        ValidationProduct::Whatsapp => "Validasi WhatsApp",
                    };
                    Some(ActivityItem {
                        id: Uuid::parse_str(&request_id).unwrap_or_else(|_| Uuid::new_v4()),
                        title: title.to_owned(),
                        detail: format!("{target_masked} · {}", outcome_label(&outcome)),
                        product: Some(product),
                        status: outcome,
                        occurred_at: chrono::DateTime::from_naive_utc_and_offset(occurred_at, Utc),
                        provider_latency_ms: Some(provider_latency_ms),
                    })
                },
            )
            .collect();

        Some(DbOverview {
            metrics,
            traffic,
            activities,
        })
    }

    pub async fn list_products(&self) -> Vec<AdminProduct> {
        let data = self.data.read().await;
        let mut products = data.products.values().cloned().collect::<Vec<_>>();
        products.sort_by(|left, right| left.code.cmp(&right.code));
        products
    }

    pub async fn update_product(
        &self,
        id: Uuid,
        input: UpdateProductRequest,
    ) -> Result<AdminProduct, AppError> {
        let mut data = self.data.write().await;
        let product = data
            .products
            .get_mut(&id)
            .ok_or_else(|| AppError::not_found("Produk tidak ditemukan"))?;

        if let Some(name) = clean_required_text(input.name, "Nama produk")? {
            product.name = name;
        }
        if let Some(description) = clean_optional_text(input.description, "Deskripsi produk")? {
            product.description = description;
        }
        if let Some(active) = input.active {
            product.active = active;
        }
        if let Some(route) = clean_required_text(input.provider_route, "Rute provider")? {
            product.provider_route = route;
        }
        if let Some(price) = input.base_price_idr {
            if price == 0 {
                return Err(AppError::bad_request(
                    "Harga per hit harus lebih besar dari Rp0",
                ));
            }
            product.base_price_idr = price;
        }
        product.updated_at = Utc::now();

        Ok(product.clone())
    }

    pub async fn list_packages(&self) -> Vec<AdminPackage> {
        let data = self.data.read().await;
        let mut packages = data.packages.values().cloned().collect::<Vec<_>>();
        packages.sort_by(|left, right| left.price_idr.cmp(&right.price_idr));
        packages
    }

    pub async fn create_package(
        &self,
        input: CreatePackageRequest,
    ) -> Result<AdminPackage, AppError> {
        validate_package_input(
            &input.name,
            &input.slug,
            input.price_idr,
            input.included_hits,
            &input.products,
            input.rate_limit_per_minute,
        )?;
        validate_promo(input.promo_percent, input.promo_ends_at)?;

        let mut data = self.data.write().await;
        if data
            .packages
            .values()
            .any(|package| package.slug == input.slug)
        {
            return Err(AppError::conflict("Slug paket sudah digunakan"));
        }

        let now = Utc::now();
        let package = AdminPackage {
            id: Uuid::now_v7(),
            name: input.name.trim().to_owned(),
            slug: input.slug.trim().to_ascii_lowercase(),
            description: input.description.trim().to_owned(),
            price_idr: input.price_idr,
            included_hits: input.included_hits,
            active: input.active,
            highlighted: input.highlighted,
            products: input.products,
            rate_limit_per_minute: input.rate_limit_per_minute,
            promo_percent: input.promo_percent,
            promo_ends_at: if input.promo_percent == 0 {
                None
            } else {
                input.promo_ends_at
            },
            created_at: now,
            updated_at: now,
        };
        data.packages.insert(package.id, package.clone());
        drop(data);
        self.persist_package(&package).await;
        Ok(package)
    }

    pub async fn update_package(
        &self,
        id: Uuid,
        input: UpdatePackageRequest,
    ) -> Result<AdminPackage, AppError> {
        // Audit 2026-10-25, K22: validate on a CLONE first. The old code
        // mutated the live package and only then called validate_promo,
        // so a rejected update (e.g. promo percent without an end date)
        // still left memory diverged from the database until restart.
        // Every early return below now leaves the stored package
        // untouched; the clone is committed only after validation passes.
        let mut data = self.data.write().await;
        let stored = data
            .packages
            .get(&id)
            .ok_or_else(|| AppError::not_found("Paket tidak ditemukan"))?;
        let mut package = stored.clone();

        if let Some(name) = clean_required_text(input.name, "Nama paket")? {
            package.name = name;
        }
        if let Some(description) = clean_optional_text(input.description, "Deskripsi paket")? {
            package.description = description;
        }
        if let Some(price) = input.price_idr {
            if price == 0 {
                return Err(AppError::bad_request(
                    "Harga paket harus lebih besar dari Rp0",
                ));
            }
            package.price_idr = price;
        }
        if let Some(hits) = input.included_hits {
            if hits == 0 {
                return Err(AppError::bad_request(
                    "Jumlah hit paket harus lebih besar dari 0",
                ));
            }
            package.included_hits = hits;
        }
        if let Some(active) = input.active {
            package.active = active;
        }
        if let Some(highlighted) = input.highlighted {
            package.highlighted = highlighted;
        }
        if let Some(products) = input.products {
            if products.is_empty() {
                return Err(AppError::bad_request(
                    "Paket harus memiliki minimal satu produk",
                ));
            }
            package.products = products;
        }
        if let Some(rate_limit) = input.rate_limit_per_minute {
            if rate_limit == 0 {
                return Err(AppError::bad_request("Rate limit harus lebih besar dari 0"));
            }
            package.rate_limit_per_minute = rate_limit;
        }
        if let Some(ends) = input.promo_ends_at {
            package.promo_ends_at = ends;
        }
        if let Some(percent) = input.promo_percent {
            package.promo_percent = percent;
            if percent == 0 {
                package.promo_ends_at = None;
            }
        }
        validate_promo(package.promo_percent, package.promo_ends_at)?;
        package.updated_at = Utc::now();
        let saved = package.clone();
        data.packages.insert(id, package);
        drop(data);
        self.persist_package(&saved).await;
        Ok(saved)
    }

    pub async fn delete_package(&self, id: Uuid) -> Result<DeletedPackage, AppError> {
        // DB-FIRST (audit 2026-10-25, B13, same pattern as assign):
        // the database delete must succeed before memory changes, or a
        // failed delete would look successful and "resurrect" on restart.
        // K30, in the SAME transaction as the package DELETE: null out
        // `package_id` on every key that references this package, so no
        // key is left pointing at a package that no longer exists. Key
        // quotas are already materialized on the key rows and are NOT
        // touched — only provenance is detached.
        let name = {
            let data = self.data.read().await;
            data.packages
                .get(&id)
                .map(|package| package.name.clone())
                .ok_or_else(|| AppError::not_found("Paket tidak ditemukan"))?
        };
        let mut keys_detached = 0usize;
        if let Some(pool) = self.pool() {
            let mut tx = pool.begin().await.map_err(|error| {
                tracing::warn!(?error, package_id = %id, "Gagal memulai transaksi hapus paket");
                AppError::internal("Paket tidak dapat dihapus dari database")
            })?;
            let detached = sqlx::query(
                "UPDATE admin_api_keys SET package_id = NULL WHERE package_id = ?",
            )
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                tracing::warn!(?error, package_id = %id, "Gagal melepas paket dari kunci");
                AppError::internal("Paket tidak dapat dihapus dari database")
            })?;
            keys_detached = detached.rows_affected() as usize;
            Self::delete_package_row(&mut tx, id).await?;
            tx.commit().await.map_err(|error| {
                tracing::warn!(?error, package_id = %id, "Gagal commit hapus paket");
                AppError::internal("Paket tidak dapat dihapus dari database")
            })?;
        }
        {
            let mut data = self.data.write().await;
            data.packages.remove(&id);
            // Mirror the detach in memory (DB rows already updated above;
            // in memory-only mode this is the only detach that happens).
            // Count memory rows only when there was no database, so the
            // reported number always matches one source of truth.
            if self.pool().is_none() {
                for record in data.api_keys.values_mut() {
                    if record.package_id == Some(id) {
                        record.package_id = None;
                        record.summary.package_id = None;
                        keys_detached += 1;
                    }
                }
            } else {
                for record in data.api_keys.values_mut() {
                    if record.package_id == Some(id) {
                        record.package_id = None;
                        record.summary.package_id = None;
                    }
                }
            }
        }
        Ok(DeletedPackage { name, keys_detached })
    }

    pub async fn list_rate_limit_policies(&self) -> Vec<RateLimitPolicy> {
        let data = self.data.read().await;
        let mut policies = data.policies.values().cloned().collect::<Vec<_>>();
        policies.sort_by(|left, right| left.name.cmp(&right.name));
        policies
    }

    pub async fn create_rate_limit_policy(
        &self,
        input: CreateRateLimitPolicyRequest,
    ) -> Result<RateLimitPolicy, AppError> {
        validate_rate_limit_input(
            &input.name,
            &input.scope,
            &input.target,
            input.requests_per_minute,
            input.burst,
            input.concurrency_limit,
        )?;

        let policy = RateLimitPolicy {
            id: Uuid::now_v7(),
            name: input.name.trim().to_owned(),
            scope: input.scope.trim().to_ascii_lowercase(),
            target: input.target.trim().to_owned(),
            requests_per_minute: input.requests_per_minute,
            burst: input.burst,
            concurrency_limit: input.concurrency_limit,
            active: input.active,
            updated_at: Utc::now(),
        };
        self.data
            .write()
            .await
            .policies
            .insert(policy.id, policy.clone());
        self.persist_policy(&policy).await;
        Ok(policy)
    }

    pub async fn update_rate_limit_policy(
        &self,
        id: Uuid,
        input: UpdateRateLimitPolicyRequest,
    ) -> Result<RateLimitPolicy, AppError> {
        let mut data = self.data.write().await;
        let policy = data
            .policies
            .get_mut(&id)
            .ok_or_else(|| AppError::not_found("Kebijakan rate limit tidak ditemukan"))?;

        if let Some(name) = clean_required_text(input.name, "Nama kebijakan")? {
            policy.name = name;
        }
        if let Some(target) = clean_required_text(input.target, "Target kebijakan")? {
            policy.target = target;
        }
        if let Some(requests_per_minute) = input.requests_per_minute {
            if requests_per_minute == 0 {
                return Err(AppError::bad_request(
                    "Permintaan per menit harus lebih besar dari 0",
                ));
            }
            policy.requests_per_minute = requests_per_minute;
        }
        if let Some(burst) = input.burst {
            if burst == 0 {
                return Err(AppError::bad_request("Burst harus lebih besar dari 0"));
            }
            policy.burst = burst;
        }
        if let Some(concurrency_limit) = input.concurrency_limit {
            if concurrency_limit == 0 {
                return Err(AppError::bad_request(
                    "Batas konkurensi harus lebih besar dari 0",
                ));
            }
            policy.concurrency_limit = concurrency_limit;
        }
        if let Some(active) = input.active {
            policy.active = active;
        }
        policy.updated_at = Utc::now();
        let saved = policy.clone();
        drop(data);
        self.persist_policy(&saved).await;
        Ok(saved)
    }

    /// DB-first like `delete_package` (audit 2026-10-25, B13): the row
    /// delete must succeed before memory changes. Returns the removed
    /// policy so the handler can name it in the audit log.
    pub async fn delete_rate_limit_policy(&self, id: Uuid) -> Result<RateLimitPolicy, AppError> {
        let exists = {
            let data = self.data.read().await;
            data.policies.contains_key(&id)
        };
        if !exists {
            return Err(AppError::not_found("Kebijakan rate limit tidak ditemukan"));
        }
        self.delete_policy_row(id).await?;
        let mut data = self.data.write().await;
        data.policies
            .remove(&id)
            .ok_or_else(|| AppError::not_found("Kebijakan rate limit tidak ditemukan"))
    }

    pub async fn list_api_keys(&self) -> Vec<AdminApiKeySummary> {
        let data = self.data.read().await;
        let mut keys = data
            .api_keys
            .values()
            .map(|record| record.summary.clone())
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        keys
    }

    pub async fn create_api_key(
        &self,
        input: CreateApiKeyRequest,
    ) -> Result<CreatedApiKey, AppError> {
        let name = clean_required_text(Some(input.name), "Nama kunci")?
            .ok_or_else(|| AppError::bad_request("Nama kunci wajib diisi"))?;
        if input.scopes.is_empty() {
            return Err(AppError::bad_request(
                "Pilih minimal satu scope untuk kunci API",
            ));
        }
        if input.scopes.iter().any(|scope| !is_valid_scope(scope)) {
            return Err(AppError::bad_request(
                "Terdapat scope API yang tidak dikenal",
            ));
        }
        let rate_limit_per_minute = input
            .rate_limit_per_minute
            .unwrap_or_else(|| self.default_rate_limit_per_minute());
        if rate_limit_per_minute == 0 {
            return Err(AppError::bad_request("Rate limit harus lebih besar dari 0"));
        }
        self.issue_api_key(
            name,
            input.scopes,
            rate_limit_per_minute,
            10_000,
            None,
            None,
            None,
        )
        .await
    }

    /// Shared key issuance: generates the secret, stores only its salted
    /// hash, persists the record, and returns the plaintext exactly once.
    #[allow(clippy::too_many_arguments)]
    async fn issue_api_key(
        &self,
        name: String,
        scopes: Vec<String>,
        rate_limit_per_minute: u32,
        quota_total: u64,
        expires_at: Option<chrono::DateTime<Utc>>,
        package_id: Option<Uuid>,
        member_id: Option<Uuid>,
    ) -> Result<CreatedApiKey, AppError> {
        // Prefixes MUST come from a CSPRNG, never from a timestamp: the old
        // UUIDv7-derived prefix collided for keys issued within the same
        // 256 ms window, and the upsert below silently overwrote the older
        // key's hash, owner and quota (audit 2026-10-25, K1). Uniqueness is
        // checked-and-inserted atomically under one write lock, and the
        // database insert is a plain INSERT: a duplicate-key error means
        // another writer won the prefix, so issuance retries with a fresh
        // prefix instead of overwriting anything.
        let mut raw_random = [0_u8; 24];
        rand::thread_rng().fill_bytes(&mut raw_random);
        let secret = hex::encode(raw_random);
        let secret_hash = hash_secret(&secret)?;

        for _ in 0..3 {
            let issued = {
                let mut data = self.data.write().await;
                let mut issued = None;
                for _ in 0..32 {
                    let prefix = generate_key_prefix();
                    if data.api_keys.contains_key(&prefix) {
                        continue;
                    }
                    let now = Utc::now();
                    let plaintext_key = format!("{prefix}_{secret}");
                    // When a key-encryption secret is configured, also store
                    // the plaintext encrypted so the owner (portal) and
                    // admins (panel) can view the key again later.
                    // Verification never uses this copy.
                    let secret_ciphertext = self
                        .key_cipher()
                        .and_then(|cipher| cipher.encrypt(&plaintext_key).ok());
                    let summary = AdminApiKeySummary {
                        id: Uuid::now_v7(),
                        name: name.clone(),
                        prefix: prefix.clone(),
                        scopes: scopes.clone(),
                        status: "active".to_owned(),
                        last_used_at: None,
                        rate_limit_per_minute,
                        quota_total,
                        expires_at,
                        package_id,
                        member_id,
                        created_at: now,
                    };
                    let record = ApiKeyRecord {
                        summary: summary.clone(),
                        secret_hash: secret_hash.clone(),
                        secret_ciphertext,
                        remaining_quota: quota_total,
                        quota_total,
                        expires_at,
                        package_id,
                        member_id,
                    };
                    data.api_keys.insert(prefix, record.clone());
                    issued = Some((record, plaintext_key));
                    break;
                }
                issued
            };
            let Some((record, plaintext_key)) = issued else {
                return Err(AppError::internal("Gagal menerbitkan kunci API unik"));
            };
            match self.persist_new_key(&record).await {
                Ok(()) => {
                    return Ok(CreatedApiKey {
                        key: record.summary.clone(),
                        plaintext_key,
                        warning: if record.secret_ciphertext.is_some() {
                            "Simpan kunci ini di tempat aman. Kunci juga dapat dilihat kembali dari portal member dan panel admin."
                        } else {
                            "Simpan kunci ini sekarang. Untuk keamanan, nilai rahasianya tidak dapat ditampilkan kembali."
                        },
                    });
                }
                Err(error) if error.code == "duplicate_key_prefix" => {
                    // Another writer claimed this prefix in the database;
                    // drop the in-memory record and retry with a fresh one.
                    let mut data = self.data.write().await;
                    data.api_keys.remove(&record.summary.prefix);
                    continue;
                }
                Err(error) => {
                    // Fail closed: never leave an in-memory-only key behind.
                    let mut data = self.data.write().await;
                    data.api_keys.remove(&record.summary.prefix);
                    return Err(error);
                }
            }
        }
        Err(AppError::internal(
            "Gagal menerbitkan kunci API unik setelah beberapa percobaan",
        ))
    }

    /// Returns the revoked summary so the handler can name the key (and
    /// its owner) in the audit log (audit 2026-10-25, B12/K32).
    pub async fn revoke_api_key(&self, id: Uuid) -> Result<AdminApiKeySummary, AppError> {
        let record = {
            let mut data = self.data.write().await;
            let record = data
                .api_keys
                .values_mut()
                .find(|record| record.summary.id == id)
                .ok_or_else(|| AppError::not_found("Kunci API tidak ditemukan"))?;
            record.summary.status = "revoked".to_owned();
            record.clone()
        };
        self.persist_key(&record).await?;
        Ok(record.summary)
    }

    // ---- Member accounts (Google sign-in) ---------------------------------

    pub async fn member_by_google_sub(
        &self,
        google_sub: &str,
    ) -> Result<Option<crate::models::MemberAccount>, AppError> {
        let Some(pool) = self.pool() else {
            return Ok(None);
        };
        let row = sqlx::query_as::<_, MemberRow>(
            "SELECT id, google_sub, email, name, picture_url, plan_kind, status, created_at, last_login_at FROM members WHERE google_sub = ?",
        )
        .bind(google_sub)
        .fetch_optional(&pool)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "Gagal membaca member dari database");
            AppError::internal("Data member tidak dapat dibaca")
        })?;
        row.map(MemberRow::into_account).transpose()
    }

    pub async fn member_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<crate::models::MemberAccount>, AppError> {
        let Some(pool) = self.pool() else {
            return Ok(None);
        };
        let row = sqlx::query_as::<_, MemberRow>(
            "SELECT id, google_sub, email, name, picture_url, plan_kind, status, created_at, last_login_at FROM members WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&pool)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "Gagal membaca member dari database");
            AppError::internal("Data member tidak dapat dibaca")
        })?;
        row.map(MemberRow::into_account).transpose()
    }

    pub async fn create_member(
        &self,
        google_sub: &str,
        email: &str,
        name: Option<&str>,
        picture_url: Option<&str>,
    ) -> Result<crate::models::MemberAccount, AppError> {
        let pool = self
            .pool()
            .ok_or_else(|| AppError::internal("Database member tidak terhubung"))?;
        let now = Utc::now();
        let member = crate::models::MemberAccount {
            id: Uuid::now_v7(),
            google_sub: google_sub.to_owned(),
            email: email.to_owned(),
            name: name.map(str::to_owned),
            picture_url: picture_url.map(str::to_owned),
            plan_kind: "trial".to_owned(),
            status: "active".to_owned(),
            created_at: now,
            last_login_at: Some(now),
        };
        sqlx::query(
            "INSERT INTO members (id, google_sub, email, name, picture_url, plan_kind, status, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(member.id.to_string())
        .bind(&member.google_sub)
        .bind(&member.email)
        .bind(&member.name)
        .bind(&member.picture_url)
        .bind(&member.plan_kind)
        .bind(&member.status)
        .bind(member.created_at)
        .bind(member.last_login_at)
        .execute(&pool)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "Gagal membuat member baru");
            AppError::internal("Akun member tidak dapat dibuat")
        })?;
        Ok(member)
    }

    /// DELIBERATE warn-only (audit 2026-10-25, K35, kept as a conscious
    /// decision): last-login is display metadata, not money, and it is
    /// rewritten on every sign-in, so a missed write self-heals. Failing
    /// the login over it would be worse than a stale timestamp.
    pub async fn touch_member_login(&self, id: Uuid) {
        let Some(pool) = self.pool() else { return };
        if let Err(error) = sqlx::query("UPDATE members SET last_login_at = ? WHERE id = ?")
            .bind(Utc::now())
            .bind(id.to_string())
            .execute(&pool)
            .await
        {
            tracing::warn!(?error, member_id = %id, "Gagal mencatat login member");
        }
    }

    /// Refresh the member's profile from the identity provider on each
    /// successful sign-in. Name/picture are only overwritten when the
    /// provider supplies them; email always follows the provider account.
    /// DELIBERATE warn-only (K35, same reasoning as `touch_member_login`):
    /// profile metadata, idempotent, rewritten on the next sign-in.
    pub async fn update_member_profile(
        &self,
        id: Uuid,
        email: &str,
        name: Option<&str>,
        picture_url: Option<&str>,
    ) {
        let Some(pool) = self.pool() else { return };
        if let Err(error) = sqlx::query(
            "UPDATE members SET email = ?, name = COALESCE(?, name), picture_url = COALESCE(?, picture_url) WHERE id = ?",
        )
        .bind(email)
        .bind(name)
        .bind(picture_url)
        .bind(id.to_string())
        .execute(&pool)
        .await
        {
            tracing::warn!(?error, member_id = %id, "Gagal memperbarui profil member");
        }
    }

    /// DELIBERATE warn-only (K35): `plan_kind` is display-only — no
    /// gating logic reads it — so a missed write is cosmetic and is
    /// corrected by the next assign. Surfacing its error to handlers
    /// is the member-auth area's call (K16); this function keeps the
    /// warn-only contract so that area's change, if any, is the single
    /// owner of the new behavior.
    /// Display-only field (audit flow K16, verified: no gating logic
    /// anywhere reads `plan_kind` — it is only rendered in profiles and
    /// admin views). It used to fail warn-only; a failed update is now
    /// surfaced to the assign handler instead of diverging silently.
    /// Caveat for the caller: `assign_plan_to_member_key` persists the
    /// key row before this call, so a failure here means the key was
    /// already assigned while the display kind stayed stale — the
    /// handler reports the error, and an `add`-mode assign must NOT be
    /// blindly retried (it would add the quota a second time); the
    /// admin should check the member's quota first.
    pub async fn set_member_plan_kind(&self, id: Uuid, plan_kind: &str) -> Result<(), AppError> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        sqlx::query("UPDATE members SET plan_kind = ? WHERE id = ?")
            .bind(plan_kind)
            .bind(id.to_string())
            .execute(&pool)
            .await
            .map_err(|error| {
                tracing::warn!(?error, member_id = %id, "Gagal memperbarui jenis paket member");
                AppError::internal("Jenis paket member tidak dapat diperbarui")
            })?;
        Ok(())
    }

    /// Every prefix ever issued to a member (all statuses): history and
    /// usage stay visible across key regenerations (audit 2026-10-25, F15).
    pub async fn prefixes_for_member(&self, member_id: Uuid) -> Vec<String> {
        let data = self.data.read().await;
        data.api_keys
            .values()
            .filter(|record| record.member_id == Some(member_id))
            .map(|record| record.summary.prefix.clone())
            .collect()
    }

    /// Summary of the key identified by its prefix, if any. Used by the
    /// portal session resolver to enforce key status on prefix sessions.
    pub async fn key_summary_by_prefix(&self, prefix: &str) -> Option<AdminApiKeySummary> {
        let data = self.data.read().await;
        data.api_keys
            .get(prefix)
            .map(|record| record.summary.clone())
    }

    /// The member's current API key record (any status), from the runtime map.
    pub async fn member_key(&self, member_id: Uuid) -> Option<(AdminApiKeySummary, u64)> {
        let data = self.data.read().await;
        data.api_keys
            .values()
            .filter(|record| record.member_id == Some(member_id))
            .max_by_key(|record| {
                (
                    record.summary.status != "revoked",
                    record.summary.created_at,
                )
            })
            .map(|record| (record.summary.clone(), record.remaining_quota))
    }

    /// Semua kunci milik satu member (semua status, terbaru dulu).
    /// Dipakai halaman detail member: riwayat kunci tetap terlihat
    /// setelah regenerasi (pola yang sama dengan F15 untuk pemakaian).
    /// Yang dikembalikan hanya ringkasan + sisa kuota — TIDAK PERNAH
    /// hash, ciphertext, atau plaintext kunci apa pun.
    pub async fn list_member_keys(
        &self,
        member_id: Uuid,
    ) -> Vec<(AdminApiKeySummary, u64)> {
        let data = self.data.read().await;
        let mut keys: Vec<(AdminApiKeySummary, u64)> = data
            .api_keys
            .values()
            .filter(|record| record.member_id == Some(member_id))
            .map(|record| (record.summary.clone(), record.remaining_quota))
            .collect();
        keys.sort_by(|a, b| b.0.created_at.cmp(&a.0.created_at));
        keys
    }

    /// Pemakaian tertagih per hari WIB dari `usage_ledger` untuk semua
    /// prefix member (regenerasi tidak memutus riwayat). Rentang
    /// dibatasi 1–90 hari. Tanpa database (mode in-memory) ledger tidak
    /// ada, jadi hasilnya kosong — pemakaian in-memory bukan sumber
    /// kebenaran dan sengaja tidak dipakai di sini.
    pub async fn member_daily_usage_from_ledger(
        &self,
        member_id: Uuid,
        days: u32,
    ) -> Vec<MemberDailyUsage> {
        let days = days.clamp(1, 90);
        let Some(pool) = self.pool() else {
            return Vec::new();
        };
        let prefixes = self.prefixes_for_member(member_id).await;
        if prefixes.is_empty() {
            return Vec::new();
        }
        // `days` sudah di-clamp ke integer dari kode (bukan string user),
        // jadi interpolasi ke INTERVAL aman; prefix tetap di-bind.
        let mut builder = sqlx::QueryBuilder::new(
            "SELECT DATE_FORMAT(CONVERT_TZ(occurred_at, '+00:00', '+07:00'), '%Y-%m-%d') AS day, \
             CAST(COALESCE(SUM(quantity), 0) AS SIGNED) AS hits \
             FROM usage_ledger WHERE operation = 'charge' AND api_key_prefix IN (",
        );
        let mut separated = builder.separated(", ");
        for prefix in &prefixes {
            separated.push_bind(prefix);
        }
        separated.push_unseparated(")");
        builder.push(format!(
            " AND occurred_at >= UTC_TIMESTAMP() - INTERVAL {days} DAY \
             GROUP BY day ORDER BY day"
        ));
        let rows: Vec<(String, i64)> = builder
            .build_query_as()
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
        rows
            .into_iter()
            .map(|(date, charged_hits)| MemberDailyUsage { date, charged_hits })
            .collect()
    }

    /// Adjust kuota manual satu kunci milik satu member (Area 4).
    /// Penyesuaian HANYA relatif — lihat `compute_adjusted_quota` untuk
    /// aturan total. Penolakan: kunci bukan milik member / tidak ada
    /// (404), kunci bukan `active` (409), delta 0 / melebihi batas /
    /// sisa hasil negatif (400). Pemeriksaan status member
    /// (active/disabled) dilakukan handler sebelum memanggil ini,
    /// karena status member hidup di tabel `members` (bukan di map
    /// kunci); store di sini menegakkan kepemilikan + status kunci.
    ///
    /// Serialisasi: seluruh hitung + tulis database + mutasi memori
    /// berjalan di bawah satu write lock (pola yang sama dengan grant),
    /// jadi dua adjust bersamaan tidak bisa menghitung dari nilai basi
    /// yang sama. Update database memakai bentuk relatif
    /// (`quota_remaining = quota_remaining +/- delta`) dengan guard
    /// status + lantai sisa untuk delta negatif; 0 baris = kunci berubah
    /// di tengah jalan (konflik, tanpa perubahan). Setelah itu snapshot
    /// kuota baru diantrekan ke quota writer dengan urutan FIFO yang
    /// sama seperti grant/assign, sehingga snapshot basi tidak bisa
    /// menimpa hasil adjust di database.
    pub async fn adjust_member_key_quota(
        &self,
        member_id: Uuid,
        key_id: Uuid,
        delta: i64,
    ) -> Result<QuotaAdjustment, AppError> {
        if delta == 0 {
            return Err(AppError::bad_request("Delta kuota tidak boleh 0"));
        }
        if delta < -MAX_QUOTA_ADJUST_DELTA || delta > MAX_QUOTA_ADJUST_DELTA {
            return Err(AppError::bad_request(
                "Delta kuota melebihi batas 10.000.000 per penyesuaian",
            ));
        }
        let mut data = self.data.write().await;
        let record = data
            .api_keys
            .values_mut()
            .find(|record| record.summary.id == key_id && record.member_id == Some(member_id))
            .ok_or_else(|| AppError::not_found("Kunci tidak ditemukan untuk member ini"))?;
        if record.summary.status != "active" {
            return Err(AppError::conflict(
                "Kunci tidak aktif; adjust hanya untuk kunci active",
            ));
        }
        let (new_total, new_remaining) =
            compute_adjusted_quota(record.quota_total, record.remaining_quota, delta)?;
        let quota_total_before = record.quota_total;
        let quota_remaining_before = record.remaining_quota;
        let prefix = record.summary.prefix.clone();
        if let Some(pool) = self.pool() {
            let updated = if delta > 0 {
                sqlx::query(
                    "UPDATE admin_api_keys SET quota_remaining = quota_remaining + ?, \
                     quota_total = ? WHERE id = ? AND member_id = ? AND status = 'active'",
                )
                .bind(delta as u64)
                .bind(new_total)
                .bind(key_id.to_string())
                .bind(member_id.to_string())
                .execute(&pool)
                .await
            } else {
                // Bentuk pengurangan eksplisit, bukan penjumlahan bilangan
                // negatif: kolomnya UNSIGNED, jadi `+ (-delta)` bisa
                // dibaca MySQL sebagai aritmetika unsigned dan meluber.
                // Guard `quota_remaining >= |delta|` membuat hasil
                // negatif mustahil di sisi database juga.
                sqlx::query(
                    "UPDATE admin_api_keys SET quota_remaining = quota_remaining - ?, \
                     quota_total = ? WHERE id = ? AND member_id = ? AND status = 'active' \
                     AND quota_remaining >= ?",
                )
                .bind(delta.unsigned_abs())
                .bind(new_total)
                .bind(key_id.to_string())
                .bind(member_id.to_string())
                .bind(delta.unsigned_abs())
                .execute(&pool)
                .await
            };
            let updated = updated.map_err(|error| {
                tracing::warn!(?error, prefix = %prefix, "Gagal menulis adjust kuota ke database");
                AppError::internal("Adjust kuota tidak dapat disimpan")
            })?;
            if updated.rows_affected() == 0 {
                return Err(AppError::conflict(
                    "Kunci berubah selama adjust; muat ulang dan coba lagi",
                ));
            }
        }
        record.quota_total = new_total;
        record.remaining_quota = new_remaining;
        record.summary.quota_total = new_total;
        self.persist_key_quota(&prefix, new_remaining).await;
        Ok(QuotaAdjustment {
            key_id,
            prefix,
            delta,
            quota_total_before,
            quota_total_after: new_total,
            quota_remaining_before,
            quota_remaining_after: new_remaining,
        })
    }

    /// Issue the member's API key (trial or plan), linked to their account.
    pub async fn create_member_api_key(
        &self,
        member: &crate::models::MemberAccount,
        quota_total: u64,
        expires_at: Option<chrono::DateTime<Utc>>,
        rate_limit_per_minute: u32,
    ) -> Result<CreatedApiKey, AppError> {
        self.issue_api_key(
            format!("Kunci member {}", member.email),
            vec!["validate:*".to_owned()],
            rate_limit_per_minute,
            quota_total,
            expires_at,
            None,
            Some(member.id),
        )
        .await
    }

    pub async fn list_members(&self) -> Vec<crate::models::MemberAccount> {
        let Some(pool) = self.pool() else {
            return Vec::new();
        };
        let rows = sqlx::query_as::<_, MemberRow>(
            "SELECT id, google_sub, email, name, picture_url, plan_kind, status, created_at, last_login_at FROM members ORDER BY created_at DESC",
        )
        .fetch_all(&pool)
        .await;
        match rows {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|row| row.into_account().ok())
                .collect(),
            Err(error) => {
                tracing::warn!(?error, "Gagal memuat daftar member");
                Vec::new()
            }
        }
    }

    /// Apply a package (or manual plan) to the member's key.
    /// mode "replace": quota and validity restart from the plan's values.
    /// mode "add": quota is added; validity extends from the later of now
    /// and the current expiry. Rate limit follows the plan when provided
    /// (package value or manual override); None keeps the current limit.
    ///
    /// CATATAN (audit 2026-10-25, K1 — sengaja TIDAK diselaraskan ke
    /// `active` seperti grant): assign adalah aksi admin EKSPLISIT,
    /// bukan jalur otomatis penagihan — admin boleh menyiapkan paket
    /// di kunci disabled sebelum mengaktifkan member lagi, dan K16
    /// (assign ke member disabled) masih menunggu keputusan
    /// tolak-vs-peringatan. Mengubah assign di sini akan mengubah
    /// perilaku admin tanpa keputusan itu, jadi pola revoked-only di
    /// fungsi ini dipertahankan dengan sadar.
    pub async fn assign_plan_to_member_key(
        &self,
        member_id: Uuid,
        quota_hits: u64,
        valid_days: i64,
        mode: &str,
        rate_limit_per_minute: Option<u32>,
        package_id: Option<Uuid>,
        plan_kind: &str,
    ) -> Result<(AdminApiKeySummary, u64), AppError> {
        // Compute the new record without mutating yet.
        let mut record = {
            let data = self.data.read().await;
            let record = data
                .api_keys
                .values()
                .filter(|record| record.member_id == Some(member_id))
                .max_by_key(|record| {
                    (
                        record.summary.status != "revoked",
                        record.summary.created_at,
                    )
                })
                .ok_or_else(|| AppError::not_found("Member belum memiliki kunci API"))?;
            if record.summary.status == "revoked" {
                return Err(AppError::conflict(
                    "Kunci member sudah dicabut; regenerasi kunci terlebih dahulu",
                ));
            }
            record.clone()
        };
        let now = Utc::now();
        match mode {
            "replace" => {
                record.quota_total = quota_hits;
                record.remaining_quota = quota_hits;
                record.expires_at = Some(now + chrono::Duration::days(valid_days));
            }
            "add" => {
                record.quota_total = record.quota_total.saturating_add(quota_hits);
                record.remaining_quota = record.remaining_quota.saturating_add(quota_hits);
                let base = record
                    .expires_at
                    .filter(|expiry| *expiry > now)
                    .unwrap_or(now);
                record.expires_at = Some(base + chrono::Duration::days(valid_days));
            }
            _ => return Err(AppError::bad_request("Mode paket tidak dikenal")),
        }
        if let Some(rate) = rate_limit_per_minute {
            record.summary.rate_limit_per_minute = rate;
        }
        record.package_id = package_id;
        record.summary.package_id = package_id;
        record.summary.quota_total = record.quota_total;
        record.summary.expires_at = record.expires_at;
        // Database FIRST (audit 2026-10-25, B5): a failed persist now fails
        // the assign instead of diverging silently, and a crash between the
        // database write and the memory update reloads the assigned values
        // on startup. Only then apply the mutation and enqueue the quota
        // snapshot under the same lock, so the writer applies snapshots in
        // true order (an older queued snapshot can no longer land after
        // the assign and erase it from the database).
        self.persist_key(&record).await?;
        {
            let mut data = self.data.write().await;
            let Some(stored) = data.api_keys.get_mut(&record.summary.prefix) else {
                // The key vanished from memory mid-assign (concurrent admin
                // delete): the database already holds the assign, so a
                // restart reconciles; report the conflict loudly instead of
                // pretending the in-memory state matches.
                return Err(AppError::conflict(
                    "Kunci member berubah selama assign; muat ulang dan coba lagi",
                ));
            };
            *stored = record.clone();
            self.persist_key_quota(&record.summary.prefix, record.remaining_quota)
                .await;
        }
        self.set_member_plan_kind(member_id, plan_kind).await?;
        Ok((record.summary, record.remaining_quota))
    }

    /// Hasil grant pembelian paket yang sudah dibayar (atomik).
    pub async fn grant_package_order(
        &self,
        order_id: Uuid,
        member_id: Uuid,
        quota_hits: u64,
        valid_days: i64,
        package_rate: u32,
        package_id: Uuid,
    ) -> Result<GrantOutcome, AppError> {
        let Some(pool) = self.pool() else {
            return Err(AppError::internal(
                "Database tidak tersedia untuk grant paket",
            ));
        };
        // K1: grant memeriksa status member DI DALAM fungsi ini (bukan
        // hanya di pemanggil). Member non-aktif tidak boleh menerima
        // kuota dari jalur otomatis mana pun; pemulihan dilakukan admin
        // setelah member diaktifkan lagi. Cek ini dilakukan SEBELUM
        // pembuatan kunci, agar member non-aktif tidak dibuatkan kunci
        // kosong oleh cabang di bawah.
        let member = self
            .member_by_id(member_id)
            .await?
            .ok_or_else(|| AppError::not_found("Member tidak ditemukan"))?;
        if member.status != "active" {
            return Err(AppError::conflict(
                "Member tidak aktif; grant ditahan untuk admin",
            ));
        }
        // Kunci target: yang terbaru milik member; bila belum ada,
        // terbitkan kunci kosong di sini (grant yang gagal tidak
        // meninggalkan kuota apa pun).
        if self.member_key(member_id).await.is_none() {
            let created = self
                .create_member_api_key(&member, 0, None, package_rate)
                .await?;
            // Nilai plaintext tidak pernah dipakai grant dan tidak boleh
            // tercatat di log mana pun.
            drop(created.plaintext_key);
        }
        let mut data = self.data.write().await;
        let record = data
            .api_keys
            .values_mut()
            .filter(|record| record.member_id == Some(member_id))
            .max_by_key(|record| {
                (
                    record.summary.status != "revoked",
                    record.summary.created_at,
                )
            })
            .ok_or_else(|| AppError::not_found("Member belum memiliki kunci API"))?;
        // K1: CAS grant kini mensyaratkan kunci `active` persis, bukan
        // sekadar "bukan revoked". Kunci `disabled` (member dinonaktifkan
        // lewat set_member_status transaksional) kini benar-benar
        // menahan grant; kunci kedaluwarsa tetap berstatus `active`
        // dengan expires_at lewat (kedaluwarsa adalah timestamp, bukan
        // status — tidak ada kode yang mengubah status menjadi
        // "expired"), jadi perpanjangan lewat pembelian tidak pecah.
        if record.summary.status != "active" {
            return Err(AppError::conflict(
                "Kunci member tidak aktif; grant ditahan untuk admin",
            ));
        }
        let key_id = record.summary.id;
        let key_prefix = record.summary.prefix.clone();
        let effect = crate::models::compute_grant_effect(
            record.quota_total,
            record.remaining_quota,
            record.expires_at,
            Utc::now(),
            quota_hits,
            valid_days,
            record.summary.rate_limit_per_minute,
            package_rate,
        );
        // Transaksi atomik: baris kunci + baris order + plan_kind berubah
        // bersamaan, dengan CAS o.status = 'paid'. Hanya satu grant yang
        // menang; grant lain untuk order yang sama melihat AlreadyGranted.
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| AppError::internal("Transaksi grant paket tidak dapat dimulai"))?;
        let updated = sqlx::query(
            "UPDATE admin_api_keys k JOIN package_orders o ON o.id = ? \
             SET k.quota_total = ?, k.quota_remaining = ?, k.expires_at = ?, \
                 k.rate_limit_per_minute = ?, k.package_id = ?, \
                 o.status = 'granted', o.granted_at = UTC_TIMESTAMP(6), \
                 o.granted_quota = ?, o.granted_expires_at = ?, o.key_id = ? \
             WHERE k.id = ? AND o.member_id = ? AND o.status = 'paid' \
                 AND k.status = 'active'",
        )
        .bind(order_id.to_string())
        .bind(effect.new_total)
        .bind(effect.new_remaining)
        .bind(effect.new_expires_at)
        .bind(effect.new_rate_limit_per_minute)
        .bind(package_id.to_string())
        .bind(effect.new_remaining)
        .bind(effect.new_expires_at)
        .bind(key_id.to_string())
        .bind(key_id.to_string())
        .bind(member_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::internal("Grant paket gagal ditulis"))?;
        // PERHATIAN: UPDATE multi-tabel MySQL melaporkan ROW_COUNT
        // sebagai JUMLAH baris yang berubah di SEMUA tabel — grant normal
        // mengubah 1 baris kunci + 1 baris order = 2, bukan 1. Pengecekan
        // lama `!= 1` membatalkan setiap grant normal (rollback lalu
        // konflik) sehingga grant QRIS tidak pernah berhasil di produksi
        // (terbukti live 2026-10-25 dengan tabel sementara: ROW_COUNT=2).
        // Yang menandakan gagal hanya 0 baris (WHERE tidak cocok).
        if updated.rows_affected() == 0 {
            tx.rollback().await.ok();
            // 0 baris = order sudah tidak berstatus paid. Bedakan grant
            // ganda dari kunci yang dicabut di tengah jalan.
            let status: Option<String> =
                sqlx::query_scalar("SELECT status FROM package_orders WHERE id = ?")
                    .bind(order_id.to_string())
                    .fetch_optional(&pool)
                    .await
                    .map_err(|_| AppError::internal("Status order tidak dapat dibaca"))?;
            return match status.as_deref() {
                Some("granted") => Ok(GrantOutcome::AlreadyGranted),
                _ => Err(AppError::conflict(
                    "Grant ditahan: kunci/member tidak aktif atau status order berubah",
                )),
            };
        }
        sqlx::query("UPDATE members SET plan_kind = 'package' WHERE id = ?")
            .bind(member_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| AppError::internal("Plan member gagal diperbarui"))?;
        tx.commit()
            .await
            .map_err(|_| AppError::internal("Transaksi grant paket gagal dikomit"))?;
        // Perbarui memori dari nilai yang baru dikomit, lalu kirim
        // snapshot kuota lewat channel — semuanya di bawah data lock,
        // sesuai invarian reserve_quota (snapshot basi tidak boleh
        // menimpa grant).
        record.quota_total = effect.new_total;
        record.remaining_quota = effect.new_remaining;
        record.expires_at = Some(effect.new_expires_at);
        record.package_id = Some(package_id);
        record.summary.quota_total = effect.new_total;
        record.summary.expires_at = Some(effect.new_expires_at);
        record.summary.rate_limit_per_minute = effect.new_rate_limit_per_minute;
        record.summary.package_id = Some(package_id);
        self.persist_key_quota(&key_prefix, effect.new_remaining)
            .await;
        drop(data);
        Ok(GrantOutcome::Granted {
            new_total: effect.new_total,
            new_remaining: effect.new_remaining,
            new_rate_limit_per_minute: effect.new_rate_limit_per_minute,
        })
    }

    pub async fn set_member_key_rate_limit(
        &self,
        member_id: Uuid,
        rate_limit_per_minute: u32,
    ) -> Result<AdminApiKeySummary, AppError> {
        let record = {
            let mut data = self.data.write().await;
            let record = data
                .api_keys
                .values_mut()
                .filter(|record| record.member_id == Some(member_id))
                .max_by_key(|record| {
                    (
                        record.summary.status != "revoked",
                        record.summary.created_at,
                    )
                })
                .ok_or_else(|| AppError::not_found("Member belum memiliki kunci API"))?;
            record.summary.rate_limit_per_minute = rate_limit_per_minute;
            record.clone()
        };
        self.persist_key(&record).await?;
        Ok(record.summary)
    }

    /// Enable/disable a member account and ALL of its keys together, in a
    /// single transaction (audit 2026-10-25, K12). The old code touched
    /// only the newest non-revoked key and persisted it warn-only, so a
    /// restart could silently revive a disabled account (and a member with
    /// several active keys was only partly disabled).
    pub async fn set_member_status(&self, member_id: Uuid, active: bool) -> Result<(), AppError> {
        if let Some(pool) = self.pool() {
            let mut tx = pool.begin().await.map_err(|error| {
                tracing::warn!(?error, "Gagal memulai transaksi status member");
                AppError::internal("Status member tidak dapat diubah")
            })?;
            // Audit 2026-10-25, K35: a 0-row members UPDATE means the
            // member does not exist — report 404 instead of success.
            // (An already-correct status still updates 1 row in MySQL
            // without CLIENT_FOUND_ROWS, so idempotent re-sets still
            // succeed; only a missing member yields 0 rows.) Roll back
            // so the key-status update below never runs for a ghost.
            let updated = sqlx::query("UPDATE members SET status = ? WHERE id = ?")
                .bind(if active { "active" } else { "disabled" })
                .bind(member_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|error| {
                    tracing::warn!(?error, "Gagal mengubah status member");
                    AppError::internal("Status member tidak dapat diubah")
                })?;
            if updated.rows_affected() == 0 {
                tx.rollback().await.ok();
                return Err(AppError::not_found("Member tidak ditemukan"));
            }
            sqlx::query(
                "UPDATE admin_api_keys SET status = ? WHERE member_id = ? AND status != 'revoked'",
            )
            .bind(if active { "active" } else { "disabled" })
            .bind(member_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                tracing::warn!(?error, "Gagal mengubah status kunci member");
                AppError::internal("Status kunci member tidak dapat diubah")
            })?;
            tx.commit().await.map_err(|error| {
                tracing::warn!(?error, "Gagal commit status member");
                AppError::internal("Status member tidak dapat diubah")
            })?;
        }
        let mut data = self.data.write().await;
        for record in data
            .api_keys
            .values_mut()
            .filter(|record| record.member_id == Some(member_id))
        {
            if record.summary.status != "revoked" {
                record.summary.status = if active { "active" } else { "disabled" }.to_owned();
            }
        }
        Ok(())
    }

    /// Revoke the member's current key and issue a replacement carrying the
    /// same quota, expiry, rate limit, and package link.
    ///
    /// Serialized per member (audit flow B4): the guard is held for the
    /// ENTIRE function — the old code revoked under a momentary lock,
    /// then released it while persisting + issuing, so two concurrent
    /// regenerations could both capture the same old key and each mint
    /// a live replacement from the same balance (two active keys, ~2x
    /// quota, only the newest visible anywhere). Sequential runs are
    /// safe by construction: the second run's "old" key is the first
    /// run's replacement, carrying the same (not doubled) balance.
    pub async fn regenerate_member_key(
        &self,
        member: &crate::models::MemberAccount,
    ) -> Result<CreatedApiKey, AppError> {
        let _key_lock = self.member_key_lock(member.id);
        let _provision_guard = _key_lock.lock().await;
        // Capture the pre-revoke status: a disabled member's replacement key
        // must stay disabled (issuance always creates active keys, which
        // would otherwise silently reactivate a suspended account).
        let mut previous_status = String::new();
        let old = {
            let mut data = self.data.write().await;
            data.api_keys
                .values_mut()
                .filter(|record| record.member_id == Some(member.id))
                .max_by_key(|record| {
                    (
                        record.summary.status != "revoked",
                        record.summary.created_at,
                    )
                })
                .map(|record| {
                    previous_status = record.summary.status.clone();
                    record.summary.status = "revoked".to_owned();
                    record.clone()
                })
        };
        let Some(old) = old else {
            return Err(AppError::not_found("Member belum memiliki kunci API"));
        };
        self.persist_key(&old).await?;
        let mut created = self
            .issue_api_key(
                old.summary.name.clone(),
                old.summary.scopes.clone(),
                old.summary.rate_limit_per_minute,
                old.quota_total,
                old.expires_at,
                old.package_id,
                Some(member.id),
            )
            .await?;
        // Preserve the remaining balance (issue_api_key starts full) and
        // the previous status (a disabled key's replacement stays disabled).
        let adjusted = {
            let mut data = self.data.write().await;
            match data.api_keys.get_mut(&created.key.prefix) {
                Some(record) => {
                    record.remaining_quota = old.remaining_quota.min(record.quota_total);
                    if previous_status == "disabled" {
                        record.summary.status = "disabled".to_owned();
                    }
                    Some(record.clone())
                }
                None => None,
            }
        };
        if let Some(record) = adjusted {
            // A failed adjust persist must fail the whole regeneration: a
            // disabled member's replacement key must never stay active in
            // the database (it would reactivate the account on restart).
            self.persist_key(&record).await?;
            // The response must reflect the adjusted record (preserved
            // status/balance), not the just-issued snapshot.
            created.key = record.summary;
        }
        Ok(created)
    }

    pub async fn trial_grant_exists(&self, google_sub: &str) -> bool {
        let Some(pool) = self.pool() else {
            return false;
        };
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM trial_grants WHERE google_sub = ?")
            .bind(google_sub)
            .fetch_one(&pool)
            .await
            .map(|count| count > 0)
            .unwrap_or(false)
    }
}

/// Outcome of a trial-grant claim (audit flow K15). The old boolean
/// conflated "another sign-in won the trial" with "the database is
/// unreachable", and the caller revoked the trial key in both cases —
/// so a transient error permanently destroyed a trial that had already
/// been issued. Only `AlreadyClaimed` may revoke the loser's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialGrantOutcome {
    /// This call inserted the row: the trial belongs to this sign-in.
    Claimed,
    /// Another sign-in already claimed the trial (duplicate PK).
    AlreadyClaimed,
    /// The claim could not be decided (no pool, or a non-duplicate
    /// database error). The caller must KEEP the key it just issued:
    /// the next login sees that active key and provisions nothing, so
    /// no second trial is ever granted for the account.
    TransientError,
}

/// True when a sqlx error is a duplicate-key violation: MySQL reports
/// it as error 1062 under SQLSTATE 23000, and different sqlx paths
/// expose either number, so check both plus the message fallback.
/// (Merged from two identical helpers added by parallel fix areas.)
pub(crate) fn is_duplicate_key_error(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(db_error) => {
            db_error.code().is_some_and(|code| {
                code.as_ref() == "23000" || code.as_ref() == "1062"
            }) || db_error.message().contains("Duplicate entry")
        }
        _ => false,
    }
}

impl AdminStore {
    /// Record a trial grant. The table's primary key (google_sub) makes
    /// the insert an atomic claim: under concurrent first sign-ins
    /// exactly one caller wins, and the loser must revoke the trial key
    /// it just issued — but only on `AlreadyClaimed`.
    pub async fn record_trial_grant(
        &self,
        member: &crate::models::MemberAccount,
        quota_hits: u64,
        expires_at: chrono::DateTime<Utc>,
    ) -> TrialGrantOutcome {
        let Some(pool) = self.pool() else {
            return TrialGrantOutcome::TransientError;
        };
        match sqlx::query(
            "INSERT INTO trial_grants (google_sub, member_id, email, quota_hits, granted_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&member.google_sub)
        .bind(member.id.to_string())
        .bind(&member.email)
        .bind(quota_hits)
        .bind(Utc::now())
        .bind(expires_at)
        .execute(&pool)
        .await
        {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    TrialGrantOutcome::Claimed
                } else {
                    TrialGrantOutcome::AlreadyClaimed
                }
            }
            Err(error) => {
                if is_duplicate_key_error(&error) {
                    tracing::warn!(?error, member_id = %member.id, "Klaim trial kalah balapan pendaftaran");
                    TrialGrantOutcome::AlreadyClaimed
                } else {
                    tracing::warn!(?error, member_id = %member.id, "Klaim trial gagal (error transient — kunci dipertahankan)");
                    TrialGrantOutcome::TransientError
                }
            }
        }
    }

    /// Build the request context for a key the caller has ALREADY
    /// authenticated by other means (the member portal session). Applies the
    /// same status/expiry checks as secret authentication, minus the secret.
    pub async fn api_key_context_by_prefix(&self, prefix: &str) -> Result<ApiKeyContext, AppError> {
        let record = {
            let data = self.data.read().await;
            data.api_keys
                .get(prefix)
                .cloned()
                .ok_or_else(|| AppError::unauthorized("API key tidak dikenali"))?
        };
        if record.summary.status != "active" {
            return Err(AppError::forbidden(
                "API key telah dinonaktifkan atau dicabut",
            ));
        }
        if let Some(expires_at) = record.expires_at {
            if expires_at <= Utc::now() {
                return Err(AppError::forbidden(
                    "Masa aktif API key telah berakhir. Silakan perpanjang paket Anda.",
                ));
            }
        }
        Ok(ApiKeyContext {
            key_id: record.summary.id,
            prefix: record.summary.prefix,
            owner_id: record.member_id,
            organization_id: None,
            scopes: record.summary.scopes,
            remaining_quota: record.remaining_quota,
            rate_limit_per_minute: record.summary.rate_limit_per_minute,
        })
    }

    pub async fn authenticate_api_key(&self, raw_key: &str) -> Result<ApiKeyContext, AppError> {
        let (prefix, secret) = split_api_key(raw_key)
            .ok_or_else(|| AppError::unauthorized("Format API key tidak valid"))?;

        let record = {
            let data = self.data.read().await;
            data.api_keys
                .get(&prefix)
                .cloned()
                .ok_or_else(|| AppError::unauthorized("API key tidak dikenali"))?
        };

        if record.summary.status != "active" {
            return Err(AppError::forbidden(
                "API key telah dinonaktifkan atau dicabut",
            ));
        }

        if let Some(expires_at) = record.expires_at {
            if expires_at <= Utc::now() {
                return Err(AppError::forbidden(
                    "Masa aktif API key telah berakhir. Silakan perpanjang paket Anda.",
                ));
            }
        }

        if !verify_secret(&secret, &record.secret_hash) {
            return Err(AppError::unauthorized("API key tidak valid"));
        }

        Ok(ApiKeyContext {
            key_id: record.summary.id,
            prefix: record.summary.prefix,
            owner_id: record.member_id,
            organization_id: None,
            scopes: record.summary.scopes,
            remaining_quota: record.remaining_quota,
            rate_limit_per_minute: record.summary.rate_limit_per_minute,
        })
    }

    /// Account view for the member portal: the key's public summary plus its
    /// current remaining quota, addressed by prefix (the map key).
    pub async fn api_key_account(&self, prefix: &str) -> Option<(AdminApiKeySummary, u64)> {
        let data = self.data.read().await;
        data.api_keys
            .get(prefix)
            .map(|record| (record.summary.clone(), record.remaining_quota))
    }

    pub async fn reserve_quota(&self, prefix: &str) -> Result<u64, AppError> {
        let mut data = self.data.write().await;
        let record = data
            .api_keys
            .get_mut(prefix)
            .ok_or_else(|| AppError::unauthorized("API key tidak dikenali"))?;
        if record.remaining_quota == 0 {
            return Err(AppError::new(
                axum::http::StatusCode::PAYMENT_REQUIRED,
                "quota_exhausted",
                "Kuota API sudah habis. Silakan lakukan top up atau ubah paket.",
            ));
        }
        record.remaining_quota -= 1;
        record.summary.last_used_at = Some(Utc::now());
        let remaining = record.remaining_quota;
        // Ordering invariant (learned live: 8 concurrent validations once
        // persisted only 7 decrements): snapshots must reach MySQL in the
        // order memory mutated. The mutation and the writer-channel send
        // both happen under this lock, and the single writer consumes FIFO —
        // the same guarantee without holding the lock across MySQL I/O.
        self.persist_key_quota(prefix, remaining).await;
        drop(data);
        Ok(remaining)
    }

    /// Live remaining quota for a prefix, if the key is known in memory.
    pub async fn quota_remaining(&self, prefix: &str) -> Option<u64> {
        let data = self.data.read().await;
        data.api_keys
            .get(prefix)
            .map(|record| record.remaining_quota)
    }

    pub async fn refund_quota(&self, prefix: &str) {
        let mut data = self.data.write().await;
        let remaining = match data.api_keys.get_mut(prefix) {
            Some(record) => {
                // Capped at the quota total (audit 2026-10-25, K1): an
                // uncapped refund could mint a free hit when a grant landed
                // between the reserve and the refund.
                record.remaining_quota =
                    record.remaining_quota.saturating_add(1).min(record.quota_total);
                Some(record.remaining_quota)
            }
            None => None,
        };
        if let Some(remaining) = remaining {
            // Same ordering rule as reserve_quota: the send happens under
            // the lock so a refund can never overtake its reserve.
            self.persist_key_quota(prefix, remaining).await;
        }
    }

    /// Claim one slot from the daily invalid free pool for (prefix, WIB
    /// day). Returns true when this result is FREE (slot consumed), false
    /// when the pool is exhausted (caller charges normally) or the claim
    /// itself failed. Failure is fail-closed toward charging: the member
    /// is never over-credited by a database error.
    ///
    /// Race safety: with a pool, the row is created idempotently and the
    /// increment is a single conditional UPDATE (`free_used < limit`), so
    /// concurrent claims at the boundary serialize on the InnoDB row lock
    /// and exactly one wins. Without a pool, the fallback map is mutated
    /// under a mutex with no await inside the critical section.
    pub async fn claim_invalid_free_slot(
        &self,
        prefix: &str,
        wib_day: chrono::NaiveDate,
    ) -> bool {
        if let Some(pool) = self.pool() {
            if sqlx::query(
                "INSERT IGNORE INTO invalid_free_daily (api_key_prefix, wib_date, free_used) VALUES (?, ?, 0)",
            )
            .bind(prefix)
            .bind(wib_day)
            .execute(&pool)
            .await
            .is_err()
            {
                tracing::warn!(prefix = %prefix, "Gagal menyiapkan baris jatah gratis invalid; hasil ditagih (fail-closed)");
                return false;
            }
            return match sqlx::query(
                "UPDATE invalid_free_daily SET free_used = free_used + 1 WHERE api_key_prefix = ? AND wib_date = ? AND free_used < ?",
            )
            .bind(prefix)
            .bind(wib_day)
            .bind(INVALID_FREE_DAILY_LIMIT)
            .execute(&pool)
            .await
            {
                // Single-table UPDATE: 1 = row changed (slot claimed),
                // 0 = WHERE unmatched (pool exhausted).
                Ok(result) => result.rows_affected() == 1,
                Err(error) => {
                    tracing::warn!(?error, prefix = %prefix, "Gagal klaim jatah gratis invalid; hasil ditagih (fail-closed)");
                    false
                }
            };
        }
        let mut map = self
            .invalid_free_fallback
            .lock()
            .expect("invalid free map");
        let used = map.entry((prefix.to_owned(), wib_day)).or_insert(0);
        if *used < INVALID_FREE_DAILY_LIMIT {
            *used += 1;
            true
        } else {
            false
        }
    }

    /// Best-effort release of a previously claimed free slot, used only when
    /// the usage event failed to enqueue after a free claim — a result the
    /// member never received must not consume the pool. Never below zero.
    pub async fn release_invalid_free_slot(
        &self,
        prefix: &str,
        wib_day: chrono::NaiveDate,
    ) {
        if let Some(pool) = self.pool() {
            let _ = sqlx::query(
                "UPDATE invalid_free_daily SET free_used = GREATEST(free_used - 1, 0) WHERE api_key_prefix = ? AND wib_date = ?",
            )
            .bind(prefix)
            .bind(wib_day)
            .execute(&pool)
            .await;
            return;
        }
        let mut map = self
            .invalid_free_fallback
            .lock()
            .expect("invalid free map");
        if let Some(used) = map.get_mut(&(prefix.to_owned(), wib_day)) {
            *used = used.saturating_sub(1);
        }
    }

    /// Free invalid results already consumed on a WIB day for one key;
    /// 0 when unknown. Powers the member overview and the admin key list.
    pub async fn invalid_free_used_today(
        &self,
        prefix: &str,
        wib_day: chrono::NaiveDate,
    ) -> u32 {
        if let Some(pool) = self.pool() {
            return sqlx::query_scalar::<_, i64>(
                "SELECT free_used FROM invalid_free_daily WHERE api_key_prefix = ? AND wib_date = ?",
            )
            .bind(prefix)
            .bind(wib_day)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten()
            .map(|value| value.max(0) as u32)
            .unwrap_or(0);
        }
        self.invalid_free_fallback
            .lock()
            .expect("invalid free map")
            .get(&(prefix.to_owned(), wib_day))
            .copied()
            .unwrap_or(0)
    }

    /// In-memory fallback history, used only when MySQL is not attached. Mirrors
    /// exactly the validations whose usage event was queued (the same set the
    /// worker persists to `validation_requests` when a database exists).
    pub async fn push_validation_history(&self, item: ValidationHistoryItem) {
        let mut data = self.data.write().await;
        data.history.push_front(item);
        data.history.truncate(HISTORY_MEMORY_CAP);
    }

    pub async fn validation_history(
        &self,
        filters: &ValidationHistoryFilters,
        limit: usize,
        offset: usize,
    ) -> (Vec<ValidationHistoryItem>, usize, (usize, usize)) {
        let data = self.data.read().await;
        let matched: Vec<ValidationHistoryItem> = data
            .history
            .iter()
            .filter(|item| filters.matches(item))
            .cloned()
            .collect();
        let total = matched.len();
        let now = chrono::Utc::now();
        let hits_last_60s = matched
            .iter()
            .filter(|item| item.occurred_at >= now - chrono::Duration::seconds(60))
            .count();
        let hits_last_3600s = matched
            .iter()
            .filter(|item| item.occurred_at >= now - chrono::Duration::seconds(3600))
            .count();
        (
            matched.into_iter().skip(offset).take(limit).collect(),
            total,
            (hits_last_60s, hits_last_3600s),
        )
    }

    /// Durable admin-audit write (audit 2026-10-25, B12). INSERTs one
    /// row into `admin_audit_log` (migration 0017). An insert failure
    /// is logged as a warning but NEVER fails the admin action that
    /// triggered it — losing an audit row is bad, failing the action
    /// over it would be worse, and the in-memory mirror (kept by the
    /// caller via `append_activity`) still shows the action until
    /// restart. No pool (memory-only mode) is a silent no-op: the
    /// mirror is the only record, as before.
    pub async fn persist_admin_audit(
        &self,
        actor: &str,
        action: &str,
        detail: &str,
        entity_type: Option<&str>,
        entity_id: Option<&str>,
    ) {
        let Some(pool) = self.pool() else { return };
        if let Err(error) = sqlx::query(
            "INSERT INTO admin_audit_log (id, occurred_at, actor, action, detail, entity_type, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(Utc::now())
        .bind(actor)
        .bind(action)
        .bind(detail)
        .bind(entity_type)
        .bind(entity_id)
        .execute(&pool)
        .await
        {
            tracing::warn!(?error, actor, action, "Gagal menulis jejak audit admin ke database");
        }
    }

    /// Paginated admin-audit read for GET /v1/admin/activity (B12).
    /// With a database, rows come from `admin_audit_log` (newest first)
    /// with exact `action` match and substring `actor` match. Without
    /// one, the in-memory mirror is used: admin actions are the
    /// `ActivityItem`s with no product (validation telemetry always
    /// carries one), with the actor recovered from the " • oleh <email>"
    /// suffix the API handler appends. Returns (page, total).
    /// Paginated admin-audit read for GET /v1/admin/activity (B12,
    /// diperluas area 7+8). Perubahan dari versi B12: `action` kini
    /// SUBSTRING (LIKE), bukan exact match — sesuai spesifikasi
    /// filter aktivitas — dan ditambah rentang tanggal `from`/`to`
    /// (inklusif, sudah dinormalisasi handler: tanggal `to` polos
    /// berarti akhir hari). `actor` tetap substring. `%`/`_` di
    /// filter diperlakukan sebagai wildcard LIKE, sama seperti
    /// perilaku actor sebelumnya.
    pub async fn list_admin_audit(
        &self,
        limit: i64,
        offset: i64,
        action_filter: Option<&str>,
        actor_filter: Option<&str>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> (Vec<AdminAuditEntry>, u64) {
        if let Some(pool) = self.pool() {
            let action_pattern = action_filter.map(|action| format!("%{action}%"));
            let actor_pattern = actor_filter.map(|actor| format!("%{actor}%"));
            let rows = sqlx::query_as::<_, AdminAuditRow>(
                "SELECT id, occurred_at, actor, action, detail, entity_type, entity_id \
                 FROM admin_audit_log \
                 WHERE (? IS NULL OR action LIKE ?) AND (? IS NULL OR actor LIKE ?) \
                 AND (? IS NULL OR occurred_at >= ?) AND (? IS NULL OR occurred_at <= ?) \
                 ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?",
            )
            .bind(action_pattern.as_deref())
            .bind(action_pattern.as_deref())
            .bind(actor_pattern.as_deref())
            .bind(actor_pattern.as_deref())
            .bind(from)
            .bind(from)
            .bind(to)
            .bind(to)
            .bind(limit)
            .bind(offset)
            .fetch_all(&pool)
            .await;
            let total = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM admin_audit_log \
                 WHERE (? IS NULL OR action LIKE ?) AND (? IS NULL OR actor LIKE ?) \
                 AND (? IS NULL OR occurred_at >= ?) AND (? IS NULL OR occurred_at <= ?)",
            )
            .bind(action_pattern.as_deref())
            .bind(action_pattern.as_deref())
            .bind(actor_pattern.as_deref())
            .bind(actor_pattern.as_deref())
            .bind(from)
            .bind(from)
            .bind(to)
            .bind(to)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
            return match rows {
                Ok(rows) => (
                    rows.into_iter().filter_map(|row| row.into_entry().ok()).collect(),
                    total as u64,
                ),
                Err(error) => {
                    tracing::warn!(?error, "Gagal membaca jejak audit admin dari database");
                    (Vec::new(), 0)
                }
            };
        }
        let data = self.data.read().await;
        let mut entries: Vec<AdminAuditEntry> = data
            .activities
            .iter()
            .filter(|item| item.product.is_none())
            .filter_map(|item| {
                // Mirror detail is "<detail> • oleh <email>".
                let (detail, actor) = match item.detail.rsplit_once(" • oleh ") {
                    Some((detail, actor)) => (detail.to_owned(), actor.to_owned()),
                    None => (item.detail.clone(), String::new()),
                };
                // Cabang memory meniru cabang DB: substring
                // case-insensitive untuk action dan actor, plus rentang
                // tanggal inklusif. (DB case-insensitive lewat collation
                // kolom; di sini dilowercase eksplisit.)
                if let Some(action) = action_filter {
                    if !item
                        .title
                        .to_ascii_lowercase()
                        .contains(&action.to_ascii_lowercase())
                    {
                        return None;
                    }
                }
                if let Some(actor_filter) = actor_filter {
                    if !actor
                        .to_ascii_lowercase()
                        .contains(&actor_filter.to_ascii_lowercase())
                    {
                        return None;
                    }
                }
                if let Some(from) = from {
                    if item.occurred_at < from {
                        return None;
                    }
                }
                if let Some(to) = to {
                    if item.occurred_at > to {
                        return None;
                    }
                }
                Some(AdminAuditEntry {
                    id: item.id,
                    occurred_at: item.occurred_at,
                    actor,
                    action: item.title.clone(),
                    detail,
                    entity_type: None,
                    entity_id: None,
                })
            })
            .collect();
        let total = entries.len() as u64;
        // In-memory activities are newest-first already; skip/take the page.
        let page = entries
            .drain(..)
            .skip(offset.max(0) as usize)
            .take(limit.max(0) as usize)
            .collect();
        (page, total)
    }

    // ---------------------------------------------------------------
    // Multi-admin (migrasi 0019, area 7+8). Semua metode ini no-op /
    // None tanpa pool (mode memory-only): resolusi peran di
    // admin_roles.rs lalu jatuh ke fallback owner, dan endpoint
    // kelola admin menolak dengan 503 dari handler (lihat api.rs).
    // ---------------------------------------------------------------

    /// Satu baris `admins` berdasarkan email ternormalisasi, atau
    /// None bila belum ada baris / tanpa database. Peran tak dikenal
    /// di database dipetakan ke viewer (fail-closed ke peran terendah).
    pub async fn get_admin_account(&self, email: &str) -> Option<AdminAccount> {
        let pool = self.pool()?;
        sqlx::query_as::<_, AdminRow>(
            "SELECT id, email, role, active, created_at, updated_at, created_by \
             FROM admins WHERE email = ?",
        )
        .bind(email)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten()
        .map(|row| row.into_account())
    }

    /// Daftar semua akun admin, urut email, untuk endpoint owner.
    pub async fn list_admin_accounts(&self) -> Vec<AdminAccount> {
        let Some(pool) = self.pool() else {
            return Vec::new();
        };
        sqlx::query_as::<_, AdminRow>(
            "SELECT id, email, role, active, created_at, updated_at, created_by \
             FROM admins ORDER BY email ASC",
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| row.into_account())
        .collect()
    }

    /// Buat akun admin baru. Email sudah harus ternormalisasi dan
    /// tervalidasi (lihat admin_roles::validate_admin_email).
    /// Duplikat -> 409, bukan 500.
    pub async fn create_admin_account(
        &self,
        email: &str,
        role: Role,
        created_by: &str,
    ) -> Result<AdminAccount, AppError> {
        let Some(pool) = self.pool() else {
            return Err(AppError::service_unavailable(
                "Kelola admin membutuhkan database.",
            ));
        };
        if self.get_admin_account(email).await.is_some() {
            return Err(AppError::conflict("Email admin sudah terdaftar"));
        }
        let id = Uuid::now_v7();
        let now = chrono::Utc::now();
        let result = sqlx::query(
            "INSERT INTO admins (id, email, role, active, created_at, updated_at, created_by) \
             VALUES (?, ?, ?, 1, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(email)
        .bind(role.as_str())
        .bind(now)
        .bind(now)
        .bind(created_by)
        .execute(&pool)
        .await;
        if let Err(error) = result {
            // Balapan dengan INSERT bersamaan: tetap laporkan 409.
            if format!("{error:?}").contains("Duplicate") {
                return Err(AppError::conflict("Email admin sudah terdaftar"));
            }
            return Err(AppError::internal("Akun admin tidak dapat dibuat"));
        }
        Ok(AdminAccount {
            id,
            email: email.to_owned(),
            role,
            active: true,
            created_at: now,
            updated_at: now,
            created_by: Some(created_by.to_owned()),
        })
    }

    /// Ubah peran dan/atau status aktif akun. Mengembalikan None bila
    /// id tidak ditemukan. `role`/`active` yang None tidak diubah.
    pub async fn update_admin_account(
        &self,
        id: Uuid,
        role: Option<Role>,
        active: Option<bool>,
    ) -> Result<Option<AdminAccount>, AppError> {
        let Some(pool) = self.pool() else {
            return Err(AppError::service_unavailable(
                "Kelola admin membutuhkan database.",
            ));
        };
        let Some(current) = sqlx::query_as::<_, AdminRow>(
            "SELECT id, email, role, active, created_at, updated_at, created_by \
             FROM admins WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&pool)
        .await
        .map_err(|_| AppError::internal("Akun admin tidak dapat dibaca"))?
        else {
            return Ok(None);
        };
        let mut account = current.into_account();
        if let Some(role) = role {
            account.role = role;
        }
        if let Some(active) = active {
            account.active = active;
        }
        sqlx::query("UPDATE admins SET role = ?, active = ? WHERE id = ?")
            .bind(account.role.as_str())
            .bind(account.active)
            .bind(id.to_string())
            .execute(&pool)
            .await
            .map_err(|_| AppError::internal("Akun admin tidak dapat diubah"))?;
        account.updated_at = chrono::Utc::now();
        Ok(Some(account))
    }

    /// Hapus akun admin. Mengembalikan true bila ada baris yang dihapus.
    pub async fn delete_admin_account(&self, id: Uuid) -> Result<bool, AppError> {
        let Some(pool) = self.pool() else {
            return Err(AppError::service_unavailable(
                "Kelola admin membutuhkan database.",
            ));
        };
        let result = sqlx::query("DELETE FROM admins WHERE id = ?")
            .bind(id.to_string())
            .execute(&pool)
            .await
            .map_err(|_| AppError::internal("Akun admin tidak dapat dihapus"))?;
        Ok(result.rows_affected() > 0)
    }

    /// Jumlah owner yang masih aktif — dipakai guard "owner terakhir"
    /// di handler agar owner tidak bisa menonaktifkan/mendemot/menghapus
    /// satu-satunya owner aktif.
    pub async fn count_active_owners(&self) -> u64 {
        let Some(pool) = self.pool() else {
            return 0;
        };
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM admins WHERE role = 'owner' AND active = 1",
        )
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(0) as u64
    }

    /// Seed malas satu email lama sebagai owner (INSERT IGNORE).
    /// Best-effort dan tidak pernah gagalkan pemanggil: bila tabel
    /// belum ada (migrasi 0019 belum jalan) atau ada balapan, fallback
    /// di admin_roles.rs tetap mengembalikan owner untuk sesi itu.
    pub async fn seed_legacy_admin(&self, email: &str) {
        let Some(pool) = self.pool() else {
            return;
        };
        let now = chrono::Utc::now();
        if let Err(error) = sqlx::query(
            "INSERT IGNORE INTO admins (id, email, role, active, created_at, updated_at, created_by) \
             VALUES (?, ?, 'owner', 1, ?, ?, NULL)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(email)
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        {
            tracing::warn!(?error, email, "Seed admin lama gagal (fallback tetap berlaku)");
        }
    }

    /// Seed eksplisit saat startup untuk semua email allowlist lama.
    /// Dipanggil main.rs setelah pool terpasang; INSERT IGNORE per
    /// email sehingga peran yang sudah diatur owner tidak tertimpa.
    pub async fn seed_legacy_admins(&self, emails: &[String]) {
        for email in emails {
            self.seed_legacy_admin(email).await;
        }
    }

    pub async fn append_activity(&self, activity: ActivityItem) {
        let mut data = self.data.write().await;
        if activity.product.is_some() {
            data.stats.total += 1;
            if activity.status == "valid" {
                data.stats.successful += 1;
            }
            if let Some(latency) = activity.provider_latency_ms {
                data.stats.provider_latency_total_ms += latency;
            }
        }
        data.activities.insert(0, activity);
        data.activities.truncate(MAX_RECENT_ACTIVITIES);
    }
}

/// API keys are high-entropy random secrets (32+ hex characters generated server-side),
/// so a fast salted SHA-256 digest is the right primitive here: unlike a human password
/// the secret cannot be dictionary-attacked, and the previous Argon2 verification cost
/// tens of milliseconds of CPU on EVERY validation request, dominating the hot path.
/// Format: `sha256$<salt_hex>$<digest_hex>` where digest = SHA-256(salt || secret).
/// Key prefixes are pure CSPRNG output (64 bit). A timestamp-derived prefix
/// (the old UUIDv7 slice) collided for keys issued within one 256 ms window.
fn generate_key_prefix() -> String {
    let mut bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("rv_live_{}", hex::encode(bytes))
}

fn hash_secret(secret: &str) -> Result<String, AppError> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let digest = secret_digest(&salt, secret);
    Ok(format!(
        "sha256${}${}",
        hex::encode(salt),
        hex::encode(digest)
    ))
}

fn secret_digest(salt: &[u8], secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn verify_secret(secret: &str, stored: &str) -> bool {
    let mut parts = stored.split('$');
    let (Some("sha256"), Some(salt_hex), Some(digest_hex), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (hex::decode(salt_hex), hex::decode(digest_hex)) else {
        return false;
    };
    let actual = secret_digest(&salt, secret);
    // Constant-time comparison so the digest cannot be probed byte by byte.
    if expected.len() != actual.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(actual.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn split_api_key(raw_key: &str) -> Option<(String, String)> {
    let (prefix, secret) = raw_key.trim().rsplit_once('_')?;
    if !prefix.starts_with("rv_")
        || secret.len() < 32
        || !secret.chars().all(|char| char.is_ascii_hexdigit())
    {
        return None;
    }
    Some((prefix.to_owned(), secret.to_owned()))
}

fn clean_required_text(value: Option<String>, label: &str) -> Result<Option<String>, AppError> {
    value
        .map(|item| {
            let item = item.trim().to_owned();
            if item.is_empty() {
                Err(AppError::bad_request(format!("{label} tidak boleh kosong")))
            } else if item.len() > 240 {
                Err(AppError::bad_request(format!("{label} terlalu panjang")))
            } else {
                Ok(item)
            }
        })
        .transpose()
}

fn clean_optional_text(value: Option<String>, label: &str) -> Result<Option<String>, AppError> {
    value
        .map(|item| {
            let item = item.trim().to_owned();
            if item.len() > 2_000 {
                Err(AppError::bad_request(format!("{label} terlalu panjang")))
            } else {
                Ok(item)
            }
        })
        .transpose()
}

fn validate_package_input(
    name: &str,
    slug: &str,
    price_idr: u64,
    included_hits: u64,
    products: &[ValidationProduct],
    rate_limit_per_minute: u32,
) -> Result<(), AppError> {
    if name.trim().is_empty() || name.trim().len() > 120 {
        return Err(AppError::bad_request(
            "Nama paket wajib diisi dan maksimal 120 karakter",
        ));
    }
    if !is_valid_slug(slug) {
        return Err(AppError::bad_request(
            "Slug paket hanya boleh huruf kecil, angka, dan tanda hubung",
        ));
    }
    if price_idr == 0 || included_hits == 0 || rate_limit_per_minute == 0 {
        return Err(AppError::bad_request(
            "Harga, jumlah hit, dan rate limit paket harus lebih besar dari 0",
        ));
    }
    if products.is_empty() {
        return Err(AppError::bad_request(
            "Paket harus memiliki minimal satu produk",
        ));
    }
    Ok(())
}

fn validate_promo(percent: u8, ends_at: Option<chrono::DateTime<Utc>>) -> Result<(), AppError> {
    if percent > 100 {
        return Err(AppError::bad_request("Potongan promo maksimal 100%"));
    }
    if percent > 0 && ends_at.is_none() {
        return Err(AppError::bad_request(
            "Promo aktif wajib diisi tanggal berakhirnya",
        ));
    }
    Ok(())
}

fn validate_rate_limit_input(
    name: &str,
    scope: &str,
    target: &str,
    requests_per_minute: u32,
    burst: u32,
    concurrency_limit: u32,
) -> Result<(), AppError> {
    if name.trim().is_empty() || target.trim().is_empty() {
        return Err(AppError::bad_request(
            "Nama dan target kebijakan wajib diisi",
        ));
    }
    if !matches!(
        scope.trim().to_ascii_lowercase().as_str(),
        "global" | "api_key" | "ip" | "package" | "endpoint"
    ) {
        return Err(AppError::bad_request(
            "Scope kebijakan rate limit tidak valid",
        ));
    }
    if requests_per_minute == 0 || burst == 0 || concurrency_limit == 0 {
        return Err(AppError::bad_request(
            "Nilai rate limit, burst, dan konkurensi harus lebih besar dari 0",
        ));
    }
    Ok(())
}

fn is_valid_scope(scope: &str) -> bool {
    matches!(
        scope,
        "validate:*" | "validate:bank_account" | "validate:ewallet" | "validate:whatsapp"
    )
}

fn is_valid_slug(slug: &str) -> bool {
    let value = slug.trim();
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|char| char.is_ascii_lowercase() || char.is_ascii_digit() || char == '-')
}

fn sample_products(now: chrono::DateTime<Utc>) -> Vec<AdminProduct> {
    vec![
        AdminProduct {
            id: Uuid::now_v7(),
            code: "bank_account_validation".to_owned(),
            name: "Validasi Rekening".to_owned(),
            description: "Validasi nama pemilik dan status rekening melalui provider resmi."
                .to_owned(),
            active: true,
            provider_route: "primary-bank-id".to_owned(),
            base_price_idr: 250,
            updated_at: now,
        },
        AdminProduct {
            id: Uuid::now_v7(),
            code: "ewallet_validation".to_owned(),
            name: "Validasi E-Wallet".to_owned(),
            description: "Cek kecocokan akun e-wallet untuk alur pembayaran yang lebih aman."
                .to_owned(),
            active: true,
            provider_route: "primary-ewallet-id".to_owned(),
            base_price_idr: 200,
            updated_at: now,
        },
        AdminProduct {
            id: Uuid::now_v7(),
            code: "whatsapp_validation".to_owned(),
            name: "Validasi WhatsApp".to_owned(),
            description: "Periksa format dan keterjangkauan nomor melalui provider yang disetujui."
                .to_owned(),
            active: true,
            provider_route: "primary-whatsapp-id".to_owned(),
            base_price_idr: 150,
            updated_at: now,
        },
    ]
}

fn sample_packages(now: chrono::DateTime<Utc>) -> Vec<AdminPackage> {
    vec![
        AdminPackage {
            id: Uuid::now_v7(),
            name: "Starter".to_owned(),
            slug: "starter".to_owned(),
            description: "Untuk uji integrasi dan volume awal.".to_owned(),
            price_idr: 99_000,
            included_hits: 500,
            active: true,
            highlighted: false,
            products: vec![ValidationProduct::BankAccount, ValidationProduct::Ewallet],
            rate_limit_per_minute: 30,
            promo_percent: 0,
            promo_ends_at: None,
            created_at: now - Duration::days(28),
            updated_at: now - Duration::days(2),
        },
        AdminPackage {
            id: Uuid::now_v7(),
            name: "Growth".to_owned(),
            slug: "growth".to_owned(),
            description: "Paket fleksibel untuk tim produk yang sedang berkembang.".to_owned(),
            price_idr: 399_000,
            included_hits: 3_000,
            active: true,
            highlighted: true,
            products: vec![
                ValidationProduct::BankAccount,
                ValidationProduct::Ewallet,
                ValidationProduct::Whatsapp,
            ],
            rate_limit_per_minute: 120,
            promo_percent: 0,
            promo_ends_at: None,
            created_at: now - Duration::days(20),
            updated_at: now - Duration::days(1),
        },
        AdminPackage {
            id: Uuid::now_v7(),
            name: "Scale".to_owned(),
            slug: "scale".to_owned(),
            description: "Kapasitas tinggi dengan limit khusus untuk trafik besar.".to_owned(),
            price_idr: 1_499_000,
            included_hits: 15_000,
            active: true,
            highlighted: false,
            products: vec![
                ValidationProduct::BankAccount,
                ValidationProduct::Ewallet,
                ValidationProduct::Whatsapp,
            ],
            rate_limit_per_minute: 600,
            promo_percent: 0,
            promo_ends_at: None,
            created_at: now - Duration::days(14),
            updated_at: now - Duration::hours(6),
        },
    ]
}

fn sample_policies(now: chrono::DateTime<Utc>) -> Vec<RateLimitPolicy> {
    vec![
        RateLimitPolicy {
            id: Uuid::now_v7(),
            name: "Pengaman global".to_owned(),
            scope: "global".to_owned(),
            target: "Semua endpoint validasi".to_owned(),
            requests_per_minute: 8_000,
            burst: 400,
            concurrency_limit: 800,
            active: true,
            updated_at: now - Duration::hours(3),
        },
        RateLimitPolicy {
            id: Uuid::now_v7(),
            name: "Kunci API standar".to_owned(),
            scope: "api_key".to_owned(),
            target: "Paket Growth".to_owned(),
            requests_per_minute: 120,
            burst: 30,
            concurrency_limit: 12,
            active: true,
            updated_at: now - Duration::hours(9),
        },
        RateLimitPolicy {
            id: Uuid::now_v7(),
            name: "Proteksi IP publik".to_owned(),
            scope: "ip".to_owned(),
            target: "Endpoint /v1/validate/*".to_owned(),
            requests_per_minute: 180,
            burst: 45,
            concurrency_limit: 24,
            active: true,
            updated_at: now - Duration::days(1),
        },
    ]
}

// ---- Database row shapes for the persisted admin store ---------------------

#[derive(sqlx::FromRow)]
struct PackageRow {
    id: String,
    name: String,
    slug: String,
    description: String,
    price_idr: u64,
    included_hits: u64,
    active: bool,
    highlighted: bool,
    products: String,
    rate_limit_per_minute: u32,
    promo_percent: u8,
    promo_ends_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl PackageRow {
    fn into_package(self) -> Result<AdminPackage, AppError> {
        Ok(AdminPackage {
            id: Uuid::parse_str(&self.id)
                .map_err(|_| AppError::internal("ID paket di database tidak valid"))?,
            name: self.name,
            slug: self.slug,
            description: self.description,
            price_idr: self.price_idr,
            included_hits: self.included_hits,
            active: self.active,
            highlighted: self.highlighted,
            products: serde_json::from_str(&self.products)
                .map_err(|_| AppError::internal("Daftar produk paket di database tidak valid"))?,
            rate_limit_per_minute: self.rate_limit_per_minute,
            promo_percent: self.promo_percent,
            promo_ends_at: self.promo_ends_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// One row of `admins` (migration 0019). `id`/`role` are stored as
/// CHAR(36)/VARCHAR and converted in `into_account`; an unknown role
/// string maps to viewer (least privilege) rather than failing the read.
#[derive(sqlx::FromRow)]
struct AdminRow {
    id: String,
    email: String,
    role: String,
    active: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    created_by: Option<String>,
}

impl AdminRow {
    fn into_account(self) -> AdminAccount {
        use std::str::FromStr as _;
        AdminAccount {
            id: Uuid::parse_str(&self.id).unwrap_or_else(|_| Uuid::nil()),
            email: self.email,
            role: Role::from_str(&self.role).unwrap_or(Role::Viewer),
            active: self.active,
            created_at: self.created_at,
            updated_at: self.updated_at,
            created_by: self.created_by,
        }
    }
}

/// One row of `admin_audit_log` (migration 0017). `id` is stored as
/// CHAR(36); `occurred_at` is a DATETIME(6) that sqlx reads as UTC.
#[derive(sqlx::FromRow)]
struct AdminAuditRow {
    id: String,
    occurred_at: chrono::DateTime<Utc>,
    actor: String,
    action: String,
    detail: String,
    entity_type: Option<String>,
    entity_id: Option<String>,
}

impl AdminAuditRow {
    fn into_entry(self) -> Result<AdminAuditEntry, AppError> {
        Ok(AdminAuditEntry {
            id: Uuid::parse_str(&self.id)
                .map_err(|_| AppError::internal("ID audit di database tidak valid"))?,
            occurred_at: self.occurred_at,
            actor: self.actor,
            action: self.action,
            detail: self.detail,
            entity_type: self.entity_type,
            entity_id: self.entity_id,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    // The pre-existing rate_limit_policies table stores ids as BINARY(16).
    id: Uuid,
    name: String,
    scope: String,
    target: String,
    requests_per_minute: u32,
    burst: u32,
    concurrency_limit: u32,
    active: bool,
    updated_at: chrono::DateTime<Utc>,
}

impl PolicyRow {
    fn into_policy(self) -> Result<RateLimitPolicy, AppError> {
        Ok(RateLimitPolicy {
            id: self.id,
            name: self.name,
            scope: self.scope,
            target: self.target,
            requests_per_minute: self.requests_per_minute,
            burst: self.burst,
            concurrency_limit: self.concurrency_limit,
            active: self.active,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: String,
    prefix: String,
    name: String,
    secret_hash: String,
    secret_ciphertext: Option<Vec<u8>>,
    scopes: String,
    status: String,
    rate_limit_per_minute: u32,
    quota_total: u64,
    quota_remaining: u64,
    expires_at: Option<chrono::DateTime<Utc>>,
    package_id: Option<String>,
    member_id: Option<String>,
    last_used_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

impl ApiKeyRow {
    fn into_record(self) -> Result<ApiKeyRecord, AppError> {
        let id = Uuid::parse_str(&self.id)
            .map_err(|_| AppError::internal("ID kunci API di database tidak valid"))?;
        let package_id = self
            .package_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| AppError::internal("ID paket kunci API tidak valid"))?;
        let member_id = self
            .member_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| AppError::internal("ID member kunci API tidak valid"))?;
        Ok(ApiKeyRecord {
            summary: AdminApiKeySummary {
                id,
                name: self.name,
                prefix: self.prefix,
                scopes: serde_json::from_str(&self.scopes).map_err(|_| {
                    AppError::internal("Daftar scope kunci API di database tidak valid")
                })?,
                status: self.status,
                last_used_at: self.last_used_at,
                rate_limit_per_minute: self.rate_limit_per_minute,
                quota_total: self.quota_total,
                expires_at: self.expires_at,
                package_id,
                member_id,
                created_at: self.created_at,
            },
            secret_hash: self.secret_hash,
            secret_ciphertext: self.secret_ciphertext,
            remaining_quota: self.quota_remaining,
            quota_total: self.quota_total,
            expires_at: self.expires_at,
            package_id,
            member_id,
        })
    }
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    id: String,
    google_sub: String,
    email: String,
    name: Option<String>,
    picture_url: Option<String>,
    plan_kind: String,
    status: String,
    created_at: chrono::DateTime<Utc>,
    last_login_at: Option<chrono::DateTime<Utc>>,
}

impl MemberRow {
    fn into_account(self) -> Result<crate::models::MemberAccount, AppError> {
        Ok(crate::models::MemberAccount {
            id: Uuid::parse_str(&self.id)
                .map_err(|_| AppError::internal("ID member di database tidak valid"))?,
            google_sub: self.google_sub,
            email: self.email,
            name: self.name,
            picture_url: self.picture_url,
            plan_kind: self.plan_kind,
            status: self.status,
            created_at: self.created_at,
            last_login_at: self.last_login_at,
        })
    }
}

#[cfg(test)]
mod key_prefix_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn prefixes_are_random_and_unique() {
        // The old UUIDv7-derived prefix collided within a 256 ms window
        // (audit 2026-10-25, K1). A thousand CSPRNG prefixes must be unique.
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let prefix = generate_key_prefix();
            assert!(prefix.starts_with("rv_live_"), "{prefix}");
            assert_eq!(prefix.len(), "rv_live_".len() + 16, "{prefix}");
            assert!(prefix["rv_live_".len()..].chars().all(|c| c.is_ascii_hexdigit()));
            assert!(seen.insert(prefix), "duplicate prefix generated");
        }
    }
}

#[cfg(test)]
mod member_key_lock_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn same_member_shares_one_lock_different_members_do_not() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let member = Uuid::now_v7();
        let first = store.member_key_lock(member);
        let second = store.member_key_lock(member);
        assert!(Arc::ptr_eq(&first, &second));
        let other = store.member_key_lock(Uuid::now_v7());
        assert!(!Arc::ptr_eq(&first, &other));
    }

    #[test]
    fn lock_starts_unlocked() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let lock = store.member_key_lock(Uuid::now_v7());
        assert!(lock.try_lock().is_ok());
    }
}

#[cfg(test)]
mod invalid_free_tests {
    use super::*;
    use chrono::NaiveDate;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 25).expect("tanggal tes valid")
    }

    fn next_day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 26).expect("tanggal tes valid")
    }

    // Billing rule 2026-10-25: the first 100 claims are free, the 101st
    // is not. (Runs on the no-pool fallback path; the SQL path uses the
    // same conditional-UPDATE semantics.)
    #[tokio::test]
    async fn first_100_free_101st_paid() {
        let store = AdminStore::new(None, 60).expect("store baru");
        for _ in 0..INVALID_FREE_DAILY_LIMIT {
            assert!(store.claim_invalid_free_slot("rv_live_a", day()).await);
        }
        assert!(!store.claim_invalid_free_slot("rv_live_a", day()).await);
        assert_eq!(
            store.invalid_free_used_today("rv_live_a", day()).await,
            INVALID_FREE_DAILY_LIMIT
        );
    }

    // Invalid and NotFound share ONE pool: the claim function is called
    // for both statuses alike, so 60 of one + 40 of the other exhaust it.
    #[tokio::test]
    async fn invalid_and_not_found_share_one_pool() {
        let store = AdminStore::new(None, 60).expect("store baru");
        for _ in 0..60 {
            assert!(store.claim_invalid_free_slot("rv_live_b", day()).await);
        }
        for _ in 0..40 {
            assert!(store.claim_invalid_free_slot("rv_live_b", day()).await);
        }
        assert!(!store.claim_invalid_free_slot("rv_live_b", day()).await);
    }

    // The pool is per key and per WIB day: another key, or the next day,
    // starts from zero.
    #[tokio::test]
    async fn pool_is_per_key_and_per_day() {
        let store = AdminStore::new(None, 60).expect("store baru");
        for _ in 0..INVALID_FREE_DAILY_LIMIT {
            assert!(store.claim_invalid_free_slot("rv_live_c", day()).await);
        }
        assert!(store.claim_invalid_free_slot("rv_live_d", day()).await);
        assert!(store.claim_invalid_free_slot("rv_live_c", next_day()).await);
        assert_eq!(store.invalid_free_used_today("rv_live_d", day()).await, 1);
        assert_eq!(
            store.invalid_free_used_today("rv_live_unknown", day()).await,
            0
        );
    }

    // Release returns a slot (enqueue-failure path) and never goes below 0.
    #[tokio::test]
    async fn release_returns_slot_and_floors_at_zero() {
        let store = AdminStore::new(None, 60).expect("store baru");
        store.release_invalid_free_slot("rv_live_e", day()).await;
        assert_eq!(store.invalid_free_used_today("rv_live_e", day()).await, 0);
        assert!(store.claim_invalid_free_slot("rv_live_e", day()).await);
        store.release_invalid_free_slot("rv_live_e", day()).await;
        assert_eq!(store.invalid_free_used_today("rv_live_e", day()).await, 0);
    }

    // Boundary race: 99 slots taken, 10 concurrent claims — exactly one
    // wins the last free slot, the other 9 pay.
    #[tokio::test]
    async fn concurrent_claims_at_boundary_grant_exactly_one() {
        let store = Arc::new(AdminStore::new(None, 60).expect("store baru"));
        for _ in 0..INVALID_FREE_DAILY_LIMIT - 1 {
            assert!(store.claim_invalid_free_slot("rv_live_f", day()).await);
        }
        let mut handles = Vec::new();
        for _ in 0..10 {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                store.claim_invalid_free_slot("rv_live_f", day()).await
            }));
        }
        let mut granted = 0;
        for handle in handles {
            if handle.await.expect("task klaim tidak boleh panik") {
                granted += 1;
            }
        }
        assert_eq!(granted, 1);
        assert_eq!(
            store.invalid_free_used_today("rv_live_f", day()).await,
            INVALID_FREE_DAILY_LIMIT
        );
    }
}

#[cfg(test)]
mod admin_audit_filter_tests {
    use super::*;
    use chrono::TimeZone as _;

    fn admin_item(title: &str, actor: &str, day: u32) -> ActivityItem {
        ActivityItem {
            id: Uuid::now_v7(),
            title: title.to_owned(),
            detail: format!("keterangan • oleh {actor}"),
            product: None,
            status: "info".to_owned(),
            occurred_at: Utc
                .with_ymd_and_hms(2026, 10, day, 12, 0, 0)
                .unwrap(),
            provider_latency_ms: None,
        }
    }

    async fn seeded_store() -> AdminStore {
        let store = AdminStore::new(None, 60).expect("store baru");
        // Urutan append dibalik oleh insert(0): append tertua dulu.
        store
            .append_activity(admin_item("Paket dibuat", "owner@contoh.id", 20))
            .await;
        store
            .append_activity(admin_item("Kunci API dicabut", "support@contoh.id", 21))
            .await;
        store
            .append_activity(admin_item("Paket dihapus", "owner@contoh.id", 22))
            .await;
        store
    }

    #[tokio::test]
    async fn filter_by_admin_substring() {
        let store = seeded_store().await;
        let (items, total) = store
            .list_admin_audit(50, 0, None, Some("support"), None, None)
            .await;
        assert_eq!(total, 1);
        assert_eq!(items[0].action, "Kunci API dicabut");
        assert_eq!(items[0].actor, "support@contoh.id");
    }

    #[tokio::test]
    async fn filter_by_action_substring_not_exact() {
        let store = seeded_store().await;
        let (items, total) = store
            .list_admin_audit(50, 0, Some("Paket"), None, None, None)
            .await;
        assert_eq!(total, 2);
        assert!(items.iter().all(|item| item.action.contains("Paket")));
    }

    #[tokio::test]
    async fn filter_by_date_range_is_inclusive() {
        let store = seeded_store().await;
        let from = Utc.with_ymd_and_hms(2026, 10, 21, 0, 0, 0).unwrap();
        let to = Utc
            .with_ymd_and_hms(2026, 10, 21, 23, 59, 59)
            .unwrap();
        let (items, total) = store
            .list_admin_audit(50, 0, None, None, Some(from), Some(to))
            .await;
        assert_eq!(total, 1);
        assert_eq!(items[0].action, "Kunci API dicabut");
    }

    #[tokio::test]
    async fn combined_filters_intersect() {
        let store = seeded_store().await;
        let from = Utc.with_ymd_and_hms(2026, 10, 19, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 10, 23, 0, 0, 0).unwrap();
        let (items, total) = store
            .list_admin_audit(50, 0, Some("Paket"), Some("owner"), Some(from), Some(to))
            .await;
        assert_eq!(total, 2);
        assert!(items.iter().all(|item| item.actor == "owner@contoh.id"));
        // Tanpa filter apa pun, semua kembali (total 3, paginasi 50).
        let (_, total) = store
            .list_admin_audit(50, 0, None, None, None, None)
            .await;
        assert_eq!(total, 3);
    }
}

#[cfg(test)]
mod quota_adjust_tests {
    use super::*;
    use crate::models::MemberAccount;

    fn member_fixture() -> MemberAccount {
        MemberAccount {
            id: Uuid::now_v7(),
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

    async fn key_for(
        store: &AdminStore,
        member: &MemberAccount,
        quota_total: u64,
    ) -> AdminApiKeySummary {
        let created = store
            .create_member_api_key(member, quota_total, None, 60)
            .await
            .expect("kunci fixture terbit");
        // Plaintext fixture TIDAK PERNAH dipakai/dicatat — langsung dibuang.
        drop(created.plaintext_key);
        created.key
    }

    #[test]
    fn compute_positive_overflow_bumps_total_only_by_overflow() {
        // Sisa 900/1000 + 250 = 1150 > total 1000 -> total ikut jadi 1150.
        assert_eq!(compute_adjusted_quota(1000, 900, 250).unwrap(), (1150, 1150));
    }

    #[test]
    fn compute_positive_within_total_keeps_total() {
        // Sisa 500/1000 + 100 = 600 <= total -> total tetap 1000.
        assert_eq!(compute_adjusted_quota(1000, 500, 100).unwrap(), (1000, 600));
    }

    #[test]
    fn compute_negative_keeps_total_and_rejects_below_zero() {
        assert_eq!(
            compute_adjusted_quota(1000, 500, -200).unwrap(),
            (1000, 300)
        );
        assert!(compute_adjusted_quota(1000, 100, -101).is_err());
        assert!(compute_adjusted_quota(1000, 0, -1).is_err());
    }

    #[test]
    fn compute_zero_and_oversize_rejected() {
        assert!(compute_adjusted_quota(1000, 500, 0).is_err());
        assert!(compute_adjusted_quota(1000, 500, MAX_QUOTA_ADJUST_DELTA + 1).is_err());
        assert!(compute_adjusted_quota(1000, 500, -MAX_QUOTA_ADJUST_DELTA - 1).is_err());
        assert!(compute_adjusted_quota(1000, 500, MAX_QUOTA_ADJUST_DELTA).is_ok());
    }

    #[tokio::test]
    async fn adjust_is_relative_not_absolute() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let member = member_fixture();
        let key = key_for(&store, &member, 1000).await;
        // Kunci baru: sisa == total == 1000. Adjust +250 harus memberi
        // 1250 (1000 + 250), BUKAN men-set sisa menjadi 250.
        let outcome = store
            .adjust_member_key_quota(member.id, key.id, 250)
            .await
            .expect("adjust positif lolos");
        assert_eq!(outcome.quota_remaining_before, 1000);
        assert_eq!(outcome.quota_remaining_after, 1250);
        assert_eq!(outcome.quota_total_before, 1000);
        assert_eq!(outcome.quota_total_after, 1250);
        // Adjust kedua -50 dari keadaan baru: 1250 - 50 = 1200, total tetap.
        let outcome = store
            .adjust_member_key_quota(member.id, key.id, -50)
            .await
            .expect("adjust negatif lolos");
        assert_eq!(outcome.quota_remaining_after, 1200);
        assert_eq!(outcome.quota_total_after, 1250);
        let keys = store.list_member_keys(member.id).await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].1, 1200);
        assert_eq!(keys[0].0.quota_total, 1250);
    }

    #[tokio::test]
    async fn adjust_rejects_zero_oversize_and_negative_result() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let member = member_fixture();
        let key = key_for(&store, &member, 100).await;
        assert!(store
            .adjust_member_key_quota(member.id, key.id, 0)
            .await
            .is_err());
        assert!(store
            .adjust_member_key_quota(member.id, key.id, MAX_QUOTA_ADJUST_DELTA + 1)
            .await
            .is_err());
        assert!(store
            .adjust_member_key_quota(member.id, key.id, -101)
            .await
            .is_err());
        // Tidak ada perubahan setelah semua penolakan.
        let keys = store.list_member_keys(member.id).await;
        assert_eq!(keys[0].1, 100);
    }

    #[tokio::test]
    async fn adjust_rejects_non_active_key() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let member = member_fixture();
        let key = key_for(&store, &member, 100).await;
        store
            .set_member_status(member.id, false)
            .await
            .expect("disable member in-memory");
        let error = store
            .adjust_member_key_quota(member.id, key.id, 10)
            .await
            .expect_err("kunci disabled harus ditolak");
        assert_eq!(error.status, axum::http::StatusCode::CONFLICT);
        // Diaktifkan lagi -> adjust jalan.
        store
            .set_member_status(member.id, true)
            .await
            .expect("enable member in-memory");
        assert!(store
            .adjust_member_key_quota(member.id, key.id, 10)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn adjust_rejects_wrong_member_and_unknown_key() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let member = member_fixture();
        let other = member_fixture();
        let key = key_for(&store, &member, 100).await;
        let error = store
            .adjust_member_key_quota(other.id, key.id, 10)
            .await
            .expect_err("kunci member lain harus 404");
        assert_eq!(error.status, axum::http::StatusCode::NOT_FOUND);
        let error = store
            .adjust_member_key_quota(member.id, Uuid::now_v7(), 10)
            .await
            .expect_err("kunci tak ada harus 404");
        assert_eq!(error.status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_member_keys_returns_all_keys_without_secrets() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let member = member_fixture();
        let first = key_for(&store, &member, 100).await;
        let second = key_for(&store, &member, 200).await;
        let keys = store.list_member_keys(member.id).await;
        assert_eq!(keys.len(), 2);
        let prefixes: Vec<&str> = keys.iter().map(|(summary, _)| summary.prefix.as_str()).collect();
        assert!(prefixes.contains(&first.prefix.as_str()));
        assert!(prefixes.contains(&second.prefix.as_str()));
        // Tipe view tidak punya field rahasia sama sekali: serialisasi
        // ringkasan tidak boleh memuat kata secret/ciphertext/plaintext.
        let serialized = serde_json::to_string(&keys[0].0).expect("serialisasi ringkasan");
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("ciphertext"));
        assert!(!serialized.contains("plaintext"));
    }

    #[tokio::test]
    async fn ledger_usage_empty_without_database() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let member = member_fixture();
        assert!(store
            .member_daily_usage_from_ledger(member.id, 30)
            .await
            .is_empty());
    }
}

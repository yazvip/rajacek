//! Pembelian paket mandiri member via QRIS Gobiz.
//!
//! Aturan keamanan yang dijaga modul ini:
//! - Token, qris_string, dan URL provider TIDAK PERNAH dikirim ke klien
//!   member (gambar QR di-render server-side menjadi SVG dari qris_string).
//! - Webhook tidak pernah langsung grant: selalu re-verifikasi lewat
//!   check-status + cocokkan nominal dulu.
//! - Grant kuota atomik (store::grant_package_order): satu transaksi
//!   MySQL mengubah kunci + order + plan_kind dengan CAS status paid,
//!   jadi webhook + polling + sweep yang bersamaan hanya satu yang menang.
//! - Satu order waiting per (member, paket) + rate limit create yang
//!   menghitung SEMUA create sukses dalam 1 jam terakhir (anti-abuse).

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::http::StatusCode;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    error::AppError,
    models::{AdminPackage, GrantOutcome},
    provider_config::CredentialCipher,
    store::AdminStore,
};

/// Durasi QRIS yang diizinkan (menit). Di luar ini create ditolak.
pub const ALLOWED_EXPIRY_MINUTES: [i64; 5] = [3, 5, 10, 12, 15];
/// Batas create order per member per jam (anti-abuse).
const CREATE_ORDERS_PER_HOUR: i64 = 5;
/// Registry lock create per member (perbaikan K21): dulu satu mutex
/// global membuat satu create yang lambat memblokir create
/// semua member. Kini tiap member punya mutex sendiri, jadi create
/// yang lambat hanya menahan create member itu sendiri. Registry
/// hanya menyimpan Weak dan dibersihkan tiap acquire, jadi entri
/// member yang sudah selesai tidak menumpuk di memori. Registry
/// dipegang tanpa await (hanya get-or-insert), jadi tidak ada
/// deadlock async. Cek waiting + create + insert tetap atomik
/// terhadap create lain member yang SAMA (deployment single-instance;
/// multi-instance butuh guard DB).
static CREATE_ORDER_LOCKS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<Uuid, std::sync::Weak<tokio::sync::Mutex<()>>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Mutex create untuk satu member: ambil dari registry atau buat baru.
fn member_create_lock(member_id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
    let mut registry = CREATE_ORDER_LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.retain(|_, weak| weak.strong_count() > 0);
    match registry.get(&member_id).and_then(std::sync::Weak::upgrade) {
        Some(lock) => lock,
        None => {
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            registry.insert(member_id, Arc::downgrade(&lock));
            lock
        }
    }
}

/// Guard create per member: member yang sama tetap serial, member
/// berbeda tidak saling blokir.
async fn member_create_guard(member_id: Uuid) -> tokio::sync::OwnedMutexGuard<()> {
    member_create_lock(member_id).lock_owned().await
}

// ---------------------------------------------------------------------------
// Pengaturan
// ---------------------------------------------------------------------------

/// Pengaturan QRIS internal (ciphertext TIDAK PERNAH diserialisasi keluar).
/// Provider Gobiz (migrasi 0039): kredensial Gobiz dienkripsi dengan
/// pola `CredentialCipher`. Nilai Gobiz mentah di sini adalah isi kolom apa adanya
/// (bisa None/kosong bila migrasi belum diterapkan); nilai efektif
/// (dengan default) lewat `gobiz_base_url_effective` /
/// `gobiz_callback_url_effective`.

pub struct QrisSettings {
    pub enabled: bool,
    pub expiry_minutes: i64,
    pub valid_days: i64,
    pub last_error: Option<String>,
    pub gobiz_base_url: Option<String>,
    pub gobiz_callback_url: Option<String>,
    pub gobiz_api_key_ciphertext: Option<Vec<u8>>,
    pub gobiz_webhook_secret_ciphertext: Option<Vec<u8>>,
}

/// Tampilan pengaturan untuk panel admin (tanpa rahasia).
#[derive(Serialize)]

pub struct QrisSettingsView {
    pub enabled: bool,
    pub expiry_minutes: i64,
    pub valid_days: i64,
    pub last_error: Option<String>,
    pub gobiz_base_url: String,
    pub gobiz_callback_url: String,
    pub has_gobiz_api_key: bool,
    pub has_gobiz_webhook_secret: bool,
}

/// Input admin. Field yang absen/kosong = pertahankan nilai lama
/// (base/callback URL kosong = pertahankan; kredensial kosong =
/// pertahankan).
#[derive(Deserialize)]

pub struct QrisSettingsInput {
    pub enabled: Option<bool>,
    pub expiry_minutes: Option<i64>,
    pub valid_days: Option<i64>,
    pub gobiz_base_url: Option<String>,
    pub gobiz_callback_url: Option<String>,
    pub gobiz_api_key: Option<String>,
    pub gobiz_webhook_secret: Option<String>,
}

impl QrisSettings {

    fn defaults() -> Self {
        Self {
            enabled: false,
            expiry_minutes: 15,
            valid_days: 30,
            last_error: None,
            gobiz_base_url: None,
            gobiz_callback_url: None,
            gobiz_api_key_ciphertext: None,
            gobiz_webhook_secret_ciphertext: None,
        }
    }

    /// Base URL Gobiz efektif: isi kolom bila non-kosong, else default
    /// worker produksi (URL layanan publik, bukan secret).
    pub(crate) fn gobiz_base_url_effective(&self) -> String {
        match self.gobiz_base_url.as_deref().map(str::trim) {
            Some(url) if !url.is_empty() => url.to_owned(),
            _ => crate::gobiz::DEFAULT_GOBIZ_BASE_URL.to_owned(),
        }
    }

    /// Callback Gobiz efektif: isi kolom bila non-kosong, else endpoint
    /// webhook Gobiz kanonis Rajacek.
    pub(crate) fn gobiz_callback_url_effective(&self) -> String {
        match self.gobiz_callback_url.as_deref().map(str::trim) {
            Some(url) if !url.is_empty() => url.to_owned(),
            _ => crate::gobiz::DEFAULT_GOBIZ_CALLBACK_URL.to_owned(),
        }
    }

    pub fn view(&self) -> QrisSettingsView {
        QrisSettingsView {
            enabled: self.enabled,
            expiry_minutes: self.expiry_minutes,
            valid_days: self.valid_days,
            last_error: self.last_error.clone(),
            gobiz_base_url: self.gobiz_base_url_effective(),
            gobiz_callback_url: self.gobiz_callback_url_effective(),
            has_gobiz_api_key: self.gobiz_api_key_ciphertext.is_some(),
            has_gobiz_webhook_secret: self.gobiz_webhook_secret_ciphertext.is_some(),
        }
    }
}

pub async fn load_qris_settings(pool: &MySqlPool) -> Result<QrisSettings, AppError> {
    // Migrasi 0039 (revisi Gobiz-only) WAJIB sudah diterapkan sebelum
    // binary baru restart: SELECT gagal jelas bila kolom Gobiz belum
    // ada (tidak ada fallback ke provider lama yang sudah dihapus).
    // Bila DB-nya sendiri bermasalah, error dipropagasikan.
    let row = sqlx::query_as::<_, QrisSettingsRow>(
        "SELECT enabled, expiry_minutes, valid_days, last_error, \
         gobiz_base_url, gobiz_callback_url, \
         gobiz_api_key_ciphertext, gobiz_webhook_secret_ciphertext \
         FROM qris_settings WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan QRIS tidak dapat dibaca"))?;
    Ok(match row {
        Some(row) => QrisSettings {
            enabled: row.enabled != 0,
            expiry_minutes: row.expiry_minutes,
            valid_days: row.valid_days,
            last_error: row.last_error,
            gobiz_base_url: row.gobiz_base_url,
            gobiz_callback_url: row.gobiz_callback_url,
            gobiz_api_key_ciphertext: row.gobiz_api_key_ciphertext,
            gobiz_webhook_secret_ciphertext: row.gobiz_webhook_secret_ciphertext,
        },
        None => QrisSettings::defaults(),
    })
}

#[derive(sqlx::FromRow)]
struct QrisSettingsRow {
    enabled: i8,
    expiry_minutes: i64,
    valid_days: i64,
    last_error: Option<String>,
    gobiz_base_url: Option<String>,
    gobiz_callback_url: Option<String>,
    gobiz_api_key_ciphertext: Option<Vec<u8>>,
    gobiz_webhook_secret_ciphertext: Option<Vec<u8>>,
}

pub(crate) async fn save_qris_settings(
    pool: &MySqlPool,
    input: QrisSettingsInput,
    cipher: &CredentialCipher,
) -> Result<QrisSettingsView, AppError> {
    if let Some(minutes) = input.expiry_minutes {
        if !ALLOWED_EXPIRY_MINUTES.contains(&minutes) {
            return Err(AppError::bad_request(
                "expiry_minutes harus salah satu dari 3, 5, 10, 12, atau 15",
            ));
        }
    }
    if let Some(days) = input.valid_days {
        if !(1..=3650).contains(&days) {
            return Err(AppError::bad_request(
                "valid_days pembelian harus 1–3650 hari",
            ));
        }
    }
    for (name, url) in [
        ("gobiz_base_url", input.gobiz_base_url.as_deref()),
        ("gobiz_callback_url", input.gobiz_callback_url.as_deref()),
    ] {
        if let Some(url) = url.map(str::trim).filter(|url| !url.is_empty()) {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(AppError::bad_request(format!(
                    "{name} harus diawali http:// atau https://",
                )));
            }
        }
    }
    let mut current = load_qris_settings(pool).await?;
    if let Some(enabled) = input.enabled {
        current.enabled = enabled;
    }
    if let Some(minutes) = input.expiry_minutes {
        current.expiry_minutes = minutes;
    }
    if let Some(days) = input.valid_days {
        current.valid_days = days;
    }
    if let Some(url) = input.gobiz_base_url {
        if !url.trim().is_empty() {
            current.gobiz_base_url = Some(url.trim().to_owned());
        }
    }
    if let Some(url) = input.gobiz_callback_url {
        if !url.trim().is_empty() {
            current.gobiz_callback_url = Some(url.trim().to_owned());
        }
    }
    if let Some(key) = input.gobiz_api_key {
        if !key.trim().is_empty() {
            current.gobiz_api_key_ciphertext = Some(
                cipher
                    .encrypt(key.trim())
                    .map_err(|_| AppError::internal("API key Gobiz tidak dapat dienkripsi"))?,
            );
        }
    }
    if let Some(secret) = input.gobiz_webhook_secret {
        if !secret.trim().is_empty() {
            current.gobiz_webhook_secret_ciphertext = Some(
                cipher
                    .encrypt(secret.trim())
                    .map_err(|_| AppError::internal("Webhook secret Gobiz tidak dapat dienkripsi"))?,
            );
        }
    }
    // Upsert HANYA kolom Gobiz: kolom QRIS lama di baris yang sama
    // SENGAJA tidak disentuh (dibiarkan mati sebagai data rollback).
    sqlx::query(
        "INSERT INTO qris_settings (id, enabled, expiry_minutes, valid_days, \
         gobiz_base_url, gobiz_callback_url, gobiz_api_key_ciphertext, \
         gobiz_webhook_secret_ciphertext) \
         VALUES (1, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE \
         enabled = VALUES(enabled), expiry_minutes = VALUES(expiry_minutes), \
         valid_days = VALUES(valid_days), \
         gobiz_base_url = VALUES(gobiz_base_url), \
         gobiz_callback_url = VALUES(gobiz_callback_url), \
         gobiz_api_key_ciphertext = VALUES(gobiz_api_key_ciphertext), \
         gobiz_webhook_secret_ciphertext = VALUES(gobiz_webhook_secret_ciphertext)",
    )
    .bind(if current.enabled { 1 } else { 0 })
    .bind(current.expiry_minutes)
    .bind(current.valid_days)
    .bind(&current.gobiz_base_url)
    .bind(&current.gobiz_callback_url)
    .bind(&current.gobiz_api_key_ciphertext)
    .bind(&current.gobiz_webhook_secret_ciphertext)
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan QRIS tidak dapat disimpan"))?;
    Ok(current.view())
}

pub async fn record_qris_error(pool: &MySqlPool, message: &str) {
    sqlx::query(
        "INSERT INTO qris_settings (id, last_error) VALUES (1, ?) \
         ON DUPLICATE KEY UPDATE last_error = VALUES(last_error)",
    )
    .bind(message)
    .execute(pool)
    .await
    .ok();
}

fn decrypt_setting(cipher: &CredentialCipher, ciphertext: &[u8]) -> Option<String> {
    cipher.decrypt(ciphertext).ok()
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (manual dengan sha2; tanpa crate hmac tambahan)
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for index in 0..64 {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for index in 0..left.len() {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

/// Verifikasi signature webhook (HMAC-SHA256 atas raw body; dipakai
/// handler Gobiz lewat `gobiz::verify_webhook_signature`). Format
/// signature tidak didokumentasikan (hex paling umum); terima hex DAN
/// base64 agar tidak gagal tertutup bila formatnya base64.
pub fn verify_webhook_signature(secret: &str, body: &[u8], signature: &str) -> bool {
    use base64::Engine;
    let expected = hmac_sha256(secret.as_bytes(), body);
    let signature = signature.trim();
    if let Ok(bytes) = hex::decode(signature) {
        if constant_time_eq(&bytes, &expected) {
            return true;
        }
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(signature) {
        if constant_time_eq(&bytes, &expected) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Status pembayaran provider
// ---------------------------------------------------------------------------

/// Status pembayaran dari provider — dipakai seluruh jalur verify,
/// sweep, dan resolve (Gobiz memetakan status worker-nya ke enum ini).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrisPaymentStatus {
    Paid {
        paid_at: Option<NaiveDateTime>,
        amount: u64,
        mutation_ref: Option<String>,
    },
    Pending {
        remaining_seconds: i64,
    },
    Expired,
    Canceled,
    NotFound,
}

// ---------------------------------------------------------------------------
// Order
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PackageOrderRow {
    pub id: String,
    pub member_id: String,
    pub key_id: Option<String>,
    pub package_id: String,
    pub package_name: String,
    pub price_idr: u64,
    pub quota_hits: u64,
    pub rate_limit_per_minute: u32,
    pub valid_days: i64,
    pub amount_idr: u64,
    pub status: String,
    pub qris_token: Option<String>,
    pub qris_string: Option<String>,
    pub qris_image_url: Option<String>,
    pub qris_expires_at: Option<NaiveDateTime>,
    pub paid_at: Option<NaiveDateTime>,
    pub granted_at: Option<NaiveDateTime>,
    pub granted_quota: Option<u64>,
    pub granted_expires_at: Option<NaiveDateTime>,
    pub mutation_ref: Option<String>,
    pub last_error: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    /// Fase 3 (B15/D3): 1 bila order ini dibatalkan kill switch saat
    /// masih waiting dan belum dibayar. Re-check terminal (B10) TIDAK
    /// boleh auto-grant order bertanda ini; pembayaran telanjur masuk
    /// ditangani resolve-berbukti admin. Kolom ini internal dan
    /// tidak pernah diserialisasi ke view member/admin.
    pub kill_switch_canceled: i8,
    /// Id pembayaran di sisi Gobiz (`pay_...`).
    #[sqlx(default)]
    pub provider_order_id: Option<String>,
    /// Nominal bayar SESUAI RESPON GOBIZ (harga + sufiks unik).
    #[sqlx(default)]
    pub expected_amount: Option<u64>,
}

/// Tampilan order untuk member: TANPA token/QRIS string/URL provider.
#[derive(Serialize)]
pub struct MemberOrderView {
    pub id: String,
    pub package_id: String,
    pub package_name: String,
    pub price_idr: u64,
    pub quota_hits: u64,
    pub rate_limit_per_minute: u32,
    pub valid_days: i64,
    pub amount_idr: u64,
    pub status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub remaining_seconds: i64,
    pub paid_at: Option<DateTime<Utc>>,
    pub granted_at: Option<DateTime<Utc>>,
    pub granted_quota: Option<u64>,
    pub granted_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

fn naive_to_utc(value: NaiveDateTime) -> DateTime<Utc> {
    value.and_utc()
}

impl PackageOrderRow {

    pub fn member_view(&self) -> MemberOrderView {
        let expires_at = self.qris_expires_at.map(naive_to_utc);
        let remaining_seconds = match (self.status.as_str(), expires_at) {
            ("waiting_payment", Some(expires)) => (expires - Utc::now()).num_seconds().max(0),
            _ => 0,
        };
        MemberOrderView {
            id: self.id.clone(),
            package_id: self.package_id.clone(),
            package_name: self.package_name.clone(),
            price_idr: self.price_idr,
            quota_hits: self.quota_hits,
            rate_limit_per_minute: self.rate_limit_per_minute,
            valid_days: self.valid_days,
            amount_idr: self.amount_idr,
            status: self.status.clone(),
            expires_at,
            remaining_seconds,
            paid_at: self.paid_at.map(naive_to_utc),
            granted_at: self.granted_at.map(naive_to_utc),
            granted_quota: self.granted_quota,
            granted_expires_at: self.granted_expires_at.map(naive_to_utc),
            created_at: naive_to_utc(self.created_at),
        }
    }
}

const ORDER_COLUMNS: &str = "id, member_id, key_id, package_id, package_name, \
    price_idr, quota_hits, rate_limit_per_minute, valid_days, amount_idr, status, \
    qris_token, qris_string, qris_image_url, qris_expires_at, paid_at, granted_at, \
    granted_quota, granted_expires_at, mutation_ref, last_error, created_at, updated_at, \
    kill_switch_canceled, provider_order_id, expected_amount";

pub async fn get_order(
    pool: &MySqlPool,
    order_id: &Uuid,
) -> Result<Option<PackageOrderRow>, AppError> {
    sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders WHERE id = ?"
    ))
    .bind(order_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Order tidak dapat dibaca"))
}

pub async fn get_order_for_member(
    pool: &MySqlPool,
    order_id: &Uuid,
    member_id: &Uuid,
) -> Result<Option<PackageOrderRow>, AppError> {
    sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders WHERE id = ? AND member_id = ?"
    ))
    .bind(order_id.to_string())
    .bind(member_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Order tidak dapat dibaca"))
}

pub async fn list_orders_for_member(
    pool: &MySqlPool,
    member_id: &Uuid,
    limit: i64,
) -> Result<Vec<PackageOrderRow>, AppError> {
    sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders WHERE member_id = ? \
         ORDER BY created_at DESC LIMIT ?"
    ))
    .bind(member_id.to_string())
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Daftar order tidak dapat dibaca"))
}

/// Daftar order member dengan offset (Area 4: halaman detail member).
/// Bentuk ringkas yang sama dengan `list_orders_for_member`, ditambah
/// OFFSET agar panel bisa menelusuri order lama tanpa memuat semuanya.
pub async fn list_orders_for_member_paged(
    pool: &MySqlPool,
    member_id: &Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<PackageOrderRow>, AppError> {
    sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders WHERE member_id = ? \
         ORDER BY created_at DESC LIMIT ? OFFSET ?"
    ))
    .bind(member_id.to_string())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Daftar order tidak dapat dibaca"))
}

pub async fn get_order_by_token(
    pool: &MySqlPool,
    token: &str,
) -> Result<Option<PackageOrderRow>, AppError> {
    sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders WHERE qris_token = ? LIMIT 1"
    ))
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Order tidak dapat dibaca"))
}

/// Tampilan order untuk panel admin: seluruh kolom + email member.
/// Token pembayaran BOLEH tampil di sini (admin saja, bukan member).
/// Begitu pula id pembayaran Gobiz + expected_amount (admin saja;
/// keduanya TIDAK masuk export CSV, sama seperti token).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AdminOrderView {
    pub id: String,
    pub member_id: String,
    pub member_email: Option<String>,
    pub key_id: Option<String>,
    pub package_id: String,
    pub package_name: String,
    pub price_idr: u64,
    pub quota_hits: u64,
    pub rate_limit_per_minute: u32,
    pub valid_days: i64,
    pub amount_idr: u64,
    pub status: String,
    pub qris_token: Option<String>,
    pub qris_expires_at: Option<NaiveDateTime>,
    pub paid_at: Option<NaiveDateTime>,
    pub granted_at: Option<NaiveDateTime>,
    pub granted_quota: Option<u64>,
    pub granted_expires_at: Option<NaiveDateTime>,
    pub mutation_ref: Option<String>,
    pub last_error: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    #[sqlx(default)]
    pub provider_order_id: Option<String>,
    #[sqlx(default)]
    pub expected_amount: Option<u64>,
}

/// Kompatibilitas mundur: daftar tanpa filter tanggal (dipakai
/// pemanggil lama). Jalur baru memakai `list_orders_admin_filtered`.
pub async fn list_orders_admin(
    pool: &MySqlPool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AdminOrderView>, AppError> {
    list_orders_admin_filtered(
        pool,
        &AdminOrderFilters {
            status: status.map(str::to_owned),
            q: None,
            from: None,
            to_exclusive: None,
        },
        limit,
        offset,
    )
    .await
}

pub async fn get_order_admin(
    pool: &MySqlPool,
    order_id: &Uuid,
) -> Result<Option<AdminOrderView>, AppError> {
    sqlx::query_as::<_, AdminOrderView>(
        "SELECT o.id, o.member_id, m.email AS member_email, o.key_id, \
         o.package_id, o.package_name, o.price_idr, o.quota_hits, \
         o.rate_limit_per_minute, o.valid_days, o.amount_idr, o.status, \
         o.provider_order_id, o.expected_amount, \
         o.qris_token, o.qris_expires_at, o.paid_at, o.granted_at, \
         o.granted_quota, o.granted_expires_at, o.mutation_ref, \
         o.last_error, o.created_at, o.updated_at \
         FROM package_orders o LEFT JOIN members m ON m.id = o.member_id \
         WHERE o.id = ?",
    )
    .bind(order_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Order tidak dapat dibaca"))
}

/// ---------------------------------------------------------------------------
/// AREA 3 — Rekonsiliasi order admin + refund-record.
/// ---------------------------------------------------------------------------
/// Status yang disimpan di `package_orders`: `waiting_payment`, `paid`,
/// `granted`, `needs_review`, `expired`, `canceled`. Di permukaan API
/// admin, `waiting` adalah alias untuk `waiting_payment` (nama yang
/// dipakai spesifikasi rekonsiliasi); ringkasan selalu memakai kunci
/// `waiting` agar konsisten dengan filter tersebut.

/// Normalisasi filter status admin: alias `waiting` -> `waiting_payment`,
/// nilai kosong -> tanpa filter. Status di luar daftar ditolak 400 —
/// nilai mentah tidak pernah sampai ke SQL sebagai filter bebas.
pub fn normalize_order_status_filter(value: Option<&str>) -> Result<Option<&'static str>, AppError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = match trimmed {
        "waiting" | "waiting_payment" => "waiting_payment",
        "paid" => "paid",
        "granted" => "granted",
        "needs_review" => "needs_review",
        "expired" => "expired",
        "canceled" => "canceled",
        _ => {
            return Err(AppError::bad_request(
                "Filter status tidak dikenal (waiting, paid, granted, needs_review, expired, canceled)",
            ));
        }
    };
    Ok(Some(normalized))
}

/// Parse tanggal filter format ketat `YYYY-MM-DD` (WIB adalah tanggal
/// kalender lokal; `created_at` disimpan UTC, jadi rentang diterapkan
/// sebagai [from 00:00, to+1 hari 00:00) atas kolom UTC — lihat
/// `list_orders_admin_filtered`. Untuk rekonsiliasi harian, selisih
/// zona ini didokumentasikan di respons panel, bukan disembunyikan).
pub fn parse_order_date(value: &str) -> Result<NaiveDate, AppError> {
    let bytes = value.as_bytes();
    let strict = value.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-';
    if !strict {
        return Err(AppError::bad_request(
            "Tanggal harus berformat YYYY-MM-DD",
        ));
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| AppError::bad_request("Tanggal tidak valid"))
}

/// Validasi rentang tanggal filter. Aturan (server-side, wajib):
/// from dan to harus berpasangan (salah satu saja -> 400), from tidak
/// boleh sesudah to, dan rentang MAKSIMAL 366 hari (batas rentang
/// wajib — mencegah pemindaian tabel tanpa batas dari panel).
pub const MAX_ORDER_DATE_RANGE_DAYS: i64 = 366;

pub fn validate_order_date_range(
    from: Option<&str>,
    to: Option<&str>,
) -> Result<Option<(NaiveDate, NaiveDate)>, AppError> {
    match (from, to) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(AppError::bad_request(
            "Rentang tanggal harus lengkap: isi from dan to sekaligus",
        )),
        (Some(from_raw), Some(to_raw)) => {
            let from_date = parse_order_date(from_raw)?;
            let to_date = parse_order_date(to_raw)?;
            if from_date > to_date {
                return Err(AppError::bad_request(
                    "Tanggal from tidak boleh sesudah to",
                ));
            }
            let span = (to_date - from_date).num_days();
            if span > MAX_ORDER_DATE_RANGE_DAYS {
                return Err(AppError::bad_request(
                    "Rentang tanggal maksimal 366 hari",
                ));
            }
            Ok(Some((from_date, to_date)))
        }
    }
}

/// Filter list order admin (gabungan AREA 3 + AREA 5, 2026-10-25).
/// `status` di sini SUDAH dinormalisasi oleh
/// [`normalize_order_status_filter`] (nilai DB, bukan alias) bila berasal
/// dari list admin; `q` dicocokkan ke id order, email member, dan nama
/// paket (LIKE dengan escape, tak peka huruf besar/kecil di collation
/// default MySQL). `from` inklusif dan `to_exclusive` eksklusif memakai
/// kolom `created_at` (UTC).
#[derive(Clone, Debug, Default)]
pub struct AdminOrderFilters {
    pub status: Option<String>,
    pub q: Option<String>,
    pub from: Option<chrono::NaiveDateTime>,
    pub to_exclusive: Option<chrono::NaiveDateTime>,
}

pub async fn list_orders_admin_filtered(
    pool: &MySqlPool,
    filters: &AdminOrderFilters,
    limit: i64,
    offset: i64,
) -> Result<Vec<AdminOrderView>, AppError> {
    let mut builder = sqlx::QueryBuilder::new(
        "SELECT o.id, o.member_id, m.email AS member_email, o.key_id, \
         o.package_id, o.package_name, o.price_idr, o.quota_hits, \
         o.rate_limit_per_minute, o.valid_days, o.amount_idr, o.status, \
         o.provider_order_id, o.expected_amount, \
         o.qris_token, o.qris_expires_at, o.paid_at, o.granted_at, \
         o.granted_quota, o.granted_expires_at, o.mutation_ref, \
         o.last_error, o.created_at, o.updated_at \
         FROM package_orders o LEFT JOIN members m ON m.id = o.member_id \
         WHERE 1 = 1",
    );
    if let Some(status) = &filters.status {
        builder.push(" AND o.status = ");
        builder.push_bind(status.clone());
    }
    if let Some(q) = &filters.q {
        let pattern = format!("%{}%", crate::models::escape_like(q));
        builder.push(" AND (o.id LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR m.email LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR o.package_name LIKE ");
        builder.push_bind(pattern);
        builder.push(")");
    }
    if let Some(from) = &filters.from {
        builder.push(" AND o.created_at >= ");
        builder.push_bind(*from);
    }
    if let Some(to) = &filters.to_exclusive {
        builder.push(" AND o.created_at < ");
        builder.push_bind(*to);
    }
    builder.push(" ORDER BY o.created_at DESC LIMIT ");
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);
    builder
        .build_query_as::<AdminOrderView>()
        .fetch_all(pool)
        .await
        .map_err(|_| AppError::internal("Daftar order tidak dapat dibaca"))
}

/// Satu baris ringkasan rekonsiliasi per status: jumlah order + total
/// nominal (amount_idr) order pada status itu.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct OrderStatusSummary {
    pub count: u64,
    pub amount_idr: u64,
}

/// Ringkasan rekonsiliasi: per status + total keseluruhan. Kunci
/// `waiting` menghitung baris `waiting_payment` di database.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ReconciliationSummary {
    pub waiting: OrderStatusSummary,
    pub paid: OrderStatusSummary,
    pub granted: OrderStatusSummary,
    pub needs_review: OrderStatusSummary,
    pub expired: OrderStatusSummary,
    pub canceled: OrderStatusSummary,
    pub total_count: u64,
    pub total_amount_idr: u64,
}

fn add_to_summary(summary: &mut ReconciliationSummary, status: &str, amount: u64) {
    let bucket = match status {
        "waiting_payment" | "waiting" => &mut summary.waiting,
        "paid" => &mut summary.paid,
        "granted" => &mut summary.granted,
        "needs_review" => &mut summary.needs_review,
        "expired" => &mut summary.expired,
        "canceled" => &mut summary.canceled,
        _ => return,
    };
    bucket.count += 1;
    bucket.amount_idr += amount;
}

/// Agregasi murni dari daftar order admin (dipakai tes konsistensi:
/// total per status dari fungsi ini harus sama dengan jumlah baris
/// yang lolos filter yang sama). Status tak dikenal diabaikan pada
/// bucket per-status tetapi tetap dihitung di total — total adalah
/// jumlah SEMUA baris, bukan jumlah bucket.
pub fn summarize_admin_orders(orders: &[AdminOrderView]) -> ReconciliationSummary {
    let mut summary = ReconciliationSummary::default();
    for order in orders {
        summary.total_count += 1;
        summary.total_amount_idr += order.amount_idr;
        add_to_summary(&mut summary, &order.status, order.amount_idr);
    }
    summary
}

/// Ringkasan rekonsiliasi dari database untuk SATU rentang tanggal
/// (GROUP BY status; rentang yang sama dengan filter daftar).
/// Mengembalikan bucket kosong (bukan error) bila tidak ada order.
pub async fn reconciliation_summary(
    pool: &MySqlPool,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<ReconciliationSummary, AppError> {
    let start = from.and_hms_opt(0, 0, 0).unwrap_or_default();
    let end = (to + chrono::Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default();
    let rows = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT status, COUNT(*), CAST(COALESCE(SUM(amount_idr), 0) AS SIGNED) \
         FROM package_orders WHERE created_at >= ? AND created_at < ? GROUP BY status",
    )
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Ringkasan rekonsiliasi tidak dapat dibaca"))?;
    let mut summary = ReconciliationSummary::default();
    for (status, count, amount) in rows {
        let count = if count < 0 { 0 } else { count as u64 };
        let amount = if amount < 0 { 0 } else { amount as u64 };
        // Total menghitung SEMUA baris GROUP BY, termasuk status tak
        // dikenal (konsisten dengan summarize_admin_orders).
        summary.total_count += count;
        summary.total_amount_idr += amount;
        // Satu baris GROUP BY per status: bucket diisi langsung dari
        // agregat, bukan lewat loop per baris.
        let bucket = match status.as_str() {
            "waiting_payment" | "waiting" => &mut summary.waiting,
            "paid" => &mut summary.paid,
            "granted" => &mut summary.granted,
            "needs_review" => &mut summary.needs_review,
            "expired" => &mut summary.expired,
            "canceled" => &mut summary.canceled,
            _ => continue,
        };
        bucket.count = count;
        bucket.amount_idr = amount;
    }
    Ok(summary)
}

/// ---------------------------------------------------------------------------
/// Refund-record (migrasi 0021). BACA DULU SEBELUM MENGUBAH:
/// - Klien QRIS di modul ini HANYA punya: create, GetStatus, cancel
///   (lihat `GobizClient`). TIDAK ADA endpoint refund uang yang terverifikasi
///   di kode maupun dokumen pohon ini, dan komentar di
///   `resolve_needs_review_order` menegaskan refund diselesaikan manual
///   di luar aplikasi. Karena itu endpoint ini TIDAK PERNAH memanggil
///   provider dan TIDAK PERNAH menggerakkan uang.
/// - Alur yang diharapkan: admin mengembalikan uang lewat dashboard
///   Gobiz secara manual, lalu MENCATATNYA di sini. `external_ref`
///   adalah nomor referensi pengembalian dari dashboard tersebut.
/// - TIDAK ADA pergerakan kuota di endpoint ini. Kompensasi kuota
///   dilakukan lewat jalur adjust kuota area lain; field
///   `compensation_note` di sini hanya catatan bebas untuk admin.
/// - Aturan refund yang diimplementasikan (satu aturan, didokumentasi):
///   refund PARSIAL BERTAHAP diizinkan, dengan TOTAL kumulatif semua
///   refund untuk satu order TIDAK BOLEH melebihi nominal order.
///   Konsekuensinya, "satu refund penuh per order" terpenuhi otomatis:
///   begitu total mencapai nominal penuh, refund berikutnya (nominal
///   > 0 apa pun) ditolak karena melampaui sisa. Duplikasi refund
///   penuh = percobaan kedua setelah total penuh -> ditolak.
/// ---------------------------------------------------------------------------

/// Satu baris pencatatan refund admin (tabel `refund_records`).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RefundRecordView {
    pub id: String,
    pub order_id: String,
    pub amount_idr: u64,
    pub reason: String,
    pub external_ref: Option<String>,
    pub compensation_note: Option<String>,
    pub recorded_by: String,
    pub created_at: NaiveDateTime,
}

/// Validasi murni field refund (tanpa DB): nominal > 0, alasan wajib
/// (setelah trim, maks 500 karakter), referensi/catatan opsional
/// (maks 191 / 500 karakter). Mengembalikan nilai yang sudah di-trim.
pub fn validate_refund_fields(
    amount_idr: u64,
    reason: &str,
    external_ref: Option<&str>,
    compensation_note: Option<&str>,
) -> Result<(u64, String, Option<String>, Option<String>), AppError> {
    if amount_idr == 0 {
        return Err(AppError::bad_request(
            "Nominal refund harus lebih dari 0",
        ));
    }
    let reason = reason.trim().to_owned();
    if reason.is_empty() {
        return Err(AppError::bad_request("Alasan refund wajib diisi"));
    }
    if reason.chars().count() > 500 {
        return Err(AppError::bad_request(
            "Alasan refund maksimal 500 karakter",
        ));
    }
    let external_ref = external_ref
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if let Some(value) = &external_ref {
        if value.chars().count() > 191 {
            return Err(AppError::bad_request(
                "Referensi eksternal maksimal 191 karakter",
            ));
        }
    }
    let compensation_note = compensation_note
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if let Some(value) = &compensation_note {
        if value.chars().count() > 500 {
            return Err(AppError::bad_request(
                "Catatan kompensasi maksimal 500 karakter",
            ));
        }
    }
    Ok((amount_idr, reason, external_ref, compensation_note))
}

/// Aturan cap kumulatif (murni, dipakai tes): total refund setelah
/// penambahan ini tidak boleh melebihi nominal order.
pub fn refund_total_after(
    already_refunded_idr: u64,
    new_amount_idr: u64,
    order_amount_idr: u64,
) -> Result<u64, AppError> {
    let total = already_refunded_idr.saturating_add(new_amount_idr);
    if total > order_amount_idr {
        return Err(AppError::conflict(
            "Total refund melebihi nominal order (termasuk refund yang sudah tercatat)",
        ));
    }
    Ok(total)
}

/// Catat refund admin untuk satu order. Menolak: order tidak ada (404),
/// order yang tidak pernah lunas (`paid_at` NULL — tidak ada bukti
/// paid, apa pun statusnya saat ini), dan nominal yang membuat total
/// kumulatif melebihi nominal order (409). Berjalan dalam satu
/// transaksi: baca order + total refund lama + insert dilakukan
/// atomik. TIDAK mengubah status order, TIDAK mengubah kuota, TIDAK
/// memanggil provider. Audit ditulis pemanggil (handler api.rs) lewat
/// `record_admin_activity` yang sudah ada.
pub async fn record_refund(
    pool: &MySqlPool,
    order_id: &Uuid,
    amount_idr: u64,
    reason: &str,
    external_ref: Option<&str>,
    compensation_note: Option<&str>,
    recorded_by: &str,
) -> Result<RefundRecordView, AppError> {
    let (amount_idr, reason, external_ref, compensation_note) =
        validate_refund_fields(amount_idr, reason, external_ref, compensation_note)?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| AppError::internal("Refund tidak dapat dicatat"))?;
    // B11: kunci baris order di dalam transaksi (SELECT ... FOR UPDATE)
    // SEBELUM membaca SUM refund — dulu SELECT biasa tanpa lock, jadi
    // dua pencatatan bersamaan sama-sama membaca total lama 0 dan
    // sama-sama lolos cap, total tercatat bisa 2x nominal order.
    let order = sqlx::query_as::<_, (u64, String, Option<NaiveDateTime>)>(
        "SELECT amount_idr, status, paid_at FROM package_orders WHERE id = ? FOR UPDATE",
    )
    .bind(order_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AppError::internal("Order tidak dapat dibaca"))?;
    let Some((order_amount_idr, order_status, paid_at)) = order else {
        return Err(AppError::not_found("Order tidak ditemukan"));
    };
    // K23: gerbang refund = status paid/granted ATAU paid_at terisi.
    // Dulu hanya paid_at: order yang sah lunas tapi paid_at-nya NULL
    // (string paid_at gagal diparsing di cabang Paid) tidak
    // bisa dicatat refund-nya sama sekali. Status paid/granted sendiri
    // hanya tercapai setelah Paid + nominal cocok, jadi status adalah
    // bukti lunas yang sah tanpa paid_at.
    if paid_at.is_none() && order_status != "paid" && order_status != "granted" {
        return Err(AppError::conflict(
            "Order belum pernah lunas (tidak ada bukti paid); refund tidak dapat dicatat",
        ));
    }
    let already: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(amount_idr), 0) AS SIGNED) FROM refund_records WHERE order_id = ?",
    )
    .bind(order_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AppError::internal("Total refund lama tidak dapat dibaca"))?;
    let already = if already < 0 { 0 } else { already as u64 };
    refund_total_after(already, amount_idr, order_amount_idr)?;
    let id = Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO refund_records (id, order_id, amount_idr, reason, external_ref, \
         compensation_note, recorded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6))",
    )
    .bind(&id)
    .bind(order_id.to_string())
    .bind(amount_idr)
    .bind(&reason)
    .bind(&external_ref)
    .bind(&compensation_note)
    .bind(recorded_by)
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::internal("Refund tidak dapat dicatat"))?;
    tx.commit()
        .await
        .map_err(|_| AppError::internal("Refund tidak dapat dicatat"))?;
    sqlx::query_as::<_, RefundRecordView>(
        "SELECT id, order_id, amount_idr, reason, external_ref, compensation_note, \
         recorded_by, created_at FROM refund_records WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Refund tidak dapat dibaca kembali"))
}

/// Total refund tercatat untuk satu order (B14). Dipakai gerbang
/// resolve; 0 bila belum ada refund tercatat.
pub async fn refund_total_for_order(
    pool: &MySqlPool,
    order_id: &str,
) -> Result<u64, AppError> {
    let total: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(amount_idr), 0) AS SIGNED) FROM refund_records WHERE order_id = ?",
    )
    .bind(order_id)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Total refund order tidak dapat dibaca"))?;
    Ok(if total < 0 { 0 } else { total as u64 })
}

/// Daftar refund yang tercatat untuk satu order (terbaru dulu).
pub async fn list_refunds_for_order(
    pool: &MySqlPool,
    order_id: &Uuid,
) -> Result<Vec<RefundRecordView>, AppError> {
    sqlx::query_as::<_, RefundRecordView>(
        "SELECT id, order_id, amount_idr, reason, external_ref, compensation_note, \
         recorded_by, created_at FROM refund_records WHERE order_id = ? \
         ORDER BY created_at DESC",
    )
    .bind(order_id.to_string())
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Daftar refund tidak dapat dibaca"))
}

pub async fn waiting_order_for_member(
    pool: &MySqlPool,
    member_id: &Uuid,
) -> Result<Option<PackageOrderRow>, AppError> {
    sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders \
         WHERE member_id = ? AND status = 'waiting_payment' \
         ORDER BY created_at DESC LIMIT 1"
    ))
    .bind(member_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Order menunggu tidak dapat dibaca"))
}

/// Notifikasi panel B2 untuk order yang BARU parkir needs_review.
/// Menggantikan alert kanal env lama (`alert_with_store`) di jalur
/// sweep/grant: satu sumber (kanal panel baru), tanpa duplikat.
/// Jejak audit/aktivitas tetap ditulis dalam semua kondisi; kirim
/// Telegram fire-and-forget (kegagalan hanya jadi log). Lookup kode
/// member gagal → kirim dilewati, audit tetap tercatat. Dipanggil
/// HANYA pada transisi baru (changed==true), bukan pengulangan.
async fn notify_needs_review_panel(
    store: &AdminStore,
    pool: &MySqlPool,
    order: &PackageOrderRow,
    status_label: &str,
    audit_title: &str,
    audit_detail: &str,
) {
    crate::alerts::record_alert_activity(store, audit_title, audit_detail).await;
    let Ok(member_uuid) = Uuid::parse_str(&order.member_id) else {
        return;
    };
    let Some(member) = store.member_by_id(member_uuid).await.ok().flatten() else {
        return;
    };
    let Some(code) = member.member_code.filter(|value| !value.is_empty()) else {
        return;
    };
    // updated_at baris yang baru dibaca = waktu transisi needs_review.
    let (title, text) = crate::telegram_settings::stuck_order_message(
        &code,
        &order.id,
        &order.package_name,
        order.amount_idr,
        status_label,
        order.updated_at,
    );
    crate::alerts::notify_admin(pool.clone(), store.credential_cipher(), title, text);
}

async fn set_order_status(
    pool: &MySqlPool,
    order_id: &str,
    from_status: &str,
    to_status: &str,
    mutation_ref: Option<&str>,
    last_error: Option<&str>,
) -> Result<bool, AppError> {
    let updated = sqlx::query(
        "UPDATE package_orders SET status = ?, mutation_ref = COALESCE(?, mutation_ref), \
         last_error = ?, updated_at = UTC_TIMESTAMP(6) \
         WHERE id = ? AND status = ?",
    )
    .bind(to_status)
    .bind(mutation_ref)
    .bind(last_error)
    .bind(order_id)
    .bind(from_status)
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Status order tidak dapat diubah"))?;
    Ok(updated.rows_affected() == 1)
}

// ---------------------------------------------------------------------------
// Kill switch (audit flow 2026-10-26, B15, keputusan D3, Fase 3)
// ---------------------------------------------------------------------------

/// Keputusan murni gerbang kill switch untuk satu order waiting:
/// batalkan HANYA bila order masih waiting, belum terbukti dibayar
/// (`paid_at` kosong), dan kill switch sedang off. Order yang sudah
/// terbayar (status `paid`/`granted`, atau `paid_at` terisi) TIDAK
/// PERNAH dibatalkan dari sini — perlindungan uang mengalahkan
/// pembatalan.
pub fn kill_switch_cancels_waiting(status: &str, paid: bool, qris_enabled: bool) -> bool {
    status == "waiting_payment" && !paid && !qris_enabled
}

/// Keputusan murni re-check terminal: order yang dibatalkan kill switch
/// TIDAK boleh auto-grant lewat re-check B10, sekalipun Gobiz
/// kemudian melaporkan Paid. Pembayaran telanjur masuk untuk order
/// seperti ini ditangani jalur resolve-berbukti admin, bukan
/// sweep/verify otomatis. Order `canceled` TANPA tanda ini (batal
/// member, batal manual lain) tetap mengikuti perilaku B10.
pub fn kill_switch_blocks_terminal_recheck(status: &str, kill_switch_canceled: bool) -> bool {
    status == "canceled" && kill_switch_canceled
}

/// Batalkan SATU order waiting atas nama kill switch. Invoice Gobiz
/// dibatalkan best-effort: gagal cancel di Gobiz TIDAK menggagalkan
/// pembatalan lokal, karena tanda `kill_switch_canceled` sudah
/// memblokir auto-grant berikutnya; invoice yang masih bisa dibayar
/// setelah itu hanya bisa di-grant lewat resolve-berbukti admin. CAS `waiting_payment + paid_at IS NULL ->
/// canceled` menjaga balapan: order yang keburu lunas/grant di antara
/// pembacaan dan UPDATE ini tidak tersentuh (mengembalikan false).
/// Mengembalikan true bila baris ini yang dibatalkan.

/// Kredensial cancel untuk kill switch (dibangun sekali dari settings
/// + cipher; dekripsi gagal -> None -> cancel provider dilewati,
/// pembatalan lokal tetap jalan).
pub(crate) struct QrisCancelCreds {
    pub gobiz_api_key: Option<String>,
    pub gobiz_base_url: String,
}

impl QrisCancelCreds {
    pub(crate) fn from_settings(settings: &QrisSettings, config: &AppConfig) -> Self {
        let cipher = crate::provider_config::CredentialCipher::new(
            config.api_key_encryption_key.as_deref(),
        );
        Self {
            gobiz_api_key: settings
                .gobiz_api_key_ciphertext
                .as_deref()
                .and_then(|ciphertext| cipher.decrypt(ciphertext).ok()),
            gobiz_base_url: settings.gobiz_base_url_effective(),
        }
    }
}

/// Status pembayaran satu order dari Gobiz — cabang TUNGGAL untuk
/// verify terminal, verify waiting, dan resolve.
/// Mengembalikan `Ok(None)` bila provider_order_id hilang —
/// pemanggil yang memutuskan: terminal -> outcome apa adanya;
/// waiting/resolve -> error internal.
/// Gobiz memakai base URL + key dari settings; key hilang ->
/// `qris_not_configured` (fail-closed, dihitung sweep sebagai
/// kegagalan check, bukan grant).
pub(crate) async fn check_order_payment(
    pool: &MySqlPool,
    config: &AppConfig,
    order: &PackageOrderRow,
) -> Result<Option<QrisPaymentStatus>, AppError> {
    let Some(payment_id) = order.provider_order_id.clone() else {
        return Ok(None);
    };
    let settings = load_qris_settings(pool).await?;
    let api_key = settings
        .gobiz_api_key_ciphertext
        .as_deref()
        .and_then(|ciphertext| decrypt_setting(&cipher_or_unavailable(config), ciphertext))
        .ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "qris_not_configured",
                "Pembayaran belum dikonfigurasi admin.",
            )
        })?;
    let client = crate::gobiz::GobizClient::new(&settings.gobiz_base_url_effective())?;
    let status = client
        .get_status(&api_key, &payment_id)
        .await
        .map_err(|error| error.to_app_error())?;
    Ok(Some(status))
}

pub(crate) async fn cancel_waiting_order_for_kill_switch(
    pool: &MySqlPool,
    creds: &QrisCancelCreds,
    order: &PackageOrderRow,
) -> Result<bool, AppError> {
    // Prasyarat yang sama dengan kill_switch_cancels_waiting, tanpa
    // parameter enabled (pemanggil sudah memutuskan kill switch off).
    if order.status != "waiting_payment" || order.paid_at.is_some() {
        return Ok(false);
    }
    // Best-effort: batalkan tagihan di provider dulu agar tidak bisa
    // dibayar setelah pembatalan lokal. Tanpa kredensial provider
    // (belum dikonfigurasi) atau bila cancel gagal, pembatalan lokal
    // tetap jalan — tanda kill_switch_canceled yang menjaga dari
    // auto-grant, bukan tagihan provider.
    if let (Some(api_key), Some(payment_id)) = (
        creds.gobiz_api_key.as_deref(),
        order.provider_order_id.as_deref(),
    ) {
        match crate::gobiz::GobizClient::new(&creds.gobiz_base_url) {
            Ok(client) => {
                if let Err(cancel_error) = client.cancel(api_key, payment_id).await {
                    tracing::warn!(?cancel_error, order_id = %order.id, "Cancel invoice Gobiz untuk kill switch gagal (best-effort); pembatalan lokal tetap jalan, auto-grant diblokir tanda kill_switch_canceled");
                }
            }
            Err(error) => {
                tracing::warn!(?error, order_id = %order.id, "Klien Gobiz untuk cancel kill switch tidak dapat dibuat; pembatalan lokal tetap jalan");
            }
        }
    }
    let updated = sqlx::query(
        "UPDATE package_orders SET status = 'canceled', kill_switch_canceled = 1, \
         last_error = 'Dibatalkan kill switch: order belum dibayar saat QRIS dinonaktifkan', \
         updated_at = UTC_TIMESTAMP(6) \
         WHERE id = ? AND status = 'waiting_payment' AND paid_at IS NULL",
    )
    .bind(&order.id)
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Order tidak dapat dibatalkan"))?;
    Ok(updated.rows_affected() == 1)
}

/// Batalkan SEMUA order waiting yang belum dibayar saat kill switch
/// dimatikan (dipanggil handler pengaturan QRIS setelah save).
/// Mengembalikan (dibatalkan, terlewat-karena-balapan). Kegagalan DB
/// per order dicatat dan dilewati — pembatalan yang terlewat tetap
/// tertangkap gerbang `verify_and_grant` saat order itu diverifikasi
/// berikutnya, jadi tidak ada order waiting yang lolos permanen.
pub(crate) async fn cancel_all_waiting_orders(
    pool: &MySqlPool,
    config: &AppConfig,
) -> (usize, usize) {
    let creds = match load_qris_settings(pool).await {
        Ok(settings) => QrisCancelCreds::from_settings(&settings, config),
        Err(error) => {
            tracing::warn!(?error, "Gagal membaca pengaturan QRIS untuk cancel kill switch; cancel tagihan provider dilewati, pembatalan lokal tetap jalan");
            QrisCancelCreds {
                gobiz_api_key: None,
                gobiz_base_url: crate::gobiz::DEFAULT_GOBIZ_BASE_URL.to_owned(),
            }
        }
    };
    let rows = match sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders \
         WHERE status = 'waiting_payment' AND paid_at IS NULL ORDER BY created_at ASC"
    ))
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(?error, "Gagal membaca order waiting untuk cancel kill switch");
            return (0, 0);
        }
    };
    let mut canceled = 0usize;
    let mut skipped = 0usize;
    for order in &rows {
        match cancel_waiting_order_for_kill_switch(pool, &creds, order).await {
            Ok(true) => canceled += 1,
            Ok(false) => skipped += 1,
            Err(error) => {
                tracing::warn!(?error, order_id = %order.id, "Cancel kill switch gagal untuk order ini; gerbang verify akan menangkapnya bila diverifikasi");
                skipped += 1;
            }
        }
    }
    (canceled, skipped)
}

// ---------------------------------------------------------------------------
// Orkestrasi: create / verify_and_grant / sweep
// ---------------------------------------------------------------------------

fn pool_or_unavailable(store: &AdminStore) -> Result<MySqlPool, AppError> {
    store.pool().ok_or_else(|| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "qris_database_unavailable",
            "Pembayaran belum tersedia (database tidak terpasang).",
        )
    })
}

fn cipher_or_unavailable(config: &AppConfig) -> CredentialCipher {
    CredentialCipher::new(config.api_key_encryption_key.as_deref())
}

/// Buat order + QRIS. Mengembalikan (view, created_baru).
/// Waiting dibatasi per (member, paket) (audit 2026-10-25, B9): order
/// waiting paket yang SAMA dikembalikan apa adanya; order waiting paket
/// BERBEDA ditolak 409 eksplisit (bukan diam-diam mengembalikan QR
/// paket yang salah). Pengecekan paket aktif / harga 0 tetap terjadi
/// SEBELUM pengecekan waiting, jadi waiting paket yang sudah
/// dinonaktifkan tetap bisa dibayar lewat daftar order / proxy QR —
/// hanya tombol Beli yang menolaknya (catatan audit B9, dipertahankan).
/// Buying requires a usable key: revoked/disabled keys are refused with a
/// clear message BEFORE any payment (audit 2026-10-25, B3). Expired keys
/// stay buyable — buying is exactly how they get renewed.
pub async fn ensure_key_buyable(store: &AdminStore, member_id: Uuid) -> Result<(), AppError> {
    if let Some((summary, _)) = store.member_key(member_id).await {
        if summary.status == "revoked" || summary.status == "disabled" {
            return Err(AppError::forbidden(
                "Kunci member sudah tidak aktif sehingga tidak dapat membeli paket. Hubungi admin untuk kunci baru.",
            ));
        }
    }
    Ok(())
}

/// Preamble create order: validasi paket/harga, settings QRIS, kunci
/// member, guard per member, waiting per (member, paket), dan rate
/// limit 5 create/jam — lalu create Gobiz (satu-satunya jalur).
pub async fn create_member_order(
    store: &AdminStore,
    config: &AppConfig,
    member_id: Uuid,
    package: &AdminPackage,
) -> Result<(MemberOrderView, bool), AppError> {

    let pool = pool_or_unavailable(store)?;
    if !package.active {
        return Err(AppError::bad_request("Paket ini sudah tidak aktif"));
    }
    // Harga yang ditagih = harga katalog dipotong promo aktif; harga
    // inilah yang dikunci ke order (snapshot) dan dibuatkan QR-nya.
    let effective = crate::models::effective_price(package, Utc::now());
    if effective == 0 {
        return Err(AppError::bad_request(
            "Paket gratis tidak dibeli lewat QRIS",
        ));
    }
    let settings = load_qris_settings(&pool).await?;
    if !settings.enabled {
        return Err(AppError::forbidden("Pembelian paket sedang tidak tersedia"));
    }
    ensure_key_buyable(store, member_id).await?;
    // Serialisasi create per member (K21): cek waiting + create +
    // insert tidak boleh disalip create lain member yang sama
    // (anti-abuse); create member lain tidak ikut tertahan.
    let _guard = member_create_guard(member_id).await;
    // B9: waiting per (member, paket). Paket sama -> kembalikan order
    // itu (tanpa create baru, tanpa hitung rate limit). Paket berbeda
    // -> 409 eksplisit yang menyebut paket yang sedang menunggu, agar
    // member menyelesaikan/membatalkan order itu dulu.
    if let Some(existing) = waiting_order_for_member(&pool, &member_id).await? {
        if existing.package_id == package.id.to_string() {
            return Ok((existing.member_view(), false));
        }
        return Err(AppError::conflict(format!(
            "Masih ada order menunggu untuk paket {} — selesaikan atau batalkan order itu dulu sebelum membeli paket {}",
            existing.package_name, package.name,
        )));
    }
    // B8: hitung SEMUA create sukses dalam 1 jam terakhir, tanpa
    // memandang status order saat ini. Definisi lama (hanya status
    // waiting) tidak pernah bisa mencapai ambang: bila ada waiting,
    // early-return di atas sudah berjalan duluan; bila tidak ada,
    // hitungannya selalu 0. Catatan urutan: audit menyarankan cek rate
    // limit SEBELUM early-return, tapi dengan definisi baru ini
    // early-return waiting TIDAK mengonsumsi create (tidak ada QR
    // baru), sehingga cek setelah early-return justru benar — dan
    // lebih ramah user (klik ulang paket yang sama tidak memakan
    // kuota rate limit). Order granted/canceled/expired dalam 1 jam
    // ikut terhitung; itu disengaja — rate limit anti-abuse, apa pun
    // nasib ordernya.
    let created_last_hour: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM package_orders WHERE member_id = ? \
         AND created_at > UTC_TIMESTAMP(6) - INTERVAL 1 HOUR",
    )
    .bind(member_id.to_string())
    .fetch_one(&pool)
    .await
    .map_err(|_| AppError::internal("Rate limit order tidak dapat dibaca"))?;
    if created_last_hour >= CREATE_ORDERS_PER_HOUR {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "qris_rate_limited",
            "Terlalu banyak pembuatan QR. Coba lagi nanti.",
        ));
    }
    // Create Gobiz di bawah (UUID order dibuat DULU agar bisa dipakai
    // sebagai order_id Gobiz). Guard per member masih dipegang (dibuat
    // di atas), rate limit sudah dicek, dan early-return waiting sudah
    // jalan.
    create_gobiz_member_order(&pool, config, member_id, package, &settings, effective)
        .await
}

/// Create order via Gobiz (satu-satunya jalur create):
/// - UUID order dibuat DULU dan dipakai sebagai `order_id` Gobiz (unik
///   per order; satu waiting per (member, paket) menjamin tak ada dua
///   order aktif yang berbagi order_id).
/// - `amount_idr` yang disimpan = `expected_amount` dari respon create
///   (harga paket + sufiks unik), BUKAN harga paket mentah — portal
///   member menampilkan `amount_idr` sebagai nominal bayar, dan
///   verifikasi grant mencocokkan `expected_amount` ini. `price_idr`
///   tetap harga paket efektif (tampil sebagai "harga paket" di riwayat
///   bila berbeda).
/// - `qris_token`/`qris_image_url` NULL (Gobiz tidak menyediakannya);
///   QR member di-render server-side dari `qris_string` (lihat
///   `order_qr`).
/// - `qris_expires_at` dari `expires_at` worker bila bisa diparsing,
///   else hitung lokal now + expiry.
/// - Cancel yatim best-effort via payment id Gobiz — kegagalan cancel
///   dicatat keras (log + `last_error`) agar admin bisa resolve manual
///   dari dashboard Gobiz. Keterbatasan ini didokumentasikan.
async fn create_gobiz_member_order(
    pool: &MySqlPool,
    config: &AppConfig,
    member_id: Uuid,
    package: &AdminPackage,
    settings: &QrisSettings,
    effective: u64,
) -> Result<(MemberOrderView, bool), AppError> {
    let api_key = settings
        .gobiz_api_key_ciphertext
        .as_deref()
        .and_then(|ciphertext| decrypt_setting(&cipher_or_unavailable(config), ciphertext))
        .ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "qris_not_configured",
                "Pembayaran belum dikonfigurasi admin.",
            )
        })?;
    let client = crate::gobiz::GobizClient::new(&settings.gobiz_base_url_effective())?;
    let order_id = Uuid::now_v7();
    let now = Utc::now();
    let expires_in_secs = settings.expiry_minutes * 60;
    let invoice = match client
        .create(
            &api_key,
            effective,
            &order_id.to_string(),
            &settings.gobiz_callback_url_effective(),
            expires_in_secs,
        )
        .await
    {
        Ok(invoice) => invoice,
        Err(error) => {
            tracing::warn!(?error, "Create Gobiz gagal");
            record_qris_error(pool, &format!("Create Gobiz gagal: {}", error.admin_message()))
                .await;
            if let Some(payment_id) = error.orphan_payment_id() {
                if let Err(cancel_error) = client.cancel(&api_key, payment_id).await {
                    tracing::error!(?cancel_error, member_id = %member_id, payment_id = %payment_id, amount = effective, "Cancel invoice Gobiz yatim gagal — invoice berbayar tanpa order");
                    record_qris_error(
                        pool,
                        &format!(
                            "Invoice Gobiz yatim gagal dibatalkan (payment {payment_id}, nominal {effective}); resolve manual dari dashboard Gobiz"
                        ),
                    )
                    .await;
                }
            }
            return Err(error.to_app_error());
        }
    };
    let expires_at = invoice
        .expires_at
        .unwrap_or(now + chrono::Duration::seconds(expires_in_secs));
    // Retry insert (K7) + guard conflict (K22).
    let mut insert_error = None;
    let mut guard_conflict = false;
    for attempt in 0..3 {
        match sqlx::query(
            "INSERT INTO package_orders (id, member_id, package_id, package_name, \
             price_idr, quota_hits, rate_limit_per_minute, valid_days, amount_idr, \
             status, provider_order_id, expected_amount, \
             qris_string, qris_expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting_payment', ?, ?, ?, ?, ?)",
        )
        .bind(order_id.to_string())
        .bind(member_id.to_string())
        .bind(package.id.to_string())
        .bind(&package.name)
        .bind(effective)
        .bind(package.included_hits)
        .bind(package.rate_limit_per_minute)
        .bind(settings.valid_days)
        .bind(invoice.expected_amount)
        .bind(&invoice.id)
        .bind(invoice.expected_amount)
        .bind(&invoice.qris_string)
        .bind(expires_at.naive_utc())
        .bind(now.naive_utc())
        .execute(pool)
        .await
        {
            Ok(_) => {
                insert_error = None;
                break;
            }
            Err(error) => {
                if crate::store::is_duplicate_key_error(&error) {
                    guard_conflict = true;
                    insert_error = Some(error);
                    break;
                }
                insert_error = Some(error);
                if attempt < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        100 * (attempt as u64 + 1),
                    ))
                    .await;
                }
            }
        }
    }
    if guard_conflict {
        if let Err(cancel_error) = client.cancel(&api_key, &invoice.id).await {
            tracing::error!(?cancel_error, member_id = %member_id, payment_id = %invoice.id, amount = effective, "Cancel invoice Gobiz yatim gagal — invoice berbayar tanpa order");
            record_qris_error(
                pool,
                &format!(
                    "Invoice Gobiz yatim gagal dibatalkan (payment {}, nominal {effective}); resolve manual dari dashboard Gobiz",
                    invoice.id
                ),
            )
            .await;
        }
        if let Some(existing) = waiting_order_for_member(pool, &member_id).await? {
            if existing.package_id == package.id.to_string() {
                return Ok((existing.member_view(), false));
            }
            return Err(AppError::conflict(format!(
                "Masih ada order menunggu untuk paket {} — selesaikan atau batalkan order itu dulu sebelum membeli paket {}",
                existing.package_name, package.name,
            )));
        }
        return Err(AppError::internal("Order tidak dapat dibuat. Coba lagi."));
    }
    if let Some(error) = insert_error {
        tracing::warn!(?error, "Insert order Gobiz gagal setelah create (3 percobaan)");
        if let Err(cancel_error) = client.cancel(&api_key, &invoice.id).await {
            tracing::error!(?cancel_error, member_id = %member_id, payment_id = %invoice.id, amount = effective, "Cancel invoice Gobiz yatim gagal — invoice berbayar tanpa order");
            record_qris_error(
                pool,
                &format!(
                    "Invoice Gobiz yatim gagal dibatalkan (payment {}, nominal {effective}); resolve manual dari dashboard Gobiz",
                    invoice.id
                ),
            )
            .await;
        }
        return Err(AppError::internal("Order tidak dapat dibuat. Coba lagi."));
    }
    let row = get_order(pool, &order_id)
        .await?
        .ok_or_else(|| AppError::internal("Order baru tidak ditemukan"))?;
    Ok((row.member_view(), true))
}

/// Verdict satu kali verifikasi order. Diserialisasi snake_case agar
/// bisa dipakai langsung sebagai field `outcome` respons resolve
/// (audit 2026-10-25, K2): "granted" | "already_granted" | "waiting" |
/// "expired" | "canceled" | "needs_review" | "rejected".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    Granted,
    AlreadyGranted,
    Waiting,
    Expired,
    Canceled,
    NeedsReview,
    /// Resolve sudah memverifikasi lewat check-status dan hasilnya
    /// MEMBUKTIKAN order belum lunas (pending/expired/canceled/
    /// not-found dari Gobiz): grant ditolak, status order TIDAK
    /// diubah. Berbeda dengan NeedsReview (tertahan tapi mungkin
    /// lunas) dan dari Err (prasyarat belum terpenuhi / upstream error).
    Rejected,
}

/// Verdict dari status baris hasil re-read, untuk call site CAS yang
/// kalah balapan (audit 2026-10-25, K3). Dipakai HANYA bila status
/// re-read bukan `paid` — baris `paid` harus didorong lewat grant_row
/// (pola mark-paid), bukan dipetakan ke verdict diam.
fn verdict_for_status(status: &str) -> VerifyOutcome {
    match status {
        "granted" => VerifyOutcome::AlreadyGranted,
        "expired" => VerifyOutcome::Expired,
        "canceled" => VerifyOutcome::Canceled,
        "needs_review" => VerifyOutcome::NeedsReview,
        _ => VerifyOutcome::Waiting,
    }
}

/// Re-check satu order terminal (`expired`/`canceled`) — B10.
/// Pengecualian B15 (Fase 3): order `canceled` bertanda kill switch
/// TIDAK di-re-check sama sekali — pulang `Canceled` apa adanya.
/// Order yang ditandai expired oleh sweep lokal bisa ternyata lunas di
/// Gobiz (bayar telat / settlement lag): dulu verify langsung pulang
/// `Expired`/`Canceled` tanpa re-check, dan sweep rutin tidak pernah
/// memungut status terminal, sehingga uang lunas menggantung tanpa
/// grant sampai admin memanggil resolve mentah. Kini SATU re-check
/// Gobiz dilakukan: hanya `Paid` + nominal COCOK yang dilanjutkan ke
/// mark-paid + grant (CAS dari status terminal saat ini); hasil lain
/// mengembalikan outcome terminal aslinya TANPA mengubah status.
/// Check yang error dipropagasikan (bukan disamarkan jadi Expired)
/// agar sweep menghitungnya sebagai kegagalan dan tombol member
/// menampilkan galat, bukan status yang menyesatkan.
async fn verify_terminal_order(
    store: &AdminStore,
    config: &AppConfig,
    order: &PackageOrderRow,
) -> Result<(MemberOrderView, VerifyOutcome), AppError> {
    let pool = pool_or_unavailable(store)?;
    let view = order.member_view();
    let original = if order.status == "expired" {
        VerifyOutcome::Expired
    } else {
        VerifyOutcome::Canceled
    };
    let order_uuid = Uuid::parse_str(&order.id)
        .map_err(|_| AppError::internal("Member order tidak valid"))?;
    let member_uuid = Uuid::parse_str(&order.member_id)
        .map_err(|_| AppError::internal("Member order tidak valid"))?;
    // Member tidak aktif = grant tidak bisa mendarat; kembalikan outcome
    // terminal apa adanya (status tidak berubah, resolve admin menjadi
    // jalurnya setelah member diaktifkan lagi).
    match store.member_by_id(member_uuid).await? {
        Some(member) if member.status == "active" => {}
        _ => return Ok((view, original)),
    }
    // B15 (Fase 3, D3): order yang dibatalkan kill switch TIDAK
    // auto-grant di sini, sekalipun Gobiz kemudian melaporkan Paid.
    // Pembayaran telanjur masuk untuk order seperti ini hanya bisa
    // di-grant lewat resolve-berbukti admin — bukan sweep,
    // webhook, atau tombol member. Order `canceled` tanpa tanda ini
    // tetap mengikuti re-check B10 di bawah.
    if kill_switch_blocks_terminal_recheck(&order.status, order.kill_switch_canceled != 0) {
        return Ok((view, original));
    }
    let status = match check_order_payment(&pool, config, order)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "Cek status QRIS gagal (re-check order terminal)");
            error
        })? {
        Some(status) => status,
        // Tanpa identifier provider, re-check tidak mungkin: outcome
        // terminal dipertahankan apa adanya.
        None => return Ok((view, original)),
    };
    match status {
        QrisPaymentStatus::Paid {
            amount,
            mutation_ref,
            paid_at,
        } => {
            let expected = order.expected_amount.ok_or_else(|| AppError::internal("Order tanpa nominal bayar Gobiz"))?;
            if amount != expected {
                // Bukti bayar ada tapi nominal beda: parkir needs_review
                // dengan penanda mismatch (resolve berikutnya fast-refuse
                // lewat guard yang sama seperti jalur waiting).
                let changed = set_order_status(
                    &pool,
                    &order.id,
                    &order.status,
                    "needs_review",
                    mutation_ref.as_deref(),
                    Some("Nominal bayar tidak sama dengan order"),
                )
                .await?;
                let row = get_order(&pool, &order_uuid).await?.unwrap_or_else(|| order.clone());
                if !changed {
                    return Ok(match row.status.as_str() {
                        "granted" => (row.member_view(), VerifyOutcome::AlreadyGranted),
                        "paid" => grant_row(store, &pool, &row).await?,
                        _ => (row.member_view(), verdict_for_status(&row.status)),
                    });
                }
                // B2 (28 Okt 2026): re-check order terminal ini sebelumnya
                // memarkir needs_review TANPA alert sama sekali — kini
                // dialihkan ke kanal panel baru (satu sumber, tanpa
                // duplikat kanal env lama).
                notify_needs_review_panel(
                    store,
                    &pool,
                    &row,
                    "Perlu ditinjau (selisih nominal)",
                    "Order perlu tinjauan",
                    &format!(
                        "Order {} parkir needs_review (re-check terminal): nominal bayar tidak sama dengan order.",
                        row.id
                    ),
                )
                .await;
                return Ok((row.member_view(), VerifyOutcome::NeedsReview));
            }
            let marked = sqlx::query(
                "UPDATE package_orders SET status = 'paid', paid_at = ?, \
                 mutation_ref = ?, updated_at = UTC_TIMESTAMP(6) \
                 WHERE id = ? AND status = ?",
            )
            .bind(paid_at)
            .bind(mutation_ref.as_deref())
            .bind(order.id.clone())
            .bind(order.status.clone())
            .execute(&pool)
            .await
            .map_err(|_| AppError::internal("Order tidak dapat ditandai lunas"))?;
            if marked.rows_affected() != 1 {
                let row = get_order(&pool, &order_uuid).await?.unwrap_or_else(|| order.clone());
                return Ok(match row.status.as_str() {
                    "granted" => (row.member_view(), VerifyOutcome::AlreadyGranted),
                    "paid" => grant_row(store, &pool, &row).await?,
                    _ => (row.member_view(), original),
                });
            }
            let row = get_order(&pool, &order_uuid)
                .await?
                .ok_or_else(|| AppError::internal("Order tidak ditemukan setelah ditandai lunas"))?;
            grant_row(store, &pool, &row).await
        }
        // Belum/tidak lunas menurut provider: outcome terminal dipertahankan.
        _ => Ok((view, original)),
    }
}

/// Verifikasi satu order sampai tuntas (dipakai webhook, tombol cek, sweep).
/// Tidak pernah menurunkan status paid, tidak pernah grant tanpa nominal
/// cocok, dan grant hanya lewat store::grant_package_order (atomik).
pub async fn verify_and_grant(
    store: &AdminStore,
    config: &AppConfig,
    order_id: Uuid,
) -> Result<(MemberOrderView, VerifyOutcome), AppError> {
    let pool = pool_or_unavailable(store)?;
    let order = get_order(&pool, &order_id)
        .await?
        .ok_or_else(|| AppError::not_found("Order tidak ditemukan"))?;
    let view = |row: &PackageOrderRow| row.member_view();
    match order.status.as_str() {
        "granted" => return Ok((view(&order), VerifyOutcome::AlreadyGranted)),
        "needs_review" => return Ok((view(&order), VerifyOutcome::NeedsReview)),
        // B10: expired/canceled TIDAK langsung pulang — satu re-check
        // Gobiz dulu (bayar telat yang terbukti lunas tetap di-grant).
        "expired" | "canceled" => {
            return verify_terminal_order(store, config, &order).await;
        }
        _ => {}
    }
    // B15 (Fase 3, D3): kill switch off membatalkan order waiting yang
    // BELUM dibayar — termasuk yang lolos dari cancel massal saat
    // toggle dimatikan (mis. pengaturan diubah langsung di DB, atau
    // cancel massal gagal untuk order ini). Gerbang ini berjalan di
    // SEMUA jalur verify (tombol member, sweep, webhook) karena
    // ketiganya bermuara di sini. Order yang sudah `paid`/`granted`
    // tidak pernah sampai ke cabang ini (pulang lebih dulu di atas),
    // dan order waiting yang `paid_at`-nya terisi tidak dibatalkan
    // (CAS di cancel_waiting_order_for_kill_switch mensyaratkan
    // paid_at IS NULL) — pengecualian keras "sudah terbayar tetap
    // grant" terjaga di kedua lapis.
    if order.status == "waiting_payment" {
        match load_qris_settings(&pool).await {
            Ok(settings) if !settings.enabled => {
                let creds = QrisCancelCreds::from_settings(&settings, config);
                let _ =
                    cancel_waiting_order_for_kill_switch(&pool, &creds, &order).await;
                // Re-read adalah otoritas hasil akhir: bila CAS kalah
                // karena order keburu lunas/grant, verdict mengikuti
                // status baru itu (grant untuk yang sudah lunas),
                // bukan `canceled` palsu.
                let row = get_order(&pool, &order_id).await?.unwrap_or(order);
                return Ok(match row.status.as_str() {
                    "granted" => (view(&row), VerifyOutcome::AlreadyGranted),
                    "paid" => grant_row(store, &pool, &row).await?,
                    "canceled" => (view(&row), VerifyOutcome::Canceled),
                    _ => (view(&row), verdict_for_status(&row.status)),
                });
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(?error, "Gagal membaca pengaturan QRIS untuk gerbang kill switch; lanjut verifikasi normal (tidak ada grant tanpa pembayaran)");
            }
        }
    }
    let member_uuid = Uuid::parse_str(&order.member_id)
        .map_err(|_| AppError::internal("Member order tidak valid"))?;
    // Member dinonaktifkan di tengah jalan: TAHAN grant TANPA mengubah
    // status order (audit 2026-10-25, B7). Kode lama memindahkan order
    // ke needs_review di sini — padahal order itu masih waiting_payment
    // dan BELUM TERBUKTI lunas — sehingga order tersebut menjadi
    // kandidat grant via resolve tanpa pembayaran. Sekarang status
    // dipertahankan (waiting_payment, atau paid bila sudah terverifikasi
    // lunas sebelumnya) dan verdict NeedsReview hanya berarti "ditahan,
    // belum dibayar / belum boleh di-grant". Sweep akan memproses
    // order ini lagi setelah member diaktifkan; resolve tidak akan
    // pernah melihatnya sebagai needs_review berbukti lunas.
    match store.member_by_id(member_uuid).await? {
        Some(member) if member.status == "active" => {}
        Some(_) => {
            tracing::info!(order_id = %order.id, "Verify ditahan: member dinonaktifkan; status order dipertahankan");
            return Ok((view(&order), VerifyOutcome::NeedsReview));
        }
        None => {
            tracing::info!(order_id = %order.id, "Verify ditahan: member tidak ditemukan; status order dipertahankan");
            return Ok((view(&order), VerifyOutcome::NeedsReview));
        }
    }
    // Sudah terverifikasi lunas sebelumnya: langsung grant (pulih dari
    // crash antara verify dan grant).
    if order.status == "paid" {
        return grant_row(store, &pool, &order).await;
    }
    let status = match check_order_payment(&pool, config, &order)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "Cek status QRIS gagal");
            error
        })? {
        Some(status) => status,
        None => {
            return Err(AppError::internal("Order tanpa ID pembayaran Gobiz"));
        }
    };
    match status {
        QrisPaymentStatus::Paid {
            amount,
            mutation_ref,
            paid_at,
        } => {
            let expected = order.expected_amount.ok_or_else(|| AppError::internal("Order tanpa nominal bayar Gobiz"))?;
            if amount != expected {
                // K3: jangan buang bool CAS. Bila verifikator lain sudah
                // mengubah status (mis. menandai paid + grant), verdict
                // diturunkan dari baris hasil re-read, bukan verdict
                // lama yang menyesatkan.
                let changed = set_order_status(
                    &pool,
                    &order.id,
                    "waiting_payment",
                    "needs_review",
                    mutation_ref.as_deref(),
                    Some("Nominal bayar tidak sama dengan order"),
                )
                .await?;
                let row = get_order(&pool, &order_id).await?.unwrap_or(order);
                if !changed {
                    return Ok(match row.status.as_str() {
                        "granted" => (view(&row), VerifyOutcome::AlreadyGranted),
                        "paid" => grant_row(store, &pool, &row).await?,
                        _ => (view(&row), verdict_for_status(&row.status)),
                    });
                }
                // B2 (28 Okt 2026): alert kanal env lama dialihkan ke
                // kanal panel baru (satu sumber, tanpa duplikat).
                // Jejak audit/aktivitas tetap ditulis di helper.
                notify_needs_review_panel(
                    store,
                    &pool,
                    &row,
                    "Perlu ditinjau (selisih nominal)",
                    "Order perlu tinjauan",
                    &format!(
                        "Order {} parkir needs_review: nominal bayar tidak sama dengan order.",
                        row.id
                    ),
                )
                .await;
                return Ok((view(&row), VerifyOutcome::NeedsReview));
            }
            // Tandai paid dulu (WHERE status = waiting), lalu grant.
            let marked = sqlx::query(
                "UPDATE package_orders SET status = 'paid', paid_at = ?, \
                 mutation_ref = ?, updated_at = UTC_TIMESTAMP(6) \
                 WHERE id = ? AND status = 'waiting_payment'",
            )
            .bind(paid_at)
            .bind(mutation_ref.as_deref())
            .bind(order.id.clone())
            .execute(&pool)
            .await
            .map_err(|_| AppError::internal("Order tidak dapat ditandai lunas"))?;
            if marked.rows_affected() != 1 {
                // Disalip grant lain: baca ulang dan laporkan hasil akhir.
                let row = get_order(&pool, &order_id).await?.unwrap_or(order);
                return Ok(match row.status.as_str() {
                    "granted" => (view(&row), VerifyOutcome::AlreadyGranted),
                    // Another verifier already marked this order paid: drive
                    // the grant instead of misreporting Waiting (audit
                    // 2026-10-25, K5). grant_row's CAS makes a double grant
                    // impossible; a loser reports AlreadyGranted.
                    "paid" => grant_row(store, &pool, &row).await?,
                    _ => (view(&row), VerifyOutcome::Waiting),
                });
            }
            let row = get_order(&pool, &order_id).await?.unwrap_or(order);
            grant_row(store, &pool, &row).await
        }
        QrisPaymentStatus::Pending { .. } => {
            // Gobiz still says pending, but our local expiry passed:
            // close the order locally instead of blocking new creates
            // forever behind the one-waiting rule (audit 2026-10-25, K4).
            if Utc::now()
                > order
                    .qris_expires_at
                    .map(naive_to_utc)
                    .unwrap_or(Utc::now())
            {
                // K3: pola yang sama — verdict dari re-read bila CAS kalah.
                let changed =
                    set_order_status(&pool, &order.id, "waiting_payment", "expired", None, None)
                        .await?;
                let row = get_order(&pool, &order_id).await?.unwrap_or(order);
                if !changed {
                    return Ok(match row.status.as_str() {
                        "granted" => (view(&row), VerifyOutcome::AlreadyGranted),
                        "paid" => grant_row(store, &pool, &row).await?,
                        _ => (view(&row), verdict_for_status(&row.status)),
                    });
                }
                return Ok((view(&row), VerifyOutcome::Expired));
            }
            Ok((view(&order), VerifyOutcome::Waiting))
        }
        QrisPaymentStatus::Expired => {
            let changed =
                set_order_status(&pool, &order.id, "waiting_payment", "expired", None, None)
                    .await?;
            let row = get_order(&pool, &order_id).await?.unwrap_or(order);
            if !changed {
                return Ok(match row.status.as_str() {
                    "granted" => (view(&row), VerifyOutcome::AlreadyGranted),
                    "paid" => grant_row(store, &pool, &row).await?,
                    _ => (view(&row), verdict_for_status(&row.status)),
                });
            }
            Ok((view(&row), VerifyOutcome::Expired))
        }
        QrisPaymentStatus::Canceled => {
            let changed =
                set_order_status(&pool, &order.id, "waiting_payment", "canceled", None, None)
                    .await?;
            let row = get_order(&pool, &order_id).await?.unwrap_or(order);
            if !changed {
                return Ok(match row.status.as_str() {
                    "granted" => (view(&row), VerifyOutcome::AlreadyGranted),
                    "paid" => grant_row(store, &pool, &row).await?,
                    _ => (view(&row), verdict_for_status(&row.status)),
                });
            }
            Ok((view(&row), VerifyOutcome::Canceled))
        }
        QrisPaymentStatus::NotFound => {
            // ID tak dikenal Gobiz: jangan buru-buru expired; tunggu
            // sampai lewat expiry lokal, sweep berikutnya yang menutupnya.
            if Utc::now()
                > order
                    .qris_expires_at
                    .map(naive_to_utc)
                    .unwrap_or(Utc::now())
            {
                // K3: pola yang sama — verdict dari re-read bila CAS kalah.
                let changed =
                    set_order_status(&pool, &order.id, "waiting_payment", "expired", None, None)
                        .await?;
                let row = get_order(&pool, &order_id).await?.unwrap_or(order);
                if !changed {
                    return Ok(match row.status.as_str() {
                        "granted" => (view(&row), VerifyOutcome::AlreadyGranted),
                        "paid" => grant_row(store, &pool, &row).await?,
                        _ => (view(&row), verdict_for_status(&row.status)),
                    });
                }
                return Ok((view(&row), VerifyOutcome::Expired));
            }
            Ok((view(&order), VerifyOutcome::Waiting))
        }
    }
}

/// Admin resolve untuk order yang tertahan (audit 2026-10-25, B7+B10).
///
/// Menerima status `needs_review`, `expired`, DAN `canceled` — tetapi
/// JANGAN PERNAH grant dari klaim saja. Aturan bukti lunasnya satu:
/// - Order yang SUDAH PERNAH mencapai `paid` punya bukti bayar yang
///   tercatat (`paid_at` hanya ditulis cabang mark-paid setelah
///   check-status Paid + nominal cocok). Order seperti ini langsung
///   di-reset ke `paid` lalu di-grant.
/// - Order TANPA bukti (`paid_at` NULL — mis. needs_review warisan dari
///   jalur "member dinonaktifkan" yang lama, atau expired/canceled yang
///   ternyata dibayar di detik-detik akhir) WAJIB re-verifikasi lewat
///   check-status Gobiz order itu dulu (by provider_order_id;
///   nominal pembanding = `expected_amount`):
///   hanya `Paid` + nominal COCOK PERSIS
///   yang dilanjutkan (ditandai `paid` via CAS, lalu di-grant seperti
///   jalur normal). Hasil lain — Pending/Expired/Canceled/NotFound —
///   menghasilkan outcome `Rejected`: grant DITOLAK, status order TIDAK
///   diubah. `Paid` dengan nominal beda ditolak keras (conflict) dan
///   penanda mismatch dicap ke `last_error` agar resolve berikutnya
///   langsung menolak tanpa check ulang.
/// - TIDAK ADA endpoint refund uang QRIS (di luar cakupan perbaikan
///   ini): order mismatch / belum terbukti lunas diselesaikan manual
///   (refund / cek mutasi) di luar aplikasi.
///
/// Guard mismatch juga ditegakkan DI DALAM CAS reset (audit 2026-10-25,
/// K36, DUGAAN — belum terbukti dapat dicapai dari jalur aplikasi):
/// `WHERE ... AND last_error NOT LIKE '%Nominal bayar tidak sama%'`.
/// Ini hardening defense-in-depth, BUKAN perbaikan bug terbukti; bila
/// guard ini yang menggagalkan CAS, admin diminta reload (pesan sama
/// seperti race status).
///
/// Member harus aktif (diperiksa di sini DAN di dalam grant — lihat K1);
/// kunci non-aktif (revoked/disabled) membuat grant_row mengembalikan
/// order ke `needs_review` alih-alih grant — perilaku itu kini benar
/// ditegakkan grant_package_order, bukan sekadar klaim komentar.
///
/// B15 (Fase 3, D3): jalur ini adalah SATU-SATUNYA jalan grant bagi
/// order `canceled` bertanda kill switch yang ternyata dibayar
/// (pembayaran telanjur masuk) — admin yang memverifikasi bukti dan
/// menekan Grant ulang, bukan auto-grant sweep/verify.
pub async fn resolve_needs_review_order(
    store: &AdminStore,
    config: &AppConfig,
    order_id: Uuid,
) -> Result<(MemberOrderView, VerifyOutcome), AppError> {
    let pool = pool_or_unavailable(store)?;
    let order = get_order(&pool, &order_id)
        .await?
        .ok_or_else(|| AppError::not_found("Order tidak ditemukan"))?;
    // B10: expired/canceled kini bisa di-resolve (hanya bila terbukti
    // lunas, lihat di bawah). waiting_payment/paid/granted tetap
    // ditolak — jalurnya verify_and_grant, bukan resolve.
    match order.status.as_str() {
        "needs_review" | "expired" | "canceled" => {}
        other => {
            return Err(AppError::conflict(format!(
                "Order berstatus {other} — hanya order needs_review, expired, atau canceled yang dapat di-resolve"
            )));
        }
    }
    if order
        .last_error
        .as_deref()
        .unwrap_or_default()
        .contains("Nominal bayar tidak sama")
    {
        return Err(AppError::conflict(
            "Order needs_review karena nominal tidak sama — grant ulang tidak diizinkan; selesaikan manual (refund/cek mutasi).",
        ));
    }
    // The member must be active again first (mirrors verify_and_grant);
    // grant_package_order itself also checks member status (K1).
    let member_uuid = Uuid::parse_str(&order.member_id)
        .map_err(|_| AppError::internal("Member order tidak valid"))?;
    match store.member_by_id(member_uuid).await? {
        Some(member) if member.status == "active" => {}
        Some(_) => {
            return Err(AppError::conflict(
                "Member masih dinonaktifkan; aktifkan member dulu, baru grant ulang.",
            ));
        }
        None => {
            return Err(AppError::conflict(
                "Member tidak ditemukan; grant ulang tidak dapat dilanjutkan.",
            ));
        }
    }
    // B14: order yang SUDAH di-refund penuh TIDAK BOLEH di-grant —
    // member akan menerima uang kembali + kuota untuk order yang sama.
    // Cek di awal (pesan jelas, tanpa mengubah status) dan diulang
    // tepat sebelum grant_row di kedua jalur di bawah (refund yang
    // tercatat bersamaan dengan re-check tidak boleh menyalip).
    // Koreksi refund-record (batalkan/koreksi catatan) dilakukan manual
    // di database — tidak ada endpoint hapus refund-record — sampai
    // saat itu grant tetap diblokir. Defense-in-depth terakhir ada di
    // dalam transaksi grant_package_order sendiri.
    let refund_total = refund_total_for_order(&pool, &order.id).await?;
    if refund_total > 0 && refund_total >= order.amount_idr {
        return Err(AppError::conflict(
            "Order sudah di-refund penuh (total refund tercatat >= nominal order); grant ditolak sampai refund-record dikoreksi.",
        ));
    }
    // B7: order tanpa bukti bayar WAJIB re-verifikasi dulu (cabang
    // provider tunggal — Gobiz by provider_order_id).
    if order.paid_at.is_none() {
        let status = match check_order_payment(&pool, config, &order)
            .await
            .map_err(|error| {
                tracing::warn!(?error, "Cek status QRIS (resolve) gagal");
                error
            })? {
            Some(status) => status,
            None => {
                return Err(AppError::internal("Order tanpa ID pembayaran Gobiz"));
            }
        };
        match status {
            QrisPaymentStatus::Paid {
                amount,
                mutation_ref,
                paid_at,
            } => {
                let expected = order.expected_amount.ok_or_else(|| AppError::internal("Order tanpa nominal bayar Gobiz"))?;
                if amount != expected {
                    // Tolak keras + cap penanda mismatch (tanpa mengubah
                    // status) agar resolve berikutnya fast-refuse.
                    sqlx::query(
                        "UPDATE package_orders SET last_error = ?, \
                         updated_at = UTC_TIMESTAMP(6) WHERE id = ? AND status = ?",
                    )
                    .bind("Nominal bayar tidak sama dengan order (cek ulang resolve)")
                    .bind(order.id.clone())
                    .bind(order.status.clone())
                    .execute(&pool)
                    .await
                    .map_err(|_| {
                        AppError::internal("Penanda mismatch order tidak dapat disimpan")
                    })?;
                    return Err(AppError::conflict(
                        "Nominal bayar dari Gobiz tidak sama dengan order — grant ulang tidak diizinkan; selesaikan manual (refund/cek mutasi).",
                    ));
                }
                // Tandai paid via CAS dari status saat ini (guard
                // mismatch K36 ikut di dalam WHERE, sama seperti reset
                // di bawah). Kalah CAS -> re-read: granted berarti
                // sudah ter-grant, paid berarti dorong grant.
                let marked = sqlx::query(
                    "UPDATE package_orders SET status = 'paid', paid_at = ?, \
                     mutation_ref = ?, updated_at = UTC_TIMESTAMP(6) \
                     WHERE id = ? AND status = ? \
                     AND (last_error IS NULL OR last_error NOT LIKE '%Nominal bayar tidak sama%')",
                )
                .bind(paid_at)
                .bind(mutation_ref.as_deref())
                .bind(order.id.clone())
                .bind(order.status.clone())
                .execute(&pool)
                .await
                .map_err(|_| AppError::internal("Order tidak dapat ditandai lunas"))?;
                if marked.rows_affected() != 1 {
                    let row = get_order(&pool, &order_id).await?.unwrap_or(order);
                    return match row.status.as_str() {
                        "granted" => Ok((row.member_view(), VerifyOutcome::AlreadyGranted)),
                        "paid" => grant_row(store, &pool, &row).await,
                        _ => Err(AppError::conflict(
                            "Status order berubah selama proses; muat ulang dan coba lagi",
                        )),
                    };
                }
                let row = get_order(&pool, &order_id).await?.ok_or_else(|| {
                    AppError::internal("Order tidak ditemukan setelah ditandai lunas")
                })?;
                // B14: ulang cek refund tepat sebelum grant (refund yang
                // tercatat selama re-check tidak boleh menyalip).
                let refund_total = refund_total_for_order(&pool, &row.id).await?;
                if refund_total > 0 && refund_total >= row.amount_idr {
                    return Err(AppError::conflict(
                        "Order sudah di-refund penuh; grant ditolak.",
                    ));
                }
                return grant_row(store, &pool, &row).await;
            }
            // Terbukti BELUM lunas: tolak grant, status tidak diubah.
            // Bukan error HTTP — ini keputusan final percobaan resolve
            // ini (outcome `rejected`); admin bisa mencoba lagi nanti
            // (mis. setelah member benar-benar membayar) dan sweep
            // rutin tetap menjadi backstop.
            QrisPaymentStatus::Pending { .. }
            | QrisPaymentStatus::Expired
            | QrisPaymentStatus::Canceled
            | QrisPaymentStatus::NotFound => {
                let row = get_order(&pool, &order_id).await?.unwrap_or(order);
                return Ok((row.member_view(), VerifyOutcome::Rejected));
            }
        }
    }
    // Order berbukti lunas (paid_at terisi): reset ke paid via CAS dari
    // status saat ini, dengan guard mismatch K36 DI DALAM WHERE.
    // Bila kunci masih non-aktif, grant_row mengembalikan order ke
    // needs_review dengan catatan baru, bukan grant.
    let reset = sqlx::query(
        "UPDATE package_orders SET status = 'paid', last_error = ?, \
         updated_at = UTC_TIMESTAMP(6) WHERE id = ? AND status = ? \
         AND (last_error IS NULL OR last_error NOT LIKE '%Nominal bayar tidak sama%')",
    )
    .bind("Grant ulang oleh admin")
    .bind(order.id.clone())
    .bind(order.status.clone())
    .execute(&pool)
    .await
    .map_err(|_| AppError::internal("Status order tidak dapat diubah"))?;
    if reset.rows_affected() != 1 {
        return Err(AppError::conflict(
            "Status order berubah selama proses; muat ulang dan coba lagi",
        ));
    }
    let row = get_order(&pool, &order_id)
        .await?
        .ok_or_else(|| AppError::internal("Order tidak ditemukan setelah reset"))?;
    // B14: ulang cek refund tepat sebelum grant.
    let refund_total = refund_total_for_order(&pool, &row.id).await?;
    if refund_total > 0 && refund_total >= row.amount_idr {
        return Err(AppError::conflict(
            "Order sudah di-refund penuh; grant ditolak.",
        ));
    }
    grant_row(store, &pool, &row).await
}

async fn grant_row(
    store: &AdminStore,
    pool: &MySqlPool,
    order: &PackageOrderRow,
) -> Result<(MemberOrderView, VerifyOutcome), AppError> {
    let member_uuid = Uuid::parse_str(&order.member_id)
        .map_err(|_| AppError::internal("Member order tidak valid"))?;
    let package_uuid = Uuid::parse_str(&order.package_id)
        .map_err(|_| AppError::internal("Paket order tidak valid"))?;
    let order_uuid =
        Uuid::parse_str(&order.id).map_err(|_| AppError::internal("ID order tidak valid"))?;
    let outcome = match store
        .grant_package_order(
            order_uuid,
            member_uuid,
            order.quota_hits,
            order.valid_days,
            order.rate_limit_per_minute,
            package_uuid,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) if error.status == StatusCode::CONFLICT => {
            // Kunci/member tidak aktif di tengah jalan (atau status
            // berubah): uang sudah lunas, jadi TAHAN untuk admin, jangan
            // error ke pemanggil (webhook akan retry tanpa henti bila
            // 500). K3: bool CAS fallback ini pun tidak dibuang — bila
            // baris ternyata sudah granted, laporkan AlreadyGranted,
            // bukan NeedsReview yang menyesatkan.
            let changed = set_order_status(
                pool,
                &order.id,
                "paid",
                "needs_review",
                None,
                Some("Grant ditahan untuk admin (kunci/member tidak aktif atau status berubah)"),
            )
            .await?;
            let row = get_order(pool, &order_uuid)
                .await?
                .unwrap_or_else(|| order.clone());
            if !changed && row.status == "granted" {
                return Ok((row.member_view(), VerifyOutcome::AlreadyGranted));
            }
            if changed {
                // B2 (28 Okt 2026): alert kanal env lama dialihkan ke
                // kanal panel baru (satu sumber, tanpa duplikat).
                // Jejak audit/aktivitas tetap ditulis di helper.
                notify_needs_review_panel(
                    store,
                    pool,
                    &row,
                    "Perlu ditinjau (grant ditahan)",
                    "Grant gagal — order perlu tinjauan",
                    &format!(
                        "Order {} gagal di-grant (kunci/member tidak aktif atau status berubah) dan diparkir needs_review.",
                        order.id
                    ),
                )
                .await;
            }
            return Ok((row.member_view(), VerifyOutcome::NeedsReview));
        }
        Err(error) => return Err(error),
    };
    let row = get_order(pool, &order_uuid)
        .await?
        .unwrap_or_else(|| order.clone());
    let result = match outcome {
        GrantOutcome::Granted { .. } => (row.member_view(), VerifyOutcome::Granted),
        GrantOutcome::AlreadyGranted => (row.member_view(), VerifyOutcome::AlreadyGranted),
    };
    // Notifikasi pembelian paket — HANYA pada grant pertama (Granted),
    // bukan AlreadyGranted (sweep/resolve berulang tidak boleh spam).
    // Fire-and-forget: grant sudah commit pada titik ini; kegagalan
    // kirim hanya jadi log. Resolve admin yang lewat jalur ini juga
    // ikut memberi notifikasi (konfirmasi atas aksinya sendiri).
    if matches!(result.1, VerifyOutcome::Granted) {
        if let Ok(Some(account)) = store.member_by_id(member_uuid).await {
            if let Some(code) = account.member_code.filter(|value| !value.is_empty()) {
                let (title, text) = crate::telegram_settings::purchase_message(
                    &code,
                    &order.package_name,
                    order.quota_hits,
                    order.amount_idr,
                    &order.id,
                    chrono::Utc::now(),
                );
                crate::alerts::notify_admin(
                    pool.clone(),
                    store.credential_cipher(),
                    title,
                    text,
                );
            }
        }
    }
    Ok(result)
}

/// Dedup spawn sweep pemicu webhook (audit 2026-10-25, K25): paling
/// banyak SATU sweep webhook berjalan dalam satu waktu. Banjir webhook
/// yang datang saat sweep sedang berjalan dilewati begitu saja (bukan
/// diantrekan): order yang lunas setelah sweep berjalan tetap tertangkap
/// sweep rutin tiap 60 detik, yang SENGAJA tidak ikut dedup ini dan
/// tetap menjadi backstop. Flag direset lewat guard Drop sehingga
/// panic di dalam sweep pun tidak mengunci flag selamanya.
static WEBHOOK_SWEEP_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

struct WebhookSweepFlagGuard;

impl Drop for WebhookSweepFlagGuard {
    fn drop(&mut self) {
        WEBHOOK_SWEEP_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

/// Spawn sweep webhook bila belum ada yang berjalan. Mengembalikan
/// true bila sweep benar-benar di-spawn, false bila dilewati karena
/// sudah ada sweep berjalan.
pub fn spawn_webhook_sweep(store: Arc<AdminStore>, config: Arc<AppConfig>) -> bool {
    if WEBHOOK_SWEEP_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        tracing::debug!("Sweep webhook sudah berjalan; spawn dilewati");
        return false;
    }
    tokio::spawn(async move {
        let _guard = WebhookSweepFlagGuard;
        sweep_open_orders_now(store, config).await;
    });
    true
}

/// Sweep sekali jalan untuk semua order terbuka (waiting + paid), dipakai
/// sebagai pemicu dari webhook: webhook TIDAK mencocokkan order apa pun
/// — ia hanya membangunkan rekonsiliasi, dan grant tetap diputuskan
/// verify_and_grant lewat check-status + cocok nominal. Satu pass, tanpa
/// loop; error per order dicatat, sweep rutin tiap menit tetap menjadi
/// backstop.
pub async fn sweep_open_orders_now(store: Arc<AdminStore>, config: Arc<AppConfig>) {
    let Ok(pool) = pool_or_unavailable(&store) else {
        return;
    };
    let candidates = sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders \
         WHERE status IN ('waiting_payment', 'paid') \
         AND check_fail_count < {SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES} \
         ORDER BY created_at ASC LIMIT 50"
    ))
    .fetch_all(&pool)
    .await;
    let candidates = match candidates {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(?error, "Sweep pemicu webhook gagal membaca order");
            return;
        }
    };
    for candidate in candidates {
        let Ok(order_id) = Uuid::parse_str(&candidate.id) else {
            continue;
        };
        if let Err(error) = verify_and_grant(&store, &config, order_id).await {
            tracing::warn!(?error, order_id = %candidate.id, "Sweep pemicu webhook gagal");
        }
    }
}

/// Sweep rekonsiliasi tiap menit: order waiting yang lewat expiry dicek
/// statusnya dulu (paid -> grant, sisanya -> expired), dan order paid yang
/// tertinggal di-grant. Tidak pernah panic; error dicatat dan dilewati.
pub async fn sweep_loop(store: Arc<AdminStore>, config: Arc<AppConfig>) {
    loop {
        sweep_once(&store, &config).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Ambang karantina sweep (B13): order yang check-nya gagal N kali
/// berturut-turut dikeluarkan dari kandidat sweep rutin (dan sweep
/// pemicu webhook) sampai resolve manual / verify sukses. N=5: cukup
/// besar untuk mentolerir blip provider sesaat, cukup kecil agar 20
/// order racun tidak pernah mengisi seluruh LIMIT pass selama
/// berjam-jam. Pelampauan ambang memicu alert admin (sekali, tepat
/// saat hitungan mencapai N — order yang sudah dikarantina tidak lagi
/// diproses sehingga alert tidak berulang tiap menit).
pub const SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES: i64 = 5;

/// Jendela re-check order terminal oleh sweep rutin (B10): order yang
/// ditandai expired/canceled dalam 24 jam terakhir masih bisa jadi
/// bayar telat. Yang lebih lama ditangani on-demand (tombol "Saya sudah
/// bayar" member / tombol resolve admin) agar sweep tidak me-re-check
/// seluruh riwayat terminal setiap menit.
const SWEEP_TERMINAL_RECENT_HOURS: i64 = 24;

/// Umur minimum order waiting segar untuk digilir sweep rutin (B12):
/// order yang baru dibuat (< 120 detik) dibiarkan menunggu webhook
/// dulu, agar sweep tidak memborbardir check-status tiap menit untuk
/// order yang baru saja dibuat — tetapi order yang webhook-nya hilang
/// tetap ter-grant dalam ~1–3 menit, bukan menunggu sampai expiry
/// lokal 15 menit.
const SWEEP_FRESH_WAITING_MIN_AGE_SECS: i64 = 120;

async fn sweep_once(store: &AdminStore, config: &AppConfig) {
    let Ok(pool) = pool_or_unavailable(store) else {
        return;
    };
    // B12/B13: EMPAT pass dengan LIMIT masing-masing, bukan satu LIMIT
    // 20 untuk semua — dulu 20 order racun tertua bisa mengisi seluruh
    // kuota pass dan order paid yang lebih baru tidak pernah digilir.
    // Pass paid didahulukan (grant tertinggal adalah yang paling
    // merugikan member), lalu waiting-lewat-expiry, waiting-segar
    // (webhook hilang), dan terminal-terbaru (bayar telat, B10).
    // Kandidat yang sudah dikarantina (check_fail_count >= N) tidak
    // diambil di pass mana pun.
    let passes: [(&str, String); 4] = [
        (
            "paid",
            format!(
                "SELECT {{ORDER_COLUMNS}} FROM package_orders \
                 WHERE status = 'paid' AND check_fail_count < {SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES} \
                 ORDER BY created_at ASC LIMIT 20"
            ),
        ),
        (
            "waiting-expired",
            format!(
                "SELECT {{ORDER_COLUMNS}} FROM package_orders \
                 WHERE status = 'waiting_payment' AND qris_expires_at < UTC_TIMESTAMP(6) \
                 AND check_fail_count < {SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES} \
                 ORDER BY created_at ASC LIMIT 20"
            ),
        ),
        (
            "waiting-fresh",
            format!(
                "SELECT {{ORDER_COLUMNS}} FROM package_orders \
                 WHERE status = 'waiting_payment' AND qris_expires_at >= UTC_TIMESTAMP(6) \
                 AND created_at < UTC_TIMESTAMP(6) - INTERVAL {SWEEP_FRESH_WAITING_MIN_AGE_SECS} SECOND \
                 AND check_fail_count < {SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES} \
                 ORDER BY created_at ASC LIMIT 20"
            ),
        ),
        (
            "terminal-recent",
            format!(
                "SELECT {{ORDER_COLUMNS}} FROM package_orders \
                 WHERE status IN ('expired', 'canceled') \
                 AND updated_at > UTC_TIMESTAMP(6) - INTERVAL {SWEEP_TERMINAL_RECENT_HOURS} HOUR \
                 AND check_fail_count < {SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES} \
                 ORDER BY updated_at DESC LIMIT 20"
            ),
        ),
    ];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (pass_name, query) in passes {
        let query = query.replace("{ORDER_COLUMNS}", ORDER_COLUMNS);
        let candidates = match sqlx::query_as::<_, PackageOrderRow>(&query)
            .fetch_all(&pool)
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(?error, pass = pass_name, "Sweep order gagal membaca kandidat");
                continue;
            }
        };
        for candidate in candidates {
            if !seen.insert(candidate.id.clone()) {
                continue;
            }
            sweep_process_candidate(store, config, &pool, &candidate).await;
        }
    }
}

/// Satu kandidat sweep: sukses (outcome apa pun, termasuk Waiting)
/// me-reset hitungan gagal ke 0; error check menaikkan hitungan, dan
/// tepat saat mencapai ambang, order dikarantina + alert admin.
async fn sweep_process_candidate(
    store: &AdminStore,
    config: &AppConfig,
    pool: &MySqlPool,
    candidate: &PackageOrderRow,
) {
    let Ok(order_id) = Uuid::parse_str(&candidate.id) else {
        return;
    };
    match verify_and_grant(store, config, order_id).await {
        Ok(_) => {
            let _ = sqlx::query(
                "UPDATE package_orders SET check_fail_count = 0 WHERE id = ? AND check_fail_count <> 0",
            )
            .bind(&candidate.id)
            .execute(pool)
            .await;
        }
        Err(error) => {
            tracing::warn!(?error, order_id = %candidate.id, "Sweep order gagal");
            let _ = sqlx::query(
                "UPDATE package_orders SET check_fail_count = check_fail_count + 1 WHERE id = ?",
            )
            .bind(&candidate.id)
            .execute(pool)
            .await;
            let count: Option<i64> = sqlx::query_scalar(
                "SELECT check_fail_count FROM package_orders WHERE id = ?",
            )
            .bind(&candidate.id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
            if count == Some(SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES) {
                crate::alerts::alert_with_store(
                    store,
                    "Order sweep dikarantina",
                    &format!(
                        "Order {} gagal check-status {}x berturut-turut; dikeluarkan dari sweep rutin sampai resolve manual (tombol Grant ulang panel).",
                        candidate.id, SWEEP_MAX_CONSECUTIVE_CHECK_FAILURES
                    ),
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_cancels_only_unpaid_waiting_orders() {
        // B15/D3: waiting + belum dibayar + switch off -> batal.
        assert!(kill_switch_cancels_waiting("waiting_payment", false, false));
        // Pengecualian keras: sudah terbayar tidak pernah dibatalkan.
        assert!(!kill_switch_cancels_waiting("waiting_payment", true, false));
        assert!(!kill_switch_cancels_waiting("paid", false, false));
        assert!(!kill_switch_cancels_waiting("granted", false, false));
        assert!(!kill_switch_cancels_waiting("expired", false, false));
        assert!(!kill_switch_cancels_waiting("canceled", false, false));
        // Switch masih on -> tidak ada pembatalan.
        assert!(!kill_switch_cancels_waiting("waiting_payment", false, true));
    }

    #[test]
    fn kill_switch_blocks_only_flagged_canceled_rechecks() {
        // B15/D3: canceled bertanda kill switch tidak auto-grant.
        assert!(kill_switch_blocks_terminal_recheck("canceled", true));
        // Canceled biasa tetap ikut re-check B10.
        assert!(!kill_switch_blocks_terminal_recheck("canceled", false));
        // Tanda pada status lain tidak memblokir apa pun (tanda hanya
        // pernah ditulis bersama status canceled).
        assert!(!kill_switch_blocks_terminal_recheck("expired", true));
        assert!(!kill_switch_blocks_terminal_recheck("waiting_payment", true));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {

        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn webhook_signature_accepts_hex_and_base64() {
        use base64::Engine;
        let secret = "rahasia-webhook";
        let body = br#"{"event":"qris.payment.success","token":"abc"}"#;
        let tag = hmac_sha256(secret.as_bytes(), body);
        assert!(verify_webhook_signature(secret, body, &hex::encode(tag)));
        assert!(verify_webhook_signature(
            secret,
            body,
            &base64::engine::general_purpose::STANDARD.encode(tag),
        ));
        assert!(!verify_webhook_signature(
            secret,
            body,
            &hex::encode([0u8; 32])
        ));
        assert!(!verify_webhook_signature("salah", body, &hex::encode(tag)));
    }

    #[test]
    fn allowed_expiry_minutes_match_docs() {
        assert_eq!(ALLOWED_EXPIRY_MINUTES, [3, 5, 10, 12, 15]);
    }

    /// K2: kosakata outcome resolve diserialisasi snake_case.
    #[test]
    fn resolve_outcome_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&VerifyOutcome::Granted).unwrap(),
            "\"granted\""
        );
        assert_eq!(
            serde_json::to_string(&VerifyOutcome::AlreadyGranted).unwrap(),
            "\"already_granted\""
        );
        assert_eq!(
            serde_json::to_string(&VerifyOutcome::NeedsReview).unwrap(),
            "\"needs_review\""
        );
        assert_eq!(
            serde_json::to_string(&VerifyOutcome::Rejected).unwrap(),
            "\"rejected\""
        );
    }
}

/// Tes AREA 3 (murni, tanpa database): rekonsiliasi, validasi rentang,
/// dan aturan refund-record. Jalur DB (`reconciliation_summary`,
/// `record_refund`, `list_refunds_for_order`) tidak dapat diuji tanpa
/// MySQL dan dicakup oleh validasi murni + review kode yang sama.
#[cfg(test)]
mod area3_tests {
    use super::{
        normalize_order_status_filter, parse_order_date, refund_total_after,
        summarize_admin_orders, validate_order_date_range, validate_refund_fields,
        AdminOrderView,
    };
    use chrono::NaiveDate;

    fn view(status: &str, amount: u64) -> AdminOrderView {
        let when = NaiveDate::from_ymd_opt(2026, 10, 25)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        AdminOrderView {
            id: "id".to_owned(),
            member_id: "member".to_owned(),
            member_email: None,
            key_id: None,
            package_id: "pkg".to_owned(),
            package_name: "Paket".to_owned(),
            price_idr: amount,
            quota_hits: 0,
            rate_limit_per_minute: 0,
            valid_days: 30,
            amount_idr: amount,
            status: status.to_owned(),
            qris_token: None,
            qris_expires_at: None,
            paid_at: None,
            granted_at: None,
            granted_quota: None,
            granted_expires_at: None,
            mutation_ref: None,
            last_error: None,
            created_at: when,
            updated_at: when,
            provider_order_id: None,
            expected_amount: None,
        }
    }

    #[test]
    fn status_filter_accepts_alias_and_rejects_unknown() {
        assert_eq!(
            normalize_order_status_filter(Some("waiting")).unwrap(),
            Some("waiting_payment")
        );
        assert_eq!(
            normalize_order_status_filter(Some("waiting_payment")).unwrap(),
            Some("waiting_payment")
        );
        assert_eq!(
            normalize_order_status_filter(Some("paid")).unwrap(),
            Some("paid")
        );
        assert_eq!(normalize_order_status_filter(None).unwrap(), None);
        assert_eq!(normalize_order_status_filter(Some("")).unwrap(), None);
        assert!(normalize_order_status_filter(Some("bogus")).is_err());
        assert!(normalize_order_status_filter(Some("PAID")).is_err());
    }

    #[test]
    fn date_parsing_is_strict_yyyy_mm_dd() {
        assert!(parse_order_date("2026-10-25").is_ok());
        assert!(parse_order_date("2026-1-5").is_err());
        assert!(parse_order_date("25-10-2026").is_err());
        assert!(parse_order_date("2026-13-01").is_err());
        assert!(parse_order_date("2026-02-30").is_err());
    }

    #[test]
    fn date_range_requires_pair_order_and_cap() {
        assert!(validate_order_date_range(None, None).unwrap().is_none());
        assert!(validate_order_date_range(Some("2026-10-01"), None).is_err());
        assert!(validate_order_date_range(None, Some("2026-10-01")).is_err());
        assert!(
            validate_order_date_range(Some("2026-10-25"), Some("2026-10-01")).is_err()
        );
        // Tepat 366 hari diizinkan, 367 ditolak.
        assert!(
            validate_order_date_range(Some("2025-01-01"), Some("2026-01-02")).is_ok()
        );
        assert!(
            validate_order_date_range(Some("2025-01-01"), Some("2026-01-03")).is_err()
        );
    }

    #[test]
    fn summary_matches_filtered_rows() {
        let orders = vec![
            view("paid", 50_000),
            view("paid", 25_000),
            view("granted", 100_000),
            view("waiting_payment", 10_000),
        ];
        let summary = summarize_admin_orders(&orders);
        assert_eq!(summary.paid.count, 2);
        assert_eq!(summary.paid.amount_idr, 75_000);
        assert_eq!(summary.granted.count, 1);
        assert_eq!(summary.granted.amount_idr, 100_000);
        assert_eq!(summary.waiting.count, 1);
        assert_eq!(summary.waiting.amount_idr, 10_000);
        assert_eq!(summary.needs_review.count, 0);
        assert_eq!(summary.total_count, 4);
        assert_eq!(summary.total_amount_idr, 185_000);
        // Konsistensi: jumlah bucket per status = jumlah baris filter itu.
        let paid_only: Vec<AdminOrderView> = orders
            .iter()
            .filter(|order| order.status == "paid")
            .cloned()
            .collect();
        assert_eq!(
            summarize_admin_orders(&paid_only).paid.count,
            summary.paid.count
        );
    }

    #[test]
    fn refund_fields_require_reason_and_positive_amount() {
        assert!(validate_refund_fields(0, "alasan", None, None).is_err());
        assert!(validate_refund_fields(10_000, "", None, None).is_err());
        assert!(validate_refund_fields(10_000, "   ", None, None).is_err());
        let (amount, reason, external, note) =
            validate_refund_fields(10_000, "  dana kembali  ", Some(" REF1 "), None)
                .unwrap();
        assert_eq!(amount, 10_000);
        assert_eq!(reason, "dana kembali");
        assert_eq!(external.as_deref(), Some("REF1"));
        assert_eq!(note, None);
    }

    #[test]
    fn refund_cap_allows_partial_up_to_full_then_rejects() {
        // Parsial bertahap diizinkan selama total <= nominal order.
        assert_eq!(refund_total_after(0, 40_000, 100_000).unwrap(), 40_000);
        assert_eq!(refund_total_after(40_000, 60_000, 100_000).unwrap(), 100_000);
        // Melebihi nominal -> ditolak.
        assert!(refund_total_after(40_000, 60_001, 100_000).is_err());
        // Duplikasi refund penuh: total sudah penuh, tambahan apa pun ditolak.
        assert!(refund_total_after(100_000, 1, 100_000).is_err());
        assert!(refund_total_after(100_000, 100_000, 100_000).is_err());
    }

    /// K21: member berbeda tidak saling blokir, member yang sama
    /// tetap serial — dibuktikan tanpa sleep lewat try_lock_owned.
    #[tokio::test]
    async fn per_member_create_lock_isolates_members() {
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        let _held_a = super::member_create_guard(a).await;
        // Member lain bisa mengunci seketika walau A sedang ditahan.
        assert!(super::member_create_lock(b).try_lock_owned().is_ok());
        // Member yang sama tetap tertahan.
        assert!(super::member_create_lock(a).try_lock_owned().is_err());
    }

    /// K21: entri registry member yang sudah selesai dibersihkan
    /// saat acquire berikutnya (tidak bocor memori). UUID acak per
    /// tes agar tidak terpengaruh tes lain yang berjalan paralel.
    #[test]
    fn per_member_create_lock_registry_is_pruned() {
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        {
            let lock_a = super::member_create_lock(a);
            drop(lock_a);
        }
        // Acquire member lain memicu prune entri A yang sudah mati.
        let _lock_b = super::member_create_lock(b);
        let registry = super::CREATE_ORDER_LOCKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!registry.contains_key(&a));
        assert!(registry.contains_key(&b));
    }

    /// K21: dua create member berbeda benar-benar berjalan bersamaan
    /// (bukan sekadar mutex berbeda di atas kertas): keduanya harus
    /// mencapai barrier yang sama; dengan mutex global, task kedua
    /// tidak akan pernah sampai dan timeout menggagalkan tes.
    #[tokio::test]
    async fn per_member_create_guards_run_concurrently() {
        use tokio::sync::Barrier;
        let barrier = std::sync::Arc::new(Barrier::new(2));
        let run = |member: uuid::Uuid, barrier: std::sync::Arc<Barrier>| async move {
            let _guard = super::member_create_guard(member).await;
            barrier.wait().await;
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                tokio::join!(
                    run(uuid::Uuid::new_v4(), std::sync::Arc::clone(&barrier)),
                    run(uuid::Uuid::new_v4(), std::sync::Arc::clone(&barrier)),
                )
            },
        )
        .await;
        assert!(result.is_ok(), "guard member berbeda saling memblokir");
    }
}

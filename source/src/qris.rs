//! Pembelian paket mandiri member via QRIS Cutiezy.
//!
//! Aturan keamanan yang dijaga modul ini:
//! - Token, qris_string, dan URL Cutiezy TIDAK PERNAH dikirim ke klien
//!   member (gambar QR disajikan lewat proxy endpoint kita sendiri).
//! - Webhook tidak pernah langsung grant: selalu re-verifikasi lewat
//!   check-status (gratis) + cocokkan nominal dulu.
//! - Grant kuota atomik (store::grant_package_order): satu transaksi
//!   MySQL mengubah kunci + order + plan_kind dengan CAS status paid,
//!   jadi webhook + polling + sweep yang bersamaan hanya satu yang menang.
//! - Satu order waiting per (member, paket) + rate limit create yang
//!   menghitung SEMUA create sukses dalam 1 jam terakhir (tiap create QR
//!   yang sukses memotong 6 hit kuota akun Cutiezy kita).

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

/// Durasi QRIS yang diizinkan Cutiezy (menit). Di luar ini create ditolak.
pub const ALLOWED_EXPIRY_MINUTES: [i64; 5] = [3, 5, 10, 12, 15];
/// Batas create order per member per jam (anti boros 6 hit Cutiezy).
const CREATE_ORDERS_PER_HOUR: i64 = 5;
/// Satu create order per proses dalam satu waktu: cek order waiting +
/// create Cutiezy + insert harus atomik terhadap create lain member yang
/// sama (deployment single-instance; multi-instance butuh guard DB).
static CREATE_ORDER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ---------------------------------------------------------------------------
// Pengaturan
// ---------------------------------------------------------------------------

/// Pengaturan QRIS internal (ciphertext TIDAK PERNAH diserialisasi keluar).
pub struct QrisSettings {
    pub enabled: bool,
    pub expiry_minutes: i64,
    pub valid_days: i64,
    pub source_id: Option<i64>,
    pub api_key_ciphertext: Option<Vec<u8>>,
    pub webhook_secret_ciphertext: Option<Vec<u8>>,
    pub last_error: Option<String>,
    pub last_cutiezy_remaining: Option<i64>,
}

/// Tampilan pengaturan untuk panel admin (tanpa rahasia).
#[derive(Serialize)]
pub struct QrisSettingsView {
    pub enabled: bool,
    pub expiry_minutes: i64,
    pub valid_days: i64,
    pub source_id: Option<i64>,
    pub has_api_key: bool,
    pub has_webhook_secret: bool,
    pub last_error: Option<String>,
    pub last_cutiezy_remaining: Option<i64>,
}

/// Input admin. Field yang absen/kosong = pertahankan nilai lama;
/// source_id memakai Option<Option<..>>: null eksplisit = hapus.
#[derive(Deserialize)]
pub struct QrisSettingsInput {
    pub enabled: Option<bool>,
    pub expiry_minutes: Option<i64>,
    pub valid_days: Option<i64>,
    pub source_id: Option<Option<i64>>,
    pub api_key: Option<String>,
    pub webhook_secret: Option<String>,
}

impl QrisSettings {
    fn defaults() -> Self {
        Self {
            enabled: false,
            expiry_minutes: 15,
            valid_days: 30,
            source_id: None,
            api_key_ciphertext: None,
            webhook_secret_ciphertext: None,
            last_error: None,
            last_cutiezy_remaining: None,
        }
    }

    pub fn view(&self) -> QrisSettingsView {
        QrisSettingsView {
            enabled: self.enabled,
            expiry_minutes: self.expiry_minutes,
            valid_days: self.valid_days,
            source_id: self.source_id,
            has_api_key: self.api_key_ciphertext.is_some(),
            has_webhook_secret: self.webhook_secret_ciphertext.is_some(),
            last_error: self.last_error.clone(),
            last_cutiezy_remaining: self.last_cutiezy_remaining,
        }
    }
}

pub async fn load_qris_settings(pool: &MySqlPool) -> Result<QrisSettings, AppError> {
    let row = sqlx::query_as::<_, QrisSettingsRow>(
        "SELECT enabled, expiry_minutes, valid_days, source_id, \
         api_key_ciphertext, webhook_secret_ciphertext, last_error, \
         last_cutiezy_remaining FROM qris_settings WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan QRIS tidak dapat dibaca"))?;
    Ok(match row {
        Some(row) => QrisSettings {
            enabled: row.enabled != 0,
            expiry_minutes: row.expiry_minutes,
            valid_days: row.valid_days,
            source_id: row.source_id,
            api_key_ciphertext: row.api_key_ciphertext,
            webhook_secret_ciphertext: row.webhook_secret_ciphertext,
            last_error: row.last_error,
            last_cutiezy_remaining: row.last_cutiezy_remaining,
        },
        None => QrisSettings::defaults(),
    })
}

#[derive(sqlx::FromRow)]
struct QrisSettingsRow {
    enabled: i8,
    expiry_minutes: i64,
    valid_days: i64,
    source_id: Option<i64>,
    api_key_ciphertext: Option<Vec<u8>>,
    webhook_secret_ciphertext: Option<Vec<u8>>,
    last_error: Option<String>,
    last_cutiezy_remaining: Option<i64>,
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
    if let Some(Some(source)) = input.source_id {
        if source <= 0 {
            return Err(AppError::bad_request("source_id harus positif"));
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
    if let Some(source) = input.source_id {
        current.source_id = source;
    }
    if let Some(key) = input.api_key {
        if !key.trim().is_empty() {
            current.api_key_ciphertext = Some(
                cipher
                    .encrypt(key.trim())
                    .map_err(|_| AppError::internal("API key QRIS tidak dapat dienkripsi"))?,
            );
        }
    }
    if let Some(secret) = input.webhook_secret {
        if !secret.trim().is_empty() {
            current.webhook_secret_ciphertext = Some(
                cipher
                    .encrypt(secret.trim())
                    .map_err(|_| AppError::internal("Webhook secret tidak dapat dienkripsi"))?,
            );
        }
    }
    sqlx::query(
        "INSERT INTO qris_settings (id, enabled, expiry_minutes, valid_days, \
         source_id, api_key_ciphertext, webhook_secret_ciphertext) \
         VALUES (1, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE \
         enabled = VALUES(enabled), expiry_minutes = VALUES(expiry_minutes), \
         valid_days = VALUES(valid_days), source_id = VALUES(source_id), \
         api_key_ciphertext = VALUES(api_key_ciphertext), \
         webhook_secret_ciphertext = VALUES(webhook_secret_ciphertext)",
    )
    .bind(if current.enabled { 1 } else { 0 })
    .bind(current.expiry_minutes)
    .bind(current.valid_days)
    .bind(current.source_id)
    .bind(&current.api_key_ciphertext)
    .bind(&current.webhook_secret_ciphertext)
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

pub async fn record_cutiezy_remaining(pool: &MySqlPool, remaining: i64) {
    sqlx::query(
        "INSERT INTO qris_settings (id, last_cutiezy_remaining) VALUES (1, ?) \
         ON DUPLICATE KEY UPDATE last_cutiezy_remaining = VALUES(last_cutiezy_remaining)",
    )
    .bind(remaining)
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

/// Verifikasi header X-Cutiezy-Signature. Format signature tidak
/// didokumentasikan di halaman QRIS (hex paling umum); terima hex DAN
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
// Klien Cutiezy
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum QrisError {
    NotConfigured(&'static str),
    Transport(String),
    Provider {
        http_status: u16,
        code: Option<String>,
        message: String,
    },
    AlreadyPaid,
    Unexpected(String),
    /// Create parsial (audit 2026-10-25, K20): Cutiezy SUDAH menerbitkan
    /// QR (token diketahui) tapi responsnya tidak bisa dipakai — flag
    /// ok/success false, atau nominal yang dikembalikan tidak sama
    /// dengan yang diminta. Pemanggil WAJIB membatalkan token ini
    /// (best-effort) agar tidak menjadi QR yatim berbayar. Pesan ke
    /// member tetap generik, sama seperti Unexpected.
    PartialCreated {
        token: String,
        message: String,
    },
}

impl QrisError {
    /// Token QR yatim yang harus dibatalkan pemanggil, bila ada (K20).
    /// Hanya PartialCreated yang membawanya; varian lain mengembalikan
    /// None karena tidak ada QR yang terbukti terbit.
    pub fn orphan_token(&self) -> Option<&str> {
        match self {
            Self::PartialCreated { token, .. } => Some(token),
            _ => None,
        }
    }

    /// Pesan aman untuk member (tanpa detail provider).
    pub fn member_message(&self) -> &'static str {
        match self {
            Self::NotConfigured(_) => "Pembayaran belum dikonfigurasi admin.",
            Self::Transport(_) => "Layanan pembayaran tidak dapat dihubungi. Coba lagi.",
            Self::Provider { .. } => "Pembayaran belum bisa dibuat. Coba lagi.",
            Self::AlreadyPaid => "Tagihan ini sudah dibayar.",
            Self::Unexpected(_) => "Terjadi kesalahan. Coba lagi.",
            Self::PartialCreated { .. } => "Terjadi kesalahan. Coba lagi.",
        }
    }

    fn to_app_error(&self) -> AppError {
        match self {
            Self::NotConfigured(message) => AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "qris_not_configured",
                *message,
            ),
            Self::Transport(_) => AppError::new(
                StatusCode::BAD_GATEWAY,
                "qris_upstream_unavailable",
                self.member_message(),
            ),
            Self::Provider { http_status, .. } => {
                if *http_status == 429 {
                    AppError::new(
                        StatusCode::TOO_MANY_REQUESTS,
                        "qris_rate_limited",
                        "Terlalu banyak permintaan pembayaran. Coba lagi sebentar.",
                    )
                } else {
                    AppError::new(
                        StatusCode::BAD_GATEWAY,
                        "qris_provider_error",
                        self.member_message(),
                    )
                }
            }
            Self::AlreadyPaid => AppError::new(
                StatusCode::CONFLICT,
                "qris_already_paid",
                self.member_message(),
            ),
            Self::Unexpected(_) | Self::PartialCreated { .. } => {
                AppError::internal(self.member_message())
            }
        }
    }
}

pub struct QrisClient {
    base_url: String,
    http: reqwest::Client,
}

impl QrisClient {
    pub fn new(base_url: &str) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|_| AppError::internal("Klien HTTP QRIS tidak dapat dibuat"))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

#[derive(Deserialize)]
struct CreateResponse {
    ok: Option<bool>,
    success: Option<bool>,
    message: Option<String>,
    data: Option<CreateData>,
    remaining_quota: Option<RemainingQuota>,
}

#[derive(Deserialize)]
struct CreateData {
    token: String,
    amount: u64,
    qris_string: Option<String>,
    image_url: Option<String>,
    // expires_at Cutiezy sengaja tidak dibaca: formatnya naive tanpa TZ,
    // expiry order dihitung sendiri dari now + expiry_minutes.
}

#[derive(Deserialize)]
struct RemainingQuota {
    remaining: Option<i64>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: Option<String>,
    message: Option<String>,
}

#[derive(Debug)]
pub struct CreatedInvoice {
    pub token: String,
    pub amount: u64,
    pub qris_string: Option<String>,
    pub image_url: Option<String>,
    /// Sisa kuota Cutiezy dari respons create (untuk panel admin).
    pub remaining_quota: Option<i64>,
}

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

#[derive(Deserialize)]
struct CheckResponse {
    status: Option<String>,
    paid_at: Option<String>,
    /// K25: nominal Cutiezy TIDAK selalu u64 JSON — terima juga string
    /// numerik ("150000") dan float integral (150000.0). Bentuk yang
    /// tidak bisa diparse (string non-numerik, float berpecahan)
    /// menjadi None → cabang Paid memakai 0 → mismatch nominal (tidak
    /// pernah grant buta). Dulu field ini Option<u64> ketat sehingga
    /// satu nominal string menggagalkan SELURUH parsing check-status.
    #[serde(default, deserialize_with = "de_flexible_amount")]
    amount: Option<u64>,
    mutation_ref: Option<String>,
    remaining_seconds: Option<i64>,
}

/// Deserializer fleksibel untuk nominal check-status (K25).
fn de_flexible_amount<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    Ok(match value {
        serde_json::Value::Number(number) => number.as_u64().or_else(|| {
            number.as_f64().filter(|float| float.fract() == 0.0 && *float >= 0.0)
                .map(|float| float as u64)
        }),
        serde_json::Value::String(text) => {
            let text = text.trim();
            text.parse::<u64>().ok().or_else(|| {
                text.parse::<f64>()
                    .ok()
                    .filter(|float| float.fract() == 0.0 && *float >= 0.0)
                    .map(|float| float as u64)
            })
        }
        _ => None,
    })
}

fn parse_cutiezy_datetime(value: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()
}

/// Cutiezy mengembalikan paid_at dalam waktu lokal WIB (naive, tanpa
/// zona) sementara semua timestamp lain disimpan sebagai UTC: geser
/// -7 jam agar konsisten. WIB tidak punya DST sehingga selisihnya tetap.
/// Tanpa ini, paid_at tampil +7 jam di semua tampilan berbasis UTC
/// (riwayat member "Lunas 26 Okt" untuk pembayaran 25 Okt malam, dan
/// panel admin menampilkan jam bayar yang tak sebidang dengan jam order).
///
/// Format yang diterima (audit 2026-10-25, K26): format legacy
/// "%Y-%m-%d %H:%M:%S" DAN bentuk ISO-8601 — naive dengan pemisah 'T'
/// (diperlakukan WIB, sama seperti format legacy) maupun RFC 3339
/// berzona eksplisit (offset-nya dipakai apa adanya, TANPA geser -7 jam
/// tambahan; menggeser lagi akan memelintir jam sebesar offsetnya).
/// Konversi zona waktu format legacy TIDAK diubah.
fn parse_cutiezy_paid_at(value: &str) -> Option<NaiveDateTime> {
    if let Some(naive) = parse_cutiezy_datetime(value) {
        return Some(naive - chrono::Duration::hours(7));
    }
    for format in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Some(naive - chrono::Duration::hours(7));
        }
    }
    if let Ok(zoned) = DateTime::parse_from_rfc3339(value) {
        return Some(zoned.with_timezone(&Utc).naive_utc());
    }
    None
}

impl QrisClient {
    /// Buat QRIS dinamis. GAGAL total (timeout/transport) tidak boleh
    /// di-retry otomatis oleh pemanggil: create yang sukses memotong 6 hit
    /// kuota Cutiezy, jadi retry bisa menggandakan biaya.
    pub async fn create(
        &self,
        api_key: &str,
        amount: u64,
        expiry_minutes: i64,
        source_id: Option<i64>,
    ) -> Result<CreatedInvoice, QrisError> {
        #[derive(Serialize)]
        struct Body {
            amount: u64,
            expiry_minutes: i64,
            #[serde(skip_serializing_if = "Option::is_none")]
            source_id: Option<i64>,
        }
        let res = self
            .http
            .post(self.url("/api/qris/create"))
            .header("X-API-Key", api_key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(20))
            .json(&Body {
                amount,
                expiry_minutes,
                source_id,
            })
            .send()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?;
        let status = res.status().as_u16();
        let body = res
            .text()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?;
        if !(200..300).contains(&status) {
            let parsed: ErrorResponse = serde_json::from_str(&body).unwrap_or(ErrorResponse {
                error: None,
                message: None,
            });
            return Err(QrisError::Provider {
                http_status: status,
                code: parsed.error,
                message: parsed
                    .message
                    .unwrap_or_else(|| "Create QRIS gagal".to_owned()),
            });
        }
        let parsed: CreateResponse = serde_json::from_str(&body).map_err(|error| {
            // 2xx tapi bodi bukan JSON (pernah teramati di diagnosa):
            // catat bodi TERPOTONG ke log server saja (admin), bukan ke
            // member — agar kegagalan berikutnya bisa didiagnosis tanpa
            // membocorkan apa pun ke klien.
            let snippet: String = body.chars().take(500).collect();
            tracing::warn!(%snippet, "Respons create QRIS 2xx bukan JSON");
            QrisError::Unexpected(error.to_string())
        })?;
        let ok = parsed.ok.unwrap_or(false) || parsed.success.unwrap_or(false);
        let Some(data) = parsed.data else {
            return Err(QrisError::Unexpected(
                parsed
                    .message
                    .unwrap_or_else(|| "Respons create QRIS tidak lengkap".to_owned()),
            ));
        };
        if !ok {
            // Parse parsial (K20): token sudah berhasil diparsing walau
            // flag ok/success false — kembalikan tokennya agar pemanggil
            // bisa membatalkan QR yatim ini.
            return Err(QrisError::PartialCreated {
                token: data.token,
                message: parsed
                    .message
                    .unwrap_or_else(|| "Respons create QRIS tidak lengkap".to_owned()),
            });
        }
        if data.amount != amount {
            // Nominal beda (K20): sama — token dikembalikan untuk cancel.
            return Err(QrisError::PartialCreated {
                token: data.token,
                message: "Nominal dari Cutiezy tidak sama dengan order".to_owned(),
            });
        }
        Ok(CreatedInvoice {
            token: data.token,
            amount: data.amount,
            qris_string: data.qris_string,
            image_url: data.image_url,
            remaining_quota: parsed.remaining_quota.and_then(|quota| quota.remaining),
        })
    }

    /// Cek status. GRATIS (0 hit) menurut dokumentasi; tanpa API key.
    pub async fn check(&self, token: &str) -> Result<QrisPaymentStatus, QrisError> {
        let res = self
            .http
            .get(self.url(&format!("/qris/check-status/{token}")))
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?;
        let status_code = res.status().as_u16();
        let body = res
            .text()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?;
        if status_code == 404 {
            return Ok(QrisPaymentStatus::NotFound);
        }
        if !(200..300).contains(&status_code) {
            let parsed: ErrorResponse = serde_json::from_str(&body).unwrap_or(ErrorResponse {
                error: None,
                message: None,
            });
            return Err(QrisError::Provider {
                http_status: status_code,
                code: parsed.error,
                message: parsed
                    .message
                    .unwrap_or_else(|| "Cek status QRIS gagal".to_owned()),
            });
        }
        let parsed: CheckResponse = serde_json::from_str(&body)
            .map_err(|error| QrisError::Unexpected(error.to_string()))?;
        let payment_status = match parsed.status.as_deref() {
            Some("paid") => {
                let paid_at = parsed.paid_at.as_deref().and_then(parse_cutiezy_paid_at);
                if parsed.paid_at.is_some() && paid_at.is_none() {
                    // K26: paid_at gagal parsing tidak boleh hilang diam-
                    // diam menjadi NULL — jejak warn ini yang tersisa.
                    tracing::warn!(
                        raw_paid_at = parsed.paid_at.as_deref().unwrap_or(""),
                        "paid_at Cutiezy gagal diparsing pada status paid; disimpan NULL",
                    );
                }
                QrisPaymentStatus::Paid {
                    paid_at,
                    amount: parsed.amount.unwrap_or(0),
                    mutation_ref: parsed.mutation_ref,
                }
            }
            Some("pending") => QrisPaymentStatus::Pending {
                remaining_seconds: parsed.remaining_seconds.unwrap_or(0),
            },
            Some("expired") => QrisPaymentStatus::Expired,
            Some("canceled") => QrisPaymentStatus::Canceled,
            other => {
                // K21: status tak dikenal BUKAN NotFound. NotFound hanya
                // untuk HTTP 404 di atas. Status asing diperlakukan
                // sebagai error agar sweep berikutnya me-retry, bukan
                // membiarkan order lunas kedaluwarsa diam-diam. Pemetaan
                // empat status yang dikenal TIDAK diubah.
                let unknown = other.unwrap_or("(kosong)");
                tracing::warn!(
                    status = unknown,
                    "Status check-status Cutiezy tak dikenal; diperlakukan sebagai error",
                );
                return Err(QrisError::Unexpected(format!(
                    "Status QRIS tak dikenal: {unknown}"
                )));
            }
        };
        Ok(payment_status)
    }

    /// Batalkan tagihan pending. Sudah lunas -> AlreadyPaid (pemanggil
    /// harus beralih ke verify_and_grant, bukan menandai canceled).
    pub async fn cancel(&self, api_key: &str, token: &str) -> Result<(), QrisError> {
        #[derive(Serialize)]
        struct Body<'a> {
            token: &'a str,
        }
        let res = self
            .http
            .post(self.url("/api/qris/cancel"))
            .header("X-API-Key", api_key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(15))
            .json(&Body { token })
            .send()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?;
        let status = res.status().as_u16();
        let body = res
            .text()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?;
        if status == 400 {
            let parsed: ErrorResponse = serde_json::from_str(&body).unwrap_or(ErrorResponse {
                error: None,
                message: None,
            });
            if parsed.status_is_paid() {
                return Err(QrisError::AlreadyPaid);
            }
        }
        if !(200..300).contains(&status) {
            let parsed: ErrorResponse = serde_json::from_str(&body).unwrap_or(ErrorResponse {
                error: None,
                message: None,
            });
            return Err(QrisError::Provider {
                http_status: status,
                code: parsed.error,
                message: parsed
                    .message
                    .unwrap_or_else(|| "Cancel QRIS gagal".to_owned()),
            });
        }
        Ok(())
    }

    /// Batas ukuran gambar QR yang diproksi (audit 2026-10-25, K24):
    /// PNG QR Cutiezy hanya puluhan KB; 1 MiB sudah sangat longgar dan
    /// menutup penyedotan memori lewat respons raksasa.
    const MAX_QR_PNG_BYTES: usize = 1_048_576;

    /// Allowlist host gambar QR (K24): host yang sama dengan base URL
    /// Cutiezy yang dikonfigurasi, atau host Cutiezy mana pun
    /// (`cutiezy.id` + subdomainnya). URL berasal dari respons Cutiezy,
    /// bukan input member — tapi respons provider yang dikompromikan
    /// tidak boleh mengubah proxy ini menjadi SSRF terbuka. Perhatian:
    /// `ends_with(".cutiezy.id")` sengaja memakai titik di depan agar
    /// `fakecutiezy.id` maupun `cutiezy.id.evil.com` tetap ditolak.
    fn qr_host_allowed(&self, url: &url::Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        if host.eq_ignore_ascii_case("cutiezy.id")
            || host.to_ascii_lowercase().ends_with(".cutiezy.id")
        {
            return true;
        }
        match url::Url::parse(&self.base_url) {
            Ok(base) => {
                // Host saja tidak cukup: port berbeda = server berbeda
                // (127.0.0.1:9999 vs 127.0.0.1:8888 harus dibedakan).
                base.host_str()
                    .is_some_and(|base_host| base_host.eq_ignore_ascii_case(host))
                    && base.port_or_known_default() == url.port_or_known_default()
            }
            Err(_) => false,
        }
    }

    /// Unduh bytes gambar QR dari image_url Cutiezy (untuk proxy server).
    pub async fn fetch_qr_png(&self, image_url: &str) -> Result<(Vec<u8>, String), QrisError> {
        let parsed_url = url::Url::parse(image_url)
            .map_err(|_| QrisError::Unexpected("URL gambar QR tidak valid".to_owned()))?;
        if !matches!(parsed_url.scheme(), "http" | "https") {
            return Err(QrisError::Unexpected(
                "Skema URL gambar QR tidak diizinkan".to_owned(),
            ));
        }
        if !self.qr_host_allowed(&parsed_url) {
            return Err(QrisError::Unexpected(
                "Host gambar QR tidak diizinkan".to_owned(),
            ));
        }
        let mut res = self
            .http
            .get(image_url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?;
        // reqwest mengikuti redirect secara bawaan: periksa URL AKHIR
        // juga, bukan hanya URL yang diminta, agar redirect ke host
        // asing tidak lolos allowlist.
        if !self.qr_host_allowed(res.url()) {
            return Err(QrisError::Unexpected(
                "Host gambar QR setelah redirect tidak diizinkan".to_owned(),
            ));
        }
        if !res.status().is_success() {
            return Err(QrisError::Unexpected(
                "Gambar QR tidak dapat diunduh".to_owned(),
            ));
        }
        let content_type = res
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("image/png")
            .to_owned();
        if !content_type.starts_with("image/") {
            return Err(QrisError::Unexpected("Gambar QR bukan image".to_owned()));
        }
        if let Some(length) = res.content_length() {
            if length > Self::MAX_QR_PNG_BYTES as u64 {
                return Err(QrisError::Unexpected(
                    "Gambar QR melebihi batas 1 MiB".to_owned(),
                ));
            }
        }
        // Baca per chunk dengan batas berjalan (bukan bytes() sekaligus):
        // Content-Length bisa absen/dibohongi, jadi batas ditegakkan
        // selama streaming, bukan setelah seluruh bodi masuk memori.
        let mut bytes = Vec::new();
        while let Some(chunk) = res
            .chunk()
            .await
            .map_err(|error| QrisError::Transport(error.to_string()))?
        {
            if bytes.len() + chunk.len() > Self::MAX_QR_PNG_BYTES {
                return Err(QrisError::Unexpected(
                    "Gambar QR melebihi batas 1 MiB".to_owned(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((bytes, content_type))
    }
}

impl ErrorResponse {
    fn status_is_paid(&self) -> bool {
        // Cancel yang sudah lunas dibalas 400 + status paid (body atau
        // pesan); terima kedua bentuknya agar tidak salah membatalkan.
        self.error.as_deref() == Some("paid")
            || self.message.as_deref().is_some_and(|message| {
                message.to_ascii_lowercase().contains("sudah dibayar")
                    || message.to_ascii_lowercase().contains("sudah lunas")
            })
    }
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
}

/// Tampilan order untuk member: TANPA token/QRIS string/URL Cutiezy.
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
    granted_quota, granted_expires_at, mutation_ref, last_error, created_at, updated_at";

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
/// Token Cutiezy BOLEH tampil di sini (admin saja, bukan member).
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
/// - Klien Cutiezy di modul ini HANYA punya: POST /api/qris/create,
///   GET /qris/check-status/{token}, POST /api/qris/cancel (lihat
///   `QrisClient`). TIDAK ADA endpoint refund uang yang terverifikasi
///   di kode maupun dokumen pohon ini, dan komentar di
///   `resolve_needs_review_order` menegaskan refund diselesaikan manual
///   di luar aplikasi. Karena itu endpoint ini TIDAK PERNAH memanggil
///   provider dan TIDAK PERNAH menggerakkan uang.
/// - Alur yang diharapkan: admin mengembalikan uang lewat dashboard
///   Cutiezy secara manual, lalu MENCATATNYA di sini. `external_ref`
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
    // (string paid_at Cutiezy gagal diparsing di cabang Paid) tidak
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

/// Baris QR yatim (K26) — token TIDAK PERNAH masuk view panel.
#[derive(Debug, Clone, sqlx::FromRow)]
struct OrphanQrRow {
    id: String,
    member_id: String,
    qris_token: String,
    amount_idr: u64,
    status: String,
}

/// Tampilan QR yatim untuk panel admin (tanpa token).
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct OrphanQrView {
    pub id: String,
    pub member_id: String,
    pub member_email: Option<String>,
    pub amount_idr: u64,
    pub status: String,
    pub resolved_order_id: Option<String>,
    pub note: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Catat QR yatim yang gagal dibatalkan (K26, best-effort). Dulu yang
/// tersisa hanya log error: bila member membayar QR itu, uang masuk
/// tanpa baris order dan tidak ada jalur grant aplikasi sama sekali
/// (hanya manual lewat dashboard Cutiezy). Kini barisnya tersimpan di
/// `orphan_qr` sehingga admin bisa me-resolve-berbukti dari panel.
pub async fn record_orphan_qr(
    pool: &MySqlPool,
    member_id: &Uuid,
    token: &str,
    amount_idr: u64,
) {
    let id = Uuid::now_v7().to_string();
    if let Err(error) = sqlx::query(
        "INSERT INTO orphan_qr (id, member_id, qris_token, amount_idr, status, created_at) \
         VALUES (?, ?, ?, ?, 'open', UTC_TIMESTAMP(6))",
    )
    .bind(&id)
    .bind(member_id.to_string())
    .bind(token)
    .bind(amount_idr)
    .execute(pool)
    .await
    {
        tracing::warn!(?error, "QR yatim gagal dicatat ke orphan_qr (hanya log yang tersisa)");
    }
}

/// Daftar QR yatim yang belum selesai (open + linked) untuk panel admin.
pub async fn list_orphan_qrs(pool: &MySqlPool) -> Result<Vec<OrphanQrView>, AppError> {
    sqlx::query_as::<_, OrphanQrView>(
        "SELECT o.id, o.member_id, m.email AS member_email, o.amount_idr, o.status, \
         o.resolved_order_id, o.note, o.created_at, o.updated_at \
         FROM orphan_qr o LEFT JOIN members m ON m.id = o.member_id \
         WHERE o.status IN ('open', 'linked') ORDER BY o.created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Daftar QR yatim tidak dapat dibaca"))
}

/// Resolve-berbukti untuk QR yatim (K26): admin memilih paket + RRN
/// dari dashboard Cutiezy, server memverifikasi lewat check-status —
/// hanya `Paid` + nominal SAMA PERSIS dengan nominal QR yatim + RRN
/// cocok (bila check-status mengembalikan mutation_ref) yang dilanjutkan
/// ke pembuatan order `paid` + grant. RRN yang diberikan admin tapi
/// tidak dikembalikan check-status dicatat sebagai referensi (atestasi
/// admin dari dashboard), bukan ditolak buta — nominal tetap gerbang
/// kerasnya. Hasil:
/// - `Granted`/`AlreadyGranted`: kuota mendarat, orphan `resolved`.
/// - `NeedsReview`: grant tertahan (kunci/member tidak aktif) — order
///   `needs_review` sudah dibuat dan orphan `linked` ke order itu agar
///   tidak bisa di-resolve ganda; lanjutkan lewat tombol resolve order.
/// - `Rejected`: check-status membuktikan belum lunas — orphan tetap
///   `open`, tidak ada order yang dibuat, tidak ada grant.
/// Retry aman: order `paid` yang sudah dibuat oleh percobaan sebelumnya
/// ditemukan lewat token dan dipakai ulang (bukan dibuat ganda).
pub async fn resolve_orphan_qr(
    store: &AdminStore,
    config: &AppConfig,
    orphan_id: Uuid,
    package_id: Uuid,
    mutation_ref_input: Option<&str>,
) -> Result<(Option<MemberOrderView>, VerifyOutcome), AppError> {
    let pool = pool_or_unavailable(store)?;
    let orphan = sqlx::query_as::<_, OrphanQrRow>(
        "SELECT id, member_id, qris_token, amount_idr, status FROM orphan_qr WHERE id = ?",
    )
    .bind(orphan_id.to_string())
    .fetch_optional(&pool)
    .await
    .map_err(|_| AppError::internal("QR yatim tidak dapat dibaca"))?
    .ok_or_else(|| AppError::not_found("QR yatim tidak ditemukan"))?;
    if orphan.status != "open" {
        return Err(AppError::conflict(
            "QR yatim ini sudah ditangani (resolved/linked); lanjutkan lewat order yang tertaut.",
        ));
    }
    let member_uuid = Uuid::parse_str(&orphan.member_id)
        .map_err(|_| AppError::internal("Member QR yatim tidak valid"))?;
    match store.member_by_id(member_uuid).await? {
        Some(member) if member.status == "active" => {}
        Some(_) => {
            return Err(AppError::conflict(
                "Member masih dinonaktifkan; aktifkan member dulu, baru resolve QR yatim.",
            ));
        }
        None => {
            return Err(AppError::conflict(
                "Member tidak ditemukan; resolve QR yatim tidak dapat dilanjutkan.",
            ));
        }
    }
    let package = store
        .list_packages()
        .await
        .into_iter()
        .find(|package| package.id == package_id)
        .filter(|package| package.active)
        .ok_or_else(|| AppError::bad_request("Paket tidak ditemukan atau tidak aktif"))?;
    // Order dari percobaan sebelumnya (retry aman): pakai ulang, jangan
    // buat ganda.
    let existing = sqlx::query_as::<_, PackageOrderRow>(&format!(
        "SELECT {ORDER_COLUMNS} FROM package_orders WHERE qris_token = ? \
         ORDER BY created_at DESC LIMIT 1"
    ))
    .bind(&orphan.qris_token)
    .fetch_optional(&pool)
    .await
    .map_err(|_| AppError::internal("Order QR yatim tidak dapat dibaca"))?;
    if let Some(row) = &existing {
        match row.status.as_str() {
            "granted" => {
                mark_orphan(&pool, &orphan.id, "resolved", Some(&row.id)).await;
                return Ok((Some(row.member_view()), VerifyOutcome::AlreadyGranted));
            }
            "needs_review" => {
                return Err(AppError::conflict(
                    "QR yatim ini sudah tertaut ke order needs_review; lanjutkan lewat tombol Grant ulang pada order itu.",
                ));
            }
            "paid" => {
                // Lanjut ke grant di bawah (order sudah ada).
            }
            _ => {
                return Err(AppError::conflict(
                    "Sudah ada order lain untuk token QR ini; tangani lewat order itu.",
                ));
            }
        }
    }
    let client = QrisClient::new(&config.qris_base_url)?;
    // Order `paid` dari percobaan sebelumnya sudah terbukti lunas —
    // langsung grant tanpa check ulang (check yang kini non-Paid tidak
    // boleh membatalkan bukti lama).
    let reuse_paid = matches!(
        existing.as_ref().map(|row| row.status.as_str()),
        Some("paid")
    );
    let (paid_at, check_ref) = if reuse_paid {
        (None, None)
    } else {
        let status = client.check(&orphan.qris_token).await.map_err(|error| {
            tracing::warn!(?error, "Cek status QRIS (resolve yatim) gagal");
            error.to_app_error()
        })?;
        match status {
            QrisPaymentStatus::Paid {
                amount,
                mutation_ref,
                paid_at,
            } => {
                if amount != orphan.amount_idr {
                    return Err(AppError::conflict(
                        "Nominal bayar dari Cutiezy tidak sama dengan nominal QR yatim — grant tidak diizinkan.",
                    ));
                }
                if let (Some(input), Some(check)) =
                    (mutation_ref_input.map(str::trim).filter(|value| !value.is_empty()), mutation_ref.as_deref())
                {
                    if input != check {
                        return Err(AppError::conflict(
                            "RRN dari dashboard tidak cocok dengan mutation_ref check-status — grant tidak diizinkan.",
                        ));
                    }
                }
                (paid_at, mutation_ref)
            }
            // Terbukti belum lunas: tolak, orphan tetap open.
            _ => return Ok((None, VerifyOutcome::Rejected)),
        }
    };
    let mutation_ref = check_ref
        .or_else(|| mutation_ref_input.map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned));
    let settings = load_qris_settings(&pool).await?;
    let order_uuid = match &existing {
        Some(row) => Uuid::parse_str(&row.id)
            .map_err(|_| AppError::internal("ID order QR yatim tidak valid"))?,
        None => {
            let order_id = Uuid::now_v7();
            let now = Utc::now();
            sqlx::query(
                "INSERT INTO package_orders (id, member_id, package_id, package_name, \
                 price_idr, quota_hits, rate_limit_per_minute, valid_days, amount_idr, \
                 status, qris_token, qris_string, qris_image_url, qris_expires_at, paid_at, \
                 mutation_ref, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paid', ?, NULL, NULL, ?, ?, ?, ?)",
            )
            .bind(order_id.to_string())
            .bind(orphan.member_id.clone())
            .bind(package.id.to_string())
            .bind(&package.name)
            .bind(orphan.amount_idr)
            .bind(package.included_hits)
            .bind(package.rate_limit_per_minute)
            .bind(settings.valid_days)
            .bind(orphan.amount_idr)
            .bind(&orphan.qris_token)
            .bind(now.naive_utc())
            .bind(paid_at)
            .bind(mutation_ref.as_deref())
            .bind(now.naive_utc())
            .execute(&pool)
            .await
            .map_err(|_| AppError::internal("Order QR yatim tidak dapat dibuat"))?;
            order_id
        }
    };
    let order_row = get_order(&pool, &order_uuid)
        .await?
        .ok_or_else(|| AppError::internal("Order QR yatim tidak ditemukan"))?;
    match store
        .grant_package_order(
            order_uuid,
            member_uuid,
            package.included_hits,
            settings.valid_days,
            package.rate_limit_per_minute,
            package.id,
        )
        .await
    {
        Ok(GrantOutcome::Granted { .. }) => {
            mark_orphan(&pool, &orphan.id, "resolved", Some(&order_row.id)).await;
            let row = get_order(&pool, &order_uuid)
                .await?
                .unwrap_or(order_row);
            Ok((Some(row.member_view()), VerifyOutcome::Granted))
        }
        Ok(GrantOutcome::AlreadyGranted) => {
            mark_orphan(&pool, &orphan.id, "resolved", Some(&order_row.id)).await;
            let row = get_order(&pool, &order_uuid)
                .await?
                .unwrap_or(order_row);
            Ok((Some(row.member_view()), VerifyOutcome::AlreadyGranted))
        }
        Err(error) if error.status == StatusCode::CONFLICT => {
            // Grant tertahan (kunci/member tidak aktif): parkir order ke
            // needs_review dan tautkan orphan agar tidak di-resolve ganda.
            let changed = set_order_status(
                &pool,
                &order_row.id,
                "paid",
                "needs_review",
                None,
                Some("Grant QR yatim ditahan untuk admin (kunci/member tidak aktif atau status berubah)"),
            )
            .await?;
            let row = get_order(&pool, &order_uuid)
                .await?
                .unwrap_or(order_row);
            if changed {
                mark_orphan(&pool, &orphan.id, "linked", Some(&row.id)).await;
            }
            Ok((Some(row.member_view()), VerifyOutcome::NeedsReview))
        }
        Err(error) => Err(error),
    }
}

async fn mark_orphan(pool: &MySqlPool, orphan_id: &str, status: &str, order_id: Option<&str>) {
    if let Err(error) = sqlx::query(
        "UPDATE orphan_qr SET status = ?, resolved_order_id = ?, updated_at = UTC_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(status)
    .bind(order_id)
    .bind(orphan_id)
    .execute(pool)
    .await
    {
        tracing::warn!(?error, "Status QR yatim gagal diperbarui");
    }
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

/// Referensi log untuk token QR: hash SHA-256 token yang dipotong
/// (12 hex) + panjang token. Cukup untuk mengorelasikan baris log
/// dengan satu QR, tanpa menulis token penuh ke jurnal — token penuh
/// memungkinkan check-status/cancel oleh siapa pun yang membaca log.
/// Hash dipilih, bukan prefix, karena panjang/format token tidak
/// dijamin sehingga prefix bisa menyingkap sebagian besar token pendek.
fn token_log_ref(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    format!(
        "sha256:{}..len{}",
        &hex::encode(hash)[..12],
        token.chars().count()
    )
}

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
    // Serialisasi create per proses: cek waiting + create + insert tidak
    // boleh disalip create lain (tiap QR sukses = 6 hit Cutiezy).
    let _guard = CREATE_ORDER_LOCK.lock().await;
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
    // ikut terhitung; itu disengaja — tiap create sukses memotong
    // 6 hit Cutiezy apa pun nasib ordernya.
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
    let api_key = settings
        .api_key_ciphertext
        .as_deref()
        .and_then(|ciphertext| decrypt_setting(&cipher_or_unavailable(config), ciphertext))
        .ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "qris_not_configured",
                "Pembayaran belum dikonfigurasi admin.",
            )
        })?;
    let client = QrisClient::new(&config.qris_base_url)?;
    let invoice = match client
        .create(
            &api_key,
            effective,
            settings.expiry_minutes,
            settings.source_id,
        )
        .await
    {
        Ok(invoice) => invoice,
        Err(error) => {
            tracing::warn!(?error, "Create QRIS gagal");
            // B11: kegagalan create kini DICATAT ke last_error panel
            // admin (record_qris_error) — sebelumnya tidak ada jalur
            // create yang memanggilnya, jadi admin hanya bisa melihat
            // kegagalan ini dari log server. Pesan admin BOLEH menyebut
            // detail provider (409 QRIS_SOURCE_REQUIRED); pesan ke
            // member tetap generik lewat to_app_error di bawah.
            let admin_note = match &error {
                QrisError::Provider {
                    http_status: 409,
                    code: Some(code),
                    ..
                } if code == "QRIS_SOURCE_REQUIRED" => {
                    "Create QRIS ditolak Cutiezy (409 QRIS_SOURCE_REQUIRED): \
                     akun Cutiezy belum punya QRIS sumber — upload QRIS sumber \
                     di dashboard Cutiezy, lalu isi source_id di pengaturan QRIS."
                        .to_owned()
                }
                QrisError::Provider {
                    http_status,
                    code,
                    message,
                } => format!(
                    "Create QRIS gagal (HTTP {http_status}, {}): {message}",
                    code.as_deref().unwrap_or("-"),
                ),
                QrisError::PartialCreated { message, .. } => {
                    format!("Create QRIS parsial (QR yatim dibatalkan best-effort): {message}")
                }
                other => format!("Create QRIS gagal: {other:?}"),
            };
            record_qris_error(&pool, &admin_note).await;
            // K20: QR yatim dari create parsial dibatalkan best-effort
            // di sini (create Cutiezy memakai auth header, bukan query,
            // jadi tidak ada kredensial di URL yang tercatat).
            if let Some(token) = error.orphan_token() {
                if let Err(cancel_error) = client.cancel(&api_key, token).await {
                    tracing::error!(?cancel_error, member_id = %member_id, token_ref = %token_log_ref(token), amount = effective, "Cancel QR yatim gagal — QR berbayar tanpa order");
                    // K26: simpan QR yatim agar bisa di-resolve-berbukti
                    // dari panel (bukan hanya log).
                    record_orphan_qr(&pool, &member_id, token, effective).await;
                }
            }
            return Err(error.to_app_error());
        }
    };
    if let Some(remaining) = invoice.remaining_quota {
        record_cutiezy_remaining(&pool, remaining).await;
    }
    let order_id = Uuid::now_v7();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::minutes(settings.expiry_minutes);
    // Retry the insert (audit 2026-10-25, K7): a transient database blip
    // used to orphan an already-issued (payable) QR with no order row.
    let mut insert_error = None;
    for attempt in 0..3 {
        match sqlx::query(
            "INSERT INTO package_orders (id, member_id, package_id, package_name, \
             price_idr, quota_hits, rate_limit_per_minute, valid_days, amount_idr, \
             status, qris_token, qris_string, qris_image_url, qris_expires_at, created_at) \
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
        .bind(effective)
        .bind(&invoice.token)
        .bind(&invoice.qris_string)
        .bind(&invoice.image_url)
        .bind(expires_at.naive_utc())
        .bind(now.naive_utc())
        .execute(&pool)
        .await
        {
            Ok(_) => {
                insert_error = None;
                break;
            }
            Err(error) => {
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
    if let Some(error) = insert_error {
        // QR sudah terbit di Cutiezy tapi order gagal tersimpan: batalkan
        // QR-nya (best-effort) agar tidak jadi QR yatim berbayar.
        tracing::warn!(?error, "Insert order gagal setelah create QRIS (3 percobaan)");
        if let Err(cancel_error) = client.cancel(&api_key, &invoice.token).await {
            // Loud: a paid orphan QR cannot be granted without an order row.
            tracing::error!(?cancel_error, member_id = %member_id, token_ref = %token_log_ref(&invoice.token), amount = effective, "Cancel QR yatim gagal — QR berbayar tanpa order");
            // K26: simpan QR yatim agar bisa di-resolve-berbukti dari panel.
            record_orphan_qr(&pool, &member_id, &invoice.token, effective).await;
        }
        return Err(AppError::internal("Order tidak dapat dibuat. Coba lagi."));
    }
    let row = get_order(&pool, &order_id)
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
    /// not-found dari Cutiezy): grant ditolak, status order TIDAK
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
/// Order yang ditandai expired oleh sweep lokal bisa ternyata lunas di
/// Cutiezy (bayar telat / settlement lag): dulu verify langsung pulang
/// `Expired`/`Canceled` tanpa re-check, dan sweep rutin tidak pernah
/// memungut status terminal, sehingga uang lunas menggantung tanpa
/// grant sampai admin memanggil resolve mentah. Kini SATU re-check
/// Cutiezy dilakukan: hanya `Paid` + nominal COCOK yang dilanjutkan ke
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
    let Some(token) = order.qris_token.clone() else {
        return Ok((view, original));
    };
    let client = QrisClient::new(&config.qris_base_url)?;
    let status = client.check(&token).await.map_err(|error| {
        tracing::warn!(?error, "Cek status QRIS gagal (re-check order terminal)");
        error.to_app_error()
    })?;
    match status {
        QrisPaymentStatus::Paid {
            amount,
            mutation_ref,
            paid_at,
        } => {
            if amount != order.amount_idr {
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
        // Belum/tidak lunas menurut Cutiezy: outcome terminal dipertahankan.
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
        // Cutiezy dulu (bayar telat yang terbukti lunas tetap di-grant).
        "expired" | "canceled" => {
            return verify_terminal_order(store, config, &order).await;
        }
        _ => {}
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
    let Some(token) = order.qris_token.clone() else {
        return Err(AppError::internal("Order tanpa token QRIS"));
    };
    let client = QrisClient::new(&config.qris_base_url)?;
    let status = client.check(&token).await.map_err(|error| {
        tracing::warn!(?error, "Cek status QRIS gagal");
        error.to_app_error()
    })?;
    match status {
        QrisPaymentStatus::Paid {
            amount,
            mutation_ref,
            paid_at,
        } => {
            if amount != order.amount_idr {
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
                // AREA 3 trigger (a): order BARU parkir ke needs_review
                // (transisi, bukan pengulangan) -> alert + jejak aktivitas.
                crate::alerts::alert_with_store(
                    store,
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
            // Cutiezy still says pending, but our local expiry passed:
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
            // Token tak dikenal Cutiezy: jangan buru-buru expired; tunggu
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
///   check-status Cutiezy dulu: hanya `Paid` + nominal COCOK PERSIS
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
    // B7: order tanpa bukti bayar WAJIB re-verifikasi dulu.
    if order.paid_at.is_none() {
        let token = order
            .qris_token
            .clone()
            .ok_or_else(|| AppError::internal("Order tanpa token QRIS"))?;
        let client = QrisClient::new(&config.qris_base_url)?;
        let status = client.check(&token).await.map_err(|error| {
            tracing::warn!(?error, "Cek status QRIS (resolve) gagal");
            error.to_app_error()
        })?;
        match status {
            QrisPaymentStatus::Paid {
                amount,
                mutation_ref,
                paid_at,
            } => {
                if amount != order.amount_idr {
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
                        "Nominal bayar dari Cutiezy tidak sama dengan order — grant ulang tidak diizinkan; selesaikan manual (refund/cek mutasi).",
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
                // AREA 3 trigger (a): grant GAGAL dan order BARU parkir
                // ke needs_review (transisi saja) -> alert + jejak.
                crate::alerts::alert_with_store(
                    store,
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
    Ok(match outcome {
        GrantOutcome::Granted { .. } => (row.member_view(), VerifyOutcome::Granted),
        GrantOutcome::AlreadyGranted => (row.member_view(), VerifyOutcome::AlreadyGranted),
    })
}

/// Apakah event webhook ini notifikasi pembayaran? Docs Cutiezy tidak
/// konsisten: halaman webhook memakai `qris.payment`, halaman QRIS sempat
/// menyebut `qris.payment.success` — terima keduanya. `test.ping` dan
/// event lain diakui (200) tapi tidak memicu apa pun.
pub(crate) fn is_payment_event(event: Option<&str>) -> bool {
    matches!(event, Some("qris.payment") | Some("qris.payment.success"))
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
/// sebagai pemicu dari webhook: webhook mutasi Cutiezy TIDAK membawa
/// token order kita (hanya reference RRN bank + nominal), jadi webhook
/// tidak boleh mencocokkan order apa pun — ia hanya membangunkan
/// rekonsiliasi, dan grant tetap diputuskan verify_and_grant lewat
/// check-status + cocok nominal. Satu pass, tanpa loop; error per order
/// dicatat, sweep rutin tiap menit tetap menjadi backstop.
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
/// besar untuk mentolerir blip Cutiezy sesaat, cukup kecil agar 20
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
    fn check_status_amount_accepts_string_and_float() {
        // K25: nominal string/float tidak boleh menggagalkan parsing.
        let numeric: CheckResponse =
            serde_json::from_str(r#"{"status":"paid","amount":150000}"#).unwrap();
        assert_eq!(numeric.amount, Some(150000));
        let string: CheckResponse =
            serde_json::from_str(r#"{"status":"paid","amount":"150000"}"#).unwrap();
        assert_eq!(string.amount, Some(150000));
        let float: CheckResponse =
            serde_json::from_str(r#"{"status":"paid","amount":150000.0}"#).unwrap();
        assert_eq!(float.amount, Some(150000));
        // String non-numerik / float berpecahan -> None (bukan gagal
        // parse seluruh bodi); cabang Paid memakai 0 -> mismatch.
        let bad: CheckResponse =
            serde_json::from_str(r#"{"status":"paid","amount":"seratus"}"#).unwrap();
        assert_eq!(bad.amount, None);
        let frac: CheckResponse =
            serde_json::from_str(r#"{"status":"paid","amount":150000.5}"#).unwrap();
        assert_eq!(frac.amount, None);
        let missing: CheckResponse = serde_json::from_str(r#"{"status":"paid"}"#).unwrap();
        assert_eq!(missing.amount, None);
    }

    #[test]
    fn token_log_ref_never_contains_full_token() {
        let token = "tok_live_contoh_token_panjang_0123456789";
        let reference = token_log_ref(token);
        assert!(
            !reference.contains(token),
            "referensi log tidak boleh memuat token penuh: {reference}"
        );
        assert_eq!(
            reference,
            token_log_ref(token),
            "referensi harus deterministik untuk token yang sama"
        );
        assert_ne!(
            reference,
            token_log_ref("tok_live_token_lain_yang_berbeda_9876543210"),
            "token berbeda harus menghasilkan referensi berbeda"
        );
        // Token pendek/kosong tidak boleh panic dan referensinya bukan token itu sendiri.
        assert!(!token_log_ref("").is_empty());
        assert_ne!(token_log_ref("x"), "x");
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
    fn allowed_expiry_minutes_match_cutiezy_docs() {
        assert_eq!(ALLOWED_EXPIRY_MINUTES, [3, 5, 10, 12, 15]);
    }

    #[test]
    fn payment_event_accepts_both_documented_names() {
        assert!(is_payment_event(Some("qris.payment")));
        assert!(is_payment_event(Some("qris.payment.success")));
        assert!(!is_payment_event(Some("test.ping")));
        assert!(!is_payment_event(Some("qris.refund")));
        assert!(!is_payment_event(None));
    }

    /// K26: format legacy WIB, ISO naive 'T', dan RFC 3339 berzona.
    #[test]
    fn cutiezy_paid_at_accepts_legacy_and_iso8601() {
        let legacy = parse_cutiezy_paid_at("2026-10-25 10:00:00").unwrap();
        // WIB 10:00 -> UTC 03:00 (geser -7 jam, perilaku lama dipertahankan).
        assert_eq!(
            legacy,
            NaiveDateTime::parse_from_str("2026-10-25 03:00:00", "%Y-%m-%d %H:%M:%S").unwrap()
        );
        // ISO naive 'T' diperlakukan WIB juga.
        assert_eq!(
            parse_cutiezy_paid_at("2026-10-25T10:00:00").unwrap(),
            legacy
        );
        // RFC 3339 +07:00 -> UTC 03:00 TANPA geser tambahan.
        assert_eq!(
            parse_cutiezy_paid_at("2026-10-25T10:00:00+07:00").unwrap(),
            legacy
        );
        // RFC 3339 Z sudah UTC: tidak digeser sama sekali.
        assert_eq!(
            parse_cutiezy_paid_at("2026-10-25T03:00:00Z").unwrap(),
            legacy
        );
        assert!(parse_cutiezy_paid_at("bukan-tanggal").is_none());
        assert!(parse_cutiezy_paid_at("").is_none());
    }

    /// K24: allowlist host — Cutiezy + base host saja.
    #[test]
    fn qr_host_allowlist_covers_cutiezy_and_base_host_only() {
        let client = QrisClient::new("https://api.cutiezy.id").unwrap();
        let allowed = |url: &str| client.qr_host_allowed(&url::Url::parse(url).unwrap());
        assert!(allowed("https://api.cutiezy.id/qr.png"));
        assert!(allowed("https://cdn.cutiezy.id/qr.png"));
        assert!(allowed("https://cutiezy.id/qr.png"));
        assert!(!allowed("https://evil.com/qr.png"));
        assert!(!allowed("https://fakecutiezy.id/qr.png"));
        assert!(!allowed("https://api.cutiezy.id.evil.com/qr.png"));
        assert!(!allowed("https://cutiezy.id.evil.com/qr.png"));
        // Base host kustom (mock lokal di tes lain) ikut diizinkan.
        let local = QrisClient::new("http://127.0.0.1:9999").unwrap();
        assert!(local.qr_host_allowed(&url::Url::parse("http://127.0.0.1:9999/qr.png").unwrap()));
        assert!(!local.qr_host_allowed(&url::Url::parse("http://127.0.0.1:8888/qr.png").unwrap()));
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

    /// Helper mock HTTP satu-respons untuk tes create/fetch di bawah:
    /// membaca header + bodi request lalu membalas payload tetap.
    fn spawn_fixed_mock(payload: Vec<u8>, content_type: &'static str) -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let text = String::from_utf8_lossy(&head);
                let content_length = text.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                });
                if let Some(len) = content_length {
                    let mut body = vec![0u8; len];
                    let _ = stream.read_exact(&mut body);
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.write_all(&payload);
            }
        });
        port
    }

    /// K20: nominal beda -> PartialCreated + token yatim bisa dibatalkan.
    #[tokio::test]
    async fn create_amount_mismatch_returns_orphan_token() {
        let port = spawn_fixed_mock(
            br#"{"ok":true,"data":{"token":"tok-yatim","amount":123,"qris_string":"000201xxx","image_url":null}}"#.to_vec(),
            "application/json",
        );
        let client = QrisClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let error = client
            .create("kunci-palsu", 99000, 15, None)
            .await
            .unwrap_err();
        assert_eq!(error.orphan_token(), Some("tok-yatim"));
        assert!(matches!(error, QrisError::PartialCreated { .. }));
        // Pesan member tetap generik (tanpa detail provider).
        assert_eq!(error.member_message(), "Terjadi kesalahan. Coba lagi.");
    }

    /// K20: 2xx non-JSON -> Unexpected tanpa token (tidak ada QR yang
    /// terbukti terbit, jadi tidak ada yang bisa dibatalkan).
    #[tokio::test]
    async fn create_non_json_2xx_has_no_orphan_token() {
        let port = spawn_fixed_mock(b"bukan-json".to_vec(), "text/html");
        let client = QrisClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let error = client
            .create("kunci-palsu", 99000, 15, None)
            .await
            .unwrap_err();
        assert_eq!(error.orphan_token(), None);
        assert!(matches!(error, QrisError::Unexpected(_)));
    }

    /// K24: host asing ditolak sebelum request; bodi raksasa ditolak
    /// batas streaming 1 MiB walau tanpa Content-Length.
    #[tokio::test]
    async fn fetch_qr_png_rejects_foreign_host_and_oversize_body() {
        let client = QrisClient::new("https://api.cutiezy.id").unwrap();
        let error = client
            .fetch_qr_png("https://example.com/qr.png")
            .await
            .unwrap_err();
        assert!(matches!(error, QrisError::Unexpected(_)));

        let big = vec![b'A'; 1_048_576 + 65_536];
        let port = spawn_fixed_mock(big, "image/png");
        let local = QrisClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let error = local
            .fetch_qr_png(&format!("http://127.0.0.1:{port}/qr.png"))
            .await
            .unwrap_err();
        assert!(matches!(error, QrisError::Unexpected(_)));
    }

    /// Klien melawan mock HTTP lokal (tanpa dependensi baru): create,
    /// check-status, cancel, dan proxy gambar QR.
    #[tokio::test]
    async fn client_talks_to_mock_cutiezy() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let text = String::from_utf8_lossy(&head);
                let content_length = text.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                });
                if let Some(len) = content_length {
                    let mut body = vec![0u8; len];
                    let _ = stream.read_exact(&mut body);
                }
                let request_line = text.lines().next().unwrap_or("");
                let (status, content_type, payload): (u16, &str, Vec<u8>) = if request_line
                    .starts_with("POST /api/qris/create")
                {
                    (
                            200,
                            "application/json",
                            format!(
                                r#"{{"ok":true,"data":{{"token":"tok123","amount":99000,"qris_string":"000201xxx","image_url":"http://127.0.0.1:{port}/qr.png"}},"remaining_quota":{{"remaining":42}}}}"#
                            )
                            .into_bytes(),
                        )
                } else if request_line.starts_with("GET /qris/check-status/") {
                    (
                            200,
                            "application/json",
                            br#"{"status":"paid","amount":99000,"paid_at":"2026-10-25 10:00:00","mutation_ref":"MUT1"}"#.to_vec(),
                        )
                } else if request_line.starts_with("POST /api/qris/cancel") {
                    (200, "application/json", br#"{"ok":true}"#.to_vec())
                } else if request_line.starts_with("GET /qr.png") {
                    (200, "image/png", b"\x89PNG\r\n\x1a\nfake".to_vec())
                } else {
                    (
                        404,
                        "application/json",
                        br#"{"error":"not_found"}"#.to_vec(),
                    )
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(&payload);
            }
        });
        let client = QrisClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let created = client.create("kunci-palsu", 99000, 15, None).await.unwrap();
        assert_eq!(created.token, "tok123");
        assert_eq!(created.amount, 99000);
        assert_eq!(created.remaining_quota, Some(42));
        assert!(created.image_url.as_deref().unwrap().ends_with("/qr.png"));
        match client.check("tok123").await.unwrap() {
            QrisPaymentStatus::Paid {
                amount,
                mutation_ref,
                paid_at,
            } => {
                assert_eq!(amount, 99000);
                assert_eq!(mutation_ref.as_deref(), Some("MUT1"));
                // Mock Cutiezy mengirim paid_at WIB 10:00 -> disimpan UTC 03:00.
                assert_eq!(
                    paid_at,
                    NaiveDateTime::parse_from_str("2026-10-25 03:00:00", "%Y-%m-%d %H:%M:%S").ok()
                );
            }
            other => panic!("status tak terduga: {other:?}"),
        }
        client.cancel("kunci-palsu", "tok123").await.unwrap();
        let (bytes, content_type) = client
            .fetch_qr_png(&format!("http://127.0.0.1:{port}/qr.png"))
            .await
            .unwrap();
        assert_eq!(content_type, "image/png");
        assert!(bytes.starts_with(b"\x89PNG"));
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
}

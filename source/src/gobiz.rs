//! Klien provider QRIS Gobiz — satu-satunya provider QRIS Rajacek.
//! Kredensial + base/callback URL diatur admin lewat panel (tersimpan
//! terenkripsi di `qris_settings`).
//!
//! Kontrak Gobiz — dibaca dari integrasi yang sudah live di ekosistem
//! ini (bukan karangan), 31 Okt 2026:
//! - Klien Go AI Gateway: `~/workspace/ai-gateway/backend/internal/gobiz/client.go`
//!   (Create/Get/Cancel + `describeError` + `parsePayment`) dan handler
//!   webhook `internal/handlers/topups.go` (`verifySignature`).
//! - Base URL default `https://gobiz-payment-v2.andrias.workers.dev`
//!   (URL layanan publik, bukan secret; di-trim trailing `/`).
//!   Auth: header `X-API-Key`. Timeout klien 30 detik,
//!   bodi respons dibatasi 1 MiB (sama seperti AI Gateway).
//! - Create: `POST {base}/v1/payments`, bodi
//!   `{amount, order_id, callback_url, expires_in (detik), unique_amount}`.
//!   AI Gateway selalu `unique_amount=true` dan `expires_in=900` (15 mnt).
//!   Jawaban 2xx (create: 201) = objek payment di top level, dengan
//!   fallback wrapper `"payment"` / `"data"`.
//! - GetStatus: `GET {base}/v1/payments/{id}` -> objek payment yang sama.
//! - Cancel: `POST {base}/v1/payments/{id}/cancel` (tanpa bodi).
//! - Objek payment: `{id, order_id, amount, expected_amount,
//!   unique_suffix, status, qris_string, callback_url, expires_at,
//!   tx_id (nullable), paid_at (nullable)}`. `expected_amount` adalah
//!   nominal yang HARUS dibayar member (harga + sufiks unik) — sampel
//!   live 12 Okt 2026: amount 10000 -> expected_amount 10458 (sufiks
//!   458, TIDAK terbatas ±99). Verifikasi grant mencocokkan
//!   `expected_amount`, bukan harga paket mentah.
//! - Status worker: `pending` | `paid` | `expired` | `cancelled`.
//!   `"failed"` hanya status lokal tabel topups AI Gateway, bukan dari
//!   worker — bila worker mengembalikannya, dipetakan ke error (retry
//!   sweep) agar tidak pernah grant maupun expired diam-diam.
//! - Error non-2xx: `{error: string}` | `{error: {code, message}}` |
//!   `{message}` | raw body, dipotong 160 karakter, format
//!   `"http {status}: {pesan}"` (gaya `describeError` AI Gateway;
//!   pemotongan di sini per karakter, bukan per byte seperti Go, agar
//!   tidak membelah karakter UTF-8).
//! - Webhook: HMAC-SHA256 atas RAW BODY dengan secret sebagai key,
//!   header `X-Webhook-Signature` (di-trim), terima encoding HEX dulu
//!   lalu base64 standar, perbandingan constant-time, header kosong
//!   -> false (persis `verifySignature` AI Gateway; implementasinya
//!   dipakai ulang dari `qris::verify_webhook_signature`).
//!
//! Aturan keamanan (tanpa kecuali):
//! - Id payment Gobiz, `qris_string`, dan URL provider TIDAK PERNAH
//!   diserialisasi ke view member. QR member tetap lewat proxy endpoint
//!   sendiri (`/v1/member/orders/:id/qr`), yang untuk Gobiz me-render
//!   SVG server-side dari `qris_string` (Gobiz tidak menyediakan
//!   image_url; render client-side dilarang karena akan mengekspos
//!   `qris_string` ke browser).
//! - Webhook TIDAK PERNAH grant langsung: hanya memicu sweep yang
//!   re-verifikasi via GetStatus + cocokkan `expected_amount` dulu;
//!   mismatch -> `needs_review`.
//! - Grant tetap lewat `store::grant_package_order` (atomik CAS);
//!   race webhook+polling+sweep hanya satu yang menang.
//!
//! Yang BELUM terkonfirmasi dari kontrak (TODO, jangan ditebak):
//! - Kode HTTP Gobiz untuk id pembayaran tak dikenal (diasumsikan 404
//!   -> `NotFound`; bila kodenya lain, sweep
//!   memperlakukannya sebagai error retryable — aman, tanpa grant
//!   salah).
//! - Bentuk error cancel atas payment yang sudah paid (tidak ditebak:
//!   `cancel_order` member melakukan GetStatus setelah cancel gagal,
//!   bukan menebak bentuk error).
//! - Kebijakan retry webhook worker (jumlah/interval tidak
//!   terkonfirmasi; sweep rutin 60 detik tetap menjadi backstop).

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::AppError;
use crate::qris::QrisPaymentStatus;
use axum::http::StatusCode;

/// Base URL worker Gobiz produksi (URL layanan publik, bukan secret).
/// Nilai default field `gobiz_base_url` di pengaturan; admin boleh
/// mengubahnya dari panel.
pub const DEFAULT_GOBIZ_BASE_URL: &str = "https://gobiz-payment-v2.andrias.workers.dev";

/// Callback default yang dikirim per payment (endpoint webhook Gobiz
/// Rajacek). Admin boleh mengubahnya dari panel.
pub const DEFAULT_GOBIZ_CALLBACK_URL: &str =
    "https://www.rajacek.com/v1/payments/qris/webhook/gobiz";

/// Nominal invoice tes Gobiz (Rp5.000): nominal terkecil yang TERBUKTI
/// diterima Gobiz di ekosistem ini (minimum deposit berikutnya di Go),
/// bukan minimum kontrak Gobiz (tidak ditemukan di kontrak). Bila Gobiz
/// menolaknya, error ditampilkan apa adanya oleh tombol tes.
pub const GOBIZ_TEST_AMOUNT: u64 = 5_000;

/// Prefix order_id invoice tes. Memenuhi syarat brief ("berprefix
/// TEST-") sekaligus pola Go (`TEST-GOBIZ-`).
pub const GOBIZ_TEST_ORDER_PREFIX: &str = "TEST-GOBIZ-";

/// Batas bodi respons Gobiz (sama seperti AI Gateway: 1 MiB).
const MAX_BODY_BYTES: usize = 1_048_576;

/// Panjang pesan error Gobiz (gaya `describeError` AI Gateway).
const ERROR_MESSAGE_MAX_CHARS: usize = 160;

/// Timeout HTTP Gobiz (sama seperti klien AI Gateway: 30 detik).
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Objek payment Gobiz (wire format worker). Semua field toleran
/// (default bila absen) agar respons yang sedikit berbeda bentuk tidak
/// menggagalkan parsing seluruh bodi; validasi isi dilakukan di
/// `create`/`get_status`, bukan di deserialisasi.
#[derive(Debug, Clone, Deserialize)]
pub struct GobizPayment {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub order_id: String,
    #[serde(default)]
    pub amount: u64,
    #[serde(default)]
    pub expected_amount: u64,
    #[serde(default)]
    pub unique_suffix: u64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub qris_string: String,
    #[serde(default)]
    pub callback_url: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub tx_id: Option<String>,
    #[serde(default)]
    pub paid_at: Option<String>,
}

/// Hasil create Gobiz yang sudah divalidasi (siap disimpan ke order).
#[derive(Debug, Clone)]
pub struct CreatedGobizInvoice {
    pub id: String,
    pub order_id: String,
    pub amount: u64,
    pub expected_amount: u64,
    pub unique_suffix: u64,
    pub qris_string: String,
    pub status: String,
    /// Expiry dari worker (RFC3339) bila bisa diparsing; bila tidak,
    /// pemanggil menghitung lokal dari now + expires_in.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Error klien Gobiz (tanpa varian AlreadyPaid:
/// bentuk error cancel-atas-paid Gobiz tidak terkonfirmasi, jadi
/// pemanggil tidak menebaknya — lihat `cancel_order` member).
#[derive(Debug)]
pub enum GobizError {
    NotConfigured,
    Transport(String),
    Provider { http_status: u16, message: String },
    /// Create 2xx tapi isi tidak lengkap (tanpa id / qris_string /
    /// expected_amount). Membawa id bila ada, untuk cancel yatim
    /// best-effort (cancel invoice yatim bila id ada).
    PartialCreated {
        payment_id: Option<String>,
        message: String,
    },
    Unexpected(String),
}

impl GobizError {
    /// Pesan generik untuk member (tanpa detail provider). Detail
    /// provider hanya masuk `last_error` panel admin (`admin_message`).
    pub fn to_app_error(&self) -> AppError {
        match self {
            GobizError::NotConfigured => AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "qris_not_configured",
                "Pembayaran belum dikonfigurasi admin.",
            ),
            GobizError::Transport(_) => AppError::new(
                StatusCode::BAD_GATEWAY,
                "qris_upstream_unavailable",
                "Layanan QRIS belum bisa dihubungi. Coba lagi.",
            ),
            GobizError::Provider { http_status, .. } => {
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
                        "Pembayaran belum bisa diproses. Coba lagi.",
                    )
                }
            }
            GobizError::PartialCreated { .. } | GobizError::Unexpected(_) => {
                AppError::internal("Pembayaran belum bisa diproses. Coba lagi.")
            }
        }
    }

    /// Pesan detail untuk admin (panel / log / tombol tes). TIDAK
    /// PERNAH berisi secret (secret tidak pernah masuk error Gobiz).
    pub fn admin_message(&self) -> String {
        match self {
            GobizError::NotConfigured => "Kredensial Gobiz belum lengkap".to_owned(),
            GobizError::Transport(message) => format!("Gobiz tidak dapat dihubungi: {message}"),
            GobizError::Provider {
                http_status,
                message,
            } => format!("Gobiz menolak (HTTP {http_status}): {message}"),
            GobizError::PartialCreated { message, .. } => {
                format!("Respons Gobiz tidak lengkap: {message}")
            }
            GobizError::Unexpected(message) => format!("Respons Gobiz tak terduga: {message}"),
        }
    }

    /// Id payment yatim dari create parsial (untuk cancel best-effort).
    pub fn orphan_payment_id(&self) -> Option<&str> {
        match self {
            GobizError::PartialCreated { payment_id, .. } => payment_id.as_deref(),
            _ => None,
        }
    }
}

/// Klien HTTP Gobiz (cermin `QrisClient`: base_url di-trim trailing
/// `/`, auth per-request lewat header `X-API-Key`).
pub struct GobizClient {
    base_url: String,
    http: reqwest::Client,
}

impl GobizClient {
    pub fn new(base_url: &str) -> Result<Self, AppError> {
        let trimmed = base_url.trim().trim_end_matches('/').to_owned();
        if trimmed.is_empty() {
            return Err(AppError::service_unavailable(
                "Pembayaran belum dikonfigurasi admin.",
            ));
        }
        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            return Err(AppError::internal("Base URL Gobiz tidak valid"));
        }
        let http = reqwest::Client::builder()
            .build()
            .map_err(|_| AppError::internal("Klien HTTP QRIS tidak dapat dibuat"))?;
        Ok(Self {
            base_url: trimmed,
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Id payment hanya boleh berisi karakter path yang aman
    /// (`pay_...` heksadesimal). Fail-closed: karakter lain ditolak
    /// sebelum sempat memecah path URL.
    fn checked_payment_id(id: &str) -> Result<&str, GobizError> {
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(GobizError::Unexpected(
                "ID pembayaran Gobiz tidak valid".to_owned(),
            ));
        }
        Ok(id)
    }

    async fn read_body_capped(
        mut res: reqwest::Response,
    ) -> Result<(u16, Vec<u8>), GobizError> {
        let status = res.status().as_u16();
        // Baca per chunk
        // dengan batas berjalan (Content-Length bisa absen/dibohongi).
        let mut bytes = Vec::new();
        while let Some(chunk) = res
            .chunk()
            .await
            .map_err(|error| GobizError::Transport(error.to_string()))?
        {
            if bytes.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(GobizError::Unexpected(
                    "Respons Gobiz melebihi batas 1 MiB".to_owned(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }

    /// Buat invoice QRIS Gobiz. `expires_in_secs` dipetakan dari
    /// `expiry_minutes` Rajacek (menit x 60); semua nilai Rajacek
    /// (>= 3 menit = >= 180 detik) memenuhi minimum 60 detik Gobiz.
    pub async fn create(
        &self,
        api_key: &str,
        amount: u64,
        order_id: &str,
        callback_url: &str,
        expires_in_secs: i64,
    ) -> Result<CreatedGobizInvoice, GobizError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            amount: u64,
            order_id: &'a str,
            callback_url: &'a str,
            expires_in: i64,
            unique_amount: bool,
        }
        let res = self
            .http
            .post(self.url("/v1/payments"))
            .header("X-API-Key", api_key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .json(&Body {
                amount,
                order_id,
                callback_url,
                expires_in: expires_in_secs,
                unique_amount: true,
            })
            .send()
            .await
            .map_err(|error| GobizError::Transport(error.to_string()))?;
        let (status, body) = Self::read_body_capped(res).await?;
        if !(200..300).contains(&status) {
            return Err(GobizError::Provider {
                http_status: status,
                message: describe_error(&body),
            });
        }
        let payment = parse_payment(&body)?;
        // Validasi create: tanpa id /
        // qris_string / expected_amount, invoice tidak bisa dipakai —
        // pemanggil membatalkan yatimnya best-effort bila id ada.
        if payment.id.is_empty() || payment.qris_string.is_empty() {
            return Err(GobizError::PartialCreated {
                payment_id: if payment.id.is_empty() {
                    None
                } else {
                    Some(payment.id)
                },
                message: "respons create tanpa id/qris_string".to_owned(),
            });
        }
        if payment.expected_amount == 0 {
            return Err(GobizError::PartialCreated {
                payment_id: Some(payment.id),
                message: "respons create tanpa expected_amount".to_owned(),
            });
        }
        Ok(CreatedGobizInvoice {
            id: payment.id,
            order_id: if payment.order_id.is_empty() {
                order_id.to_owned()
            } else {
                payment.order_id
            },
            amount: payment.amount,
            expected_amount: payment.expected_amount,
            unique_suffix: payment.unique_suffix,
            qris_string: payment.qris_string,
            status: payment.status,
            expires_at: payment
                .expires_at
                .as_deref()
                .and_then(parse_rfc3339_utc),
        })
    }

    /// Status pembayaran dari worker (GetStatus). Dipetakan ke enum
    /// `QrisPaymentStatus` bersama agar seluruh jalur
    /// verify/sweep/resolve bisa dipakai ulang tanpa cabang kedua.
    pub async fn get_status(
        &self,
        api_key: &str,
        payment_id: &str,
    ) -> Result<QrisPaymentStatus, GobizError> {
        let id = Self::checked_payment_id(payment_id)?;
        let res = self
            .http
            .get(self.url(&format!("/v1/payments/{id}")))
            .header("X-API-Key", api_key)
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .send()
            .await
            .map_err(|error| GobizError::Transport(error.to_string()))?;
        let (status, body) = Self::read_body_capped(res).await?;
        if status == 404 {
            // Asumsi (TODO di header modul): id tak dikenal -> NotFound,
            // Jalur verify memperlakukan NotFound sebagai
            // "tunggu sampai expiry lokal", bukan expired langsung.
            return Ok(QrisPaymentStatus::NotFound);
        }
        if !(200..300).contains(&status) {
            return Err(GobizError::Provider {
                http_status: status,
                message: describe_error(&body),
            });
        }
        let payment = parse_payment(&body)?;
        map_payment_to_status(&payment)
    }

    /// Batalkan invoice pending. TIDAK ada varian AlreadyPaid: bentuk
    /// error cancel-atas-paid Gobiz tidak terkonfirmasi — pemanggil
    /// (cancel member) melakukan GetStatus setelah cancel gagal, bukan
    /// menebak bentuk error.
    pub async fn cancel(&self, api_key: &str, payment_id: &str) -> Result<(), GobizError> {
        let id = Self::checked_payment_id(payment_id)?;
        let res = self
            .http
            .post(self.url(&format!("/v1/payments/{id}/cancel")))
            .header("X-API-Key", api_key)
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .send()
            .await
            .map_err(|error| GobizError::Transport(error.to_string()))?;
        let (status, body) = Self::read_body_capped(res).await?;
        if !(200..300).contains(&status) {
            return Err(GobizError::Provider {
                http_status: status,
                message: describe_error(&body),
            });
        }
        Ok(())
    }
}

/// Parse objek payment Gobiz: top level dulu, lalu fallback wrapper
/// `"payment"` / `"data"` (gaya `parsePayment` AI Gateway).
fn parse_payment(body: &[u8]) -> Result<GobizPayment, GobizError> {
    if let Ok(payment) = serde_json::from_slice::<GobizPayment>(body) {
        if !payment.id.is_empty() || !payment.status.is_empty() {
            return Ok(payment);
        }
    }
    #[derive(Deserialize)]
    struct Wrapper {
        payment: Option<GobizPayment>,
        data: Option<GobizPayment>,
    }
    if let Ok(wrapper) = serde_json::from_slice::<Wrapper>(body) {
        if let Some(payment) = wrapper.payment.or(wrapper.data) {
            return Ok(payment);
        }
    }
    Err(GobizError::Unexpected(
        "Respons Gobiz bukan objek payment".to_owned(),
    ))
}

/// Petakan payment worker ke status verify bersama. `paid` memakai
/// `expected_amount` (nominal yang benar-benar dibayar member); bila
/// worker tidak mengirimnya, jatuh ke `amount` — verifikasi kemudian
/// membandingkannya dengan `expected_amount` lokal, sehingga selisih
/// apa pun berakhir di `needs_review` (fail-closed), bukan grant.
fn map_payment_to_status(payment: &GobizPayment) -> Result<QrisPaymentStatus, GobizError> {
    match payment.status.as_str() {
        "paid" => {
            let paid_at = payment
                .paid_at
                .as_deref()
                .and_then(parse_rfc3339_utc)
                .map(|dt| dt.naive_utc());
            if payment.paid_at.is_some() && paid_at.is_none() {
                tracing::warn!(
                    raw_paid_at = payment.paid_at.as_deref().unwrap_or(""),
                    "paid_at Gobiz gagal diparsing pada status paid; disimpan NULL",
                );
            }
            Ok(QrisPaymentStatus::Paid {
                paid_at,
                amount: if payment.expected_amount > 0 {
                    payment.expected_amount
                } else {
                    payment.amount
                },
                mutation_ref: payment.tx_id.clone(),
            })
        }
        "pending" => {
            let remaining_seconds = payment
                .expires_at
                .as_deref()
                .and_then(parse_rfc3339_utc)
                .map(|expires| (expires - Utc::now()).num_seconds().max(0))
                .unwrap_or(0);
            Ok(QrisPaymentStatus::Pending { remaining_seconds })
        }
        "expired" => Ok(QrisPaymentStatus::Expired),
        "cancelled" => Ok(QrisPaymentStatus::Canceled),
        other => {
            // Status tak dikenal = error agar sweep
            // me-retry, bukan membiarkan order lunas menggantung.
            // Termasuk "failed" (status lokal AI Gateway, bukan worker).
            tracing::warn!(
                status = other,
                "Status Gobiz tak dikenal; diperlakukan sebagai error",
            );
            Err(GobizError::Unexpected(format!(
                "Status Gobiz tak dikenal: {other}"
            )))
        }
    }
}

/// Parse RFC3339 (dengan zona waktu) ke UTC. Gobiz mengirim
/// `expires_at`/`paid_at` berformat RFC3339 (`...Z`).
fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Ekstrak pesan error non-2xx gaya `describeError` AI Gateway:
/// `{error: string}` | `{error: {code, message}}` | `{message}` |
/// raw body; dipotong 160 karakter + "…" (per karakter, bukan byte).
fn describe_error(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct ErrorEnvelope {
        error: Option<serde_json::Value>,
        message: Option<String>,
    }
    if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(body) {
        if let Some(error) = &envelope.error {
            if let Some(text) = error.as_str() {
                if !text.is_empty() {
                    return truncate_chars(text, ERROR_MESSAGE_MAX_CHARS);
                }
            }
            if error.is_object() {
                let code = error
                    .get("code")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let message = error
                    .get("message")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let combined = format!("{code} {message}").trim().to_owned();
                if !combined.is_empty() {
                    return truncate_chars(&combined, ERROR_MESSAGE_MAX_CHARS);
                }
            }
        }
        if let Some(message) = &envelope.message {
            if !message.is_empty() {
                return truncate_chars(message, ERROR_MESSAGE_MAX_CHARS);
            }
        }
    }
    let raw = String::from_utf8_lossy(body).trim().to_owned();
    if raw.is_empty() {
        return "Gobiz tidak memberi pesan error".to_owned();
    }
    truncate_chars(&raw, ERROR_MESSAGE_MAX_CHARS)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut truncated: String = value.chars().take(max_chars).collect();
    truncated.push('…');
    truncated
}

/// Verifikasi signature webhook Gobiz: HMAC-SHA256 atas RAW BODY,
/// header `X-Webhook-Signature` (di-trim), terima hex lalu base64,
/// constant-time (persis `verifySignature` AI Gateway). Implementasi
/// dipakai ulang dari `qris` agar tidak ada dua implementasi HMAC yang
/// bisa berdrift.
pub fn verify_webhook_signature(secret: &str, body: &[u8], signature: &str) -> bool {
    crate::qris::verify_webhook_signature(secret, body, signature)
}

/// Envelope webhook Gobiz (gaya AI Gateway): `{event, data: {id,
/// order_id, tx_id, paid_at}}`. Hanya `event == "payment.paid"` yang
/// memicu sweep; event lain di-ack 200 tanpa sweep. Payload diparsing
/// toleran (field absen -> None) — webhook tidak pernah grant langsung,
/// jadi isi envelope hanya dipakai untuk log, bukan keputusan.
#[derive(Debug, Deserialize, Default)]
pub struct GobizWebhookPayload {
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub data: Option<GobizWebhookData>,
}

#[derive(Debug, Deserialize, Default)]
pub struct GobizWebhookData {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub order_id: Option<String>,
    #[serde(default)]
    pub tx_id: Option<String>,
    #[serde(default)]
    pub paid_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_payment_top_level_and_wrappers() {
        let top: GobizPayment = parse_payment(
            br#"{"id":"pay_abc","order_id":"o1","amount":10000,"expected_amount":10458,"unique_suffix":458,"status":"pending","qris_string":"00020101","expires_at":"2026-10-12T05:00:28.498Z"}"#,
        )
        .unwrap();
        assert_eq!(top.id, "pay_abc");
        assert_eq!(top.expected_amount, 10458);
        assert_eq!(top.unique_suffix, 458);
        let wrapped: GobizPayment =
            parse_payment(br#"{"payment":{"id":"pay_w","status":"paid","expected_amount":5000}}"#)
                .unwrap();
        assert_eq!(wrapped.id, "pay_w");
        let data_wrapped: GobizPayment =
            parse_payment(br#"{"data":{"id":"pay_d","status":"pending"}}"#).unwrap();
        assert_eq!(data_wrapped.id, "pay_d");
        assert!(parse_payment(br#"{"nonsense":true}"#).is_err());
    }

    #[test]
    fn describe_error_shapes_mirror_ai_gateway() {
        assert_eq!(
            describe_error(br#"{"error":"kuota habis"}"#),
            "kuota habis"
        );
        assert_eq!(
            describe_error(br#"{"error":{"code":"BAD_AMOUNT","message":"nominal tidak valid"}}"#),
            "BAD_AMOUNT nominal tidak valid"
        );
        assert_eq!(
            describe_error(br#"{"message":"gagal"}"#),
            "gagal"
        );
        assert_eq!(describe_error(b"raw text"), "raw text");
        assert_eq!(
            describe_error(b""),
            "Gobiz tidak memberi pesan error"
        );
        let long = "x".repeat(200);
        let body = format!("{{\"error\":\"{long}\"}}");
        let out = describe_error(body.as_bytes());
        assert_eq!(out.chars().count(), 161);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn map_payment_status_paid_uses_expected_amount() {
        let payment = GobizPayment {
            id: "pay_1".to_owned(),
            order_id: "o1".to_owned(),
            amount: 10000,
            expected_amount: 10458,
            unique_suffix: 458,
            status: "paid".to_owned(),
            qris_string: String::new(),
            callback_url: String::new(),
            expires_at: None,
            tx_id: Some("tx-9".to_owned()),
            paid_at: Some("2026-10-12T05:01:00Z".to_owned()),
        };
        match map_payment_to_status(&payment).unwrap() {
            QrisPaymentStatus::Paid {
                amount,
                mutation_ref,
                paid_at,
            } => {
                assert_eq!(amount, 10458);
                assert_eq!(mutation_ref.as_deref(), Some("tx-9"));
                assert!(paid_at.is_some());
            }
            other => panic!("status salah: {other:?}"),
        }
        // expected_amount absen -> jatuh ke amount (verifikasi lalu
        // membandingkan dengan expected lokal -> needs_review bila beda).
        let mut no_expected = payment.clone();
        no_expected.expected_amount = 0;
        match map_payment_to_status(&no_expected).unwrap() {
            QrisPaymentStatus::Paid { amount, .. } => assert_eq!(amount, 10000),
            other => panic!("status salah: {other:?}"),
        }
        // paid_at tak bisa diparsing -> None, bukan gagal total.
        let mut bad_paid_at = payment.clone();
        bad_paid_at.paid_at = Some("bukan-tanggal".to_owned());
        match map_payment_to_status(&bad_paid_at).unwrap() {
            QrisPaymentStatus::Paid { paid_at, .. } => assert!(paid_at.is_none()),
            other => panic!("status salah: {other:?}"),
        }
    }

    #[test]
    fn map_payment_status_pending_expired_cancelled_unknown() {
        let base = GobizPayment {
            id: "pay_1".to_owned(),
            order_id: "o1".to_owned(),
            amount: 5000,
            expected_amount: 5000,
            unique_suffix: 0,
            status: "pending".to_owned(),
            qris_string: String::new(),
            callback_url: String::new(),
            expires_at: Some("2099-01-01T00:00:00Z".to_owned()),
            tx_id: None,
            paid_at: None,
        };
        match map_payment_to_status(&base).unwrap() {
            QrisPaymentStatus::Pending { remaining_seconds } => {
                assert!(remaining_seconds > 0);
            }
            other => panic!("status salah: {other:?}"),
        }
        for (status, expected) in [
            ("expired", "Expired"),
            ("cancelled", "Canceled"),
        ] {
            let mut payment = base.clone();
            payment.status = status.to_owned();
            let mapped = map_payment_to_status(&payment).unwrap();
            assert_eq!(format!("{mapped:?}").split(' ').next().unwrap(), expected);
        }
        // "failed" (status lokal AI Gateway) + status asing = error.
        for status in ["failed", "refunded", ""] {
            let mut payment = base.clone();
            payment.status = status.to_owned();
            assert!(map_payment_to_status(&payment).is_err(), "{status}");
        }
    }

    #[test]
    fn webhook_signature_hex_base64_wrong_empty() {
        // Vektor HMAC-SHA256 yang sudah diketahui (bukan dihitung dari
        // implementasi sendiri): key "key", pesan "The quick brown fox
        // jumps over the lazy dog" -> f7bc83f4... (RFC 4231, kasus 2).
        let secret = "key";
        let body = b"The quick brown fox jumps over the lazy dog";
        let hex_sig = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";
        assert!(verify_webhook_signature(secret, body, hex_sig));
        assert!(verify_webhook_signature(
            secret,
            body,
            &format!("  {hex_sig}  ")
        ));
        let b64_sig = "97yD9DBThCSxMpjmqm+xQ+9NWaFJRhdZl0edvC0aPNg=";
        assert!(verify_webhook_signature(secret, body, b64_sig));
        assert!(!verify_webhook_signature(secret, body, "deadbeef"));
        assert!(!verify_webhook_signature(secret, body, ""));
        assert!(!verify_webhook_signature("salah", body, hex_sig));
    }
}

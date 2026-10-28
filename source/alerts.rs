//! Alert operator via Telegram (AREA 3: rekonsiliasi + refund-record +
//! alert).
//!
//! Dispatcher ini sengaja TIPIS dan TIDAK PERNAH memblokir jalur
//! validasi/pembayaran:
//!
//! - Secret HANYA dibaca dari environment (`TELEGRAM_BOT_TOKEN` dan
//!   `TELEGRAM_CHAT_ID`). Tidak ada nilai secret yang di-hardcode di
//!   sini, dan nilai secret TIDAK PERNAH ditulis ke log (hanya status
//!   kirim / kode HTTP yang dicatat, tanpa URL dan tanpa isi respons).
//! - Bila salah satu env tidak ter-set (atau kosong), pengiriman
//!   dilewati dan kejadian hanya ditulis ke log. Pemanggil yang punya
//!   akses ke store dapat memakai [`alert_with_store`] agar kejadian
//!   itu juga tercatat sebagai baris aktivitas admin; pemanggil tanpa
//!   store (circuit breaker, worker stream) hanya mendapat log —
//!   mereka memang tidak memegang handle store.
//! - Bila env ter-set, pengiriman dilakukan fire-and-forget lewat
//!   [`tokio::spawn`] dengan timeout HTTP singkat (3 detik), sehingga
//!   Telegram yang lambat/down tidak menunda respons apa pun.
//! - `TELEGRAM_API_BASE_URL` adalah override KHUSUS pengujian/pengembangan
//!   (default: host API Telegram publik). Override ini TIDAK membawa
//!   secret apa pun; ia hanya mengganti host tujuan agar tes dapat
//!   mengarah ke server lokal tanpa menyentuh jaringan.
//!
//! Anti-spam: dispatcher ini TIDAK melakukan throttling sendiri.
//! Setiap titik pemanggil HANYA memanggilnya pada TRANSISI (mis.
//! status order benar-benar berubah menjadi `needs_review`, circuit
//! breaker benar-benar baru terbuka, alarm XLEN baru melewati ambang
//! pada siklus yang sudah ada), bukan pada setiap pengulangan kondisi
//! yang sama — jadi satu kondisi yang menetap tidak membanjiri chat.

use std::time::Duration;

use crate::store::AdminStore;

/// Timeout HTTP untuk satu percobaan kirim Telegram. Singkat dengan
/// sengaja: alert tidak boleh menahan jalur apa pun lebih lama dari ini,
/// dan pengirimannya pun berjalan di task latar terpisah.
pub const TELEGRAM_SEND_TIMEOUT: Duration = Duration::from_secs(3);

/// Host API Telegram default. Override via env hanya untuk tes/dev.
pub(crate) fn telegram_base_url() -> String {
    std::env::var("TELEGRAM_API_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "https://api.telegram.org".to_owned())
}

/// Apakah alert Telegram aktif (kedua env wajib ter-set dan tak kosong)?
/// Fungsi murni atas pasangan nilai ini dipakai tes; [`alerts_enabled`]
/// adalah pembungkus env-nya.
pub fn alerts_enabled_from(token: Option<&str>, chat_id: Option<&str>) -> bool {
    matches!(token, Some(value) if !value.trim().is_empty())
        && matches!(chat_id, Some(value) if !value.trim().is_empty())
}

/// Apakah alert Telegram aktif berdasarkan environment saat ini?
pub fn alerts_enabled() -> bool {
    alerts_enabled_from(
        std::env::var("TELEGRAM_BOT_TOKEN").ok().as_deref(),
        std::env::var("TELEGRAM_CHAT_ID").ok().as_deref(),
    )
}

/// Teks pesan alert: judul satu baris + detail. Tidak pernah memuat
/// secret, token, URL provider, atau kredensial apa pun — pemanggil
/// wajib menjaga detailnya tetap bebas secret.
pub fn build_alert_text(title: &str, detail: &str) -> String {
    format!("{title}\n{detail}")
}

/// Satu percobaan kirim ke Bot API. Mengembalikan Err pada transport
/// gagal, timeout, atau status non-2xx. TIDAK PERNAH mencatat token,
/// chat id, URL, atau isi body ke log — hanya status HTTP.
///
/// `parse_mode` hanya dikirim bila `Some`: kanal alert lama memanggil
/// dengan `None` sehingga JSON-nya byte-identik dengan sebelumnya
/// (teks polos lama tidak pernah terpapar aturan parse HTML). Hanya
/// jalur notifikasi admin baru yang memakai `Some("HTML")`, dan teksnya
/// sudah di-escape di pembangun pesan.
pub(crate) async fn send_telegram_message(
    base_url: &str,
    token: &str,
    chat_id: &str,
    text: &str,
    parse_mode: Option<&str>,
) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        chat_id: &'a str,
        text: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        parse_mode: Option<&'a str>,
    }
    let client = reqwest::Client::builder()
        .timeout(TELEGRAM_SEND_TIMEOUT)
        .build()
        .map_err(|_| "Klien HTTP Telegram tidak dapat dibuat".to_owned())?;
    // Token hanya hidup di segmen path URL ini; URL tidak pernah di-log.
    let url = format!(
        "{}/bot{}/sendMessage",
        base_url.trim_end_matches('/'),
        token
    );
    let response = client
        .post(url)
        .json(&Body {
            chat_id,
            text,
            parse_mode,
        })
        .send()
        .await
        .map_err(|error| format!("Transport Telegram gagal: {error}"))?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("Telegram menolak pesan (HTTP {status})"))
    }
}

/// Hasil upaya kirim terakhir di PROSES ini (K35, Fase 3): pengiriman
/// bersifat fire-and-forget, jadi satu-satunya rekaman hasil yang bisa
/// dibaca panel adalah yang ditulis task latar ke memori proses ini.
/// Restart proses mengosongkannya kembali (status lalu melaporkan
/// `never_attempted` lagi — itu jujur: tidak ada upaya yang tercatat
/// di proses yang sedang berjalan). Panggilan tanpa env Telegram
/// BUKAN upaya kirim dan tidak dicatat di sini; `enabled: false`
/// sudah menyatakan Telegram belum dikonfigurasi.
#[derive(Clone, Debug)]
pub struct AlertAttempt {
    /// "sent" atau "failed".
    pub outcome: &'static str,
    pub title: String,
    pub attempted_at: chrono::DateTime<chrono::Utc>,
}

static LAST_ALERT_ATTEMPT: std::sync::Mutex<Option<AlertAttempt>> =
    std::sync::Mutex::new(None);

/// Catat hasil satu upaya kirim (dipakai task latar `alert`, dan tes).
pub fn record_alert_attempt(outcome: &'static str, title: &str) {
    let attempt = AlertAttempt {
        outcome,
        title: title.to_owned(),
        attempted_at: chrono::Utc::now(),
    };
    if let Ok(mut slot) = LAST_ALERT_ATTEMPT.lock() {
        *slot = Some(attempt);
    }
}

/// Kirim alert secara fire-and-forget. Fungsi ini KEMBALI SEGERA dalam
/// semua kondisi: tanpa env ia hanya menulis log; dengan env ia
/// men-spawn task latar dan langsung kembali tanpa menunggu hasil.
/// Tidak pernah panic dan tidak pernah mengembalikan error ke pemanggil
/// (kegagalan kirim hanya menjadi log di task latar + rekaman upaya
/// terakhir untuk panel, lihat [`AlertAttempt`]).
pub fn alert(title: &str, detail: &str) {
    let title = title.to_owned();
    let detail = detail.to_owned();
    let (token, chat_id) = match (
        std::env::var("TELEGRAM_BOT_TOKEN").ok(),
        std::env::var("TELEGRAM_CHAT_ID").ok(),
    ) {
        (Some(token), Some(chat_id))
            if alerts_enabled_from(Some(&token), Some(&chat_id)) =>
        {
            (token, chat_id)
        }
        _ => {
            tracing::warn!(title = %title, detail = %detail, "Alert (Telegram nonaktif): kejadian hanya dicatat di log");
            return;
        }
    };
    let base_url = telegram_base_url();
    let text = build_alert_text(&title, &detail);
    tokio::spawn(async move {
        match send_telegram_message(&base_url, &token, &chat_id, &text, None).await {
            Ok(()) => {
                tracing::info!(title = %title, "Alert Telegram terkirim");
                record_alert_attempt("sent", &title);
            }
            Err(error) => {
                tracing::warn!(title = %title, error = %error, "Alert Telegram gagal terkirim");
                record_alert_attempt("failed", &title);
            }
        }
    });
}

/// Hasil satu upaya kirim notifikasi admin (dipakai endpoint tes panel
/// dan job kedaluwarsa yang menunggu hasil, bukan fire-and-forget).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminNotifyOutcome {
    /// Pesan terkirim ke Bot API (HTTP 2xx).
    Sent,
    /// Tidak ada kredensial lengkap (panel kosong dan env kosong).
    NotConfigured,
    /// Kredensial ada tapi pengiriman gagal (pesan generik, tanpa secret).
    Failed(String),
}

/// Satu upaya kirim notifikasi admin, menunggu hasil. Resolusi
/// kredensial: pengaturan panel dulu, lalu env (lihat
/// `telegram_settings::resolve_credentials`). Tidak pernah panic dan
/// tidak pernah membocorkan token/chat ke log — hanya hasil upaya.
///
/// `text` adalah teks HTML lengkap dari pembangun pesan
/// (`telegram_settings`): sudah berisi header brand, judul tebal, dan
/// nilai yang di-escape — dikirim apa adanya dengan parse mode HTML.
/// `title` polos hanya untuk log dan rekaman upaya panel.
pub(crate) async fn send_admin_message_once(
    pool: &sqlx::MySqlPool,
    cipher: Option<&crate::provider_config::CredentialCipher>,
    title: &str,
    text: &str,
) -> AdminNotifyOutcome {
    let Some((token, chat_id)) =
        crate::telegram_settings::resolve_credentials(pool, cipher).await
    else {
        tracing::warn!(
            "Notifikasi admin dormant: bot token/chat ID Telegram belum dikonfigurasi"
        );
        return AdminNotifyOutcome::NotConfigured;
    };
    let base_url = telegram_base_url();
    match send_telegram_message(&base_url, &token, &chat_id, text, Some("HTML")).await {
        Ok(()) => {
            tracing::info!(title = %title, "Notifikasi admin Telegram terkirim");
            record_alert_attempt("sent", title);
            AdminNotifyOutcome::Sent
        }
        Err(error) => {
            tracing::warn!(title = %title, error = %error, "Notifikasi admin Telegram gagal terkirim");
            record_alert_attempt("failed", title);
            AdminNotifyOutcome::Failed(error)
        }
    }
}

/// Notifikasi admin fire-and-forget untuk jalur request (signup, grant).
/// KEMBALI SEGERA: pemuatan pengaturan + pengiriman berjalan di task
/// latar; kegagalan hanya jadi log + rekaman upaya terakhir. Tidak
/// pernah menggagalkan pemanggil.
pub(crate) fn notify_admin(
    pool: sqlx::MySqlPool,
    cipher: Option<crate::provider_config::CredentialCipher>,
    title: String,
    text: String,
) {
    tokio::spawn(async move {
        let _ = send_admin_message_once(&pool, cipher.as_ref(), &title, &text).await;
    });
}

/// Alert + jejak aktivitas admin (untuk pemanggil yang memegang store,
/// mis. jalur order QRIS). Baris aktivitas ditulis DALAM SEMUA kondisi
/// (Telegram aktif maupun tidak) agar ada jejak yang bisa dilihat di
/// panel; pengiriman Telegram-nya tetap fire-and-forget via [`alert`].
/// Tidak pernah menggagalkan pemanggil: penulisan audit menelan
/// kegagalannya sendiri di dalam store.
pub async fn alert_with_store(store: &AdminStore, title: &str, detail: &str) {
    alert(title, detail);
    store
        .persist_admin_audit("sistem-alert", title, detail, None, None)
        .await;
    store
        .append_activity(crate::models::ActivityItem {
            id: uuid::Uuid::now_v7(),
            title: title.to_owned(),
            detail: detail.to_owned(),
            product: None,
            status: "info".to_owned(),
            occurred_at: chrono::Utc::now(),
            provider_latency_ms: None,
        })
        .await;
}

/// Status alert untuk panel admin (K35, Fase 3): BUKAN lagi sekadar
/// "env ter-set". `delivery_state` melaporkan kesehatan pengiriman
/// NYATA di proses ini:
/// - "never_attempted": belum pernah ada upaya kirim sejak proses
///   berjalan (jangan tampilkan "aktif" yang menyesatkan untuk kondisi
///   ini — panel wajib menulis "belum pernah mengirim" secara eksplisit).
/// - "last_sent": upaya terakhir berhasil.
/// - "last_failed": upaya terakhir gagal (token/chat salah, jaringan
///   putus, dsb.) — panel wajib menampilkan peringatan persisten.
/// Tidak pernah mengembalikan nilai env apa pun; judul upaya terakhir
/// adalah judul tetap pemanggil (tanpa secret/detail).
#[derive(serde::Serialize)]
pub struct AlertStatus {
    pub enabled: bool,
    pub delivery_state: &'static str,
    pub last_attempt_outcome: Option<&'static str>,
    pub last_attempt_title: Option<String>,
    pub last_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Perakit murni status dari nilai env + upaya terakhir, agar bisa
/// dites tanpa menyentuh env global maupun memori statis proses.
pub fn alert_status_from(enabled: bool, last: Option<&AlertAttempt>) -> AlertStatus {
    match last {
        None => AlertStatus {
            enabled,
            delivery_state: "never_attempted",
            last_attempt_outcome: None,
            last_attempt_title: None,
            last_attempt_at: None,
        },
        Some(attempt) => AlertStatus {
            enabled,
            delivery_state: if attempt.outcome == "sent" {
                "last_sent"
            } else {
                "last_failed"
            },
            last_attempt_outcome: Some(attempt.outcome),
            last_attempt_title: Some(attempt.title.clone()),
            last_attempt_at: Some(attempt.attempted_at),
        },
    }
}

pub fn alert_status() -> AlertStatus {
    let last = LAST_ALERT_ATTEMPT.lock().ok().and_then(|slot| slot.clone());
    alert_status_from(alerts_enabled(), last.as_ref())
}

#[cfg(test)]
mod tests {
    use super::{alert_status_from, alerts_enabled_from, build_alert_text, send_telegram_message, alert, AlertAttempt};
    use std::time::Instant;

    #[test]
    fn alerts_enabled_requires_both_env_values() {
        assert!(alerts_enabled_from(Some("token"), Some("123")));
        assert!(!alerts_enabled_from(None, Some("123")));
        assert!(!alerts_enabled_from(Some("token"), None));
        assert!(!alerts_enabled_from(Some(""), Some("123")));
        assert!(!alerts_enabled_from(Some("token"), Some("   ")));
        assert!(!alerts_enabled_from(None, None));
    }

    #[test]
    fn alert_text_is_title_plus_detail() {
        assert_eq!(
            build_alert_text("Judul", "Detail"),
            "Judul\nDetail".to_owned()
        );
    }

    #[tokio::test]
    async fn send_to_closed_port_fails_without_panic() {
        // Port 9 (discard) pada loopback praktis selalu tertutup: kirim
        // harus gagal cepat sebagai Err, bukan panic dan bukan hang.
        let started = Instant::now();
        let result = send_telegram_message(
            "http://127.0.0.1:9",
            "dummy-token",
            "123",
            "tes",
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(
            started.elapsed() < super::TELEGRAM_SEND_TIMEOUT + std::time::Duration::from_secs(2),
            "kirim ke port tertutup harus gagal jauh sebelum timeout"
        );
    }

    #[tokio::test]
    async fn alert_returns_immediately_with_dummy_env() {
        // Fungsi alert() sendiri harus kembali segera apa pun kondisi
        // jaringan: pengiriman berjalan di task latar, bukan di sini.
        // Base URL diarahkan ke port tertutup agar tidak ada jaringan
        // nyata yang terlibat; token dummy tidak pernah di-log.
        std::env::set_var("TELEGRAM_BOT_TOKEN", "dummy-token-untuk-tes");
        std::env::set_var("TELEGRAM_CHAT_ID", "123");
        std::env::set_var("TELEGRAM_API_BASE_URL", "http://127.0.0.1:9");
        let started = Instant::now();
        alert("Tes alert", "detail tes");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "alert() harus kembali segera (fire-and-forget), bukan menunggu jaringan"
        );
        std::env::remove_var("TELEGRAM_BOT_TOKEN");
        std::env::remove_var("TELEGRAM_CHAT_ID");
        std::env::remove_var("TELEGRAM_API_BASE_URL");
    }

    #[test]
    fn alert_status_reports_real_delivery_not_just_env_presence() {
        // K35: tanpa upaya apa pun, status jujur "belum pernah
        // mengirim" — bahkan bila env ter-set (enabled saja bukan bukti
        // pengiriman berhasil).
        let never = alert_status_from(true, None);
        assert_eq!(never.delivery_state, "never_attempted");
        assert!(never.last_attempt_at.is_none());
        let failed = alert_status_from(
            true,
            Some(&AlertAttempt {
                outcome: "failed",
                title: "Circuit breaker provider terbuka".to_owned(),
                attempted_at: chrono::Utc::now(),
            }),
        );
        assert_eq!(failed.delivery_state, "last_failed");
        assert_eq!(failed.last_attempt_outcome, Some("failed"));
        let sent = alert_status_from(
            false,
            Some(&AlertAttempt {
                outcome: "sent",
                title: "Order perlu tinjauan".to_owned(),
                attempted_at: chrono::Utc::now(),
            }),
        );
        assert_eq!(sent.delivery_state, "last_sent");
    }

    #[tokio::test]
    async fn alert_without_env_returns_immediately_and_does_not_panic() {
        std::env::remove_var("TELEGRAM_BOT_TOKEN");
        std::env::remove_var("TELEGRAM_CHAT_ID");
        let started = Instant::now();
        alert("Tes tanpa env", "hanya log");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}

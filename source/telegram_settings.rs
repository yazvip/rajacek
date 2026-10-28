//! Notifikasi bot Telegram admin: member baru, member beli paket, dan
//! paket hampir kedaluwarsa (24 jam).
//!
//! Desain (bukan duplikat `alerts.rs` — pengirim HTTP-nya dipakai ulang
//! dari sana):
//!
//! - **Konfigurasi lewat panel, bukan env.** Bot token + chat ID
//!   disimpan di tabel `telegram_settings` (pola `qris_settings`):
//!   token terenkripsi AES-256-GCM (`CredentialCipher`, kunci yang sama
//!   dengan settings QRIS), chat ID plaintext (bukan kredensial — tanpa
//!   token, chat ID saja tidak bisa dipakai mengirim). Panel tidak
//!   pernah menerima token utuh: hanya status terisi + 4 karakter
//!   terakhir.
//! - **Fallback env.** Bila panel belum diisi, notifikasi memakai
//!   `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` bila keduanya ter-set
//!   (perilaku alert lama). Bila keduanya kosong, notifikasi DORMAN:
//!   hanya log peringatan, tidak pernah menggagalkan flow utama.
//! - **Non-blocking.** Jalur request (signup, grant) hanya men-spawn
//!   task latar (`alerts::notify_admin`); kegagalan kirim hanya jadi
//!   log + rekaman upaya terakhir. Job kedaluwarsa berjalan di worker
//!   (bukan di jalur request) dan menandai bucket HANYA setelah kirim
//!   berhasil, sehingga gagal kirim dicoba lagi pada tick berikutnya.
//! - **Minimal.** Pesan hanya berisi kode member, nama paket, hit,
//!   nominal, dan waktu. TIDAK PERNAH: nomor rekening/target mentah,
//!   nama pemilik rekening, kunci API, token, atau data pelanggan lain.
//! - **Format premium.** Parse mode HTML: header brand `👑 RAJACEK`,
//!   pemisah, judul berikon tebal, satu ikon per baris detail.
//!   Nilai luar (kode, email, nama paket) di-escape agar tidak merusak
//!   markup. Kanal alert env lama tidak memakai parse mode HTML dan
//!   formatnya tidak diubah.
//! - **Anti-spam kedaluwarsa.** Satu pesan per bucket, sekali saja
//!   (`expiry_notified_at`). Bucket trial (tanpa package_id maupun
//!   order_id) dikecualikan dari notifikasi ini.

use chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc};
use sqlx::MySqlPool;

use crate::alerts;
use crate::error::AppError;
use crate::provider_config::CredentialCipher;

/// Jendela notifikasi kedaluwarsa: bucket yang kedaluwarsa dalam 24 jam
/// ke depan (eksklusif masa lalu, inklusif tepat 24 jam).
pub const EXPIRY_WINDOW_HOURS: i64 = 24;

/// Interval job kedaluwarsa di worker.
pub const EXPIRY_JOB_INTERVAL_SECS: u64 = 6 * 3_600;

// ---------------------------------------------------------------------------
// Pengaturan
// ---------------------------------------------------------------------------

/// Baris `telegram_settings` (id selalu 1).
pub struct TelegramSettings {
    pub bot_token_ciphertext: Option<Vec<u8>>,
    pub chat_id: Option<String>,
}

/// Tampilan untuk panel admin (Manager). TIDAK PERNAH membawa token
/// utuh — hanya status + 4 akhir + chat ID (bukan kredensial).
#[derive(serde::Serialize)]
pub struct TelegramSettingsView {
    pub configured: bool,
    pub has_bot_token: bool,
    pub chat_id: Option<String>,
    pub bot_token_tail: Option<String>,
}

/// Input admin. Absen = pertahankan nilai lama; string kosong = hapus
/// nilai itu; non-kosong = ganti (token dienkripsi saat simpan).
#[derive(serde::Deserialize)]
pub struct TelegramSettingsInput {
    pub bot_token: Option<String>,
    pub chat_id: Option<String>,
}

pub async fn load_telegram_settings(
    pool: &MySqlPool,
) -> Result<TelegramSettings, AppError> {
    let row = sqlx::query_as::<_, TelegramSettingsRow>(
        "SELECT bot_token_ciphertext, chat_id FROM telegram_settings WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan Telegram tidak dapat dibaca"))?;
    Ok(match row {
        Some(row) => TelegramSettings {
            bot_token_ciphertext: row.bot_token_ciphertext,
            chat_id: row.chat_id,
        },
        None => TelegramSettings {
            bot_token_ciphertext: None,
            chat_id: None,
        },
    })
}

#[derive(sqlx::FromRow)]
struct TelegramSettingsRow {
    bot_token_ciphertext: Option<Vec<u8>>,
    chat_id: Option<String>,
}

impl TelegramSettings {
    /// Tampilan panel. Dekripsi gagal (mis. kunci rotasi) diperlakukan
    /// sebagai "token ada tapi tidak bisa dibaca": status terisi tetap
    /// benar, ekor kosong, dan pengiriman akan gagal dengan log —
    /// tampilan tidak pernah menggagalkan panel.
    pub(crate) fn view(&self, cipher: &CredentialCipher) -> TelegramSettingsView {
        let token = self
            .bot_token_ciphertext
            .as_deref()
            .and_then(|ciphertext| cipher.decrypt(ciphertext).ok());
        let has_bot_token = self.bot_token_ciphertext.is_some();
        let chat_id = self
            .chat_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        TelegramSettingsView {
            configured: token.is_some() && chat_id.is_some(),
            has_bot_token,
            chat_id,
            bot_token_tail: token.as_deref().map(token_tail),
        }
    }

    /// Token terdekripsi + chat ID, bila keduanya ada dan token bisa
    /// dibaca. Gagal baca apa pun → None (pemanggil lanjut ke fallback
    /// env atau dormant — tidak pernah error ke flow utama).
    pub(crate) fn credentials(&self, cipher: &CredentialCipher) -> Option<(String, String)> {
        let token = self
            .bot_token_ciphertext
            .as_deref()
            .and_then(|ciphertext| cipher.decrypt(ciphertext).ok())
            .filter(|value| !value.trim().is_empty())?;
        let chat_id = self
            .chat_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())?;
        Some((token, chat_id.to_owned()))
    }
}

/// Resolusi kredensial: panel dulu, lalu env. Mengembalikan None bila
/// keduanya tidak lengkap. Gagal baca DB diperlakukan sama dengan
/// "panel belum diisi" (fail-safe, bukan error) — pemanggil mencatat
/// peringatan dan melanjutkan tanpa mengirim.
pub(crate) async fn resolve_credentials(
    pool: &MySqlPool,
    cipher: Option<&CredentialCipher>,
) -> Option<(String, String)> {
    if let Some(cipher) = cipher {
        if let Ok(settings) = load_telegram_settings(pool).await {
            if let Some(creds) = settings.credentials(cipher) {
                return Some(creds);
            }
        }
    }
    let token = std::env::var("TELEGRAM_BOT_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let chat_id = std::env::var("TELEGRAM_CHAT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty());
    match (token, chat_id) {
        (Some(token), Some(chat_id)) => Some((token, chat_id)),
        _ => None,
    }
}

pub(crate) async fn save_telegram_settings(
    pool: &MySqlPool,
    input: TelegramSettingsInput,
    cipher: &CredentialCipher,
) -> Result<TelegramSettingsView, AppError> {
    // Audit flow B6 (pola QRIS): secret baru tidak boleh dienkripsi
    // dengan kunci fallback pengembangan. Penyimpanan tanpa secret baru
    // (ubah/hapus chat ID saja) tetap diizinkan.
    let carries_new_secret = input
        .bot_token
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if carries_new_secret && cipher.is_fallback() {
        return Err(AppError::service_unavailable(
            "API_KEY_ENCRYPTION_KEY belum dikonfigurasi; token Telegram baru tidak disimpan agar tidak terenkripsi dengan kunci fallback.",
        ));
    }
    if let Some(token) = input.bot_token.as_deref() {
        if !token.trim().is_empty() && token.trim().len() > 512 {
            return Err(AppError::bad_request(
                "Bot token terlalu panjang (maks 512 karakter)",
            ));
        }
    }
    if let Some(chat_id) = input.chat_id.as_deref() {
        if !chat_id.trim().is_empty() && chat_id.trim().len() > 64 {
            return Err(AppError::bad_request(
                "Chat ID terlalu panjang (maks 64 karakter)",
            ));
        }
    }
    let mut current = load_telegram_settings(pool).await?;
    if let Some(token) = input.bot_token {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            current.bot_token_ciphertext = None;
        } else {
            current.bot_token_ciphertext = Some(
                cipher
                    .encrypt(trimmed)
                    .map_err(|_| AppError::internal("Token Telegram tidak dapat dienkripsi"))?,
            );
        }
    }
    if let Some(chat_id) = input.chat_id {
        let trimmed = chat_id.trim();
        if trimmed.is_empty() {
            current.chat_id = None;
        } else {
            current.chat_id = Some(trimmed.to_owned());
        }
    }
    sqlx::query(
        "INSERT INTO telegram_settings (id, bot_token_ciphertext, chat_id) \
         VALUES (1, ?, ?) ON DUPLICATE KEY UPDATE \
         bot_token_ciphertext = VALUES(bot_token_ciphertext), \
         chat_id = VALUES(chat_id)",
    )
    .bind(&current.bot_token_ciphertext)
    .bind(&current.chat_id)
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan Telegram tidak dapat disimpan"))?;
    Ok(current.view(cipher))
}

/// 4 karakter terakhir token (untuk tampilan panel). Token yang lebih
/// pendek dari 4 karakter dikembalikan utuh — token bot nyata jauh
/// lebih panjang, jadi ini hanya pengaman tepi.
pub fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 4 {
        token.to_owned()
    } else {
        chars[chars.len() - 4..].iter().collect()
    }
}

// ---------------------------------------------------------------------------
// Format pesan (fungsi murni — dites tanpa DB/jaringan)
// ---------------------------------------------------------------------------

const MONTHS_ID: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des",
];

/// "28 Okt 2026, 15:04 WIB" dari waktu UTC.
pub fn format_wib_datetime(moment: DateTime<Utc>) -> String {
    let wib = moment + chrono::Duration::hours(7);
    format!(
        "{} {} {}, {:02}:{:02} WIB",
        wib.day(),
        MONTHS_ID[wib.month0() as usize],
        wib.year(),
        wib.hour(),
        wib.minute()
    )
}

/// "28 Okt 2026, 15:04 WIB" dari DATETIME UTC (naive) di DB.
pub fn format_wib_naive(moment: NaiveDateTime) -> String {
    format_wib_datetime(DateTime::<Utc>::from_naive_utc_and_offset(moment, Utc))
}

/// "Rp150.000" (pemisah ribuan titik, tanpa desimal).
pub fn format_rupiah(amount: u64) -> String {
    format!("Rp{}", group_thousands(amount))
}

/// "5.000 hit".
pub fn format_hits(hits: u64) -> String {
    format!("{} hit", group_thousands(hits))
}

fn group_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push('.');
        }
        out.push(ch);
    }
    out
}

/// "INV-1A2B3C4D" dari id order (pola portal: 8 hex pertama tanpa
/// strip, huruf besar; id penuh tetap dipakai semua panggilan API).
pub fn invoice_short(order_id: &str) -> String {
    let compact: String = order_id.chars().filter(|ch| *ch != '-').collect();
    let short: String = compact.chars().take(8).collect();
    format!("INV-{}", short.to_uppercase())
}

/// Escape nilai interpolasi untuk parse mode HTML Telegram (`&`, `<`,
/// `>`). Nilai yang diketik admin (nama paket) dan email wajib lewat
/// sini agar tidak merusak markup atau menyuntikkan tag. Nilai yang
/// diformat server (rupiah, hit, waktu WIB, INV-pendek) hanya berisi
/// angka/titik/tanda hubung sehingga tidak perlu di-escape.
pub fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Teks lengkap satu pesan notifikasi admin (parse mode HTML): baris
/// brand, pemisah, judul berikon tebal, lalu baris detail. Judul polos
/// (tanpa markup) dipakai terpisah untuk log dan rekaman upaya panel.
pub fn admin_message_text(icon: &str, title: &str, detail: &str) -> String {
    format!(
        "👑 <b>RAJACEK</b>\n{}\n{} <b>{}</b>\n{}",
        "─".repeat(17),
        icon,
        title,
        detail
    )
}

/// Status trial untuk pesan member baru.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrialNote {
    /// Trial di-grant (klaim berhasil atau error transient yang
    /// mempertahankan kunci berkuota — pola K15).
    Granted { quota_hits: u64, valid_days: i64 },
    /// Trial ditahan batas IP (soft-deny antifarm).
    Held,
    /// Tanpa trial (tidak ada baris trial di pesan).
    None,
}

/// (judul polos untuk log/panel, teks HTML lengkap) notifikasi member
/// baru. Satu ikon per baris; nilai luar di-escape.
pub fn new_member_message(
    member_code: &str,
    email: &str,
    trial: TrialNote,
    now: DateTime<Utc>,
) -> (String, String) {
    let title = "Member Baru".to_owned();
    let mut detail = format!(
        "🆔 Kode: {}\n📧 Email: {}\n🕐 Waktu: {}",
        escape_html(member_code),
        escape_html(email),
        format_wib_datetime(now)
    );
    match trial {
        TrialNote::Granted {
            quota_hits,
            valid_days,
        } => {
            detail = format!(
                "🆔 Kode: {}\n📧 Email: {}\n🎁 Trial: {} / {} hari\n🕐 Waktu: {}",
                escape_html(member_code),
                escape_html(email),
                format_hits(quota_hits),
                valid_days,
                format_wib_datetime(now)
            );
        }
        TrialNote::Held => {
            detail = format!(
                "🆔 Kode: {}\n📧 Email: {}\n🎁 Trial: ditahan (batas IP)\n🕐 Waktu: {}",
                escape_html(member_code),
                escape_html(email),
                format_wib_datetime(now)
            );
        }
        TrialNote::None => {}
    }
    (title.clone(), admin_message_text("🎉", &title, &detail))
}

/// (judul polos untuk log/panel, teks HTML lengkap) notifikasi
/// pembelian paket (grant berhasil).
pub fn purchase_message(
    member_code: &str,
    package_name: &str,
    quota_hits: u64,
    amount_idr: u64,
    order_id: &str,
    now: DateTime<Utc>,
) -> (String, String) {
    let title = "Paket Dibeli".to_owned();
    let detail = format!(
        "🆔 Kode: {}\n📦 Paket: {}\n⚡ Kuota: {}\n💰 Nominal: {}\n🧾 Invoice: {}\n🕐 Waktu: {}",
        escape_html(member_code),
        escape_html(package_name),
        format_hits(quota_hits),
        format_rupiah(amount_idr),
        invoice_short(order_id),
        format_wib_datetime(now)
    );
    (title.clone(), admin_message_text("🛍️", &title, &detail))
}

/// (judul polos untuk log/panel, teks HTML lengkap) notifikasi paket
/// hampir kedaluwarsa.
pub fn expiry_message(
    member_code: &str,
    package_name: &str,
    remaining_hits: u64,
    expires_at: NaiveDateTime,
) -> (String, String) {
    let title = "Paket Hampir Kedaluwarsa".to_owned();
    let detail = format!(
        "🆔 Kode: {}\n📦 Paket: {}\n⚡ Sisa: {}\n📅 Kedaluwarsa: {}",
        escape_html(member_code),
        escape_html(package_name),
        format_hits(remaining_hits),
        format_wib_naive(expires_at)
    );
    (
        title.clone(),
        admin_message_text("⏰", &title, &detail),
    )
}

/// (judul polos untuk log/panel, teks HTML lengkap) pesan tes dari
/// panel admin.
pub fn test_message() -> (String, String) {
    let title = "Tes Notifikasi Rajacek".to_owned();
    (
        title.clone(),
        admin_message_text(
            "✅",
            &title,
            "Bot Telegram admin terhubung dan dapat mengirim pesan.",
        ),
    )
}

// ---------------------------------------------------------------------------
// Job kedaluwarsa (worker)
// ---------------------------------------------------------------------------

/// Baris kandidat dari `quota_buckets` untuk satu tick.
#[derive(sqlx::FromRow)]
pub struct ExpiryCandidate {
    pub id: String,
    pub member_id: Option<String>,
    pub order_id: Option<String>,
    pub package_id: Option<String>,
    pub remaining_hits: u64,
    pub expires_at: NaiveDateTime,
}

/// Predikat seleksi murni (dipakai tes): sisa > 0, punya paket
/// (package_id atau order_id terisi — bucket trial tanpa keduanya
/// dikecualikan), dan expires_at dalam (sekarang, sekarang+24 jam].
pub fn bucket_in_expiry_window(
    remaining_hits: u64,
    package_id: Option<&str>,
    order_id: Option<&str>,
    expires_at: NaiveDateTime,
    now: NaiveDateTime,
) -> bool {
    if remaining_hits == 0 {
        return false;
    }
    let has_package = package_id
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        || order_id.map(|value| !value.is_empty()).unwrap_or(false);
    if !has_package {
        return false;
    }
    if expires_at <= now {
        return false;
    }
    let window_end = now + chrono::Duration::hours(EXPIRY_WINDOW_HOURS);
    expires_at <= window_end
}

async fn resolve_package_name(
    pool: &MySqlPool,
    candidate: &ExpiryCandidate,
) -> String {
    if let Some(order_id) = candidate.order_id.as_deref().filter(|v| !v.is_empty()) {
        let name: Option<String> = sqlx::query_scalar(
            "SELECT package_name FROM package_orders WHERE id = ?",
        )
        .bind(order_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        if let Some(name) = name.filter(|v| !v.trim().is_empty()) {
            return name;
        }
    }
    if let Some(package_id) = candidate.package_id.as_deref().filter(|v| !v.is_empty()) {
        let name: Option<String> = sqlx::query_scalar(
            "SELECT name FROM admin_packages WHERE id = ?",
        )
        .bind(package_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        if let Some(name) = name.filter(|v| !v.trim().is_empty()) {
            return name;
        }
        let name: Option<String> = sqlx::query_scalar(
            "SELECT name FROM packages WHERE id = ?",
        )
        .bind(package_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        if let Some(name) = name.filter(|v| !v.trim().is_empty()) {
            return name;
        }
    }
    "Paket".to_owned()
}

/// Satu tick job kedaluwarsa. Mengembalikan jumlah pesan terkirim.
/// Dormant (tanpa kredensial) → Ok(0) + satu baris log per tick.
/// Bucket yang gagal kirim tetap NULL sehingga dicoba lagi tick
/// berikutnya; bucket yang sudah lewat expiry tidak pernah diberitahu
/// (di luar jendela seleksi).
pub async fn notify_expiring_buckets(
    pool: &MySqlPool,
    encryption_key: Option<&str>,
) -> Result<usize, AppError> {
    let cipher = CredentialCipher::new(encryption_key);
    let Some((token, chat_id)) = resolve_credentials(pool, Some(&cipher)).await else {
        tracing::warn!(
            "Notifikasi kedaluwarsa dormant: bot token/chat ID Telegram belum dikonfigurasi"
        );
        return Ok(0);
    };
    let now = Utc::now().naive_utc();
    let window_end = now + chrono::Duration::hours(EXPIRY_WINDOW_HOURS);
    let candidates = sqlx::query_as::<_, ExpiryCandidate>(
        "SELECT id, member_id, order_id, package_id, remaining_hits, expires_at \
         FROM quota_buckets \
         WHERE remaining_hits > 0 AND expires_at > ? AND expires_at <= ? \
         AND expiry_notified_at IS NULL \
         AND (package_id IS NOT NULL OR order_id IS NOT NULL) \
         ORDER BY expires_at ASC",
    )
    .bind(now)
    .bind(window_end)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Bucket kedaluwarsa tidak dapat dibaca"))?;
    let base_url = alerts::telegram_base_url();
    let mut sent = 0usize;
    for candidate in candidates {
        let Some(member_id) = candidate.member_id.as_deref().filter(|v| !v.is_empty()) else {
            continue;
        };
        let member_code: Option<String> = sqlx::query_scalar(
            "SELECT member_code FROM members WHERE id = ?",
        )
        .bind(member_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        let Some(member_code) = member_code.filter(|v| !v.is_empty()) else {
            tracing::warn!(
                bucket_id = %candidate.id,
                "Notifikasi kedaluwarsa dilewati: kode member tidak ditemukan"
            );
            continue;
        };
        let package_name = resolve_package_name(pool, &candidate).await;
        let (title, text) = expiry_message(
            &member_code,
            &package_name,
            candidate.remaining_hits,
            candidate.expires_at,
        );
        match alerts::send_telegram_message(&base_url, &token, &chat_id, &text, Some("HTML")).await {
            Ok(()) => {
                let marked = sqlx::query(
                    "UPDATE quota_buckets SET expiry_notified_at = ? \
                     WHERE id = ? AND expiry_notified_at IS NULL",
                )
                .bind(now)
                .bind(&candidate.id)
                .execute(pool)
                .await
                .map_err(|_| AppError::internal("Penanda notifikasi kedaluwarsa gagal ditulis"))?;
                if marked.rows_affected() == 1 {
                    sent += 1;
                    alerts::record_alert_attempt("sent", &title);
                }
            }
            Err(error) => {
                tracing::warn!(
                    bucket_id = %candidate.id,
                    error = %error,
                    "Notifikasi kedaluwarsa gagal terkirim; dicoba lagi pada tick berikutnya"
                );
                alerts::record_alert_attempt("failed", &title);
            }
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn token_tail_uses_last_four_chars() {
        assert_eq!(token_tail("1234567890abcdef"), "cdef");
        assert_eq!(token_tail("abc"), "abc");
    }

    #[test]
    fn wib_datetime_formats_with_offset_and_month_names() {
        let moment = Utc.with_ymd_and_hms(2026, 10, 28, 3, 4, 0).unwrap();
        assert_eq!(format_wib_datetime(moment), "28 Okt 2026, 10:04 WIB");
        let new_year = Utc.with_ymd_and_hms(2026, 12, 31, 20, 0, 0).unwrap();
        assert_eq!(format_wib_datetime(new_year), "1 Jan 2027, 03:00 WIB");
    }

    #[test]
    fn rupiah_and_hits_group_thousands_with_dots() {
        assert_eq!(format_rupiah(0), "Rp0");
        assert_eq!(format_rupiah(1000), "Rp1.000");
        assert_eq!(format_rupiah(150000), "Rp150.000");
        assert_eq!(format_rupiah(1000000), "Rp1.000.000");
        assert_eq!(format_hits(5000), "5.000 hit");
        assert_eq!(format_hits(0), "0 hit");
    }

    #[test]
    fn invoice_short_strips_dashes_and_uppercases() {
        assert_eq!(
            invoice_short("01a16156-4f29-7034-ab51-f5c699827826"),
            "INV-01A16156"
        );
        assert_eq!(invoice_short("abc"), "INV-ABC");
    }

    #[test]
    fn expiry_window_boundaries_are_exact() {
        let now = NaiveDateTime::parse_from_str("2026-10-28 10:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap();
        let in_window =
            NaiveDateTime::parse_from_str("2026-10-29 09:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let exactly_24h =
            NaiveDateTime::parse_from_str("2026-10-29 10:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let past_24h =
            NaiveDateTime::parse_from_str("2026-10-29 10:00:01", "%Y-%m-%d %H:%M:%S").unwrap();
        let past =
            NaiveDateTime::parse_from_str("2026-10-28 09:59:59", "%Y-%m-%d %H:%M:%S").unwrap();
        assert!(bucket_in_expiry_window(10, Some("pkg"), None, in_window, now));
        assert!(bucket_in_expiry_window(10, None, Some("ord"), exactly_24h, now));
        assert!(!bucket_in_expiry_window(10, Some("pkg"), None, past_24h, now));
        assert!(!bucket_in_expiry_window(10, Some("pkg"), None, past, now));
        assert!(!bucket_in_expiry_window(0, Some("pkg"), None, in_window, now));
        // Bucket trial (tanpa package_id maupun order_id) dikecualikan.
        assert!(!bucket_in_expiry_window(10, None, None, in_window, now));
        assert!(!bucket_in_expiry_window(10, Some(""), Some(""), in_window, now));
    }

    #[test]
    fn admin_message_text_has_brand_header_divider_and_bold_title() {
        let text = admin_message_text("🎉", "Member Baru", "🆔 Kode: RC000001");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "👑 <b>RAJACEK</b>");
        assert_eq!(lines[1].chars().count(), 17);
        assert!(lines[1].chars().all(|ch| ch == '─'));
        assert_eq!(lines[2], "🎉 <b>Member Baru</b>");
        assert_eq!(lines[3], "🆔 Kode: RC000001");
    }

    #[test]
    fn escape_html_neutralizes_markup_in_values() {
        assert_eq!(
            escape_html("A&B <C> \"D\""),
            "A&amp;B &lt;C&gt; \"D\""
        );
        let (_, text) = purchase_message(
            "RC000001",
            "Paket & <Promo>",
            100,
            1000,
            "01a16156-4f29-7034-ab51-f5c699827826",
            Utc.with_ymd_and_hms(2026, 10, 28, 3, 4, 0).unwrap(),
        );
        assert!(text.contains("📦 Paket: Paket &amp; &lt;Promo&gt;"));
        assert!(!text.contains("Paket & <Promo>"));
    }

    #[test]
    fn new_member_message_covers_trial_variants() {
        let now = Utc.with_ymd_and_hms(2026, 10, 28, 3, 4, 0).unwrap();
        let (title, text) = new_member_message(
            "RC000001",
            "member@contoh.id",
            TrialNote::Granted {
                quota_hits: 1000,
                valid_days: 7,
            },
            now,
        );
        assert_eq!(title, "Member Baru");
        assert_eq!(
            text,
            "👑 <b>RAJACEK</b>\n─────────────────\n🎉 <b>Member Baru</b>\n🆔 Kode: RC000001\n📧 Email: member@contoh.id\n🎁 Trial: 1.000 hit / 7 hari\n🕐 Waktu: 28 Okt 2026, 10:04 WIB"
        );
        let (_, held) =
            new_member_message("RC000002", "a@b.id", TrialNote::Held, now);
        assert!(held.contains("🎁 Trial: ditahan (batas IP)"));
        let (_, none) =
            new_member_message("RC000003", "a@b.id", TrialNote::None, now);
        assert!(!none.contains("🎁 Trial:"));
    }

    #[test]
    fn purchase_message_is_minimal_and_exact() {
        let now = Utc.with_ymd_and_hms(2026, 10, 28, 3, 4, 0).unwrap();
        let (title, text) = purchase_message(
            "RC000001",
            "Starter",
            5000,
            150000,
            "01a16156-4f29-7034-ab51-f5c699827826",
            now,
        );
        assert_eq!(title, "Paket Dibeli");
        assert_eq!(
            text,
            "👑 <b>RAJACEK</b>\n─────────────────\n🛍️ <b>Paket Dibeli</b>\n🆔 Kode: RC000001\n📦 Paket: Starter\n⚡ Kuota: 5.000 hit\n💰 Nominal: Rp150.000\n🧾 Invoice: INV-01A16156\n🕐 Waktu: 28 Okt 2026, 10:04 WIB"
        );
    }

    #[test]
    fn expiry_message_shows_wib_deadline() {
        let expires =
            NaiveDateTime::parse_from_str("2026-10-29 03:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let (title, text) = expiry_message("RC000001", "Starter", 123, expires);
        assert_eq!(title, "Paket Hampir Kedaluwarsa");
        assert_eq!(
            text,
            "👑 <b>RAJACEK</b>\n─────────────────\n⏰ <b>Paket Hampir Kedaluwarsa</b>\n🆔 Kode: RC000001\n📦 Paket: Starter\n⚡ Sisa: 123 hit\n📅 Kedaluwarsa: 29 Okt 2026, 10:30 WIB"
        );
    }

    #[test]
    fn test_message_uses_brand_header_and_checkmark_title() {
        let (title, text) = test_message();
        assert_eq!(title, "Tes Notifikasi Rajacek");
        assert_eq!(
            text,
            "👑 <b>RAJACEK</b>\n─────────────────\n✅ <b>Tes Notifikasi Rajacek</b>\nBot Telegram admin terhubung dan dapat mengirim pesan."
        );
    }

    #[test]
    fn settings_view_never_carries_the_full_token() {
        let cipher = CredentialCipher::new(Some("kunci-pengujian-yang-cukup-panjang-0123456789"));
        let settings = TelegramSettings {
            bot_token_ciphertext: Some(cipher.encrypt("token-rahasia-abcdef1234").unwrap()),
            chat_id: Some("123456".to_owned()),
        };
        let view = settings.view(&cipher);
        assert!(view.configured);
        assert!(view.has_bot_token);
        assert_eq!(view.chat_id.as_deref(), Some("123456"));
        assert_eq!(view.bot_token_tail.as_deref(), Some("1234"));
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("token-rahasia-abcdef1234"));
        let empty = TelegramSettings {
            bot_token_ciphertext: None,
            chat_id: None,
        }
        .view(&cipher);
        assert!(!empty.configured);
        assert!(!empty.has_bot_token);
        assert!(empty.bot_token_tail.is_none());
    }
}

//! Notifikasi member via bot Telegram yang SAMA dengan bot admin.
//!
//! Bot, token, dan webhook tidak berubah: modul ini hanya menambah
//! penerima (chat member) dan jenis pesan baru di atas infrastruktur
//! yang sudah ada (`telegram_settings::resolve_credentials` untuk token,
//! `alerts::send_telegram_message` untuk pengiriman).
//!
//! Aturan keras yang dijaga modul ini:
//! - Opt-in eksplisit: semua toggle default MATI; tanpa tautan aktif
//!   tidak ada pesan apa pun yang keluar.
//! - Privasi member-facing: builder pesan HANYA menerima nama paket,
//!   kuota/hit, nominal, tanggal, dan status order. Builder tidak
//!   pernah menerima kunci API, target validasi, nama/URL provider,
//!   IP, atau chat_id — jadi nilai-nilai itu tidak mungkin bocor
//!   lewat pesan, apa pun yang dilakukan pemanggil.
//! - Dedupe di database (`member_notification_log`, UNIQUE(kind,
//!   ref_key)): restart worker / pengiriman ulang tidak menggandakan
//!   pesan. Hanya baris `sent` yang menghalangi kirim ulang; `failed`
//!   boleh dicoba lagi pada tick berikutnya.
//! - Fail-open untuk pemanggil bisnis: `notify_member_purchase`
//!   tidak pernah mengembalikan error ke jalur transisi order; gagal
//!   kirim hanya jadi log + baris `failed`.
//! - Bila bot belum dikonfigurasi (tidak ada token), pengiriman
//!   dilewati diam-diam (dormant) seperti notifikasi admin — tidak
//!   pernah menggagalkan flow apa pun.

use axum::{extract::State, http::HeaderMap, Json};
use chrono::{DateTime, Duration, NaiveDateTime, Timelike, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, MySqlPool};
use uuid::Uuid;

use crate::api::AppState;
use crate::error::AppError;
use crate::provider_config::CredentialCipher;
use crate::telegram_settings::{admin_message_text, escape_html, format_hits, format_rupiah};

// ---------------------------------------------------------------------------
// Konstanta
// ---------------------------------------------------------------------------

/// Panjang kode tautan (alfanumerik, aman untuk payload deep-link
/// `/start` Telegram yang dibatasi 64 byte).
pub const LINK_CODE_LEN: usize = 12;
/// Masa berlaku kode tautan sejak dibuat.
pub const LINK_CODE_TTL_MINUTES: i64 = 15;
/// Jeda antar kirim broadcast (hormati limit Bot API).
pub const BROADCAST_DELAY_MS: u64 = 100;
/// Interval loop sisa masa aktif member (sama seperti job admin).
pub const MEMBER_EXPIRY_JOB_INTERVAL_SECS: u64 = 6 * 3_600;
/// Interval pengecekan jendela rekapan.
pub const RECAP_CHECK_INTERVAL_SECS: u64 = 30 * 60;
/// Jendela kirim rekapan (WIB): 07:00–07:29.
pub const RECAP_WINDOW_START_MINUTES: u32 = 7 * 60;
pub const RECAP_WINDOW_END_MINUTES: u32 = 7 * 60 + 29;
/// Ambang sisa masa aktif (hari).
pub const EXPIRY_3D_DAYS: i64 = 3;
pub const EXPIRY_1D_DAYS: i64 = 1;

// Kind log pengiriman (UNIQUE(kind, ref_key) di member_notification_log).
pub const KIND_PURCHASE_CREATED: &str = "purchase_created";
pub const KIND_PURCHASE_GRANTED: &str = "purchase_granted";
pub const KIND_PURCHASE_EXPIRED: &str = "purchase_expired";
pub const KIND_PURCHASE_CANCELED: &str = "purchase_canceled";
pub const KIND_PURCHASE_NEEDS_REVIEW: &str = "purchase_needs_review";
pub const KIND_EXPIRY_3D: &str = "expiry_3d";
pub const KIND_EXPIRY_1D: &str = "expiry_1d";
pub const KIND_RECAP: &str = "recap";
pub const KIND_BROADCAST: &str = "broadcast";
pub const KIND_TEST: &str = "test";

// ---------------------------------------------------------------------------
// Preferensi
// ---------------------------------------------------------------------------

/// Toggle notifikasi per member. Default: SEMUA MATI (opt-in eksplisit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberNotificationPrefs {
    pub notify_expiry: bool,
    pub notify_admin: bool,
    pub notify_purchase: bool,
    pub notify_recap: bool,
}

impl Default for MemberNotificationPrefs {
    fn default() -> Self {
        Self {
            notify_expiry: false,
            notify_admin: false,
            notify_purchase: false,
            notify_recap: false,
        }
    }
}

/// Toggle yang menggerbang satu kind. None = tanpa gerbang toggle
/// (dipakai pesan tes: cukup tautan aktif).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefToggle {
    Expiry,
    Admin,
    Purchase,
    Recap,
}

/// Kind -> toggle penggerbangnya. Pure agar bisa dites tanpa database.
pub fn toggle_for_kind(kind: &str) -> Option<PrefToggle> {
    match kind {
        KIND_PURCHASE_CREATED
        | KIND_PURCHASE_GRANTED
        | KIND_PURCHASE_EXPIRED
        | KIND_PURCHASE_CANCELED
        | KIND_PURCHASE_NEEDS_REVIEW => Some(PrefToggle::Purchase),
        KIND_EXPIRY_3D | KIND_EXPIRY_1D => Some(PrefToggle::Expiry),
        KIND_RECAP => Some(PrefToggle::Recap),
        KIND_BROADCAST => Some(PrefToggle::Admin),
        _ => None,
    }
}

impl MemberNotificationPrefs {
    fn toggle_on(&self, toggle: PrefToggle) -> bool {
        match toggle {
            PrefToggle::Expiry => self.notify_expiry,
            PrefToggle::Admin => self.notify_admin,
            PrefToggle::Purchase => self.notify_purchase,
            PrefToggle::Recap => self.notify_recap,
        }
    }
}

// ---------------------------------------------------------------------------
// Fungsi murni: kode tautan, parsing perintah, jendela, seleksi
// ---------------------------------------------------------------------------

/// Kode tautan acak 12 karakter [A-Za-z0-9].
pub fn generate_link_code() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(LINK_CODE_LEN)
        .map(char::from)
        .collect()
}

/// Format kode tautan: tepat 12 karakter alfanumerik.
pub fn is_valid_link_code_format(code: &str) -> bool {
    code.len() == LINK_CODE_LEN && code.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Parse `/start <kode>` dari teks pesan. Mengembalikan kode bila teks
/// adalah perintah /start (boleh bersufiks @namabot, sesuai perilaku
/// grup Telegram) dengan TEPAT satu argumen. `/start` tanpa argumen
/// mengembalikan None agar jatuh ke perilaku lama (help admin).
/// Perintah dicocokkan case-insensitive seperti `botcmd`.
pub fn parse_start_link(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let mut parts = trimmed.split_whitespace();
    let command = parts.next()?;
    if !command.starts_with('/') {
        return None;
    }
    let name = command[1..].split('@').next().unwrap_or("");
    if !name.eq_ignore_ascii_case("start") {
        return None;
    }
    let arg = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(arg.to_owned())
}

/// Apakah teks adalah perintah `/stop` (boleh bersufiks @namabot).
pub fn parse_stop(text: &str) -> bool {
    let mut parts = text.trim().split_whitespace();
    let Some(command) = parts.next() else {
        return false;
    };
    if !command.starts_with('/') || parts.next().is_some() {
        return false;
    }
    let name = command[1..].split('@').next().unwrap_or("");
    name.eq_ignore_ascii_case("stop")
}

/// Status validasi satu baris kode tautan (baris sudah dibaca dari DB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCodeError {
    AlreadyUsed,
    Expired,
}

/// Validasi murni atas baris kode: belum dipakai + belum kedaluwarsa.
/// Baris yang tidak ditemukan ditangani pemanggil sebagai Invalid.
pub fn validate_link_code_row(
    used_at: Option<NaiveDateTime>,
    expires_at: NaiveDateTime,
    now: NaiveDateTime,
) -> Result<(), LinkCodeError> {
    if used_at.is_some() {
        return Err(LinkCodeError::AlreadyUsed);
    }
    if expires_at <= now {
        return Err(LinkCodeError::Expired);
    }
    Ok(())
}

/// Kind kedaluwarsa yang jatuh tempo untuk satu bucket. Jendela dibuat
/// disjoin supaya satu bucket menerima 3d dulu (saat masuk 1–3 hari)
/// lalu 1d (saat masuk 0–1 hari), tidak pernah keduanya sekaligus.
/// Pure agar bisa dites tanpa database.
pub fn expiry_kind_due(
    expires_at: NaiveDateTime,
    now: NaiveDateTime,
) -> Option<&'static str> {
    if expires_at <= now {
        return None;
    }
    if expires_at <= now + Duration::days(EXPIRY_1D_DAYS) {
        return Some(KIND_EXPIRY_1D);
    }
    if expires_at <= now + Duration::days(EXPIRY_3D_DAYS) {
        return Some(KIND_EXPIRY_3D);
    }
    None
}

/// Apakah menit-ke-n dalam hari WIB berada di jendela rekapan.
pub fn recap_window_open(wib_minute_of_day: u32) -> bool {
    (RECAP_WINDOW_START_MINUTES..=RECAP_WINDOW_END_MINUTES).contains(&wib_minute_of_day)
}

/// Rekapan hanya dikirim bila ada aktivitas (anti-spam): hit > 0 atau
/// ada order dalam 24 jam. Nol aktivitas = lewati diam-diam.
pub fn should_send_recap(hits_24h: i64, orders_24h: i64) -> bool {
    hits_24h > 0 || orders_24h > 0
}

/// Seleksi penerima broadcast: hanya member tertaut + toggle admin aktif.
pub fn broadcast_recipient(linked: bool, notify_admin: bool) -> bool {
    linked && notify_admin
}

/// Dedupe murni: true bila sudah ada baris `sent` untuk (kind, ref_key).
/// Dipakai tes; fungsi DB `was_sent` memakai aturan yang sama di SQL.
pub fn is_duplicate_sent(
    existing: &[(String, String, String)],
    kind: &str,
    ref_key: &str,
) -> bool {
    existing
        .iter()
        .any(|(k, r, s)| k == kind && r == ref_key && s == "sent")
}

/// Label status order berbahasa Indonesia untuk pesan member.
pub fn order_status_label(status: &str) -> &'static str {
    match status {
        "waiting_payment" => "Menunggu pembayaran",
        "paid" => "Lunas (menunggu grant)",
        "granted" => "Lunas",
        "expired" => "Kedaluwarsa",
        "canceled" => "Dibatalkan",
        "needs_review" => "Perlu peninjauan",
        other => {
            let _ = other;
            "Tidak diketahui"
        }
    }
}

/// Tanggal WIB (YYYY-MM-DD) dari waktu UTC — kunci dedupe rekapan.
pub fn wib_date_label(now_utc: DateTime<Utc>) -> String {
    (now_utc + Duration::hours(7)).format("%Y-%m-%d").to_string()
}

/// Datetime UTC (naive) -> string WIB "DD-MM-YYYY HH:MM WIB".
pub fn wib_datetime_string(moment_naive_utc: NaiveDateTime) -> String {
    (moment_naive_utc + Duration::hours(7))
        .format("%d-%m-%Y %H:%M WIB")
        .to_string()
}

// ---------------------------------------------------------------------------
// Builder pesan (HTML, nilai dinamis selalu di-escape)
// ---------------------------------------------------------------------------

/// Semua builder memakai format yang sama dengan notifikasi admin:
/// header brand + judul tebal dari `admin_message_text`, detail per
/// baris. TIDAK ADA builder yang menerima kunci, target, provider,
/// IP, atau chat_id — nilai terlarang tidak mungkin masuk pesan.

pub fn link_confirmed_message() -> String {
    admin_message_text(
        "✅",
        "Telegram Terhubung",
        "Akun Telegram ini sudah terhubung ke akun member Rajacek. Notifikasi yang Anda aktifkan di portal akan dikirim ke chat ini. Kirim /stop kapan saja untuk memutuskan tautan.",
    )
}

pub fn link_rejected_message() -> String {
    admin_message_text(
        "❌",
        "Kode Tidak Valid",
        "Kode tautan tidak ditemukan, sudah dipakai, atau sudah kedaluwarsa (berlaku 15 menit). Buat kode baru dari portal member, lalu kirim /start <kode> di sini.",
    )
}

pub fn link_conflict_message() -> String {
    admin_message_text(
        "❌",
        "Chat Sudah Tertaut",
        "Chat Telegram ini sudah tertaut ke akun member lain. Kirim /stop untuk memutuskan tautan lama, lalu kirim /start <kode> lagi.",
    )
}

pub fn unlink_confirmed_message() -> String {
    admin_message_text(
        "✅",
        "Tautan Diputus",
        "Akun Telegram ini sudah diputuskan dari akun member Rajacek. Notifikasi tidak akan dikirim lagi ke chat ini.",
    )
}

pub fn test_message() -> String {
    admin_message_text(
        "🔔",
        "Notifikasi Percobaan",
        "Ini pesan tes dari portal member. Tautan Telegram Anda berfungsi — notifikasi yang Anda aktifkan akan dikirim ke chat ini.",
    )
}

pub fn purchase_created_message(
    package_name: &str,
    amount_idr: i64,
    pay_deadline_wib: &str,
) -> String {
    admin_message_text(
        "🧾",
        "Order Dibuat — Menunggu Pembayaran",
        &format!(
            "📦 Paket: {}\n💰 Nominal: {}\n🕐 Batas bayar: {}\n\nSelesaikan pembayaran sebelum batas di atas agar kuota langsung aktif.",
            escape_html(package_name),
            format_rupiah(amount_idr as u64),
            escape_html(pay_deadline_wib),
        ),
    )
}

pub fn purchase_granted_message(
    package_name: &str,
    quota_hits: i64,
    expires_wib: &str,
) -> String {
    admin_message_text(
        "🎉",
        "Pembayaran Lunas — Kuota Aktif",
        &format!(
            "📦 Paket: {}\n⚡ Kuota aktif: {}\n🕐 Aktif s/d: {}\n\nKuota sudah bisa dipakai untuk validasi.",
            escape_html(package_name),
            format_hits(quota_hits as u64),
            escape_html(expires_wib),
        ),
    )
}

pub fn purchase_expired_message(package_name: &str) -> String {
    admin_message_text(
        "⌛",
        "Order Kedaluwarsa",
        &format!(
            "📦 Paket: {}\n\nBatas pembayaran sudah lewat dan order dibatalkan otomatis. Buat order baru dari portal bila masih ingin membeli paket ini.",
            escape_html(package_name),
        ),
    )
}

pub fn purchase_canceled_message(package_name: &str) -> String {
    admin_message_text(
        "🚫",
        "Order Dibatalkan",
        &format!(
            "📦 Paket: {}\n\nOrder ini sudah dibatalkan. Tidak ada kuota yang ditambahkan.",
            escape_html(package_name),
        ),
    )
}

pub fn purchase_needs_review_message(package_name: &str, amount_idr: i64) -> String {
    admin_message_text(
        "⚠️",
        "Pembayaran Perlu Peninjauan",
        &format!(
            "📦 Paket: {}\n💰 Nominal: {}\n\nPembayaran Anda sudah tercatat, tetapi grant kuota ditahan untuk peninjauan admin. Admin akan menyelesaikan order ini — Anda akan menerima kabar saat kuota aktif.",
            escape_html(package_name),
            format_rupiah(amount_idr as u64),
        ),
    )
}

pub fn expiry_message(
    days_left: i64,
    package_name: &str,
    remaining_hits: i64,
    expires_wib: &str,
) -> String {
    admin_message_text(
        "⏳",
        "Paket Hampir Kedaluwarsa",
        &format!(
            "📦 Paket: {}\n⚡ Sisa kuota: {}\n🕐 Kedaluwarsa: {} ({} lagi)\n\nPerpanjang paket sebelum tanggal di atas agar validasi tidak terhenti.",
            escape_html(package_name),
            format_hits(remaining_hits as u64),
            escape_html(expires_wib),
            if days_left <= 1 {
                "kurang dari 1 hari".to_owned()
            } else {
                format!("{days_left} hari")
            },
        ),
    )
}

/// Data rekapan 24 jam (sudah diagregasi dari DB oleh job).
pub struct RecapData {
    pub hits_24h: i64,
    pub remaining_total: i64,
    pub nearest: Option<(String, String)>,
    pub orders_24h: i64,
    pub latest_order: Option<(String, String, i64)>,
}

pub fn recap_message(data: &RecapData, wib_date: &str) -> String {
    let nearest_line = match &data.nearest {
        Some((name, expires)) => format!(
            "📦 Paket terdekat kedaluwarsa: {} (s/d {})",
            escape_html(name),
            escape_html(expires)
        ),
        None => "📦 Tidak ada paket yang segera kedaluwarsa.".to_owned(),
    };
    let order_line = match &data.latest_order {
        Some((name, status, amount)) => format!(
            "🧾 Order terbaru: {} — {} ({})",
            escape_html(name),
            escape_html(status),
            format_rupiah(*amount as u64)
        ),
        None => "🧾 Tidak ada order dalam 24 jam.".to_owned(),
    };
    admin_message_text(
        "📊",
        "Rekapan 24 Jam",
        &format!(
            "🗓️ Periode: {}\n⚡ Hit 24 jam terakhir: {}\n💼 Sisa kuota total: {}\n{}\n🧾 Jumlah order 24 jam: {}\n{}",
            escape_html(wib_date),
            format_hits(data.hits_24h as u64),
            format_hits(data.remaining_total as u64),
            nearest_line,
            data.orders_24h,
            order_line,
        ),
    )
}

pub fn admin_broadcast_message(title: &str, body: &str) -> String {
    // Isi dari admin: judul + isi tetap di-escape agar tidak merusak
    // parse HTML dan tidak bisa menyuntikkan markup — backend TIDAK
    // memfilter isinya, hanya meng-escape-nya.
    admin_message_text("📣", &escape_html(title), &escape_html(body))
}

// ---------------------------------------------------------------------------
// Baris database + akses data
// ---------------------------------------------------------------------------

/// Tautan chat member (nilai chat_id TIDAK PERNAH diserialisasi ke
/// portal/panel — handler hanya mengirim status + tanggal tautan).
pub struct MemberTelegramLink {
    pub chat_id: String,
    pub linked_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct MemberTelegramLinkRow {
    chat_id: String,
    linked_at: NaiveDateTime,
}

#[derive(FromRow)]
struct MemberPrefsRow {
    notify_expiry: i8,
    notify_admin: i8,
    notify_purchase: i8,
    notify_recap: i8,
}

#[derive(FromRow)]
struct LinkCodeRow {
    member_id: String,
    expires_at: NaiveDateTime,
    used_at: Option<NaiveDateTime>,
}

#[derive(FromRow)]
struct LogRow {
    kind: String,
    ref_key: String,
    status: String,
}

fn db_err() -> AppError {
    AppError::internal("Data notifikasi Telegram tidak dapat dibaca")
}

pub async fn get_link(
    pool: &MySqlPool,
    member_id: &Uuid,
) -> Result<Option<MemberTelegramLink>, AppError> {
    let row = sqlx::query_as::<_, MemberTelegramLinkRow>(
        "SELECT chat_id, linked_at FROM member_telegram_links WHERE member_id = ?",
    )
    .bind(member_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| db_err())?;
    Ok(row.map(|row| MemberTelegramLink {
        chat_id: row.chat_id,
        linked_at: row.linked_at.and_utc(),
    }))
}

pub async fn is_linked_chat(pool: &MySqlPool, chat_id: i64) -> Result<bool, AppError> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT member_id FROM member_telegram_links WHERE chat_id = ?")
            .bind(chat_id.to_string())
            .fetch_optional(pool)
            .await
            .map_err(|_| db_err())?;
    Ok(found.is_some())
}

pub async fn get_prefs(
    pool: &MySqlPool,
    member_id: &Uuid,
) -> Result<MemberNotificationPrefs, AppError> {
    let row = sqlx::query_as::<_, MemberPrefsRow>(
        "SELECT notify_expiry, notify_admin, notify_purchase, notify_recap \
         FROM member_notification_prefs WHERE member_id = ?",
    )
    .bind(member_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| db_err())?;
    Ok(match row {
        Some(row) => MemberNotificationPrefs {
            notify_expiry: row.notify_expiry != 0,
            notify_admin: row.notify_admin != 0,
            notify_purchase: row.notify_purchase != 0,
            notify_recap: row.notify_recap != 0,
        },
        // Tanpa baris = semua mati (opt-in eksplisit).
        None => MemberNotificationPrefs::default(),
    })
}

pub async fn upsert_prefs(
    pool: &MySqlPool,
    member_id: &Uuid,
    prefs: &MemberNotificationPrefs,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO member_notification_prefs \
         (member_id, notify_expiry, notify_admin, notify_purchase, notify_recap) \
         VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE notify_expiry = VALUES(notify_expiry), \
         notify_admin = VALUES(notify_admin), notify_purchase = VALUES(notify_purchase), \
         notify_recap = VALUES(notify_recap)",
    )
    .bind(member_id.to_string())
    .bind(i8::from(prefs.notify_expiry))
    .bind(i8::from(prefs.notify_admin))
    .bind(i8::from(prefs.notify_purchase))
    .bind(i8::from(prefs.notify_recap))
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Preferensi notifikasi tidak dapat disimpan"))?;
    Ok(())
}

/// Buat kode tautan baru (menggantikan kode lama yang belum dipakai
/// milik member itu). Mengembalikan (kode, kedaluwarsa).
pub async fn create_link_code(
    pool: &MySqlPool,
    member_id: &Uuid,
    now: NaiveDateTime,
) -> Result<(String, NaiveDateTime), AppError> {
    sqlx::query("DELETE FROM member_telegram_link_codes WHERE member_id = ? AND used_at IS NULL")
        .bind(member_id.to_string())
        .execute(pool)
        .await
        .map_err(|_| db_err())?;
    let code = generate_link_code();
    let expires_at = now + Duration::minutes(LINK_CODE_TTL_MINUTES);
    sqlx::query(
        "INSERT INTO member_telegram_link_codes (code, member_id, expires_at) VALUES (?, ?, ?)",
    )
    .bind(&code)
    .bind(member_id.to_string())
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Kode tautan tidak dapat dibuat"))?;
    Ok((code, expires_at))
}

/// Hasil percobaan tautan dari webhook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAttempt {
    Linked,
    Conflict,
    Invalid,
}

/// Tautkan chat ke member pemilik kode. Urutan: validasi kode ->
/// cek konflik chat -> tandai kode dipakai (CAS) -> simpan tautan.
/// Kode yang gagal karena konflik chat TIDAK dikonsumsi pada cek awal,
/// sehingga member bisa /stop tautan lama lalu memakai kode yang sama.
pub async fn try_link_chat(
    pool: &MySqlPool,
    code: &str,
    chat_id: i64,
    now: NaiveDateTime,
) -> Result<LinkAttempt, AppError> {
    if !is_valid_link_code_format(code) {
        return Ok(LinkAttempt::Invalid);
    }
    let row = sqlx::query_as::<_, LinkCodeRow>(
        "SELECT member_id, expires_at, used_at FROM member_telegram_link_codes WHERE code = ?",
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(|_| db_err())?;
    let Some(row) = row else {
        return Ok(LinkAttempt::Invalid);
    };
    if validate_link_code_row(row.used_at, row.expires_at, now).is_err() {
        return Ok(LinkAttempt::Invalid);
    }
    let member_id = row.member_id.clone();
    // Konflik: chat sudah tertaut ke member lain.
    let owner: Option<String> =
        sqlx::query_scalar("SELECT member_id FROM member_telegram_links WHERE chat_id = ?")
            .bind(chat_id.to_string())
            .fetch_optional(pool)
            .await
            .map_err(|_| db_err())?;
    if let Some(owner) = owner {
        if owner != member_id {
            return Ok(LinkAttempt::Conflict);
        }
        // Chat sudah tertaut ke member yang sama: tautan ulang = sukses
        // (tetap konsumsi kode agar tidak bisa dipakai berulang).
    }
    // Konsumsi kode (CAS: hanya bila masih unused).
    let claimed = sqlx::query(
        "UPDATE member_telegram_link_codes SET used_at = ? WHERE code = ? AND used_at IS NULL",
    )
    .bind(now)
    .bind(code)
    .execute(pool)
    .await
    .map_err(|_| db_err())?;
    if claimed.rows_affected() != 1 {
        return Ok(LinkAttempt::Invalid);
    }
    // Simpan/ganti tautan (member PK; chat UNIQUE sudah dicek di atas).
    let linked = sqlx::query(
        "INSERT INTO member_telegram_links (member_id, chat_id, linked_at) VALUES (?, ?, ?) \
         ON DUPLICATE KEY UPDATE chat_id = VALUES(chat_id), linked_at = VALUES(linked_at)",
    )
    .bind(&member_id)
    .bind(chat_id.to_string())
    .bind(now)
    .execute(pool)
    .await;
    match linked {
        Ok(_) => Ok(LinkAttempt::Linked),
        Err(_) => {
            // Balapan konflik chat di antara cek dan insert: kode sudah
            // terpakai, tapi tautan gagal — laporkan konflik agar member
            // membuat kode baru setelah /stop.
            Ok(LinkAttempt::Conflict)
        }
    }
}

pub async fn unlink_chat_by_chat(pool: &MySqlPool, chat_id: i64) -> Result<bool, AppError> {
    let deleted = sqlx::query("DELETE FROM member_telegram_links WHERE chat_id = ?")
        .bind(chat_id.to_string())
        .execute(pool)
        .await
        .map_err(|_| db_err())?;
    Ok(deleted.rows_affected() == 1)
}

pub async fn unlink_member(pool: &MySqlPool, member_id: &Uuid) -> Result<bool, AppError> {
    let deleted = sqlx::query("DELETE FROM member_telegram_links WHERE member_id = ?")
        .bind(member_id.to_string())
        .execute(pool)
        .await
        .map_err(|_| db_err())?;
    Ok(deleted.rows_affected() == 1)
}

pub async fn log_notification(
    pool: &MySqlPool,
    member_id: &Uuid,
    kind: &str,
    ref_key: &str,
    status: &str,
    error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO member_notification_log (id, member_id, kind, ref_key, status, error) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE status = VALUES(status), error = VALUES(error), \
         sent_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(member_id.to_string())
    .bind(kind)
    .bind(ref_key)
    .bind(status)
    .bind(error)
    .execute(pool)
    .await
    .map_err(|_| db_err())?;
    Ok(())
}

pub async fn was_sent(pool: &MySqlPool, kind: &str, ref_key: &str) -> Result<bool, AppError> {
    let row = sqlx::query_as::<_, LogRow>(
        "SELECT kind, ref_key, status FROM member_notification_log \
         WHERE kind = ? AND ref_key = ?",
    )
    .bind(kind)
    .bind(ref_key)
    .fetch_optional(pool)
    .await
    .map_err(|_| db_err())?;
    Ok(matches!(row, Some(row) if row.status == "sent"))
}

// ---------------------------------------------------------------------------
// Pengiriman terpusat
// ---------------------------------------------------------------------------

/// Hasil pengiriman. `Failed` tetap tercatat di log; pemanggil bisnis
/// TIDAK BOLEH menggagalkan transisinya karena hasil ini.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    Sent,
    SkippedNoLink,
    SkippedNoBot,
    SkippedToggleOff,
    SkippedDuplicate,
    Failed(String),
}

/// Kirim ke chat member TANPA cek toggle (pemanggil sudah menyeleksi:
/// broadcast, pesan tes). Cek tautan + dedupe `sent` + kirim + catat.
pub async fn send_to_member_chat(
    pool: &MySqlPool,
    cipher: Option<&CredentialCipher>,
    member_id: &Uuid,
    kind: &str,
    ref_key: &str,
    text: &str,
) -> SendOutcome {
    let link = match get_link(pool, member_id).await {
        Ok(Some(link)) => link,
        Ok(None) => return SendOutcome::SkippedNoLink,
        Err(error) => return SendOutcome::Failed(error.to_string()),
    };
    match was_sent(pool, kind, ref_key).await {
        Ok(true) => return SendOutcome::SkippedDuplicate,
        Ok(false) => {}
        Err(error) => return SendOutcome::Failed(error.to_string()),
    }
    let Some((token, _)) =
        crate::telegram_settings::resolve_credentials(pool, cipher).await
    else {
        // Bot belum dikonfigurasi: dormant, tanpa baris log failed agar
        // tick berikutnya mencoba lagi secara alami.
        return SendOutcome::SkippedNoBot;
    };
    let base_url = crate::alerts::telegram_base_url();
    match crate::alerts::send_telegram_message(&base_url, &token, &link.chat_id, text, Some("HTML"))
        .await
    {
        Ok(()) => {
            if let Err(error) = log_notification(pool, member_id, kind, ref_key, "sent", None).await
            {
                tracing::warn!(?error, kind, "Log notifikasi terkirim gagal ditulis");
            }
            SendOutcome::Sent
        }
        Err(error) => {
            if let Err(log_error) =
                log_notification(pool, member_id, kind, ref_key, "failed", Some(&error)).await
            {
                tracing::warn!(?log_error, kind, "Log notifikasi gagal gagal ditulis");
            }
            SendOutcome::Failed(error)
        }
    }
}

/// Kirim dengan gerbang toggle kind. Tes memakai `send_to_member_chat`
/// langsung (tanpa toggle) — kind `test` tidak punya toggle.
pub async fn send_member_notification(
    pool: &MySqlPool,
    cipher: Option<&CredentialCipher>,
    member_id: &Uuid,
    kind: &str,
    ref_key: &str,
    text: &str,
) -> SendOutcome {
    if let Some(toggle) = toggle_for_kind(kind) {
        match get_prefs(pool, member_id).await {
            Ok(prefs) if prefs.toggle_on(toggle) => {}
            Ok(_) => return SendOutcome::SkippedToggleOff,
            Err(error) => return SendOutcome::Failed(error.to_string()),
        }
    }
    send_to_member_chat(pool, cipher, member_id, kind, ref_key, text).await
}

// ---------------------------------------------------------------------------
// Hook pembelian (fail-open: tidak pernah mengembalikan error)
// ---------------------------------------------------------------------------

/// Event pembelian yang memicu notifikasi member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurchaseEvent {
    Created,
    Granted,
    Expired,
    Canceled,
    NeedsReview,
}

impl PurchaseEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            PurchaseEvent::Created => KIND_PURCHASE_CREATED,
            PurchaseEvent::Granted => KIND_PURCHASE_GRANTED,
            PurchaseEvent::Expired => KIND_PURCHASE_EXPIRED,
            PurchaseEvent::Canceled => KIND_PURCHASE_CANCELED,
            PurchaseEvent::NeedsReview => KIND_PURCHASE_NEEDS_REVIEW,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            PurchaseEvent::Created => "created",
            PurchaseEvent::Granted => "granted",
            PurchaseEvent::Expired => "expired",
            PurchaseEvent::Canceled => "canceled",
            PurchaseEvent::NeedsReview => "needs_review",
        }
    }
}

#[derive(FromRow)]
struct OrderNotifyRow {
    member_id: String,
    package_name: String,
    amount_idr: i64,
    quota_hits: i64,
    qris_expires_at: Option<NaiveDateTime>,
    granted_quota: Option<i64>,
    granted_expires_at: Option<NaiveDateTime>,
}

/// Kirim notifikasi satu event pembelian. Dipanggil pemanggil dalam
/// `tokio::spawn` (fire-and-forget) dari jalur request, atau langsung
/// dari job latar — fungsi ini sendiri tidak pernah Err.
pub async fn notify_member_purchase(
    pool: &MySqlPool,
    cipher: Option<&CredentialCipher>,
    order_id: &str,
    event: PurchaseEvent,
) {
    let row = sqlx::query_as::<_, OrderNotifyRow>(
        "SELECT member_id, package_name, amount_idr, quota_hits, qris_expires_at, \
         granted_quota, granted_expires_at FROM package_orders WHERE id = ?",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await;
    let Ok(Some(row)) = row else {
        tracing::warn!(order_id, "Notifikasi pembelian dilewati: order tidak ditemukan");
        return;
    };
    let Ok(member_uuid) = Uuid::parse_str(&row.member_id) else {
        tracing::warn!(order_id, "Notifikasi pembelian dilewati: member_id tidak valid");
        return;
    };
    let text = match event {
        PurchaseEvent::Created => {
            let deadline = row
                .qris_expires_at
                .map(wib_datetime_string)
                .unwrap_or_else(|| "segera".to_owned());
            purchase_created_message(&row.package_name, row.amount_idr, &deadline)
        }
        PurchaseEvent::Granted => {
            let quota = row.granted_quota.unwrap_or(row.quota_hits);
            let expires = row
                .granted_expires_at
                .map(wib_datetime_string)
                .unwrap_or_else(|| "tanpa batas".to_owned());
            purchase_granted_message(&row.package_name, quota, &expires)
        }
        PurchaseEvent::Expired => purchase_expired_message(&row.package_name),
        PurchaseEvent::Canceled => purchase_canceled_message(&row.package_name),
        PurchaseEvent::NeedsReview => {
            purchase_needs_review_message(&row.package_name, row.amount_idr)
        }
    };
    let ref_key = format!("{order_id}:{}", event.as_str());
    match send_member_notification(pool, cipher, &member_uuid, event.kind(), &ref_key, &text).await
    {
        SendOutcome::Failed(error) => {
            tracing::warn!(order_id, kind = event.kind(), error, "Notifikasi pembelian gagal");
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Job worker: sisa masa aktif + rekapan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryRun {
    pub candidates: usize,
    pub sent: usize,
    pub failed: usize,
}

#[derive(FromRow)]
struct ExpiryBucketRow {
    id: String,
    member_id: String,
    remaining_hits: i64,
    expires_at: NaiveDateTime,
    package_name: Option<String>,
}

/// Satu tick job sisa masa aktif member: bucket non-trial milik member
/// (sisa > 0) yang masuk jendela 3 hari. Bucket yang sama menerima 3d
/// dulu lalu 1d (jendela disjoin di `expiry_kind_due`); dedupe log
/// mencegah kirim ulang pada tick berikutnya. Job admin yang sudah ada
/// TIDAK disentuh — ini loop terpisah untuk member.
pub async fn run_member_expiry_job(
    pool: &MySqlPool,
    cipher: Option<&CredentialCipher>,
    now: DateTime<Utc>,
) -> Result<ExpiryRun, AppError> {
    let now_naive = now.naive_utc();
    let window_end = now_naive + Duration::days(EXPIRY_3D_DAYS);
    let rows = sqlx::query_as::<_, ExpiryBucketRow>(
        "SELECT b.id, b.member_id, b.remaining_hits, b.expires_at, \
         COALESCE(po.package_name, ap.name, 'Paket') AS package_name \
         FROM quota_buckets b LEFT JOIN package_orders po ON po.id = b.order_id \
         LEFT JOIN admin_packages ap ON ap.id = b.package_id \
         WHERE b.member_id IS NOT NULL AND b.remaining_hits > 0 \
         AND b.expires_at > ? AND b.expires_at <= ? \
         AND (b.package_id IS NOT NULL OR b.order_id IS NOT NULL) \
         ORDER BY b.expires_at ASC",
    )
    .bind(now_naive)
    .bind(window_end)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Bucket kedaluwarsa member tidak dapat dibaca"))?;
    let mut run = ExpiryRun {
        candidates: rows.len(),
        sent: 0,
        failed: 0,
    };
    for row in rows {
        let Some(kind) = expiry_kind_due(row.expires_at, now_naive) else {
            continue;
        };
        let Ok(member_uuid) = Uuid::parse_str(&row.member_id) else {
            continue;
        };
        let days_left = (row.expires_at - now_naive).num_days().max(0);
        let text = expiry_message(
            days_left,
            row.package_name.as_deref().unwrap_or("Paket"),
            row.remaining_hits,
            &wib_datetime_string(row.expires_at),
        );
        let ref_key = format!("{}:{}", row.id, kind);
        match send_member_notification(pool, cipher, &member_uuid, kind, &ref_key, &text).await {
            SendOutcome::Sent => run.sent += 1,
            SendOutcome::Failed(_) => run.failed += 1,
            _ => {}
        }
    }
    Ok(run)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecapRun {
    pub window_open: bool,
    pub considered: usize,
    pub sent: usize,
    pub skipped_inactive: usize,
    pub failed: usize,
}

/// Satu tick job rekapan. Di luar jendela 07:00–07:29 WIB langsung
/// kembali tanpa menyentuh database member (kecuali log dedupe tidak
/// diperlukan: ref_key tanggal WIB + status `sent` mencegah kirim
/// ganda bila worker restart di dalam jendela).
pub async fn run_member_recap_job(
    pool: &MySqlPool,
    cipher: Option<&CredentialCipher>,
    now: DateTime<Utc>,
) -> Result<RecapRun, AppError> {
    let wib = now + Duration::hours(7);
    let minute_of_day = wib.hour() * 60 + wib.minute();
    if !recap_window_open(minute_of_day) {
        return Ok(RecapRun {
            window_open: false,
            considered: 0,
            sent: 0,
            skipped_inactive: 0,
            failed: 0,
        });
    }
    let wib_date = wib_date_label(now);
    let recipients = sqlx::query_scalar::<_, String>(
        "SELECT l.member_id FROM member_telegram_links l \
         JOIN member_notification_prefs p ON p.member_id = l.member_id \
         WHERE p.notify_recap = 1",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Penerima rekapan tidak dapat dibaca"))?;
    let mut run = RecapRun {
        window_open: true,
        considered: recipients.len(),
        sent: 0,
        skipped_inactive: 0,
        failed: 0,
    };
    for member_id in recipients {
        let Ok(member_uuid) = Uuid::parse_str(&member_id) else {
            continue;
        };
        // Prefix kunci member (admin_api_keys, bukan map memori store
        // — job worker hanya memegang pool).
        let prefixes = sqlx::query_scalar::<_, String>(
            "SELECT prefix FROM admin_api_keys WHERE member_id = ?",
        )
        .bind(&member_id)
        .fetch_all(pool)
        .await
        .map_err(|_| AppError::internal("Prefix kunci member tidak dapat dibaca"))?;
        let hits_24h: i64 = if prefixes.is_empty() {
            0
        } else {
            let mut builder = sqlx::QueryBuilder::new(
                "SELECT COUNT(*) FROM validation_requests WHERE api_key_prefix IN (",
            );
            let mut separated = builder.separated(", ");
            for prefix in &prefixes {
                separated.push_bind(prefix);
            }
            separated.push_unseparated(") AND occurred_at >= UTC_TIMESTAMP() - INTERVAL 24 HOUR");
            builder
                .build_query_scalar()
                .fetch_one(pool)
                .await
                .map_err(|_| AppError::internal("Hit 24 jam tidak dapat dibaca"))?
        };
        let remaining_total: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(remaining_hits), 0) FROM quota_buckets \
             WHERE member_id = ? AND remaining_hits > 0 \
             AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP(6))",
        )
        .bind(&member_id)
        .fetch_one(pool)
        .await
        .map_err(|_| AppError::internal("Sisa kuota member tidak dapat dibaca"))?;
        let nearest = sqlx::query_as::<_, (Option<String>, NaiveDateTime)>(
            "SELECT COALESCE(po.package_name, ap.name, 'Paket'), b.expires_at \
             FROM quota_buckets b LEFT JOIN package_orders po ON po.id = b.order_id \
             LEFT JOIN admin_packages ap ON ap.id = b.package_id \
             WHERE b.member_id = ? AND b.remaining_hits > 0 AND b.expires_at > UTC_TIMESTAMP(6) \
             ORDER BY b.expires_at ASC LIMIT 1",
        )
        .bind(&member_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| AppError::internal("Paket terdekat kedaluwarsa tidak dapat dibaca"))?
        .map(|(name, expires)| {
            (
                name.unwrap_or_else(|| "Paket".to_owned()),
                wib_datetime_string(expires),
            )
        });
        let orders_24h: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM package_orders \
             WHERE member_id = ? AND created_at >= UTC_TIMESTAMP() - INTERVAL 24 HOUR",
        )
        .bind(&member_id)
        .fetch_one(pool)
        .await
        .map_err(|_| AppError::internal("Order 24 jam tidak dapat dibaca"))?;
        if !should_send_recap(hits_24h, orders_24h) {
            // Nol aktivitas: lewati diam-diam TANPA mencatat `sent`
            // (tidak menghalangi apa pun; besok dievaluasi lagi).
            tracing::info!(member_id, "Rekapan dilewati: tanpa aktivitas 24 jam");
            run.skipped_inactive += 1;
            continue;
        }
        let latest = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT package_name, status, amount_idr FROM package_orders \
             WHERE member_id = ? AND created_at >= UTC_TIMESTAMP() - INTERVAL 24 HOUR \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&member_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| AppError::internal("Order terbaru tidak dapat dibaca"))?
        .map(|(name, status, amount)| (name, order_status_label(&status).to_owned(), amount));
        let data = RecapData {
            hits_24h,
            remaining_total,
            nearest,
            orders_24h,
            latest_order: latest,
        };
        let text = recap_message(&data, &wib_date);
        let ref_key = format!("{member_id}:{wib_date}");
        match send_member_notification(pool, cipher, &member_uuid, KIND_RECAP, &ref_key, &text)
            .await
        {
            SendOutcome::Sent => run.sent += 1,
            SendOutcome::Failed(error) => {
                tracing::warn!(member_id, error, "Rekapan gagal terkirim");
                run.failed += 1;
            }
            _ => {}
        }
    }
    Ok(run)
}

// ---------------------------------------------------------------------------
// Broadcast admin
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct BroadcastSummary {
    pub broadcast_id: String,
    pub total: usize,
    pub sent: usize,
    pub failed: usize,
}

/// Kirim broadcast sekuensial ke semua member tertaut + toggle admin
/// aktif. Jeda 100 ms antar kirim. Tiap hasil dicatat (kind=broadcast,
/// ref_key=broadcast_id:member_id). Judul/isi sudah di-escape di
/// builder — backend tidak memfilter isi (wewenang admin).
pub async fn broadcast_to_members(
    pool: &MySqlPool,
    cipher: Option<&CredentialCipher>,
    title: &str,
    body: &str,
) -> Result<BroadcastSummary, AppError> {
    let broadcast_id = Uuid::now_v7().to_string();
    let recipients = sqlx::query_scalar::<_, String>(
        "SELECT l.member_id FROM member_telegram_links l \
         JOIN member_notification_prefs p ON p.member_id = l.member_id \
         WHERE p.notify_admin = 1",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Penerima broadcast tidak dapat dibaca"))?;
    let text = admin_broadcast_message(title, body);
    let mut summary = BroadcastSummary {
        broadcast_id: broadcast_id.clone(),
        total: recipients.len(),
        sent: 0,
        failed: 0,
    };
    for (index, member_id) in recipients.iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(BROADCAST_DELAY_MS)).await;
        }
        let Ok(member_uuid) = Uuid::parse_str(member_id) else {
            summary.failed += 1;
            continue;
        };
        let ref_key = format!("{broadcast_id}:{member_id}");
        // Penerima sudah terseleksi toggle admin; kirim tanpa cek ulang.
        match send_to_member_chat(pool, cipher, &member_uuid, KIND_BROADCAST, &ref_key, &text)
            .await
        {
            SendOutcome::Sent => summary.sent += 1,
            _ => summary.failed += 1,
        }
    }
    Ok(summary)
}

// ---------------------------------------------------------------------------
// Cabang webhook: /start <kode> dan /stop (SEBELUM gate chat admin)
// ---------------------------------------------------------------------------

/// Hasil penanganan update oleh cabang member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberUpdateOutcome {
    /// Balas teks ini ke chat pengirim, lalu selesai.
    Replied(String),
    /// Sudah ditangani tanpa balasan (chat tertaut mengirim hal lain).
    SilentHandled,
    /// Bukan urusan cabang member — lanjut ke jalur lama (gate admin).
    NotMember,
}

/// Apakah chat ini chat admin (pengecualian gerbang member). Pure.
pub fn is_admin_chat(chat_id: i64, admin_chat_id: Option<i64>) -> bool {
    admin_chat_id == Some(chat_id)
}

/// Tangani satu pesan teks dari webhook. TIDAK PERNAH mengubah perilaku
/// chat admin:
/// - `/start` tanpa argumen -> NotMember (jalur lama: help admin).
/// - Perintah/teks lain dari chat admin -> NotMember (jalur lama),
///   WALAU chat admin itu tertaut sebagai member (tautan tidak boleh
///   membungkam perintah admin).
/// - `/start <kode>` dan `/stop` berlaku untuk semua chat (termasuk
///   chat admin yang sengaja menautkan akun membernya).
/// - Chat tertaut non-admin yang mengirim hal lain -> diam.
pub async fn handle_member_update(
    pool: &MySqlPool,
    chat_id: i64,
    text: &str,
    admin_chat_id: Option<i64>,
) -> MemberUpdateOutcome {
    let now = Utc::now().naive_utc();
    if let Some(code) = parse_start_link(text) {
        return match try_link_chat(pool, &code, chat_id, now).await {
            Ok(LinkAttempt::Linked) => MemberUpdateOutcome::Replied(link_confirmed_message()),
            Ok(LinkAttempt::Conflict) => {
                MemberUpdateOutcome::Replied(link_conflict_message())
            }
            Ok(LinkAttempt::Invalid) => {
                MemberUpdateOutcome::Replied(link_rejected_message())
            }
            Err(_) => MemberUpdateOutcome::SilentHandled,
        };
    }
    if parse_stop(text) {
        return match unlink_chat_by_chat(pool, chat_id).await {
            Ok(true) => MemberUpdateOutcome::Replied(unlink_confirmed_message()),
            // Tidak tertaut: jatuh ke jalur lama (warn + diam, sama
            // seperti perilaku sebelum fitur ini).
            _ => MemberUpdateOutcome::NotMember,
        };
    }
    // Pengecualian admin: chat admin TIDAK PERNAH ditelan cabang member
    // (kecuali /start <kode> dan /stop di atas yang memang aksi member).
    if is_admin_chat(chat_id, admin_chat_id) {
        return MemberUpdateOutcome::NotMember;
    }
    match is_linked_chat(pool, chat_id).await {
        Ok(true) => MemberUpdateOutcome::SilentHandled,
        _ => MemberUpdateOutcome::NotMember,
    }
}

// ---------------------------------------------------------------------------
// Endpoint portal member (auth sesi member, sama seperti endpoint lain)
// ---------------------------------------------------------------------------

fn require_member_uuid(
    session: &crate::member::MemberSession,
) -> Result<Uuid, AppError> {
    session.member.as_ref().map(|member| member.id).ok_or_else(|| {
        AppError::unauthorized("Notifikasi Telegram hanya untuk akun member")
    })
}

fn pool_or_503(state: &AppState) -> Result<MySqlPool, AppError> {
    state.store.pool().ok_or_else(|| {
        AppError::service_unavailable("Database tidak tersedia untuk notifikasi")
    })
}

fn member_cipher(state: &AppState) -> CredentialCipher {
    CredentialCipher::new(state.config.api_key_encryption_key.as_deref())
}

#[derive(Serialize)]
pub struct NotificationsStatusResponse {
    pub linked: bool,
    pub linked_at: Option<DateTime<Utc>>,
    pub prefs: MemberNotificationPrefs,
}

/// GET /v1/member/notifications — status tautan + 4 toggle.
/// Nilai chat_id TIDAK PERNAH dikirim ke portal.
pub async fn notifications_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NotificationsStatusResponse>, AppError> {
    let session = crate::member::resolve_session(&state, &headers).await?;
    let member_id = require_member_uuid(&session)?;
    let pool = pool_or_503(&state)?;
    let link = get_link(&pool, &member_id).await?;
    let prefs = get_prefs(&pool, &member_id).await?;
    Ok(Json(NotificationsStatusResponse {
        linked: link.is_some(),
        linked_at: link.map(|link| link.linked_at),
        prefs,
    }))
}

#[derive(Serialize)]
pub struct LinkCodeResponse {
    pub code: String,
    pub expires_at: DateTime<Utc>,
    /// Username bot untuk deep-link t.me. None = tidak ada konstanta
    /// username di kode — portal menampilkan instruksi manual
    /// ("buka bot lalu kirim /start <kode>"), TIDAK mengarang username.
    pub bot_username: Option<String>,
    pub instruction: String,
}

/// POST /v1/member/notifications/link-code — buat kode baru.
pub async fn create_link_code_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<LinkCodeResponse>, AppError> {
    let session = crate::member::resolve_session(&state, &headers).await?;
    let member_id = require_member_uuid(&session)?;
    let pool = pool_or_503(&state)?;
    let (code, expires_at) = create_link_code(&pool, &member_id, Utc::now().naive_utc()).await?;
    Ok(Json(LinkCodeResponse {
        instruction: format!("Buka bot Telegram Rajacek lalu kirim /start {code}"),
        code,
        expires_at: expires_at.and_utc(),
        bot_username: None,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefsInput {
    pub notify_expiry: bool,
    pub notify_admin: bool,
    pub notify_purchase: bool,
    pub notify_recap: bool,
}

/// POST /v1/member/notifications/prefs — simpan 4 toggle (tipe ketat:
/// field harus boolean, field tak dikenal ditolak).
pub async fn update_prefs_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PrefsInput>,
) -> Result<Json<MemberNotificationPrefs>, AppError> {
    let session = crate::member::resolve_session(&state, &headers).await?;
    let member_id = require_member_uuid(&session)?;
    let pool = pool_or_503(&state)?;
    let prefs = MemberNotificationPrefs {
        notify_expiry: input.notify_expiry,
        notify_admin: input.notify_admin,
        notify_purchase: input.notify_purchase,
        notify_recap: input.notify_recap,
    };
    upsert_prefs(&pool, &member_id, &prefs).await?;
    Ok(Json(prefs))
}

/// POST /v1/member/notifications/unlink — putuskan tautan.
pub async fn unlink_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NotificationsStatusResponse>, AppError> {
    let session = crate::member::resolve_session(&state, &headers).await?;
    let member_id = require_member_uuid(&session)?;
    let pool = pool_or_503(&state)?;
    unlink_member(&pool, &member_id).await?;
    let prefs = get_prefs(&pool, &member_id).await?;
    Ok(Json(NotificationsStatusResponse {
        linked: false,
        linked_at: None,
        prefs,
    }))
}

#[derive(Serialize)]
pub struct TestNotificationResponse {
    pub sent: bool,
    pub detail: String,
}

/// POST /v1/member/notifications/test — kirim pesan tes ke chat tertaut.
/// Tanpa gerbang toggle (tes harus jalan walau toggle mati), tapi tetap
/// wajib tertaut; ref_key unik per panggilan (tanpa dedupe jangka
/// panjang — tiap tes memang boleh terkirim).
pub async fn test_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TestNotificationResponse>, AppError> {
    let session = crate::member::resolve_session(&state, &headers).await?;
    let member_id = require_member_uuid(&session)?;
    let pool = pool_or_503(&state)?;
    let cipher = member_cipher(&state);
    let ref_key = Uuid::now_v7().to_string();
    match send_to_member_chat(
        &pool,
        Some(&cipher),
        &member_id,
        KIND_TEST,
        &ref_key,
        &test_message(),
    )
    .await
    {
        SendOutcome::Sent => Ok(Json(TestNotificationResponse {
            sent: true,
            detail: "Pesan tes terkirim ke Telegram Anda.".to_owned(),
        })),
        SendOutcome::SkippedNoLink => Err(AppError::bad_request(
            "Akun Telegram belum terhubung. Hubungkan dulu lewat kode tautan.",
        )),
        SendOutcome::SkippedNoBot => Err(AppError::service_unavailable(
            "Bot Telegram belum dikonfigurasi admin.",
        )),
        SendOutcome::SkippedDuplicate => Ok(Json(TestNotificationResponse {
            sent: false,
            detail: "Pesan tes sudah terkirim.".to_owned(),
        })),
        SendOutcome::SkippedToggleOff => Ok(Json(TestNotificationResponse {
            sent: false,
            detail: "Pesan tes dilewati.".to_owned(),
        })),
        SendOutcome::Failed(error) => Ok(Json(TestNotificationResponse {
            sent: false,
            detail: format!("Pesan tes gagal terkirim: {error}"),
        })),
    }
}

// ---------------------------------------------------------------------------
// Tes unit (murni, tanpa database dan tanpa HTTP nyata)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use std::collections::HashSet;

    fn naive(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, min, 0)
            .unwrap()
    }

    #[test]
    fn link_code_format_and_uniqueness() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let code = generate_link_code();
            assert_eq!(code.len(), LINK_CODE_LEN, "kode: {code}");
            assert!(is_valid_link_code_format(&code), "kode: {code}");
            assert!(seen.insert(code), "kode ganda terbit");
        }
        assert!(!is_valid_link_code_format("pendek"));
        assert!(!is_valid_link_code_format("ABCDEF1234567"));
        assert!(!is_valid_link_code_format("ABCDEF12345-"));
        assert!(!is_valid_link_code_format("ABCDEF12345 "));
    }

    #[test]
    fn link_code_validation_states() {
        let now = naive(2026, 11, 3, 10, 0);
        assert_eq!(
            validate_link_code_row(None, naive(2026, 11, 3, 10, 15), now),
            Ok(())
        );
        assert_eq!(
            validate_link_code_row(Some(now), naive(2026, 11, 3, 10, 15), now),
            Err(LinkCodeError::AlreadyUsed)
        );
        assert_eq!(
            validate_link_code_row(None, naive(2026, 11, 3, 10, 0), now),
            Err(LinkCodeError::Expired)
        );
        assert_eq!(
            validate_link_code_row(None, naive(2026, 11, 3, 9, 59), now),
            Err(LinkCodeError::Expired)
        );
    }

    #[test]
    fn start_and_stop_parsing() {
        assert_eq!(
            parse_start_link("/start ABCDEF123456"),
            Some("ABCDEF123456".to_owned())
        );
        assert_eq!(
            parse_start_link("/start@rajacek_bot ABCDEF123456"),
            Some("ABCDEF123456".to_owned())
        );
        assert_eq!(parse_start_link("/start"), None);
        assert_eq!(parse_start_link("/start a b"), None);
        assert_eq!(parse_start_link("/stats"), None);
        assert_eq!(parse_start_link("halo"), None);
        assert_eq!(parse_start_link("/START ABCDEF123456"), Some("ABCDEF123456".to_owned()));
        assert!(parse_stop("/stop"));
        assert!(parse_stop("/stop@rajacek_bot"));
        assert!(parse_stop("/STOP"));
        assert!(!parse_stop("/stop sekarang"));
        assert!(!parse_stop("/start ABCDEF123456"));
    }

    #[test]
    fn prefs_default_all_off() {
        let prefs = MemberNotificationPrefs::default();
        assert!(!prefs.notify_expiry);
        assert!(!prefs.notify_admin);
        assert!(!prefs.notify_purchase);
        assert!(!prefs.notify_recap);
        assert!(!prefs.toggle_on(PrefToggle::Expiry));
        let on = MemberNotificationPrefs {
            notify_purchase: true,
            ..Default::default()
        };
        assert!(on.toggle_on(PrefToggle::Purchase));
        assert!(!on.toggle_on(PrefToggle::Recap));
    }

    #[test]
    fn toggle_mapping_per_kind() {
        assert_eq!(toggle_for_kind(KIND_PURCHASE_CREATED), Some(PrefToggle::Purchase));
        assert_eq!(toggle_for_kind(KIND_PURCHASE_GRANTED), Some(PrefToggle::Purchase));
        assert_eq!(toggle_for_kind(KIND_PURCHASE_EXPIRED), Some(PrefToggle::Purchase));
        assert_eq!(toggle_for_kind(KIND_PURCHASE_CANCELED), Some(PrefToggle::Purchase));
        assert_eq!(
            toggle_for_kind(KIND_PURCHASE_NEEDS_REVIEW),
            Some(PrefToggle::Purchase)
        );
        assert_eq!(toggle_for_kind(KIND_EXPIRY_3D), Some(PrefToggle::Expiry));
        assert_eq!(toggle_for_kind(KIND_EXPIRY_1D), Some(PrefToggle::Expiry));
        assert_eq!(toggle_for_kind(KIND_RECAP), Some(PrefToggle::Recap));
        assert_eq!(toggle_for_kind(KIND_BROADCAST), Some(PrefToggle::Admin));
        assert_eq!(toggle_for_kind(KIND_TEST), None);
        assert_eq!(toggle_for_kind("tidak_dikenal"), None);
    }

    #[test]
    fn purchase_builders_contain_key_facts_and_no_forbidden_values() {
        let created = purchase_created_message("Scale", 1_499_000, "03-11-2026 15:00 WIB");
        assert!(created.contains("Scale"));
        assert!(created.contains("Rp1.499.000"));
        assert!(created.contains("03-11-2026 15:00 WIB"));
        let granted = purchase_granted_message("Scale", 350_000, "03-12-2026 15:00 WIB");
        assert!(granted.contains("350.000"));
        assert!(granted.contains("03-12-2026 15:00 WIB"));
        let expired = purchase_expired_message("Scale");
        assert!(expired.contains("Kedaluwarsa"));
        let canceled = purchase_canceled_message("Scale");
        assert!(canceled.contains("Dibatalkan"));
        let review = purchase_needs_review_message("Scale", 1_499_000);
        assert!(review.contains("Peninjauan"));
        assert!(review.contains("Rp1.499.000"));
        // Builder tidak pernah menerima kunci/target/provider/URL — dan
        // outputnya tidak boleh mengandung pola-pola itu.
        for text in [&created, &granted, &expired, &canceled, &review] {
            assert!(!text.contains("rc_"), "pesan: {text}");
            assert!(!text.contains("rv_"), "pesan: {text}");
            assert!(!text.contains("http"), "pesan: {text}");
            assert!(!text.contains("tukangcek"), "pesan: {text}");
            assert!(!text.contains("cutiezy"), "pesan: {text}");
        }
    }

    #[test]
    fn builders_escape_markup_in_package_names() {
        let text = purchase_granted_message("<b>Paket</b>", 1000, "03-12-2026 15:00 WIB");
        assert!(text.contains("&lt;b&gt;Paket&lt;/b&gt;"));
        assert!(!text.contains("<b>Paket</b>"));
        let broadcast = admin_broadcast_message("<script>", "isi <b>tebal</b>");
        assert!(broadcast.contains("&lt;script&gt;"));
        assert!(broadcast.contains("isi &lt;b&gt;tebal&lt;/b&gt;"));
    }

    #[test]
    fn expiry_builders_for_both_thresholds() {
        let three = expiry_message(3, "Scale", 12_000, "06-11-2026 10:00 WIB");
        assert!(three.contains("Scale"));
        assert!(three.contains("12.000"));
        assert!(three.contains("06-11-2026 10:00 WIB"));
        assert!(three.contains("3 hari"));
        let one = expiry_message(0, "Scale", 500, "04-11-2026 10:00 WIB");
        assert!(one.contains("kurang dari 1 hari"));
    }

    #[test]
    fn expiry_kind_due_windows_are_disjoint() {
        let now = naive(2026, 11, 3, 10, 0);
        // 2 hari lagi -> hanya 3d.
        assert_eq!(
            expiry_kind_due(naive(2026, 11, 5, 10, 0), now),
            Some(KIND_EXPIRY_3D)
        );
        // 12 jam lagi -> hanya 1d.
        assert_eq!(
            expiry_kind_due(naive(2026, 11, 3, 22, 0), now),
            Some(KIND_EXPIRY_1D)
        );
        // Tepat 1 hari -> 1d (batas inklusif).
        assert_eq!(
            expiry_kind_due(naive(2026, 11, 4, 10, 0), now),
            Some(KIND_EXPIRY_1D)
        );
        // Tepat 3 hari -> 3d.
        assert_eq!(
            expiry_kind_due(naive(2026, 11, 6, 10, 0), now),
            Some(KIND_EXPIRY_3D)
        );
        // 5 hari lagi -> belum jatuh tempo.
        assert_eq!(expiry_kind_due(naive(2026, 11, 8, 10, 0), now), None);
        // Sudah lewat -> tidak ada.
        assert_eq!(expiry_kind_due(naive(2026, 11, 3, 9, 0), now), None);
    }

    #[test]
    fn recap_builder_and_gating() {
        let data = RecapData {
            hits_24h: 120,
            remaining_total: 50_000,
            nearest: Some(("Scale".to_owned(), "06-11-2026 10:00 WIB".to_owned())),
            orders_24h: 1,
            latest_order: Some(("Scale".to_owned(), "Lunas".to_owned(), 1_499_000)),
        };
        let text = recap_message(&data, "2026-11-03");
        assert!(text.contains("120"));
        assert!(text.contains("50.000"));
        assert!(text.contains("Scale"));
        assert!(text.contains("Rp1.499.000"));
        assert!(text.contains("2026-11-03"));
        let empty = RecapData {
            hits_24h: 0,
            remaining_total: 50_000,
            nearest: None,
            orders_24h: 0,
            latest_order: None,
        };
        let empty_text = recap_message(&empty, "2026-11-03");
        assert!(empty_text.contains("Tidak ada paket yang segera kedaluwarsa"));
        assert!(!should_send_recap(0, 0));
        assert!(should_send_recap(1, 0));
        assert!(should_send_recap(0, 1));
        assert!(should_send_recap(5, 2));
    }

    #[test]
    fn recap_window_boundaries() {
        assert!(!recap_window_open(7 * 60 - 1));
        assert!(recap_window_open(7 * 60));
        assert!(recap_window_open(7 * 60 + 29));
        assert!(!recap_window_open(7 * 60 + 30));
        assert!(!recap_window_open(12 * 60));
    }

    #[test]
    fn broadcast_recipient_selection() {
        assert!(broadcast_recipient(true, true));
        assert!(!broadcast_recipient(true, false));
        assert!(!broadcast_recipient(false, true));
        assert!(!broadcast_recipient(false, false));
    }

    #[test]
    fn duplicate_detection_only_blocks_sent() {
        let rows = vec![
            ("recap".to_owned(), "m1:2026-11-03".to_owned(), "sent".to_owned()),
            ("recap".to_owned(), "m2:2026-11-03".to_owned(), "failed".to_owned()),
        ];
        assert!(is_duplicate_sent(&rows, "recap", "m1:2026-11-03"));
        // Gagal bukan duplikat: boleh dicoba lagi.
        assert!(!is_duplicate_sent(&rows, "recap", "m2:2026-11-03"));
        assert!(!is_duplicate_sent(&rows, "recap", "m3:2026-11-03"));
        assert!(!is_duplicate_sent(&rows, "expiry_1d", "m1:2026-11-03"));
    }

    #[test]
    fn order_status_labels_indonesian() {
        assert_eq!(order_status_label("waiting_payment"), "Menunggu pembayaran");
        assert_eq!(order_status_label("granted"), "Lunas");
        assert_eq!(order_status_label("expired"), "Kedaluwarsa");
        assert_eq!(order_status_label("canceled"), "Dibatalkan");
        assert_eq!(order_status_label("needs_review"), "Perlu peninjauan");
    }

    #[test]
    fn wib_formatting() {
        // 2026-11-03 00:00 UTC = 07:00 WIB.
        assert_eq!(
            wib_datetime_string(naive(2026, 11, 3, 0, 0)),
            "03-11-2026 07:00 WIB"
        );
        let utc = DateTime::from_timestamp(1_792_800_000, 0).unwrap();
        assert_eq!(wib_date_label(utc), "2026-10-24");
    }

    #[test]
    fn admin_chat_exemption_rule() {
        assert!(is_admin_chat(12345, Some(12345)));
        assert!(!is_admin_chat(12345, Some(99999)));
        assert!(!is_admin_chat(12345, None));
    }

    #[test]
    fn system_messages_have_no_forbidden_values() {
        for text in [
            link_confirmed_message(),
            link_rejected_message(),
            link_conflict_message(),
            unlink_confirmed_message(),
            test_message(),
        ] {
            assert!(!text.contains("rc_"));
            assert!(!text.contains("rv_"));
            assert!(!text.contains("http"));
        }
    }
}

// ---------------------------------------------------------------------------
// Pembungkus job untuk worker (worker hanya memegang string kunci,
// bukan cipher — pola yang sama dengan job kedaluwarsa admin).
// ---------------------------------------------------------------------------

/// Tick sisa masa aktif member dengan kunci mentah (worker).
pub async fn run_member_expiry_job_with_key(
    pool: &MySqlPool,
    encryption_key: Option<&str>,
    now: DateTime<Utc>,
) -> Result<ExpiryRun, AppError> {
    let cipher = CredentialCipher::new(encryption_key);
    run_member_expiry_job(pool, Some(&cipher), now).await
}

/// Tick rekapan dengan kunci mentah (worker).
pub async fn run_member_recap_job_with_key(
    pool: &MySqlPool,
    encryption_key: Option<&str>,
    now: DateTime<Utc>,
) -> Result<RecapRun, AppError> {
    let cipher = CredentialCipher::new(encryption_key);
    run_member_recap_job(pool, Some(&cipher), now).await
}

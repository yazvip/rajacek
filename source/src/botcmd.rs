//! Perintah bot Telegram interaktif (read-only, admin saja) — 28 Okt 2026.
//!
//! Arsitektur: webhook, bukan polling. Telegram memanggil
//! `POST /v1/telegram/webhook` (handler di api.rs); modul ini hanya berisi
//! parsing perintah, query baca, dan format balasan premium (header yang
//! sama dengan notifikasi: 👑 RAJACEK + pemisah + judul berikon tebal,
//! parse_mode HTML, semua nilai di-escape).
//!
//! Batasan keamanan yang dijaga di sini dan di handler:
//! - Verifikasi `X-Telegram-Bot-Api-Secret-Token` (lihat
//!   `verify_webhook_secret`) — secret salah/tanpa secret → 403.
//! - Allowlist chat: hanya chat ID admin yang terkonfigurasi di setting
//!   panel yang dilayani; chat lain diabaikan diam-diam (200, tanpa balasan).
//! - TIDAK ADA aksi tulis lewat bot di ronde ini: semua perintah read-only.
//! - Yang dikirim ke Telegram TIDAK PERNAH memuat: target mentah (hanya
//!   target_masked dari DB), nama pemilik rekening, kunci, token, atau
//!   alamat IP. Sumber data memakai nama tampilan yang sama dengan panel
//!   admin ("Sumber data: TukangCek") — itu data admin, bukan member.

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::Deserialize;
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::error::AppError;
use crate::store::{aggregate_trial_monitor, effective_plan_kind, AdminStore};
use crate::telegram_settings::{
    admin_message_text, escape_html, format_wib_datetime, format_wib_naive,
};

/// Payload update Telegram minimal yang dipakai handler. Field lain
/// diabaikan (serde default) — hanya pesan teks dari satu chat yang
/// diproses; edited/callback/group message tanpa teks lolos sebagai None.
#[derive(Debug, Deserialize)]
pub struct TelegramUpdate {
    pub message: Option<TelegramMessage>,
}

#[derive(Debug, Deserialize)]
pub struct TelegramMessage {
    pub chat: TelegramChat,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TelegramChat {
    pub id: i64,
}

/// Perintah bot yang dikenali. Argumen None = perintah dipanggil tanpa
/// argumen (handler membalas petunjuk format, bukan error).
#[derive(Debug, PartialEq, Eq)]
pub enum BotCommand {
    Start,
    Help,
    Stats,
    Saldo(Option<String>),
    Riwayat(Option<String>),
    Trial,
    Unknown(String),
}

/// Parse teks pesan menjadi perintah. Mengembalikan None untuk pesan
/// non-perintah (harus diabaikan diam-diam, tanpa balasan).
///
/// - Nama perintah dipotong di spasi pertama; sufiks `@namabot` diabaikan
///   (Telegram mengirim `/stats@rajacek_bot` di grup).
/// - Perintah dikenali case-insensitive (`/STATS` = `/stats`); argumen
///   dipertahankan apa adanya (kode member dan request id case-sensitive).
pub fn parse_command(text: &str) -> Option<BotCommand> {
    let trimmed = text.trim();
    let body = trimmed.strip_prefix('/')?;
    let (raw_name, rest) = match body.find(char::is_whitespace) {
        Some(idx) => (&body[..idx], body[idx..].trim()),
        None => (body, ""),
    };
    let name = raw_name.split('@').next().unwrap_or("").to_ascii_lowercase();
    let arg = if rest.is_empty() {
        None
    } else {
        Some(rest.split_whitespace().next().unwrap_or("").to_owned())
    };
    Some(match name.as_str() {
        "start" => BotCommand::Start,
        "help" => BotCommand::Help,
        "stats" => BotCommand::Stats,
        "saldo" => BotCommand::Saldo(arg),
        "riwayat" => BotCommand::Riwayat(arg),
        "trial" => BotCommand::Trial,
        _ => BotCommand::Unknown(name),
    })
}

/// Verifikasi secret webhook. Keduanya wajib ada dan sama persis;
/// perbandingan diakumulasi tanpa early-exit supaya tidak bocor lewat
/// timing (secret bukan rahasia tingkat tinggi, tapi murah dilakukan).
pub fn verify_webhook_secret(provided: Option<&str>, expected: Option<&str>) -> bool {
    let (Some(provided), Some(expected)) = (provided, expected) else {
        return false;
    };
    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    if provided.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Nama perintah untuk log (tanpa argumen — argumen tidak di-log).
pub fn command_name(command: &BotCommand) -> &'static str {
    match command {
        BotCommand::Start => "start",
        BotCommand::Help => "help",
        BotCommand::Stats => "stats",
        BotCommand::Saldo(_) => "saldo",
        BotCommand::Riwayat(_) => "riwayat",
        BotCommand::Trial => "trial",
        BotCommand::Unknown(_) => "unknown",
    }
}

/// Format kode member valid: `RC` + 6 digit (RC000001). Di luar itu
/// handler membalas "format kode tidak valid" tanpa bocoran apa pun.
pub fn valid_member_code(code: &str) -> bool {
    code.len() == 8
        && code.starts_with("RC")
        && code[3..].chars().all(|c| c.is_ascii_digit())
}

/// Format request id valid: 10 karakter alfanumerik (lihat generator
/// request id di kode). Di luar itu → balasan format tidak valid.
pub fn valid_request_id(request_id: &str) -> bool {
    request_id.len() == 10
        && request_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric())
}

fn detail_row(icon: &str, label: &str, value: &str) -> String {
    format!("{icon} {label}: {value}")
}

/// Daftar perintah (dipakai /start, /help, dan perintah tak dikenal).
pub fn help_message() -> String {
    let detail = [
        detail_row("📊", "Stats", "/stats — ringkasan hari ini (WIB)"),
        detail_row("💳", "Saldo", "/saldo RC000001 — sisa kuota member"),
        detail_row("📜", "Riwayat", "/riwayat [request id] — detail satu validasi"),
        detail_row("🎁", "Trial", "/trial — ringkasan monitor trial"),
    ]
    .join("\n");
    admin_message_text("🤖", "Perintah Bot Rajacek", &detail)
}

// ---------------------------------------------------------------------------
// /stats — ringkasan hari ini (WIB)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct TodayStats {
    pub validations: u64,
    pub orders_granted: u64,
    pub revenue_idr: u64,
    pub new_members: u64,
    pub trial_grants: u64,
}

/// Awal hari WIB dalam UTC: tanggal WIB hari ini pukul 00:00 WIB.
/// Semua kolom waktu tersimpan UTC, jadi agregat memakai batas ini
/// (bukan NOW() MySQL — jam VPS UTC+8, bukan UTC+7).
fn wib_day_start_utc(now: DateTime<Utc>) -> NaiveDateTime {
    let wib_now = now + Duration::hours(7);
    let date = wib_now.date_naive();
    date.and_hms_opt(0, 0, 0)
        .unwrap_or_else(|| date.and_hms_opt(0, 0, 1).unwrap())
        .checked_sub_signed(Duration::hours(7))
        .unwrap_or(date.and_hms_opt(0, 0, 0).unwrap())
}

pub async fn today_stats(pool: &MySqlPool) -> Result<TodayStats, AppError> {
    let start = wib_day_start_utc(Utc::now());
    let validations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM validation_requests WHERE occurred_at >= ?",
    )
    .bind(start)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Query database gagal"))?;
    let (orders_granted, revenue_idr): (i64, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(CAST(SUM(amount_idr) AS SIGNED), 0) FROM package_orders \
         WHERE status = 'granted' AND granted_at >= ?",
    )
    .bind(start)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Query database gagal"))?;
    let new_members: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM members WHERE created_at >= ?",
    )
    .bind(start)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Query database gagal"))?;
    let trial_grants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM trial_grants WHERE granted_at >= ?",
    )
    .bind(start)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Query database gagal"))?;
    Ok(TodayStats {
        validations: validations.max(0) as u64,
        orders_granted: orders_granted.max(0) as u64,
        revenue_idr: revenue_idr.unwrap_or(0).max(0) as u64,
        new_members: new_members.max(0) as u64,
        trial_grants: trial_grants.max(0) as u64,
    })
}

pub fn stats_message(stats: &TodayStats, date_label: &str) -> String {
    let detail = [
        detail_row("📅", "Tanggal", date_label),
        detail_row("✅", "Total validasi", &stats.validations.to_string()),
        detail_row(
            "🛍️",
            "Paket terjual",
            &format!("{} paket", stats.orders_granted),
        ),
        detail_row(
            "💰",
            "Omzet",
            &format!("Rp {}", crate::telegram_settings::format_idr(stats.revenue_idr)),
        ),
        detail_row("🆕", "Member baru", &stats.new_members.to_string()),
        detail_row("🎁", "Trial grant", &stats.trial_grants.to_string()),
    ]
    .join("\n");
    admin_message_text("📊", "Statistik Hari Ini", &detail)
}

// ---------------------------------------------------------------------------
// /saldo — sisa kuota member berdasarkan kode
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SaldoInfo {
    pub code: String,
    pub plan_effective: String,
    pub status: String,
    pub remaining: u64,
    pub total: u64,
    pub expiry: Option<DateTime<Utc>>,
}

pub async fn member_saldo(
    pool: &MySqlPool,
    store: &AdminStore,
    code: &str,
) -> Result<Option<SaldoInfo>, AppError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, plan_kind, status FROM members WHERE member_code = ?",
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Query database gagal"))?;
    let Some((id, plan_kind, status)) = row else {
        return Ok(None);
    };
    let member_id = Uuid::parse_str(&id).map_err(|_| AppError::internal("ID member tidak valid"))?;
    let (remaining, total, expiry) = match store.member_key(member_id).await {
        Some((summary, remaining)) => (remaining, summary.quota_total, summary.expires_at),
        None => (0, 0, None),
    };
    let trial_map = store.trial_expiry_by_member().await;
    let plan_effective = effective_plan_kind(&plan_kind, trial_map.get(&member_id).copied(), Utc::now());
    Ok(Some(SaldoInfo {
        code: code.to_owned(),
        plan_effective,
        status,
        remaining,
        total,
        expiry,
    }))
}

fn plan_label(plan_effective: &str) -> &str {
    match plan_effective {
        "trial" => "Trial",
        "package" => "Paket",
        "manual" => "Manual",
        "umum" => "Umum",
        other => other,
    }
}

pub fn saldo_message(info: &SaldoInfo) -> String {
    let expiry = match info.expiry {
        Some(moment) => format_wib_datetime(moment),
        None => "Tidak pernah kedaluwarsa".to_owned(),
    };
    let detail = [
        detail_row("🆔", "Kode member", &escape_html(&info.code)),
        detail_row("⚡", "Sisa kuota", &format!("{} hit", info.remaining)),
        detail_row("📦", "Total kuota", &format!("{} hit", info.total)),
        detail_row("📅", "Masa aktif", &expiry),
        detail_row("🏷️", "Plan", &escape_html(plan_label(&info.plan_effective))),
        detail_row(
            "📌",
            "Status",
            if info.status == "active" { "Aktif" } else { "Nonaktif" },
        ),
    ]
    .join("\n");
    admin_message_text("💳", "Saldo Member", &detail)
}

pub fn saldo_not_found_message(code: &str) -> String {
    admin_message_text(
        "❓",
        "Member Tidak Ditemukan",
        &detail_row("🆔", "Kode", &escape_html(code)),
    )
}

pub fn saldo_format_message() -> String {
    admin_message_text(
        "⚠️",
        "Format Kode Tidak Valid",
        &detail_row("ℹ️", "Format", "Gunakan /saldo RC000001 (RC + 6 digit)"),
    )
}

// ---------------------------------------------------------------------------
// /riwayat — detail satu validasi (target TERSAMAR saja)
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub struct RiwayatInfo {
    pub request_id: String,
    pub occurred_at: NaiveDateTime,
    pub member_code: Option<String>,
    pub product_code: String,
    pub target_masked: String,
    pub outcome: String,
    pub endpoint_name: Option<String>,
}

pub async fn riwayat_detail(
    pool: &MySqlPool,
    request_id: &str,
) -> Result<Option<RiwayatInfo>, AppError> {
    let row: Option<RiwayatInfo> = sqlx::query_as(
        "SELECT vr.request_id, vr.occurred_at AS occurred_at, m.member_code, vr.product_code, \
         vr.target_masked, vr.outcome, te.name AS endpoint_name \
         FROM validation_requests vr \
         LEFT JOIN admin_api_keys k ON k.prefix = vr.api_key_prefix \
         LEFT JOIN members m ON m.id = k.member_id \
         LEFT JOIN third_party_endpoints te ON te.id = vr.provider_endpoint_id \
         WHERE vr.request_id = ?",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Query database gagal"))?;
    Ok(row)
}

fn product_label(product_code: &str) -> &str {
    match product_code {
        "bank_account" => "Rekening",
        "ewallet" => "E-Wallet",
        "whatsapp" => "WhatsApp",
        "pln" => "PLN",
        other => other,
    }
}

fn outcome_label(outcome: &str) -> &str {
    match outcome {
        "valid" => "Valid",
        "invalid" => "Invalid",
        "not_found" => "Tidak ditemukan",
        "not_kyc" => "Belum KYC",
        "pending" => "Pending",
        "provider_error" => "Error provider",
        "rate_limited" => "Rate limited",
        "quota_exhausted" => "Kuota habis",
        other => other,
    }
}

pub fn riwayat_message(info: &RiwayatInfo) -> String {
    let endpoint = info
        .endpoint_name
        .as_deref()
        .unwrap_or("tidak tercatat (data lama)");
    let member = info.member_code.as_deref().unwrap_or("—");
    let detail = [
        detail_row("🕐", "Waktu", &format_wib_naive(info.occurred_at)),
        // Nilai dari DB di-escape semua: kode member, label produk/hasil
        // (passthrough `other`), dan nama endpoint (input admin) bisa
        // saja mengandung karakter HTML.
        detail_row("🆔", "Kode member", &escape_html(member)),
        detail_row("📦", "Produk", &escape_html(product_label(&info.product_code))),
        // target_masked dari DB — TIDAK PERNAH target mentah.
        detail_row("🎯", "Target", &escape_html(&info.target_masked)),
        detail_row("✅", "Hasil", &escape_html(outcome_label(&info.outcome))),
        detail_row("🔌", "Sumber data", &escape_html(endpoint)),
    ]
    .join("\n");
    admin_message_text("📜", "Detail Validasi", &detail)
}

pub fn riwayat_not_found_message(request_id: &str) -> String {
    admin_message_text(
        "❓",
        "Validasi Tidak Ditemukan",
        &detail_row("🧾", "Request ID", &escape_html(request_id)),
    )
}

pub fn riwayat_format_message() -> String {
    admin_message_text(
        "⚠️",
        "Format Request ID Tidak Valid",
        &detail_row(
            "ℹ️",
            "Format",
            "Gunakan /riwayat [request id 10 karakter], mis. /riwayat pHZl49uxzV",
        ),
    )
}

// ---------------------------------------------------------------------------
// /trial — ringkasan monitor trial (TANPA alamat IP)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct TrialSummary {
    pub grants_24h: u64,
    pub grants_7d: u64,
    pub total_grants: u64,
    pub held_7d: u64,
    pub ips_at_limit_24h: u64,
    pub alert: bool,
}

pub async fn trial_summary(
    pool: &MySqlPool,
    store: &AdminStore,
) -> Result<TrialSummary, AppError> {
    let rows = store.trial_monitor_rows().await;
    let total = store.trial_grants_total().await;
    let stats = aggregate_trial_monitor(&rows, total, Utc::now());
    let week_ago = (Utc::now() - Duration::days(7)).naive_utc();
    let held_7d: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM members m WHERE NOT EXISTS \
         (SELECT 1 FROM trial_grants g WHERE g.member_id = m.id) \
         AND m.created_at >= ?",
    )
    .bind(week_ago)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Query database gagal"))?;
    Ok(TrialSummary {
        grants_24h: stats.grants_24h,
        grants_7d: stats.grants_7d,
        total_grants: stats.total_grants,
        held_7d: held_7d.max(0) as u64,
        ips_at_limit_24h: stats.ips_at_limit_24h,
        alert: stats.alert,
    })
}

pub fn trial_message(summary: &TrialSummary) -> String {
    let detail = [
        detail_row("🕐", "Grant 24 jam", &summary.grants_24h.to_string()),
        detail_row("📅", "Grant 7 hari", &summary.grants_7d.to_string()),
        detail_row("📦", "Total grant", &summary.total_grants.to_string()),
        detail_row(
            "⏸️",
            "Trial ditahan (7 hari)",
            &summary.held_7d.to_string(),
        ),
        detail_row(
            "🚨",
            "IP mencapai batas (24 jam)",
            &summary.ips_at_limit_24h.to_string(),
        ),
        detail_row(
            "🔔",
            "Status alert",
            if summary.alert { "AKTIF" } else { "Normal" },
        ),
    ]
    .join("\n");
    admin_message_text("🎁", "Monitor Trial", &detail)
}

/// Pesan kesalahan generik — tanpa detail internal (jalur bot tidak
/// boleh membocorkan error DB/API ke Telegram).
pub fn error_message() -> String {
    admin_message_text(
        "⚠️",
        "Terjadi Kesalahan",
        "Tidak dapat memproses perintah saat ini. Coba lagi sebentar.",
    )
}

/// Jalankan satu perintah dan kembalikan teks balasan HTML lengkap.
/// TIDAK PERNAH mengembalikan Err ke pemanggil webhook: kegagalan query
/// menjadi pesan kesalahan generik (webhook tetap 200 supaya Telegram
/// tidak menumpuk retry atas kesalahan sementara).
pub async fn execute_command(
    pool: &MySqlPool,
    store: &AdminStore,
    command: &BotCommand,
) -> String {
    match command {
        BotCommand::Start | BotCommand::Help => help_message(),
        BotCommand::Stats => match today_stats(pool).await {
            Ok(stats) => {
                let date_label = (Utc::now() + Duration::hours(7)).format("%d %B %Y").to_string();
                stats_message(&stats, &date_label)
            }
            Err(error) => {
                // Kegagalan query tidak lagi bisu: catat WARN dengan
                // pesan error generik saja (tanpa argumen perintah).
                tracing::warn!(command = "stats", error = %error, "Perintah bot gagal");
                error_message()
            }
        },
        BotCommand::Saldo(code) => match code {
            None => saldo_format_message(),
            Some(code) if !valid_member_code(code) => saldo_format_message(),
            Some(code) => match member_saldo(pool, store, code).await {
                Ok(Some(info)) => saldo_message(&info),
                Ok(None) => saldo_not_found_message(code),
                Err(error) => {
                    tracing::warn!(command = "saldo", error = %error, "Perintah bot gagal");
                    error_message()
                }
            },
        },
        BotCommand::Riwayat(request_id) => match request_id {
            None => riwayat_format_message(),
            Some(request_id) if !valid_request_id(request_id) => riwayat_format_message(),
            Some(request_id) => match riwayat_detail(pool, request_id).await {
                Ok(Some(info)) => riwayat_message(&info),
                Ok(None) => riwayat_not_found_message(request_id),
                Err(error) => {
                    tracing::warn!(command = "riwayat", error = %error, "Perintah bot gagal");
                    error_message()
                }
            },
        },
        BotCommand::Trial => match trial_summary(pool, store).await {
            Ok(summary) => trial_message(&summary),
            Err(error) => {
                tracing::warn!(command = "trial", error = %error, "Perintah bot gagal");
                error_message()
            }
        },
        BotCommand::Unknown(_) => help_message(),
    }
}

/// Label tanggal WIB hari ini (dipakai judul balasan /stats di handler
/// bila diperlukan secara terpisah).
pub fn today_wib_date_label() -> String {
    (Utc::now() + Duration::hours(7))
        .format("%d %B %Y")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parse_command_recognizes_all_commands() {
        assert_eq!(parse_command("/start"), Some(BotCommand::Start));
        assert_eq!(parse_command("/help"), Some(BotCommand::Help));
        assert_eq!(parse_command("/stats"), Some(BotCommand::Stats));
        assert_eq!(parse_command("/trial"), Some(BotCommand::Trial));
        assert_eq!(
            parse_command("/saldo RC000001"),
            Some(BotCommand::Saldo(Some("RC000001".to_owned())))
        );
        assert_eq!(
            parse_command("/riwayat pHZl49uxzV"),
            Some(BotCommand::Riwayat(Some("pHZl49uxzV".to_owned())))
        );
    }

    #[test]
    fn parse_command_ignores_non_commands_and_bot_suffix() {
        assert_eq!(parse_command("halo"), None);
        assert_eq!(parse_command(""), None);
        assert_eq!(parse_command("  /stats"), Some(BotCommand::Stats));
        assert_eq!(
            parse_command("/stats@rajacek_bot"),
            Some(BotCommand::Stats)
        );
        assert_eq!(
            parse_command("/SALDO RC000001"),
            Some(BotCommand::Saldo(Some("RC000001".to_owned())))
        );
    }

    #[test]
    fn parse_command_unknown_and_missing_arg() {
        assert_eq!(
            parse_command("/foo"),
            Some(BotCommand::Unknown("foo".to_owned()))
        );
        assert_eq!(parse_command("/saldo"), Some(BotCommand::Saldo(None)));
        assert_eq!(parse_command("/riwayat"), Some(BotCommand::Riwayat(None)));
    }

    #[test]
    fn verify_webhook_secret_requires_both_and_exact_match() {
        assert!(verify_webhook_secret(Some("abc"), Some("abc")));
        assert!(!verify_webhook_secret(None, Some("abc")));
        assert!(!verify_webhook_secret(Some("abc"), None));
        assert!(!verify_webhook_secret(None, None));
        assert!(!verify_webhook_secret(Some("abc"), Some("abd")));
        assert!(!verify_webhook_secret(Some("abc"), Some("abcd")));
    }

    #[test]
    fn valid_member_code_and_request_id_formats() {
        assert!(valid_member_code("RC000001"));
        assert!(!valid_member_code("RC1"));
        assert!(!valid_member_code("rc000001"));
        assert!(!valid_member_code("RC0000012"));
        assert!(!valid_member_code("RC00000A"));
        assert!(valid_request_id("pHZl49uxzV"));
        assert!(!valid_request_id("short"));
        assert!(!valid_request_id("pHZl49uxzV!"));
        assert!(!valid_request_id("pHZl49uxzV1"));
    }

    #[test]
    fn help_message_lists_all_commands() {
        let text = help_message();
        for cmd in ["/stats", "/saldo", "/riwayat", "/trial"] {
            assert!(text.contains(cmd), "help hilang {cmd}");
        }
        assert!(text.contains("RAJACEK"));
    }

    /// Pesan bot dikirim dengan parse_mode HTML: satu `<` mentah di luar
    /// tag <b> yang disengaja membuat Telegram menolak pesan (400).
    /// Regresi bug /start 28 Okt 2026 (`<request id>` mentah di help).
    fn assert_no_raw_angle_brackets(text: &str) {
        let stripped = text.replace("<b>", "").replace("</b>", "");
        assert!(
            !stripped.contains('<') && !stripped.contains('>'),
            "karakter sudut mentah tersisa: {text}"
        );
    }

    #[test]
    fn bot_messages_have_no_raw_angle_brackets() {
        assert_no_raw_angle_brackets(&help_message());
        assert_no_raw_angle_brackets(&riwayat_format_message());
        assert_no_raw_angle_brackets(&saldo_format_message());
        assert_no_raw_angle_brackets(&error_message());
        assert_no_raw_angle_brackets(&saldo_not_found_message("RC000001"));
        assert_no_raw_angle_brackets(&riwayat_not_found_message("pHZl49uxzV"));
        assert_no_raw_angle_brackets(&stats_message(
            &TodayStats {
                validations: 1,
                orders_granted: 0,
                revenue_idr: 0,
                new_members: 0,
                trial_grants: 0,
            },
            "28 Oktober 2026",
        ));
        assert_no_raw_angle_brackets(&saldo_message(&SaldoInfo {
            code: "RC000001".to_owned(),
            plan_effective: "trial".to_owned(),
            status: "active".to_owned(),
            remaining: 1,
            total: 2,
            expiry: None,
        }));
        assert_no_raw_angle_brackets(&riwayat_message(&RiwayatInfo {
            request_id: "pHZl49uxzV".to_owned(),
            occurred_at: NaiveDateTime::parse_from_str("2026-10-28 10:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
            member_code: Some("RC000001".to_owned()),
            product_code: "bank_account".to_owned(),
            target_masked: "****1234".to_owned(),
            outcome: "valid".to_owned(),
            endpoint_name: Some("TukangCek".to_owned()),
        }));
        assert_no_raw_angle_brackets(&trial_message(&TrialSummary {
            grants_24h: 0,
            grants_7d: 0,
            total_grants: 0,
            held_7d: 0,
            ips_at_limit_24h: 0,
            alert: false,
        }));
        assert!(!help_message().contains("<request id>"));
        assert!(!riwayat_format_message().contains("<request id"));
    }

    #[test]
    fn bot_messages_escape_hostile_db_values() {
        // Nilai dari DB (nama endpoint input admin, plan tersimpan,
        // target tersamar) tidak boleh lolos mentah ke parse HTML.
        let text = riwayat_message(&RiwayatInfo {
            request_id: "pHZl49uxzV".to_owned(),
            occurred_at: NaiveDateTime::parse_from_str("2026-10-28 10:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
            member_code: Some("RC000001".to_owned()),
            product_code: "bank_account".to_owned(),
            target_masked: "****<tag>".to_owned(),
            outcome: "valid".to_owned(),
            endpoint_name: Some("A<&>B".to_owned()),
        });
        assert!(!text.contains("****<tag>"));
        assert!(text.contains("****&lt;tag&gt;"));
        assert!(!text.contains("A<&>B"));
        assert!(text.contains("A&lt;&amp;&gt;B"));
        let saldo = saldo_message(&SaldoInfo {
            code: "RC000001".to_owned(),
            plan_effective: "<tag>".to_owned(),
            status: "active".to_owned(),
            remaining: 1,
            total: 2,
            expiry: None,
        });
        assert!(!saldo.contains("Plan: <tag>"));
        assert!(saldo.contains("&lt;tag&gt;"));
    }

    #[test]
    fn stats_message_shows_figures_and_date() {
        let stats = TodayStats {
            validations: 42,
            orders_granted: 3,
            revenue_idr: 150000,
            new_members: 2,
            trial_grants: 1,
        };
        let text = stats_message(&stats, "28 Oktober 2026");
        assert!(text.contains("42"));
        assert!(text.contains("3 paket"));
        assert!(text.contains("150.000"));
        assert!(text.contains("28 Oktober 2026"));
    }

    #[test]
    fn saldo_message_shows_remaining_and_expiry() {
        let info = SaldoInfo {
            code: "RC000001".to_owned(),
            plan_effective: "trial".to_owned(),
            status: "active".to_owned(),
            remaining: 999,
            total: 1000,
            expiry: Some(Utc.with_ymd_and_hms(2026, 11, 4, 10, 0, 0).unwrap()),
        };
        let text = saldo_message(&info);
        assert!(text.contains("RC000001"));
        assert!(text.contains("999 hit"));
        assert!(text.contains("Trial"));
        assert!(text.contains("Aktif"));
    }

    #[test]
    fn riwayat_message_uses_masked_target_only() {
        let info = RiwayatInfo {
            request_id: "pHZl49uxzV".to_owned(),
            occurred_at: NaiveDateTime::parse_from_str("2026-10-28 10:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap(),
            member_code: Some("RC000001".to_owned()),
            product_code: "bank_account".to_owned(),
            target_masked: "****1234".to_owned(),
            outcome: "valid".to_owned(),
            endpoint_name: Some("TukangCek".to_owned()),
        };
        let text = riwayat_message(&info);
        assert!(text.contains("****1234"));
        assert!(text.contains("TukangCek"));
        assert!(text.contains("Valid"));
        assert!(!text.contains("target_raw"));
    }

    #[test]
    fn trial_message_has_no_ip_content() {
        let summary = TrialSummary {
            grants_24h: 5,
            grants_7d: 12,
            total_grants: 30,
            held_7d: 2,
            ips_at_limit_24h: 1,
            alert: false,
        };
        let text = trial_message(&summary);
        assert!(text.contains("Grant 24 jam: 5"));
        assert!(text.contains("Normal"));
        assert!(!text.to_ascii_lowercase().contains("192.168"));
    }

    #[test]
    fn wib_day_start_is_midnight_wib_in_utc() {
        // 28 Okt 2026 09:00 WIB = 02:00 UTC → awal hari = 27 Okt 17:00 UTC.
        let now = Utc.with_ymd_and_hms(2026, 10, 28, 2, 0, 0).unwrap();
        let start = wib_day_start_utc(now);
        assert_eq!(
            start.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-10-27 17:00:00"
        );
    }
}

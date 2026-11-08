//! Layanan cek ID game via Cutiezy (migrasi 0042).
//!
//! Satu provider (Cutiezy), 17 service GET
//! `https://api.cutiezy.id/api/check/games/{service}` dengan API key di
//! header `X-API-Key` (tidak pernah di URL/log). Respons Cutiezy:
//! `{ "ok": true, "data": { "nickname": ... } }` atau
//! `{ "ok": false, "message": ... }`. Hanya respons `region-ml` yang
//! contohnya resmi; field game lain dipetakan defensif (hanya nickname
//! + zone/country/server bila ada) dan wajib diverifikasi per game
//! sebelum game diaktifkan admin.
//!
//! Billing TIDAK memakai kuota validasi: game memotong hit game dari
//! bucket yang sama (kolom game_*), pool gratisnya pun terpisah
//! (`game_invalid_free_daily`). Modul ini hanya dispatch + mapping;
//! keputusan tagih/refund ada di `execute_validation` (api.rs).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde::Deserialize;
use sqlx::MySqlPool;

use crate::error::AppError;
use crate::models::ValidationStatus;
use crate::provider_config::CredentialCipher;

pub const GAMES_BASE_URL: &str = "https://api.cutiezy.id";
pub const GAMES_HOST: &str = "api.cutiezy.id";
/// ID endpoint sintetis untuk circuit breaker + pacer guard (satu
/// server logis untuk semua game, sama seperti satu endpoint provider).
pub const GAMES_ENDPOINT_ID: &str = "cutiezy-games";
/// Timeout per upaya (dokumen menyarankan 10 detik untuk kasus invalid
/// yang lambat).
pub const GAMES_TIMEOUT: Duration = Duration::from_millis(10_000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameParamKind {
    /// User ID angka (3–30 digit).
    UserId,
    /// Riot ID teks (3–50 karakter, `#` harus di-encode — reqwest
    /// `.query()` melakukannya).
    RiotId,
    /// Username teks (3–30 karakter), parameternya `username`.
    Username,
}

#[derive(Clone, Debug)]
pub struct GameService {
    pub code: &'static str,
    pub service: &'static str,
    pub name: &'static str,
    pub needs_zone: bool,
    pub param_kind: GameParamKind,
}

/// Katalog 17 service (dokumen Cutiezy 2026-11-08). Urutan = urutan
/// dokumen; `code` dipakai sebagai `code` v3 (1:1 dengan service).
pub const GAME_SERVICES: &[GameService] = &[
    GameService { code: "region-ml", service: "region-ml", name: "Mobile Legends — Region", needs_zone: true, param_kind: GameParamKind::UserId },
    GameService { code: "mlbb-bundle", service: "mlbb-bundle", name: "Mobile Legends — Bundle", needs_zone: true, param_kind: GameParamKind::UserId },
    GameService { code: "mlcreate", service: "mlcreate", name: "Mobile Legends — Umur Akun", needs_zone: true, param_kind: GameParamKind::UserId },
    GameService { code: "first-topup", service: "first-topup", name: "Mobile Legends — First Top Up", needs_zone: true, param_kind: GameParamKind::UserId },
    GameService { code: "first-mcgg", service: "first-mcgg", name: "Magic Chess — First Top Up", needs_zone: true, param_kind: GameParamKind::UserId },
    GameService { code: "mcgg", service: "mcgg", name: "Magic Chess Go Go", needs_zone: true, param_kind: GameParamKind::UserId },
    GameService { code: "undawn", service: "undawn", name: "Garena Undawn", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "free-fire", service: "free-fire", name: "Free Fire", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "pubg", service: "pubg", name: "PUBG Mobile", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "codm", service: "codm", name: "Call of Duty Mobile", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "zenless", service: "zenless", name: "Zenless Zone Zero", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "hok", service: "hok", name: "Honor of Kings", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "blood-strike", service: "blood-strike", name: "Blood Strike", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "valorant", service: "valorant", name: "Valorant", needs_zone: false, param_kind: GameParamKind::RiotId },
    GameService { code: "genshin", service: "genshin", name: "Genshin Impact", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "hsr", service: "hsr", name: "Honkai Star Rail", needs_zone: false, param_kind: GameParamKind::UserId },
    GameService { code: "roblox", service: "roblox", name: "Roblox", needs_zone: false, param_kind: GameParamKind::Username },
];

/// Pencarian case-insensitive (konsisten dengan slug e-wallet).
pub fn find_game_service(code: &str) -> Option<&'static GameService> {
    let normalized = code.trim().to_ascii_lowercase();
    GAME_SERVICES.iter().find(|service| service.code == normalized)
}

/// Validasi parameter SEBELUM provider dipanggil (tidak memotong kuota).
/// Pesan berbahasa Indonesia, tanpa membocorkan isi key/config.
pub fn validate_game_params(
    service: &GameService,
    user_id: &str,
    zone_id: Option<&str>,
) -> Result<(), AppError> {
    let user_id = user_id.trim();
    match service.param_kind {
        GameParamKind::UserId => {
            if user_id.len() < 3 || user_id.len() > 30 || !user_id.bytes().all(|b| b.is_ascii_digit()) {
                return Err(AppError::bad_request(
                    "User ID game harus 3–30 digit angka",
                ));
            }
        }
        GameParamKind::RiotId => {
            if user_id.chars().count() < 3 || user_id.chars().count() > 50 {
                return Err(AppError::bad_request(
                    "Riot ID harus 3–50 karakter",
                ));
            }
        }
        GameParamKind::Username => {
            if user_id.chars().count() < 3 || user_id.chars().count() > 30 {
                return Err(AppError::bad_request(
                    "Username Roblox harus 3–30 karakter",
                ));
            }
        }
    }
    if service.needs_zone {
        match zone_id.map(str::trim).filter(|value| !value.is_empty()) {
            None => {
                return Err(AppError::bad_request(
                    "zone_id wajib diisi untuk game ini (Zone / Server ID)",
                ));
            }
            Some(zone) => {
                if zone.len() > 12 || !zone.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(AppError::bad_request(
                        "zone_id harus 1–12 digit angka",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(GAMES_TIMEOUT)
            .build()
            .expect("reqwest client games selalu bisa dibuat")
    })
}

#[derive(Debug, serde::Serialize)]
pub struct GamesSettingsView {
    pub api_key_configured: bool,
}

#[derive(sqlx::FromRow)]
struct GamesSettingsRow {
    api_key_ciphertext: Option<Vec<u8>>,
}

pub async fn load_games_settings(pool: &MySqlPool) -> Result<GamesSettingsView, AppError> {
    let row = sqlx::query_as::<_, GamesSettingsRow>(
        "SELECT api_key_ciphertext FROM games_settings WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan games tidak dapat dibaca"))?;
    Ok(GamesSettingsView {
        api_key_configured: row
            .map(|row| row.api_key_ciphertext.map(|value| !value.is_empty()).unwrap_or(false))
            .unwrap_or(false),
    })
}

pub async fn load_games_api_key(
    pool: &MySqlPool,
    cipher: &CredentialCipher,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query_as::<_, GamesSettingsRow>(
        "SELECT api_key_ciphertext FROM games_settings WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan games tidak dapat dibaca"))?;
    Ok(match row.and_then(|row| row.api_key_ciphertext) {
        Some(ciphertext) if !ciphertext.is_empty() => cipher.decrypt(&ciphertext).ok(),
        _ => None,
    })
}

pub async fn save_games_api_key(
    pool: &MySqlPool,
    cipher: &CredentialCipher,
    api_key: Option<&str>,
) -> Result<GamesSettingsView, AppError> {
    if cipher.is_fallback() {
        return Err(AppError::internal(
            "Kunci enkripsi kredensial belum dikonfigurasi server",
        ));
    }
    let trimmed = api_key.map(str::trim).filter(|value| !value.is_empty());
    let ciphertext = match trimmed {
        Some(key) => Some(
            cipher
                .encrypt(key)
                .map_err(|_| AppError::internal("API key games tidak dapat dienkripsi"))?,
        ),
        None => None,
    };
    sqlx::query(
        "INSERT INTO games_settings (id, api_key_ciphertext) VALUES (1, ?) \
         ON DUPLICATE KEY UPDATE api_key_ciphertext = VALUES(api_key_ciphertext)",
    )
    .bind(ciphertext.as_deref())
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Pengaturan games tidak dapat disimpan"))?;
    Ok(GamesSettingsView { api_key_configured: trimmed.is_some() })
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct GameServiceRow {
    pub code: String,
    pub service: String,
    pub name: String,
    pub needs_zone: bool,
    pub param_kind: String,
    pub enabled: bool,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn load_game_services(pool: &MySqlPool) -> Result<Vec<GameServiceRow>, AppError> {
    let rows = sqlx::query_as::<_, GameServiceRow>(
        "SELECT code, service, name, needs_zone, param_kind, enabled, verified_at \
         FROM game_services ORDER BY code",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("Daftar game tidak dapat dibaca"))?;
    Ok(rows)
}

pub async fn set_game_service_enabled(
    pool: &MySqlPool,
    code: &str,
    enabled: bool,
) -> Result<GameServiceRow, AppError> {
    let normalized = code.trim().to_ascii_lowercase();
    if find_game_service(&normalized).is_none() {
        return Err(AppError::not_found("Game tidak dikenal"));
    }
    let updated = sqlx::query(
        "UPDATE game_services SET enabled = ? WHERE code = ?",
    )
    .bind(enabled)
    .bind(&normalized)
    .execute(pool)
    .await
    .map_err(|_| AppError::internal("Status game tidak dapat diubah"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::not_found("Game tidak dikenal"));
    }
    let row = sqlx::query_as::<_, GameServiceRow>(
        "SELECT code, service, name, needs_zone, param_kind, enabled, verified_at \
         FROM game_services WHERE code = ?",
    )
    .bind(&normalized)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::internal("Daftar game tidak dapat dibaca"))?;
    Ok(row)
}

pub async fn mark_game_service_verified(pool: &MySqlPool, code: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE game_services SET verified_at = UTC_TIMESTAMP(6) WHERE code = ?")
        .bind(code.trim().to_ascii_lowercase())
        .execute(pool)
        .await
        .map_err(|_| AppError::internal("Status verifikasi game tidak dapat disimpan"))?;
    Ok(())
}

pub async fn game_service_enabled(pool: &MySqlPool, code: &str) -> Result<bool, AppError> {
    let row = sqlx::query_as::<_, (i8,)>(
        "SELECT enabled FROM game_services WHERE code = ?",
    )
    .bind(code.trim().to_ascii_lowercase())
    .fetch_optional(pool)
    .await
    .map_err(|_| AppError::internal("Daftar game tidak dapat dibaca"))?;
    Ok(row.map(|(enabled,)| enabled != 0).unwrap_or(false))
}

/// Bentuk respons Cutiezy (defensif: semua field opsional kecuali `ok`).
#[derive(Debug, Deserialize)]
struct CutiezyGameResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<CutiezyGameData>,
}

#[derive(Debug, Deserialize)]
struct CutiezyGameData {
    #[serde(default)]
    nickname: Option<serde_json::Value>,
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    zone: Option<serde_json::Value>,
    #[serde(default)]
    country: Option<serde_json::Value>,
    #[serde(default)]
    server: Option<serde_json::Value>,
}

fn value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

#[derive(Debug)]
pub struct GameCheckOutcome {
    pub status: ValidationStatus,
    pub nickname: Option<String>,
    pub zone: Option<String>,
    pub country: Option<String>,
    pub server: Option<String>,
    pub provider_latency_ms: u64,
    pub attempts: u32,
    /// Pesan mentah Cutiezy (hanya untuk Tester admin, tidak pernah ke member).
    pub raw_message: Option<String>,
    /// Body mentah (dipotong) untuk Tester admin.
    pub raw_body: String,
}

fn canonical_game_message(status: ValidationStatus) -> &'static str {
    match status {
        ValidationStatus::Valid => "ID game ditemukan.",
        ValidationStatus::NotFound => "ID game tidak ditemukan.",
        ValidationStatus::RateLimited => "Batas permintaan tercapai. Silakan coba kembali setelah jeda yang ditentukan.",
        _ => "Respons diterima dari provider validasi.",
    }
}

/// Satu panggilan cek ke Cutiezy. `guard` boleh None (mis. tes tanpa
/// database guard); bila ada, breaker + pacer dipakai seperti provider
/// lain. Mengembalikan outcome (bukan Err) untuk semua jawaban
/// provider yang terdefinisi — hanya kegagalan internal (mis. key
/// belum dikonfigurasi) yang menjadi Err.
pub async fn check_game(
    guard: Option<&std::sync::Arc<crate::provider_guard::ProviderGuard>>,
    api_key: &str,
    service: &GameService,
    user_id: &str,
    zone_id: Option<&str>,
) -> Result<GameCheckOutcome, AppError> {
    let started = Instant::now();
    let mut ticket = None;
    if let Some(guard) = guard {
        match guard
            .try_acquire(
                crate::models::ValidationProduct::Game,
                GAMES_ENDPOINT_ID,
                false,
            )
            .await
        {
            Ok(Some(held)) => ticket = Some(held),
            Ok(None) => {
                // Antrean penuh: perlakukan sebagai RateLimited (refund,
                // tanpa potong) seperti guard provider lain.
                return Ok(GameCheckOutcome {
                    status: ValidationStatus::RateLimited,
                    nickname: None,
                    zone: None,
                    country: None,
                    server: None,
                    provider_latency_ms: started.elapsed().as_millis() as u64,
                    attempts: 1,
                    raw_message: None,
                    raw_body: String::new(),
                });
            }
            Err(error) => return Err(error),
        }
        if let Err(error) = guard.pace(GAMES_HOST).await {
            if let Some(held) = ticket {
                guard.record_neutral(&held).await;
            }
            return Err(error);
        }
    }

    let url = format!("{GAMES_BASE_URL}/api/check/games/{}", service.service);
    let mut request = http_client()
        .get(&url)
        .header("X-API-Key", api_key)
        .header("Accept", "application/json");
    match service.param_kind {
        GameParamKind::Username => {
            request = request.query(&[("username", user_id)]);
        }
        _ => {
            request = request.query(&[("user_id", user_id)]);
        }
    }
    if service.needs_zone {
        if let Some(zone) = zone_id.map(str::trim).filter(|value| !value.is_empty()) {
            request = request.query(&[("zone_id", zone)]);
        }
    }

    let outcome = match request.send().await {
        Ok(response) => {
            let http_status = response.status();
            let body = response.text().await.unwrap_or_default();
            let raw_body: String = body.chars().take(4096).collect();
            let parsed: Option<CutiezyGameResponse> = serde_json::from_str(&body).ok();
            let outcome = map_game_response(http_status.as_u16(), parsed, &raw_body, started);
            if let Some(guard) = guard {
                if let Some(held) = ticket.take() {
                    // Sukses = jawaban definitif provider (2xx ter-parse);
                    // sisanya netral/gagal sesuai status HTTP.
                    if http_status.is_success() && outcome.status != ValidationStatus::ProviderError
                    {
                        guard.record_success(&held).await;
                    } else if http_status.is_server_error() {
                        guard.record_failure(&held).await;
                    } else {
                        guard.record_neutral(&held).await;
                    }
                }
            }
            outcome
        }
        Err(error) => {
            if let Some(guard) = guard {
                if let Some(held) = ticket.take() {
                    guard.record_failure(&held).await;
                }
            }
            let _ = error;
            GameCheckOutcome {
                status: ValidationStatus::ProviderError,
                nickname: None,
                zone: None,
                country: None,
                server: None,
                provider_latency_ms: started.elapsed().as_millis() as u64,
                attempts: 1,
                raw_message: Some("timeout atau koneksi ke Cutiezy gagal".to_owned()),
                raw_body: String::new(),
            }
        }
    };
    if let Some(held) = ticket {
        if let Some(guard) = guard {
            guard.record_neutral(&held).await;
        }
    }
    Ok(outcome)
}

fn map_game_response(
    http_status: u16,
    parsed: Option<CutiezyGameResponse>,
    raw_body: &str,
    started: Instant,
) -> GameCheckOutcome {
    let latency = started.elapsed().as_millis() as u64;
    let base = |status: ValidationStatus,
                nickname: Option<String>,
                zone: Option<String>,
                country: Option<String>,
                server: Option<String>,
                raw_message: Option<String>| GameCheckOutcome {
        status,
        nickname,
        zone,
        country,
        server,
        provider_latency_ms: latency,
        attempts: 1,
        raw_message,
        raw_body: raw_body.to_owned(),
    };
    if http_status == 429 {
        return base(ValidationStatus::RateLimited, None, None, None, None, None);
    }
    let Some(response) = parsed else {
        // Bukan JSON (mis. halaman blokir firewall / timeout HTML):
        // ProviderError, pesan member tetap generik.
        return base(
            ValidationStatus::ProviderError,
            None,
            None,
            None,
            None,
            Some(format!("HTTP {http_status}: respons bukan JSON")),
        );
    };
    if !response.ok {
        let message = response.message.clone().unwrap_or_default();
        let lowered = message.to_ascii_lowercase();
        // IP belum didaftarkan di slot IP Cutiezy (403): ProviderError,
        // bukan NotFound — ID-nya belum sempat diperiksa.
        if lowered.contains("tidak ditemukan") || lowered.contains("not found") {
            return base(
                ValidationStatus::NotFound,
                None,
                None,
                None,
                None,
                response.message,
            );
        }
        return base(
            ValidationStatus::ProviderError,
            None,
            None,
            None,
            None,
            response.message,
        );
    }
    let Some(data) = response.data else {
        return base(
            ValidationStatus::ProviderError,
            None,
            None,
            None,
            None,
            Some("respons ok tanpa data".to_owned()),
        );
    };
    let nickname = data.nickname.as_ref().and_then(value_to_string);
    match nickname {
        Some(name) => base(
            ValidationStatus::Valid,
            Some(name),
            data.zone.as_ref().and_then(value_to_string),
            data.country.as_ref().and_then(value_to_string),
            data.server.as_ref().and_then(value_to_string),
            None,
        ),
        None => base(
            ValidationStatus::ProviderError,
            None,
            None,
            None,
            None,
            Some("respons ok tanpa nickname".to_owned()),
        ),
    }
}

/// Pesan member untuk status game (ditulis Rajacek, bukan dari upstream).
pub fn game_member_message(status: ValidationStatus) -> &'static str {
    canonical_game_message(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_17_services() {
        assert_eq!(GAME_SERVICES.len(), 17);
        assert!(find_game_service("REGION-ML").is_some());
        assert!(find_game_service("roblox").is_some());
        assert!(find_game_service("tidak-ada").is_none());
    }

    #[test]
    fn params_ml_requires_zone() {
        let service = find_game_service("region-ml").unwrap();
        assert!(validate_game_params(service, "861363893", None).is_err());
        assert!(validate_game_params(service, "861363893", Some("12422")).is_ok());
        assert!(validate_game_params(service, "86", Some("12422")).is_err());
        assert!(validate_game_params(service, "861363893", Some("abc")).is_err());
    }

    #[test]
    fn params_roblox_and_valorant_text() {
        let roblox = find_game_service("roblox").unwrap();
        assert!(validate_game_params(roblox, "builderman", None).is_ok());
        assert!(validate_game_params(roblox, "ab", None).is_err());
        let valorant = find_game_service("valorant").unwrap();
        assert!(validate_game_params(valorant, "NamaPlayer#1234", None).is_ok());
        assert!(validate_game_params(valorant, "ab", None).is_err());
        let ff = find_game_service("free-fire").unwrap();
        assert!(validate_game_params(ff, "123456789", None).is_ok());
        assert!(validate_game_params(ff, "12a456789", None).is_err());
    }

    #[test]
    fn map_ok_response() {
        let started = Instant::now();
        let parsed = serde_json::from_str::<CutiezyGameResponse>(
            r#"{"ok":true,"data":{"nickname":"Nama Player","id":861363893,"zone":12422,"country":"Indonesia"}}"#,
        )
        .ok();
        let outcome = map_game_response(200, parsed, "{}", started);
        assert_eq!(outcome.status, ValidationStatus::Valid);
        assert_eq!(outcome.nickname.as_deref(), Some("Nama Player"));
        assert_eq!(outcome.zone.as_deref(), Some("12422"));
        assert_eq!(outcome.country.as_deref(), Some("Indonesia"));
    }

    #[test]
    fn map_not_found_response() {
        let started = Instant::now();
        let parsed = serde_json::from_str::<CutiezyGameResponse>(
            r#"{"ok":false,"message":"User ID tidak ditemukan"}"#,
        )
        .ok();
        let outcome = map_game_response(200, parsed, "{}", started);
        assert_eq!(outcome.status, ValidationStatus::NotFound);
        let parsed = serde_json::from_str::<CutiezyGameResponse>(
            r#"{"ok":false,"message":"IP tidak diizinkan"}"#,
        )
        .ok();
        let outcome = map_game_response(403, parsed, "{}", started);
        assert_eq!(outcome.status, ValidationStatus::ProviderError);
    }
}

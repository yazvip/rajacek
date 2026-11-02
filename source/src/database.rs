use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result};
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    MySqlPool,
};

use crate::models::UsageEvent;

/// INSERT for `provider_request_logs` (migration 0040), kept as a named
/// constant for the same lockstep test as the history INSERT above.
/// Idempotency: the id is derived deterministically from
/// (event_id, attempt index) — a redelivered event re-inserts the exact
/// same rows, and INSERT IGNORE drops the duplicates (same pattern as
/// the history/ledger inserts above).
const PERSIST_PROVIDER_REQUEST_LOG_SQL: &str = r#"
            INSERT IGNORE INTO provider_request_logs (
                id, request_id, endpoint_name, method, request_redacted,
                response_status, response_body, truncated, latency_ms, created_at
            ) VALUES (
                UUID_TO_BIN(?), ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
"#;

/// Deterministic log-row id: SHA-256(event_id || index), first 16 bytes
/// as a UUID. Stable across redeliveries, distinct per attempt index.
fn provider_request_log_id(event_id: &uuid::Uuid, index: usize) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(event_id.as_bytes());
    hasher.update((index as u64).to_le_bytes());
    let digest = hasher.finalize();
    let bytes: [u8; 16] = digest[..16]
        .try_into()
        .expect("SHA-256 selalu >= 16 byte");
    uuid::Uuid::from_bytes(bytes).to_string()
}
/// Columns target_raw + account_name come from migration 0024 and are
/// admin-history only; member responses never read them. Column
/// provider_endpoint_id comes from migration 0033 (winning endpoint id,
/// NULL for pre-feature rows); it uses a CASE bind because sqlx has no
/// native Option<Uuid>-to-BINARY(16) mapping in this query style, the
/// same pattern as the price_snapshot_id bind in the ledger INSERT below.
const PERSIST_VALIDATION_REQUEST_SQL: &str = r#"
            INSERT IGNORE INTO validation_requests (
                id, request_id, event_id, api_key_prefix, product_code, outcome,
                target_fingerprint, target_masked, target_raw, account_name,
                provider_reference, provider_endpoint_id, provider_hint, provider_latency_ms,
                rajacek_processing_ms, total_latency_ms, attempts,
                occurred_at, channel
            ) VALUES (
                UUID_TO_BIN(?), ?, UUID_TO_BIN(?), ?, ?, ?, ?, ?, ?, ?, ?,
                CASE WHEN ? IS NULL THEN NULL ELSE UUID_TO_BIN(?) END, ?,
                ?, ?, ?, ?, ?, ?
            )
            "#;

/// MySQL system-of-record access.
///
/// The API hot path does not write directly through this type. The worker consumes durable
/// usage events and calls [`Database::persist_usage_event`] in idempotent transactions, which
/// keeps member-facing latency independent from normal MySQL write time.
pub struct Database {
    pool: MySqlPool,
}

impl Database {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let options = MySqlConnectOptions::from_str(database_url)
            .context("DATABASE_URL tidak valid untuk MySQL")?;
        let pool = MySqlPoolOptions::new()
            .min_connections(1)
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .context("Tidak dapat membuat pool koneksi MySQL")?;
        sqlx::query("SELECT 1")
            .execute(&pool)
            .await
            .context("MySQL tidak dapat menjalankan pemeriksaan kesiapan")?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// Bungkus pool yang sudah ada (dipakai jalur admin DLQ replay,
    /// Fase 3/B26: API tidak memegang `Database`, hanya pool store —
    /// replay memakai `persist_usage_event` yang sama dengan worker
    /// sehingga idempotensinya identik, bukan INSERT tiruan).
    pub fn from_pool(pool: MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Migrasi database gagal dijalankan")
    }

    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("Pemeriksaan kesehatan MySQL gagal")?;
        Ok(())
    }

    /// Stores a stream-delivered usage event exactly once.
    ///
    /// Both target request logging and charge ledger insertion are guarded by unique `event_id`
    /// indexes. Redis Streams may redeliver an event after worker recovery, so `INSERT IGNORE`
    /// is intentional and does not indicate a silently ignored financial error.
    pub async fn persist_usage_event(&self, event: &UsageEvent) -> Result<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("Gagal membuka transaksi ledger")?;
        let event_id = event.event_id.to_string();
        let product_code = event.product.as_str();
        let outcome = event.status.as_str();
        let provider_endpoint_id = event.provider_endpoint_id.map(|value| value.to_string());

        sqlx::query(PERSIST_VALIDATION_REQUEST_SQL)
            .bind(&event_id)
            .bind(&event.request_id)
            .bind(&event_id)
            .bind(&event.api_key_prefix)
            .bind(product_code)
            .bind(outcome)
            .bind(&event.target_fingerprint)
            .bind(&event.target_masked)
            .bind(&event.target_raw)
            .bind(&event.account_name)
            .bind(&event.provider_reference)
            .bind(&provider_endpoint_id)
            .bind(&provider_endpoint_id)
            .bind(&event.provider_hint)
            .bind(event.provider_latency_ms)
            .bind(event.rajacek_processing_ms)
            .bind(event.total_latency_ms)
            .bind(event.attempts)
            .bind(event.occurred_at)
            .bind(&event.channel)
            .execute(&mut *transaction)
            .await
            .context("Gagal menyimpan audit validasi")?;

        // Tab Logs admin (migrasi 0040): traffic provider per percobaan
        // dari event yang sama, dalam transaksi yang sama dengan riwayat
        // (atomik: tidak ada riwayat tanpa log-nya, dan sebaliknya).
        // DIAGNOSTIK, bukan billing: gagal tulis log (mis. tabel belum
        // ter-migrasi saat swap) HANYA diperingatkan lalu dilewati —
        // tidak pernah menggagalkan riwayat/ledger. Event tanpa log
        // (demo, event lama, replay) tidak menambah query sama sekali.
        if !event.provider_attempt_logs.is_empty() {
            for (index, log) in event.provider_attempt_logs.iter().enumerate() {
                if let Err(error) = sqlx::query(PERSIST_PROVIDER_REQUEST_LOG_SQL)
                    .bind(provider_request_log_id(&event.event_id, index))
                    .bind(&event.request_id)
                    .bind(&log.endpoint_name)
                    .bind(&log.method)
                    .bind(&log.request_redacted)
                    .bind(log.response_status)
                    .bind(&log.response_body)
                    .bind(log.truncated)
                    .bind(log.latency_ms)
                    .bind(event.occurred_at)
                    .execute(&mut *transaction)
                    .await
                {
                    tracing::warn!(
                        request_id = %event.request_id,
                        error = ?error,
                        "Log provider gagal disimpan; riwayat/ledger tetap dikomit (diagnostik saja)"
                    );
                    break;
                }
            }
        }

        // Billing rule 2026-10-25: only actually-charged validations create
        // a ledger 'charge' row. Free-pool invalid results (charged=false)
        // and pre-`charged` events (default true) keep the old behavior via
        // the is_billable() half of this condition.
        if event.status.is_billable() && event.charged {
            let price_snapshot_id = event.price_snapshot_id.map(|value| value.to_string());
            sqlx::query(
                r#"
                INSERT IGNORE INTO usage_ledger (
                    id, event_id, request_id, api_key_prefix, product_code, operation,
                    outcome, quantity, amount_idr, price_snapshot_id, occurred_at
                ) VALUES (
                    UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, ?, 'charge', ?, 1, 0,
                    CASE WHEN ? IS NULL THEN NULL ELSE UUID_TO_BIN(?) END, ?
                )
                "#,
            )
            .bind(&event_id)
            .bind(&event_id)
            .bind(&event.request_id)
            .bind(&event.api_key_prefix)
            .bind(product_code)
            .bind(outcome)
            .bind(&price_snapshot_id)
            .bind(&price_snapshot_id)
            .bind(event.occurred_at)
            .execute(&mut *transaction)
            .await
            .context("Gagal menyimpan ledger penggunaan")?;
        }

        transaction
            .commit()
            .await
            .context("Gagal mengunci transaksi ledger")?;
        Ok(())
    }
}

#[cfg(test)]
mod persist_sql_tests {
    use super::*;

    #[test]
    fn validation_request_insert_covers_migration_0024_columns() {
        // sqlx::query tidak dicek saat compile, jadi kunci guard ini:
        // kolom baru migrasi 0024 harus ada di INSERT. Jumlah
        // placeholder TIDAK diasersi di sini lagi (dulu 17) karena
        // migrasi 0033 menambah satu kolom CASE dua placeholder — total
        // dikunci oleh validation_request_insert_covers_migration_0033_
        // endpoint_column di bawah, bukan di dua tempat.
        assert!(PERSIST_VALIDATION_REQUEST_SQL.contains("target_raw"));
        assert!(PERSIST_VALIDATION_REQUEST_SQL.contains("account_name"));
        assert!(PERSIST_VALIDATION_REQUEST_SQL.contains("target_masked"));
    }

    #[test]
    fn provider_request_log_insert_matches_migration_0040() {
        assert!(PERSIST_PROVIDER_REQUEST_LOG_SQL.contains("provider_request_logs"));
        for column in [
            "endpoint_name",
            "method",
            "request_redacted",
            "response_status",
            "response_body",
            "truncated",
            "latency_ms",
            "created_at",
        ] {
            assert!(
                PERSIST_PROVIDER_REQUEST_LOG_SQL.contains(column),
                "kolom {column} hilang dari INSERT log"
            );
        }
        assert_eq!(
            PERSIST_PROVIDER_REQUEST_LOG_SQL.matches('?').count(),
            10,
            "bind dan placeholder tidak seimbang"
        );
    }

    #[test]
    fn provider_request_log_id_is_deterministic_per_attempt() {
        let event_id = uuid::Uuid::parse_str("0199a5a5-0000-7000-8000-000000000001").unwrap();
        let first = provider_request_log_id(&event_id, 0);
        assert_eq!(first, provider_request_log_id(&event_id, 0));
        assert_ne!(first, provider_request_log_id(&event_id, 1));
        assert_ne!(
            first,
            provider_request_log_id(
                &uuid::Uuid::parse_str("0199a5a5-0000-7000-8000-000000000002").unwrap(),
                0
            )
        );
        // Bentuk UUID valid (36 karakter dengan strip) agar UUID_TO_BIN
        // tidak pernah menolaknya.
        assert_eq!(first.len(), 36);
        assert!(uuid::Uuid::parse_str(&first).is_ok());
    }

    #[test]
    fn validation_request_insert_covers_migration_0033_endpoint_column() {
        // Migrasi 0033 menambah satu kolom (provider_endpoint_id) yang
        // di-bind lewat CASE dua placeholder (NULL-aman), jadi total
        // placeholder naik 17 -> 19. Jumlah ini harus sama dengan jumlah
        // bind di persist_usage_event.
        assert!(PERSIST_VALIDATION_REQUEST_SQL.contains("provider_endpoint_id"));
        let placeholders = PERSIST_VALIDATION_REQUEST_SQL.matches('?').count();
        assert_eq!(placeholders, 20, "bind dan placeholder tidak seimbang");
    }
}

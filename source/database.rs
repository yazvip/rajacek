use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result};
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    MySqlPool,
};

use crate::models::UsageEvent;

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

        sqlx::query(
            r#"
            INSERT IGNORE INTO validation_requests (
                id, request_id, event_id, api_key_prefix, product_code, outcome,
                target_fingerprint, target_masked, provider_reference, provider_latency_ms,
                rajacek_processing_ms, total_latency_ms, attempts,
                occurred_at, channel
            ) VALUES (
                UUID_TO_BIN(?), ?, UUID_TO_BIN(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            "#,
        )
        .bind(&event_id)
        .bind(&event.request_id)
        .bind(&event_id)
        .bind(&event.api_key_prefix)
        .bind(product_code)
        .bind(outcome)
        .bind(&event.target_fingerprint)
        .bind(&event.target_masked)
        .bind(&event.provider_reference)
        .bind(event.provider_latency_ms)
        .bind(event.rajacek_processing_ms)
        .bind(event.total_latency_ms)
        .bind(event.attempts)
        .bind(event.occurred_at)
        .bind(&event.channel)
        .execute(&mut *transaction)
        .await
        .context("Gagal menyimpan audit validasi")?;

        if event.status.is_billable() {
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

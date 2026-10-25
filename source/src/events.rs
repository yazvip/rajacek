use std::sync::Arc;

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use tokio::sync::mpsc;

use crate::{error::AppError, models::UsageEvent};

#[async_trait]
pub trait UsageEventSink: Send + Sync {
    /// Persists a compact usage intent before a billable response is returned.
    /// The consumer must remain idempotent because delivery can be at-least-once.
    async fn enqueue(&self, event: UsageEvent) -> Result<(), AppError>;
    fn mode(&self) -> &'static str;
}

pub async fn build_usage_event_sink(
    redis_url: Option<&str>,
    stream_name: String,
) -> Result<Arc<dyn UsageEventSink>, AppError> {
    match redis_url {
        Some(redis_url) => Ok(Arc::new(
            RedisStreamEventSink::connect(redis_url, stream_name).await?,
        )),
        None => Ok(Arc::new(LocalEventSink::new())),
    }
}

pub struct RedisStreamEventSink {
    // ConnectionManager clones share one multiplexed connection; no Mutex needed.
    connection: ConnectionManager,
    stream_name: String,
}

impl RedisStreamEventSink {
    pub async fn connect(redis_url: &str, stream_name: String) -> Result<Self, AppError> {
        let client = redis::Client::open(redis_url)
            .map_err(|_| AppError::service_unavailable("Konfigurasi Redis tidak valid"))?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| AppError::service_unavailable("Redis tidak dapat dihubungi"))?;
        Ok(Self {
            connection,
            stream_name,
        })
    }
}

#[async_trait]
impl UsageEventSink for RedisStreamEventSink {
    async fn enqueue(&self, event: UsageEvent) -> Result<(), AppError> {
        let payload = serde_json::to_string(&event).map_err(|error| {
            tracing::error!(error = ?error, "Serialisasi event penggunaan gagal");
            AppError::internal("Event penggunaan tidak dapat disiapkan")
        })?;
        let mut connection = self.connection.clone();
        redis::cmd("XADD")
            .arg(&self.stream_name)
            .arg("*")
            .arg("event_id")
            .arg(event.event_id.to_string())
            .arg("payload")
            .arg(payload)
            .query_async::<String>(&mut connection)
            .await
            .map_err(|error| {
                tracing::error!(error = ?error, "Pengiriman event penggunaan ke Redis Stream gagal");
                AppError::service_unavailable(
                    "Pencatatan penggunaan belum tersedia. Permintaan tidak dapat diselesaikan dengan aman.",
                )
            })?;
        Ok(())
    }

    fn mode(&self) -> &'static str {
        "redis_stream"
    }
}

/// In-memory development sink. It is not suitable for production because a process restart
/// loses events. It intentionally uses a bounded, non-blocking channel so slow log processing
/// cannot delay API responses during local UI and contract development.
pub struct LocalEventSink {
    sender: mpsc::Sender<UsageEvent>,
}

impl LocalEventSink {
    pub fn new() -> Self {
        let (sender, mut receiver) = mpsc::channel::<UsageEvent>(2_048);
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                tracing::info!(
                    event_id = %event.event_id,
                    request_id = %event.request_id,
                    product = %event.product.as_str(),
                    status = ?event.status,
                    "Event penggunaan demo diterima worker lokal"
                );
            }
        });
        Self { sender }
    }
}

#[async_trait]
impl UsageEventSink for LocalEventSink {
    async fn enqueue(&self, event: UsageEvent) -> Result<(), AppError> {
        self.sender.try_send(event).map_err(|error| {
            tracing::error!(error = ?error, "Antrean event lokal penuh atau ditutup");
            AppError::service_unavailable(
                "Antrean pencatatan penggunaan penuh. Silakan ulangi permintaan beberapa saat lagi.",
            )
        })
    }

    fn mode(&self) -> &'static str {
        "local_development"
    }
}

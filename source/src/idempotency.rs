use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use redis::{aio::ConnectionManager, Script};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex, Notify},
    time::sleep,
};

use crate::{error::AppError, models::ValidationResponse};

// Must exceed the worst-case provider latency (60 s timeout x 3 attempts):
// an in-flight entry expiring first made complete() fail and let a retry
// double-charge (audit 2026-10-25, K3).
const IN_FLIGHT_TTL: Duration = Duration::from_secs(300);
const WAIT_FOR_OWNER_LIMIT: Duration = Duration::from_secs(18);
const OWNER_POLL_INTERVAL: Duration = Duration::from_millis(40);

pub enum IdempotencyDecision {
    Execute,
    Replay(ValidationResponse),
}

/// Coordinates paid validation retries so one `Idempotency-Key` cannot trigger multiple
/// provider calls or ledger charges. Production uses Redis so all API replicas share the same
/// state; the local implementation exists only for development without Redis.
#[async_trait]
pub trait IdempotencyCoordinator: Send + Sync {
    async fn begin(
        &self,
        key: &str,
        request_fingerprint: &str,
    ) -> Result<IdempotencyDecision, AppError>;

    async fn complete(
        &self,
        key: &str,
        request_fingerprint: &str,
        response: ValidationResponse,
    ) -> Result<(), AppError>;

    async fn abandon(&self, key: &str, request_fingerprint: &str);
}

pub async fn build_idempotency_coordinator(
    redis_url: Option<&str>,
    ttl: Duration,
) -> Result<Arc<dyn IdempotencyCoordinator>, AppError> {
    match redis_url {
        Some(redis_url) => Ok(Arc::new(
            RedisIdempotencyCoordinator::connect(redis_url, ttl).await?,
        )),
        None => {
            tracing::warn!(
                "Redis tidak dikonfigurasi; memakai idempotensi proses-lokal untuk pengembangan saja"
            );
            Ok(Arc::new(LocalIdempotencyCoordinator::new(ttl)))
        }
    }
}

struct LocalEntry {
    request_fingerprint: String,
    state: LocalEntryState,
    started_at: Instant,
}

enum LocalEntryState {
    InFlight(Arc<Notify>),
    Completed(LocalStoredResponse),
}

struct LocalStoredResponse {
    response: ValidationResponse,
    expires_at: Instant,
}

/// Development-only implementation. It cannot coordinate retries across API processes.
pub struct LocalIdempotencyCoordinator {
    entries: Mutex<HashMap<String, LocalEntry>>,
    ttl: Duration,
}

impl LocalIdempotencyCoordinator {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }
}

#[async_trait]
impl IdempotencyCoordinator for LocalIdempotencyCoordinator {
    async fn begin(
        &self,
        key: &str,
        request_fingerprint: &str,
    ) -> Result<IdempotencyDecision, AppError> {
        loop {
            let waiter = {
                let mut entries = self.entries.lock().await;
                remove_expired(&mut entries);

                match entries.get(key) {
                    Some(LocalEntry {
                        request_fingerprint: existing_fingerprint,
                        state: LocalEntryState::Completed(stored),
                        ..
                    }) => {
                        if existing_fingerprint != request_fingerprint {
                            return Err(idempotency_conflict());
                        }
                        return Ok(IdempotencyDecision::Replay(stored.response.clone()));
                    }
                    Some(LocalEntry {
                        request_fingerprint: existing_fingerprint,
                        state: LocalEntryState::InFlight(notify),
                        ..
                    }) => {
                        if existing_fingerprint != request_fingerprint {
                            return Err(idempotency_conflict());
                        }
                        // Subscribe while holding the entry lock so completion cannot happen
                        // between reading the state and constructing the owned wait future.
                        Some(notify.clone().notified_owned())
                    }
                    None => {
                        entries.insert(
                            key.to_owned(),
                            LocalEntry {
                                request_fingerprint: request_fingerprint.to_owned(),
                                state: LocalEntryState::InFlight(Arc::new(Notify::new())),
                                started_at: Instant::now(),
                            },
                        );
                        return Ok(IdempotencyDecision::Execute);
                    }
                }
            };

            if let Some(waiter) = waiter {
                // Bound the wait (audit 2026-10-25, K9): an owner that
                // crashed without complete/abandon used to park waiters
                // forever. On timeout the loop re-reads the entry, which by
                // then is completed, expired, or abandoned.
                let _ = tokio::time::timeout(WAIT_FOR_OWNER_LIMIT, waiter).await;
            }
        }
    }

    async fn complete(
        &self,
        key: &str,
        request_fingerprint: &str,
        response: ValidationResponse,
    ) -> Result<(), AppError> {
        let notify = {
            let mut entries = self.entries.lock().await;
            let Some(entry) = entries.get_mut(key) else {
                return Err(idempotency_state_lost());
            };
            if entry.request_fingerprint != request_fingerprint {
                return Err(idempotency_conflict());
            }
            let notify = match &entry.state {
                LocalEntryState::InFlight(notify) => Some(notify.clone()),
                LocalEntryState::Completed(_) => return Ok(()),
            };
            entry.state = LocalEntryState::Completed(LocalStoredResponse {
                response,
                expires_at: Instant::now() + self.ttl,
            });
            notify
        };
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
        Ok(())
    }

    async fn abandon(&self, key: &str, request_fingerprint: &str) {
        let notify = {
            let mut entries = self.entries.lock().await;
            let Some(entry) = entries.get(key) else {
                return;
            };
            if entry.request_fingerprint != request_fingerprint {
                return;
            }
            let entry = entries.remove(key);
            match entry.map(|entry| entry.state) {
                Some(LocalEntryState::InFlight(notify)) => Some(notify),
                _ => None,
            }
        };
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RedisEntryState {
    InFlight,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RedisEntry {
    request_fingerprint: String,
    state: RedisEntryState,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<ValidationResponse>,
}

pub struct RedisIdempotencyCoordinator {
    // See rate_limit.rs: ConnectionManager clones share one multiplexed connection,
    // so no Mutex is needed (or wanted) around it.
    connection: ConnectionManager,
    completed_ttl: Duration,
    complete_script: Script,
    abandon_script: Script,
}

impl RedisIdempotencyCoordinator {
    pub async fn connect(redis_url: &str, completed_ttl: Duration) -> Result<Self, AppError> {
        let client = redis::Client::open(redis_url)
            .map_err(|_| AppError::service_unavailable("Konfigurasi Redis tidak valid"))?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| AppError::service_unavailable("Redis tidak dapat dihubungi"))?;

        Ok(Self {
            connection,
            completed_ttl,
            complete_script: Script::new(
                r#"
                local current_raw = redis.call('GET', KEYS[1])
                if not current_raw then return 0 end
                local current = cjson.decode(current_raw)
                if current.request_fingerprint ~= ARGV[1] or current.state ~= 'in_flight' then
                    return 0
                end
                redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
                return 1
                "#,
            ),
            abandon_script: Script::new(
                r#"
                local current_raw = redis.call('GET', KEYS[1])
                if not current_raw then return 0 end
                local current = cjson.decode(current_raw)
                if current.request_fingerprint ~= ARGV[1] or current.state ~= 'in_flight' then
                    return 0
                end
                return redis.call('DEL', KEYS[1])
                "#,
            ),
        })
    }

    async fn read(&self, redis_key: &str) -> Result<Option<RedisEntry>, AppError> {
        let payload = {
            let mut connection = self.connection.clone();
            redis::cmd("GET")
                .arg(redis_key)
                .query_async::<Option<String>>(&mut connection)
                .await
                .map_err(redis_unavailable)?
        };
        payload
            .map(|payload| {
                serde_json::from_str::<RedisEntry>(&payload).map_err(|error| {
                    tracing::error!(error = ?error, "Status idempotensi Redis tidak dapat dipahami");
                    AppError::service_unavailable(
                        "Status idempotensi sedang tidak tersedia. Silakan ulangi dengan Idempotency-Key yang sama.",
                    )
                })
            })
            .transpose()
    }

    async fn try_begin(&self, redis_key: &str, entry: &RedisEntry) -> Result<bool, AppError> {
        let serialized = serde_json::to_string(entry).map_err(|error| {
            tracing::error!(error = ?error, "Status idempotensi tidak dapat diserialisasi");
            AppError::internal("Status idempotensi tidak dapat disiapkan")
        })?;
        let mut connection = self.connection.clone();
        let result = redis::cmd("SET")
            .arg(redis_key)
            .arg(serialized)
            .arg("NX")
            .arg("PX")
            .arg(IN_FLIGHT_TTL.as_millis() as u64)
            .query_async::<Option<String>>(&mut connection)
            .await
            .map_err(redis_unavailable)?;
        Ok(result.is_some())
    }
}

#[async_trait]
impl IdempotencyCoordinator for RedisIdempotencyCoordinator {
    async fn begin(
        &self,
        key: &str,
        request_fingerprint: &str,
    ) -> Result<IdempotencyDecision, AppError> {
        let redis_key = redis_key(key);
        let proposed = RedisEntry {
            request_fingerprint: request_fingerprint.to_owned(),
            state: RedisEntryState::InFlight,
            response: None,
        };
        let started_at = Instant::now();

        loop {
            if self.try_begin(&redis_key, &proposed).await? {
                return Ok(IdempotencyDecision::Execute);
            }

            let Some(existing) = self.read(&redis_key).await? else {
                continue;
            };
            if existing.request_fingerprint != request_fingerprint {
                return Err(idempotency_conflict());
            }
            match existing.state {
                RedisEntryState::Completed => {
                    let response = existing.response.ok_or_else(idempotency_state_lost)?;
                    return Ok(IdempotencyDecision::Replay(response));
                }
                RedisEntryState::InFlight => {
                    if started_at.elapsed() >= WAIT_FOR_OWNER_LIMIT {
                        return Err(AppError::conflict(
                            "Permintaan dengan Idempotency-Key yang sama masih diproses. Ulangi kembali sesaat lagi menggunakan kunci yang sama.",
                        ));
                    }
                    sleep(OWNER_POLL_INTERVAL).await;
                }
            }
        }
    }

    async fn complete(
        &self,
        key: &str,
        request_fingerprint: &str,
        response: ValidationResponse,
    ) -> Result<(), AppError> {
        let completed = RedisEntry {
            request_fingerprint: request_fingerprint.to_owned(),
            state: RedisEntryState::Completed,
            response: Some(response),
        };
        let serialized = serde_json::to_string(&completed).map_err(|error| {
            tracing::error!(error = ?error, "Respons idempotensi tidak dapat diserialisasi");
            AppError::internal("Respons idempotensi tidak dapat disiapkan")
        })?;
        let redis_key = redis_key(key);
        let mut connection = self.connection.clone();
        let completed: i64 = self
            .complete_script
            .key(redis_key)
            .arg(request_fingerprint)
            .arg(serialized)
            .arg(self.completed_ttl.as_millis() as u64)
            .invoke_async(&mut connection)
            .await
            .map_err(redis_unavailable)?;
        if completed == 1 {
            Ok(())
        } else {
            Err(idempotency_state_lost())
        }
    }

    async fn abandon(&self, key: &str, request_fingerprint: &str) {
        let redis_key = redis_key(key);
        let result = {
            let mut connection = self.connection.clone();
            self.abandon_script
                .key(redis_key)
                .arg(request_fingerprint)
                .invoke_async::<i64>(&mut connection)
                .await
        };
        if let Err(error) = result {
            tracing::warn!(error = ?error, "Tidak dapat membersihkan status idempotensi yang gagal");
        }
    }
}

fn remove_expired(entries: &mut HashMap<String, LocalEntry>) {
    let now = Instant::now();
    entries.retain(|_, entry| match &entry.state {
        // In-flight entries expire too (audit 2026-10-25, K9): without this
        // a dead owner's entry never cleared. Waiters recover via the
        // bounded wait above, which re-reads state after each timeout.
        LocalEntryState::InFlight(_) => entry.started_at + IN_FLIGHT_TTL > now,
        LocalEntryState::Completed(stored) => stored.expires_at > now,
    });
}

fn redis_key(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!("idem:v1:{}", hex::encode(digest))
}

fn idempotency_conflict() -> AppError {
    AppError::conflict("Idempotency-Key telah digunakan untuk permintaan yang berbeda")
}

fn idempotency_state_lost() -> AppError {
    AppError::service_unavailable(
        "Status idempotensi tidak konsisten. Ulangi permintaan menggunakan Idempotency-Key yang sama.",
    )
}

fn redis_unavailable(error: redis::RedisError) -> AppError {
    tracing::error!(error = ?error, "Redis idempotensi gagal");
    AppError::service_unavailable(
        "Layanan idempotensi sedang tidak tersedia. Silakan ulangi beberapa saat lagi.",
    )
}

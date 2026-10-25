//! Server-side session revocation (audit 2026-10-25, B8).
//!
//! Logout used to delete only the browser cookie, so a copied JWT stayed
//! valid until expiry (8 h admin / 12 h member). Revoked token ids live in
//! Redis with a TTL equal to the token's remaining lifetime.
//!
//! Fail-open by design (kept deliberately, audit flow 2026-10-25 B5):
//! if Redis is unavailable, checks pass and a warning is logged, so a
//! Redis outage cannot log every user out. Revocation is a second layer
//! on top of expiry, not a replacement for it. The fail-open is made
//! honest instead of silent: `revoke` now reports success, and both
//! logout handlers surface a failed revoke to the caller (a `warning`
//! field) instead of answering a quiet 204. Fail-closed was considered
//! for sensitive endpoints (reveal, sandbox, purchase) and deliberately
//! NOT applied: a Redis outage would then lock every member out of the
//! portal, while the exposure window of a stolen session is bounded by
//! the 12 h expiry and, since the member/auth fix, by key binding (a
//! regenerated key invalidates old member sessions, B3).
//!
//! Reconnect (audit flow B5): a failed connection at boot used to leave
//! revocation a permanent no-op until process restart. The Redis URL is
//! now retained and a lazy reconnect is attempted on the next use after
//! a cooldown (30 s), so a Redis that comes back later restores
//! revocation without a restart. Attempts are throttled by the cooldown
//! so a dead Redis does not add a connection attempt to every request.

use std::time::{Duration, Instant};

use redis::aio::ConnectionManager;
use tokio::sync::Mutex;

const RECONNECT_COOLDOWN: Duration = Duration::from_secs(30);

fn block_key(jti: &str) -> String {
    format!("session_block:{jti}")
}

pub struct SessionRevocation {
    connection: Mutex<Option<ConnectionManager>>,
    redis_url: Option<String>,
    last_reconnect_attempt: Mutex<Option<Instant>>,
}

impl SessionRevocation {
    pub async fn new(redis_url: Option<&str>) -> Self {
        let url = redis_url.map(str::to_owned);
        let connection = match &url {
            Some(url) => match redis::Client::open(url.as_str()) {
                Ok(client) => match client.get_connection_manager().await {
                    Ok(connection) => Some(connection),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "Revokasi sesi dinonaktifkan: Redis tidak dapat dihubungi"
                        );
                        None
                    }
                },
                Err(error) => {
                    tracing::warn!(?error, "Revokasi sesi dinonaktifkan: URL Redis tidak valid");
                    None
                }
            },
            None => None,
        };
        Self {
            connection: Mutex::new(connection),
            redis_url: url,
            last_reconnect_attempt: Mutex::new(None),
        }
    }

    /// The live connection, reconnecting lazily (at most once per
    /// cooldown) when the initial connection failed or was lost. Returns
    /// `None` when no Redis URL is configured or the cooldown has not
    /// elapsed since the last failed attempt.
    async fn connection(&self) -> Option<ConnectionManager> {
        {
            let guard = self.connection.lock().await;
            if let Some(connection) = guard.clone() {
                return Some(connection);
            }
        }
        let url = self.redis_url.clone()?;
        {
            let mut last = self.last_reconnect_attempt.lock().await;
            if let Some(attempted) = *last {
                if attempted.elapsed() < RECONNECT_COOLDOWN {
                    return None;
                }
            }
            *last = Some(Instant::now());
        }
        match redis::Client::open(url.as_str()) {
            Ok(client) => match client.get_connection_manager().await {
                Ok(connection) => {
                    let mut guard = self.connection.lock().await;
                    *guard = Some(connection.clone());
                    Some(connection)
                }
                Err(error) => {
                    tracing::warn!(?error, "Reconnect revocasi sesi gagal");
                    None
                }
            },
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "Reconnect revocasi sesi gagal: URL Redis tidak valid"
                );
                None
            }
        }
    }

    /// Mark a token id revoked until `ttl` elapses. Returns `true` when
    /// the block was recorded. Returns `false` (and logs) when Redis is
    /// unreachable or no connection exists — callers MUST surface that
    /// to the user instead of reporting a successful logout.
    pub async fn revoke(&self, jti: &str, ttl: Duration) -> bool {
        let Some(mut connection) = self.connection().await else {
            tracing::warn!("Gagal mencatat revocasi sesi: Redis tidak terhubung");
            return false;
        };
        let secs = ttl.as_secs().max(1);
        match redis::cmd("SET")
            .arg(block_key(jti))
            .arg("1")
            .arg("EX")
            .arg(secs)
            .query_async::<Option<String>>(&mut connection)
            .await
        {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(?error, "Gagal mencatat revocasi sesi");
                false
            }
        }
    }

    /// True when the token id is on the blocklist. Fail-open on Redis
    /// errors (warned), so revocation never becomes a login outage.
    pub async fn is_revoked(&self, jti: &str) -> bool {
        let Some(mut connection) = self.connection().await else {
            return false;
        };
        match redis::cmd("EXISTS")
            .arg(block_key(jti))
            .query_async::<i64>(&mut connection)
            .await
        {
            Ok(count) => count > 0,
            Err(error) => {
                tracing::warn!(?error, "Pemeriksaan revocasi sesi gagal (fail-open)");
                false
            }
        }
    }
}

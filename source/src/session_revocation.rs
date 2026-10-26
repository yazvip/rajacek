//! Server-side session revocation (audit 2026-10-25, B8).
//!
//! Logout used to delete only the browser cookie, so a copied JWT stayed
//! valid until expiry (8 h admin / 12 h member). Revoked token ids live in
//! Redis with a TTL equal to the token's remaining lifetime.
//!
//! Fail-CLOSED since audit flow 2026-10-26, Fase 3 (B19, keputusan D1):
//! when a Redis URL is configured but the revocation check cannot be
//! completed (connection lost, command error), the token is REJECTED —
//! login dies while Redis is down, by design, so a stolen token cannot
//! ride out a Redis outage until expiry. The old fail-open (checks pass
//! + warn) is gone from every authentication gate; gates MUST use
//! [`SessionRevocation::check_revoked`], never the legacy
//! [`SessionRevocation::is_revoked`] boolean.
//!
//! Two deliberate boundaries of the fail-closed rule:
//! - When NO Redis URL is configured at all (memory-only/dev mode),
//!   revocation simply does not exist, so the check reports `Clear` —
//!   there is no Redis to be "down". Production always configures a
//!   Redis URL, so this branch never weakens a production gate.
//! - `revoke` (logout) still reports success honestly: a failed revoke
//!   is surfaced to the caller as a `warning` instead of a quiet
//!   success, exactly as before — logout honesty is unchanged, only
//!   the verification side turned fail-closed.
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

    /// Outcome of a revocation check (B19 fail-closed, Fase 3).
    /// - `Clear`: the token id is not on the blocklist, OR no Redis URL
    ///   is configured (revocation absent by design, dev/memory-only).
    /// - `Revoked`: the token id is on the blocklist — reject it.
    /// - `Unavailable`: a Redis URL IS configured but the check could
    ///   not be completed — gates MUST reject the token (fail-closed),
    ///   never treat this as "not revoked".
    pub async fn check_revoked(&self, jti: &str) -> RevocationCheck {
        if self.redis_url.is_none() {
            return RevocationCheck::Clear;
        }
        let Some(mut connection) = self.connection().await else {
            return RevocationCheck::Unavailable;
        };
        match redis::cmd("EXISTS")
            .arg(block_key(jti))
            .query_async::<i64>(&mut connection)
            .await
        {
            Ok(count) => {
                if count > 0 {
                    RevocationCheck::Revoked
                } else {
                    RevocationCheck::Clear
                }
            }
            Err(error) => {
                tracing::warn!(?error, "Pemeriksaan revocasi sesi gagal (fail-closed)");
                RevocationCheck::Unavailable
            }
        }
    }

    /// Legacy boolean view: true only when positively revoked. Kept for
    /// non-gate callers; authentication gates MUST use
    /// [`SessionRevocation::check_revoked`] instead, because this
    /// boolean cannot distinguish "not revoked" from "check failed".
    pub async fn is_revoked(&self, jti: &str) -> bool {
        matches!(
            self.check_revoked(jti).await,
            RevocationCheck::Revoked
        )
    }
}

/// Hasil pemeriksaan revocasi sesi (lihat
/// [`SessionRevocation::check_revoked`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationCheck {
    Clear,
    Revoked,
    Unavailable,
}

impl RevocationCheck {
    /// True only for a positively confirmed non-revoked token. Gates
    /// reject on anything else (revoked OR unavailable).
    pub fn is_clear(self) -> bool {
        matches!(self, RevocationCheck::Clear)
    }
}

#[cfg(test)]
mod tests {
    use super::{RevocationCheck, SessionRevocation};

    #[tokio::test]
    async fn no_redis_url_means_revocation_absent_not_unavailable() {
        // Memory-only/dev mode: no URL configured -> Clear, so local
        // tests and dev servers keep working without a Redis.
        let revocation = SessionRevocation::new(None).await;
        assert_eq!(
            revocation.check_revoked("jti-apa-pun").await,
            RevocationCheck::Clear
        );
    }

    #[tokio::test]
    async fn unreachable_configured_redis_is_unavailable_not_clear() {
        // B19 trigger: Redis configured but unusable -> the gate must
        // see Unavailable, never a silent Clear. The URL uses an
        // unknown scheme on purpose: `Client::open` fails FAST on it,
        // while a refused TCP connection would make the connection
        // manager retry in the background (that path is exercised by
        // production reconnects, not by this unit test).
        let revocation =
            SessionRevocation::new(Some("bogus-scheme://127.0.0.1:9/")).await;
        assert_eq!(
            revocation.check_revoked("jti-apa-pun").await,
            RevocationCheck::Unavailable
        );
        assert!(!revocation.is_revoked("jti-apa-pun").await);
    }

    #[test]
    fn only_clear_passes_the_gate() {
        assert!(RevocationCheck::Clear.is_clear());
        assert!(!RevocationCheck::Revoked.is_clear());
        assert!(!RevocationCheck::Unavailable.is_clear());
    }
}

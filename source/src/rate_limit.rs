use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use redis::{aio::ConnectionManager, Script};
use tokio::sync::Mutex;

use crate::{error::AppError, models::RateLimitAdmission};

const WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_LUA: &str = r#"
local window_ms = tonumber(ARGV[1])
local allowed = 1
local primary_remaining = 0
local retry_after_ms = 0

for index, key in ipairs(KEYS) do
  local limit = tonumber(ARGV[index + 1])
  local current = redis.call('INCR', key)
  if current == 1 then
    redis.call('PEXPIRE', key, window_ms)
  end

  if current > limit then
    allowed = 0
    local ttl = redis.call('PTTL', key)
    if ttl > retry_after_ms then
      retry_after_ms = ttl
    end
  end

  if index == 1 then
    primary_remaining = math.max(0, limit - current)
  end
end

return {allowed, primary_remaining, retry_after_ms}
"#;

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn admit(
        &self,
        api_key_prefix: &str,
        client_ip: &str,
        api_key_limit_per_minute: u32,
    ) -> Result<RateLimitAdmission, AppError>;

    /// The current default limit (drives the per-IP limit, the global ceiling,
    /// and the fallback for newly created API keys). Adjustable live by admin.
    fn default_limit_per_minute(&self) -> u32;

    fn set_default_limit_per_minute(&self, limit: u32);
}

pub async fn build_rate_limiter(
    redis_url: Option<&str>,
    default_limit_per_minute: u32,
) -> Result<Arc<dyn RateLimiter>, AppError> {
    match redis_url {
        Some(redis_url) => {
            let limiter = RedisRateLimiter::connect(redis_url, default_limit_per_minute).await?;
            Ok(Arc::new(limiter))
        }
        None => {
            tracing::warn!(
                "Redis tidak dikonfigurasi; memakai rate limiter lokal untuk pengembangan saja"
            );
            Ok(Arc::new(LocalRateLimiter::new(default_limit_per_minute)))
        }
    }
}

pub struct RedisRateLimiter {
    // ConnectionManager is built for cheap cloning and multiplexes one shared
    // connection internally; wrapping it in a Mutex serialized every request.
    connection: ConnectionManager,
    script: Script,
    default_limit_per_minute: std::sync::atomic::AtomicU32,
}

impl RedisRateLimiter {
    pub async fn connect(redis_url: &str, default_limit_per_minute: u32) -> Result<Self, AppError> {
        let client = redis::Client::open(redis_url)
            .map_err(|_| AppError::service_unavailable("Konfigurasi Redis tidak valid"))?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| AppError::service_unavailable("Redis tidak dapat dihubungi"))?;

        Ok(Self {
            connection,
            script: Script::new(RATE_LIMIT_LUA),
            default_limit_per_minute: std::sync::atomic::AtomicU32::new(
                default_limit_per_minute.max(1),
            ),
        })
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    fn default_limit_per_minute(&self) -> u32 {
        self.default_limit_per_minute
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_default_limit_per_minute(&self, limit: u32) {
        self.default_limit_per_minute
            .store(limit.max(1), std::sync::atomic::Ordering::Relaxed);
    }

    async fn admit(
        &self,
        api_key_prefix: &str,
        client_ip: &str,
        api_key_limit_per_minute: u32,
    ) -> Result<RateLimitAdmission, AppError> {
        let api_key_limit = api_key_limit_per_minute.max(1);
        let default_limit = self.default_limit_per_minute();
        let ip_limit = default_limit.saturating_mul(3).max(api_key_limit);
        let global_limit = default_limit.saturating_mul(100).max(1_000);
        let minute_bucket = UtcMinuteBucket::current();
        let safe_ip = sanitize_segment(client_ip);

        let mut connection = self.connection.clone();
        let values: Vec<i64> = self
            .script
            .key(format!("rl:api_key:{minute_bucket}:{api_key_prefix}"))
            .key(format!("rl:ip:{minute_bucket}:{safe_ip}"))
            .key(format!("rl:global:{minute_bucket}"))
            .arg(WINDOW.as_millis() as i64)
            .arg(api_key_limit as i64)
            .arg(ip_limit as i64)
            .arg(global_limit as i64)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| {
                tracing::error!(error = ?error, "Redis rate limiter gagal");
                AppError::service_unavailable(
                    "Layanan pembatasan trafik sedang tidak tersedia. Silakan ulangi beberapa saat lagi.",
                )
            })?;

        let allowed = values.first().copied().unwrap_or_default() == 1;
        let remaining = values.get(1).copied().unwrap_or_default().max(0) as u32;
        let retry_after_seconds = values
            .get(2)
            .copied()
            .unwrap_or_default()
            .max(0)
            .div_euclid(1_000) as u64
            + 1;

        Ok(RateLimitAdmission {
            allowed,
            remaining,
            retry_after_seconds,
        })
    }
}

struct LocalWindow {
    started_at: Instant,
    count: u32,
}

/// Local limiter is intentionally limited to development/test mode. Production requires Redis
/// to coordinate enforcement across horizontally scaled API replicas.
pub struct LocalRateLimiter {
    windows: Mutex<HashMap<String, LocalWindow>>,
    default_limit_per_minute: std::sync::atomic::AtomicU32,
}

impl LocalRateLimiter {
    pub fn new(default_limit_per_minute: u32) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            default_limit_per_minute: std::sync::atomic::AtomicU32::new(
                default_limit_per_minute.max(1),
            ),
        }
    }

    async fn consume(&self, key: String, limit: u32) -> (bool, u32, u64) {
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        let entry = windows.entry(key).or_insert(LocalWindow {
            started_at: now,
            count: 0,
        });
        if now.duration_since(entry.started_at) >= WINDOW {
            entry.started_at = now;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        let allowed = entry.count <= limit;
        let remaining = limit.saturating_sub(entry.count);
        let retry_after_seconds = WINDOW
            .saturating_sub(now.duration_since(entry.started_at))
            .as_secs()
            .saturating_add(1);
        (allowed, remaining, retry_after_seconds)
    }
}

#[async_trait]
impl RateLimiter for LocalRateLimiter {
    fn default_limit_per_minute(&self) -> u32 {
        self.default_limit_per_minute
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_default_limit_per_minute(&self, limit: u32) {
        self.default_limit_per_minute
            .store(limit.max(1), std::sync::atomic::Ordering::Relaxed);
    }

    async fn admit(
        &self,
        api_key_prefix: &str,
        client_ip: &str,
        api_key_limit_per_minute: u32,
    ) -> Result<RateLimitAdmission, AppError> {
        let minute = UtcMinuteBucket::current();
        let (api_key_allowed, remaining, api_key_retry_after_seconds) = self
            .consume(
                format!("api_key:{minute}:{api_key_prefix}"),
                api_key_limit_per_minute.max(1),
            )
            .await;
        let (ip_allowed, _, ip_retry_after_seconds) = self
            .consume(
                format!("ip:{minute}:{}", sanitize_segment(client_ip)),
                self.default_limit_per_minute()
                    .saturating_mul(3)
                    .max(api_key_limit_per_minute),
            )
            .await;
        let (global_allowed, _, global_retry_after_seconds) = self
            .consume(
                format!("global:{minute}"),
                self.default_limit_per_minute()
                    .saturating_mul(100)
                    .max(1_000),
            )
            .await;

        Ok(RateLimitAdmission {
            allowed: api_key_allowed && ip_allowed && global_allowed,
            remaining,
            retry_after_seconds: api_key_retry_after_seconds
                .max(ip_retry_after_seconds)
                .max(global_retry_after_seconds),
        })
    }
}

struct UtcMinuteBucket;

impl UtcMinuteBucket {
    fn current() -> i64 {
        chrono::Utc::now().timestamp().div_euclid(60)
    }
}

fn sanitize_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '-')
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalRateLimiter, RateLimiter};

    #[tokio::test]
    async fn default_limit_change_applies_live_to_ip_bucket() {
        let limiter = LocalRateLimiter::new(60);
        assert_eq!(limiter.default_limit_per_minute(), 60);
        limiter.set_default_limit_per_minute(1);
        assert_eq!(limiter.default_limit_per_minute(), 1);
        // IP bucket = max(default*3, key limit) = 3/minute here (key limit 2).
        for index in 0..3 {
            let admission = limiter
                .admit(&format!("key-{index}"), "203.0.113.9", 2)
                .await
                .expect("admission evaluates");
            assert!(admission.allowed, "request {index} within IP bucket");
        }
        let fourth = limiter
            .admit("key-lain", "203.0.113.9", 2)
            .await
            .expect("admission evaluates");
        assert!(
            !fourth.allowed,
            "4th request from same IP exceeds default*3"
        );
        // A different IP is unaffected.
        let other_ip = limiter
            .admit("key-lain", "203.0.113.10", 2)
            .await
            .expect("admission evaluates");
        assert!(other_ip.allowed);
    }
}

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
/// Sliding-window limiter (K7, menggantikan fixed-window menit kalender).
/// Dulu kunci memakai bucket menit kalender (`timestamp/60`) dengan
/// `INCR` sebelum cek batas, sehingga burst di perbatasan menit bisa
/// mencapai ~2x limit dalam jendela geser 60 detik, dan request yang
/// ditolak satu bucket tetap membakar bucket lain. Kini tiap kunci
/// menyimpan log timestamp (sorted set) 60 detik terakhir: hitung dulu
/// SEMUA bucket, dan catat timestamp baru HANYA bila semua bucket
/// mengizinkan — request yang ditolak tidak mengonsumsi apa pun, dan
/// jendela berjalan mengikuti waktu nyata, bukan batas menit kalender.
/// Limit per menit, penolakan di atas limit, dan bentuk hasil
/// (`allowed`/`remaining`/`retry_after`) tidak berubah.
const RATE_LIMIT_LUA: &str = r#"
local window_ms = tonumber(ARGV[1])
local now_ms = tonumber(ARGV[2])
local member = ARGV[3]
local cutoff = now_ms - window_ms
local allowed = 1
local primary_remaining = 0
local retry_after_ms = 0
local counts = {}

for index, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
  local count = redis.call('ZCARD', key)
  counts[index] = count
  local limit = tonumber(ARGV[index + 3])
  if count >= limit then
    allowed = 0
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    if #oldest >= 2 then
      local wait = tonumber(oldest[2]) + window_ms - now_ms
      if wait > retry_after_ms then
        retry_after_ms = wait
      end
    end
  end
end

if allowed == 1 then
  for index, key in ipairs(KEYS) do
    redis.call('ZADD', key, now_ms, member)
    redis.call('PEXPIRE', key, window_ms)
  end
  primary_remaining = math.max(0, tonumber(ARGV[4]) - counts[1] - 1)
else
  primary_remaining = math.max(0, tonumber(ARGV[4]) - counts[1])
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
        let safe_ip = sanitize_segment(client_ip);
        // Timestamp + ID unik per percobaan: anggota sorted set harus
        // unik agar dua admit dalam milidetik yang sama tidak saling
        // menimpa (ZADD dengan anggota sama hanya memperbarui skor).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0);
        let member = format!("{now_ms}:{}", uuid::Uuid::now_v7());

        let mut connection = self.connection.clone();
        let values: Vec<i64> = self
            .script
            .key(format!("rl:sw:api_key:{api_key_prefix}"))
            .key(format!("rl:sw:ip:{safe_ip}"))
            .key(format!("rl:sw:global"))
            .arg(WINDOW.as_millis() as i64)
            .arg(now_ms)
            .arg(member)
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

/// Local limiter is intentionally limited to development/test mode. Production requires Redis
/// to coordinate enforcement across horizontally scaled API replicas.
/// Cerminan lokal skrip Lua sliding-window di atas: tiap kunci menyimpan
/// deque timestamp 60 detik terakhir; entri basi di-prune tiap admit,
/// dan timestamp baru dicatat HANYA bila semua bucket mengizinkan.
pub struct LocalRateLimiter {
    windows: Mutex<HashMap<String, std::collections::VecDeque<Instant>>>,
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
        let api_key_limit = api_key_limit_per_minute.max(1);
        let ip_limit = self
            .default_limit_per_minute()
            .saturating_mul(3)
            .max(api_key_limit);
        let global_limit = self
            .default_limit_per_minute()
            .saturating_mul(100)
            .max(1_000);
        let keys = [
            (format!("api_key:{api_key_prefix}"), api_key_limit),
            (format!("ip:{}", sanitize_segment(client_ip)), ip_limit),
            ("global".to_owned(), global_limit),
        ];
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        // Fase 1: prune + hitung semua bucket (jendela geser 60 detik).
        let mut counts = Vec::with_capacity(keys.len());
        let mut allowed = true;
        let mut retry_after_seconds = 0u64;
        for (key, limit) in &keys {
            let deque = windows.entry(key.clone()).or_default();
            while let Some(oldest) = deque.front() {
                if now.duration_since(*oldest) >= WINDOW {
                    deque.pop_front();
                } else {
                    break;
                }
            }
            let count = deque.len() as u32;
            counts.push(count);
            if count >= *limit {
                allowed = false;
                if let Some(oldest) = deque.front() {
                    let wait = WINDOW
                        .saturating_sub(now.duration_since(*oldest))
                        .as_secs()
                        .saturating_add(1);
                    retry_after_seconds = retry_after_seconds.max(wait);
                }
            }
        }
        // Fase 2: catat HANYA bila semua bucket mengizinkan — request
        // yang ditolak tidak mengonsumsi bucket mana pun.
        if allowed {
            for (key, _) in &keys {
                windows.entry(key.clone()).or_default().push_back(now);
            }
        }
        let remaining = api_key_limit.saturating_sub(counts[0] + u32::from(allowed));
        Ok(RateLimitAdmission {
            allowed,
            remaining,
            retry_after_seconds,
        })
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

    #[tokio::test]
    async fn sliding_window_denied_requests_consume_nothing() {
        // K7: request yang ditolak tidak boleh menggerus bucket — deque
        // harus berhenti di limit, bukan terus membengkak tiap deny.
        let limiter = LocalRateLimiter::new(60);
        for _ in 0..2 {
            let admission = limiter
                .admit("key-x", "203.0.113.20", 2)
                .await
                .expect("admission evaluates");
            assert!(admission.allowed);
        }
        for _ in 0..5 {
            let admission = limiter
                .admit("key-x", "203.0.113.20", 2)
                .await
                .expect("admission evaluates");
            assert!(!admission.allowed);
            assert_eq!(admission.remaining, 0);
            assert!(admission.retry_after_seconds > 0);
        }
        let windows = limiter.windows.lock().await;
        assert_eq!(
            windows
                .get("api_key:key-x")
                .map(std::collections::VecDeque::len),
            Some(2),
            "denied requests must not append to the window log"
        );
    }

    #[tokio::test]
    async fn sliding_window_prunes_entries_older_than_window() {
        // K7: entri lebih tua dari 60 detik tidak lagi menghitung —
        // jendela berjalan, bukan bucket menit kalender.
        use super::{Instant, WINDOW};
        let limiter = LocalRateLimiter::new(60);
        {
            let mut windows = limiter.windows.lock().await;
            let mut deque = std::collections::VecDeque::new();
            deque.push_back(Instant::now() - WINDOW - std::time::Duration::from_secs(1));
            deque.push_back(Instant::now() - WINDOW - std::time::Duration::from_secs(1));
            windows.insert("api_key:key-tua".to_owned(), deque);
        }
        let admission = limiter
            .admit("key-tua", "203.0.113.21", 2)
            .await
            .expect("admission evaluates");
        assert!(admission.allowed, "stale entries must be pruned first");
        assert_eq!(admission.remaining, 1);
    }
}

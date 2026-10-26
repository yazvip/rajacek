//! Concurrency, pacing, and health protection for outbound provider
//! (Tukangcek) calls, with settings that can be changed live from the admin
//! panel.
//!
//! The pacing gate is per upstream host, because a provider's rate limit
//! applies per account and one account maps to one host: consecutive hits to
//! the SAME host start at least `pace_interval_ms` apart (334 ms ≈ max 3
//! hits/second per host), while a different host paces independently. Bank
//! and e-wallet legs that share one host (one account) still share one slot
//! clock. Callers whose slot lies beyond `pace_max_wait_ms` are shed with 429.
//!
//! Two further mechanisms are keyed per validation product:
//!
//! 1. **Semaphore** — at most `max_concurrency_per_product` calls per product may be
//!    in flight at once (PLN excepted: it has its own cap
//!    `max_concurrency_pln`, default 3). Additional callers wait up to `queue_wait_ms` for a slot;
//!    after that they are rejected with 429 instead of piling onto the provider.
//! 2. **Circuit breaker (per server)** — after `failure_threshold` consecutive
//!    provider failures (transport errors, HTTP 429, or HTTP 5xx) the circuit for
//!    that ENDPOINT opens for `cooldown_seconds`: the endpoint is skipped (races
//!    use the remaining healthy servers) and only when every server of a product
//!    is open do calls fail fast with 503. After the cooldown exactly one probe
//!    call is let through; its success closes the circuit, its failure re-opens
//!    it for another cooldown.
//!
//! Client/config problems (unknown bank code, unconfigured endpoint, HTTP 400/401)
//! are recorded as *neutral*: they neither trip nor reset the breaker.
//!
//! All four numbers live in a `RwLock<ProviderGuardConfig>` and the semaphore
//! capacity is dynamic, so `update_config` takes effect immediately — no restart.
//! Environment variables only seed the initial values.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, RwLock},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::{error::AppError, models::ValidationProduct};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct ProviderGuardConfig {
    pub max_concurrency_per_product: u32,
    /// Dedicated concurrency cap for PLN (B24): the four products have
    /// separate semaphores, but they used to share this single value, so
    /// there was no PLN-specific limit at all. PLN keeps its own slot
    /// count (default 3, conservative for the Chikamm upstream); the
    /// other three products keep sharing max_concurrency_per_product.
    #[serde(default = "default_max_concurrency_pln")]
    pub max_concurrency_pln: u32,
    pub queue_wait_ms: u64,
    pub failure_threshold: u32,
    pub cooldown_seconds: u64,
    /// Total attempts per member request against the provider (1 = no retry).
    /// Only transient failures are retried; persisted configs from before this
    /// field existed deserialize to the default of 2.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Minimum spacing between consecutive provider hits across ALL products
    /// (the provider's rate limit is per account, not per product). 334 ms
    /// caps the outbound rate at 3 hits/second; 0 disables pacing.
    #[serde(default = "default_pace_interval_ms")]
    pub pace_interval_ms: u64,
    /// How long a caller may wait for its pacing slot before the request is
    /// rejected with 429 instead of queueing without bound.
    #[serde(default = "default_pace_max_wait_ms")]
    pub pace_max_wait_ms: u64,
}

fn default_max_attempts() -> u32 {
    2
}

fn default_max_concurrency_pln() -> u32 {
    3
}

fn default_pace_interval_ms() -> u64 {
    334
}

fn default_pace_max_wait_ms() -> u64 {
    10_000
}

impl Default for ProviderGuardConfig {
    fn default() -> Self {
        Self {
            max_concurrency_per_product: 16,
            max_concurrency_pln: default_max_concurrency_pln(),
            queue_wait_ms: 2_000,
            failure_threshold: 5,
            cooldown_seconds: 30,
            max_attempts: default_max_attempts(),
            pace_interval_ms: default_pace_interval_ms(),
            pace_max_wait_ms: default_pace_max_wait_ms(),
        }
    }
}

impl ProviderGuardConfig {
    /// Range checks shared by the admin API. Startup env parsing rejects zero for
    /// the structural values; the panel enforces the full operating ranges.
    pub fn validate_for_admin(&self) -> Result<(), AppError> {
        if !(1..=128).contains(&self.max_concurrency_per_product) {
            return Err(AppError::bad_request(
                "Konkurensi maks per produk harus antara 1 dan 128",
            ));
        }
        if !(1..=128).contains(&self.max_concurrency_pln) {
            return Err(AppError::bad_request(
                "Konkurensi maks PLN harus antara 1 dan 128",
            ));
        }
        if self.queue_wait_ms > 10_000 {
            return Err(AppError::bad_request("Tunggu antre maks 10000 ms"));
        }
        if !(1..=50).contains(&self.failure_threshold) {
            return Err(AppError::bad_request(
                "Ambang kegagalan circuit breaker harus antara 1 dan 50",
            ));
        }
        if !(1..=600).contains(&self.cooldown_seconds) {
            return Err(AppError::bad_request(
                "Cooldown circuit breaker harus antara 1 dan 600 detik",
            ));
        }
        if !(1..=3).contains(&self.max_attempts) {
            return Err(AppError::bad_request(
                "Maks percobaan per request harus antara 1 dan 3",
            ));
        }
        if self.pace_interval_ms > 5_000 {
            return Err(AppError::bad_request(
                "Jarak antar hit provider harus antara 0 dan 5000 ms",
            ));
        }
        if self.pace_max_wait_ms > 60_000 {
            return Err(AppError::bad_request(
                "Tunggu antre pacer harus antara 0 dan 60000 ms",
            ));
        }
        Ok(())
    }
}

/// Snapshot of ONE endpoint's breaker, for the per-route health table
/// (AREA 2). Per-product aggregation (`status()`) cannot show which route
/// is open; this does. `circuit` is "closed" | "open" | "half_open":
/// open while the cooldown is still running, half_open once the cooldown
/// has elapsed and the next call is the probe (or a probe is in flight).
#[derive(Clone, Debug, Serialize)]
pub struct GuardEndpointStatus {
    pub endpoint_id: String,
    pub product: ValidationProduct,
    pub circuit: &'static str,
    pub consecutive_failures: u32,
}

/// Snapshot of one product's guard state, shown in the admin panel.
#[derive(Clone, Debug, Serialize)]
pub struct GuardProductStatus {
    pub product: ValidationProduct,
    pub circuit: &'static str, // "closed" | "open" | "half_open"
    pub consecutive_failures: u32,
    pub in_flight: u32,
    pub max_concurrency: u32,
}

/// Dynamic-capacity counting semaphore: `max` can change while calls are in
/// flight. Raising the max wakes queued callers; lowering it never cancels
/// in-flight calls — new ones simply wait until `in_flight < max` again.
struct DynSemaphore {
    state: StdMutex<DynState>,
    notify: Notify,
}

#[derive(Clone, Copy)]
struct DynState {
    max: u32,
    in_flight: u32,
}

struct DynPermit {
    semaphore: Arc<DynSemaphore>,
}

impl DynSemaphore {
    fn new(max: u32) -> Arc<Self> {
        Arc::new(Self {
            state: StdMutex::new(DynState {
                max: max.max(1),
                in_flight: 0,
            }),
            notify: Notify::new(),
        })
    }

    fn in_flight_and_max(&self) -> (u32, u32) {
        let state = self.state.lock().expect("semaphore state lock");
        (state.in_flight, state.max)
    }

    fn set_max(&self, max: u32) {
        {
            let mut state = self.state.lock().expect("semaphore state lock");
            state.max = max.max(1);
        }
        self.notify.notify_waiters();
    }

    async fn acquire(self: &Arc<Self>, wait: Duration) -> Option<DynPermit> {
        let deadline = Instant::now() + wait;
        loop {
            {
                let mut state = self.state.lock().expect("semaphore state lock");
                if state.in_flight < state.max {
                    state.in_flight += 1;
                    return Some(DynPermit {
                        semaphore: self.clone(),
                    });
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            // Notify uses permit semantics for notify_one, and set_max/release use
            // notify_waiters/notify_one, so a wakeup racing this registration is
            // not lost.
            if tokio::time::timeout(remaining, self.notify.notified())
                .await
                .is_err()
            {
                return None;
            }
        }
    }
}

impl Drop for DynPermit {
    fn drop(&mut self) {
        {
            let mut state = self.semaphore.state.lock().expect("semaphore state lock");
            state.in_flight = state.in_flight.saturating_sub(1);
        }
        self.semaphore.notify.notify_one();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    Normal,
    Probe,
}

/// How long a half-open probe lease lasts. A probe call that never reports
/// back (its future was dropped when a race finished early) must not wedge
/// the endpoint forever: after this lease another probe may take over. Real
/// calls finish far sooner (endpoint timeout × attempts stays under ~30 s).
const PROBE_LEASE: Duration = Duration::from_secs(120);

#[derive(Default)]
struct BreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
    probe_since: Option<Instant>,
}

impl BreakerState {
    fn probe_active(&self, now: Instant) -> bool {
        self.probe_since
            .is_some_and(|since| now.saturating_duration_since(since) < PROBE_LEASE)
    }
}

/// One endpoint's breaker, tagged with its product for status aggregation.
struct EndpointBreaker {
    product: ValidationProduct,
    state: BreakerState,
}

/// A held slot. The permit is released when the ticket drops; the caller must
/// report the call outcome exactly once through one of the `record_*` methods.
pub struct GuardTicket {
    _permit: DynPermit,
    admission: Admission,
    endpoint_id: String,
    product: ValidationProduct,
}

pub struct ProviderGuard {
    config: RwLock<ProviderGuardConfig>,
    semaphores: [Arc<DynSemaphore>; 4],
    /// Circuit breakers keyed by endpoint (server) id, created on first use.
    endpoint_breakers: Mutex<HashMap<String, EndpointBreaker>>,
    /// Next free start slot per upstream host (lowercased). Keys are
    /// admin-configured endpoint hosts, so the set is bounded by the
    /// endpoint catalog; entries whose slot is in the past are pruned on
    /// each call, so only hosts with an outstanding reservation stay.
    pace_slots: StdMutex<HashMap<String, Instant>>,
}

fn product_index(product: ValidationProduct) -> usize {
    match product {
        ValidationProduct::BankAccount => 0,
        ValidationProduct::Ewallet => 1,
        ValidationProduct::Whatsapp => 2,
        // New product, new slot: PLN gets its own per-product semaphore
        // and breaker partition like every other product (added with the
        // Pln variant; the array below must stay in this exact order).
        ValidationProduct::Pln => 3,
    }
}

const PRODUCTS: [ValidationProduct; 4] = [
    ValidationProduct::BankAccount,
    ValidationProduct::Ewallet,
    ValidationProduct::Whatsapp,
    ValidationProduct::Pln,
];

impl ProviderGuard {
    /// Effective semaphore capacity for one product (B24): PLN has its
    /// own cap; every other product shares the global per-product cap.
    /// This is the single place the admission path reads a capacity
    /// from, so the per-product split cannot silently collapse back
    /// to one shared value.
    fn concurrency_for(config: &ProviderGuardConfig, product: ValidationProduct) -> u32 {
        match product {
            ValidationProduct::Pln => config.max_concurrency_pln,
            _ => config.max_concurrency_per_product,
        }
    }

    pub fn new(config: ProviderGuardConfig) -> Self {
        Self {
            semaphores: [
                DynSemaphore::new(config.max_concurrency_per_product),
                DynSemaphore::new(config.max_concurrency_per_product),
                DynSemaphore::new(config.max_concurrency_per_product),
                DynSemaphore::new(config.max_concurrency_pln),
            ],
            endpoint_breakers: Mutex::new(HashMap::new()),
            pace_slots: StdMutex::new(HashMap::new()),
            config: RwLock::new(config),
        }
    }

    pub fn config(&self) -> ProviderGuardConfig {
        *self.config.read().expect("guard config lock")
    }

    /// Applies new settings immediately: semaphore capacities are resized and
    /// breaker parameters are read live from the shared config from now on.
    /// In-flight calls are never interrupted.
    pub fn update_config(&self, config: ProviderGuardConfig) {
        {
            let mut stored = self.config.write().expect("guard config lock");
            *stored = config;
        }
        for (index, product) in PRODUCTS.iter().enumerate() {
            self.semaphores[index].set_max(Self::concurrency_for(&config, *product));
        }
        tracing::info!(
            max_concurrency = config.max_concurrency_per_product,
            max_concurrency_pln = config.max_concurrency_pln,
            queue_wait_ms = config.queue_wait_ms,
            failure_threshold = config.failure_threshold,
            cooldown_seconds = config.cooldown_seconds,
            "Pengaturan provider guard diperbarui"
        );
    }

    pub async fn status(&self) -> Vec<GuardProductStatus> {
        let now = Instant::now();
        let breakers = self.endpoint_breakers.lock().await;
        let mut statuses = Vec::with_capacity(3);
        for (index, product) in PRODUCTS.iter().enumerate() {
            // Aggregate the product's per-server breakers: "open" only when
            // EVERY known server is open; any impaired server shows as
            // half_open (the product still serves via the healthy ones).
            let mut any = false;
            let mut any_open = false;
            let mut all_open = true;
            let mut any_half = false;
            let mut max_failures = 0;
            for entry in breakers.values().filter(|entry| entry.product == *product) {
                any = true;
                max_failures = max_failures.max(entry.state.consecutive_failures);
                match entry.state.open_until {
                    Some(until) if until > now => any_open = true,
                    Some(_) => {
                        any_half = true;
                        all_open = false;
                    }
                    None => all_open = false,
                }
            }
            let circuit = if any && all_open && any_open {
                "open"
            } else if any_open || any_half {
                "half_open"
            } else {
                "closed"
            };
            let (in_flight, max) = self.semaphores[index].in_flight_and_max();
            statuses.push(GuardProductStatus {
                product: *product,
                circuit,
                consecutive_failures: max_failures,
                in_flight,
                max_concurrency: max,
            });
        }
        statuses
    }

    /// Per-endpoint breaker snapshot for the admin health endpoint
    /// (AREA 2). Read-only: it never creates breaker entries, so routes
    /// that never served traffic simply do not appear (the caller maps
    /// them to "closed").
    pub async fn endpoint_snapshot(&self) -> Vec<GuardEndpointStatus> {
        let now = Instant::now();
        let breakers = self.endpoint_breakers.lock().await;
        breakers
            .iter()
            .map(|(endpoint_id, entry)| {
                let circuit = match entry.state.open_until {
                    Some(until) if until > now => "open",
                    Some(_) => "half_open",
                    None => "closed",
                };
                GuardEndpointStatus {
                    endpoint_id: endpoint_id.clone(),
                    product: entry.product,
                    circuit,
                    consecutive_failures: entry.state.consecutive_failures,
                }
            })
            .collect()
    }

    /// Checks the circuit OF THIS ENDPOINT, then waits (bounded) for a
    /// product concurrency slot. Each in-flight upstream attempt holds its
    /// own slot, so a race over two servers takes two permits.
    pub async fn acquire(
        &self,
        product: ValidationProduct,
        endpoint_id: &str,
    ) -> Result<GuardTicket, AppError> {
        let index = product_index(product);
        let admission = {
            let mut breakers = self.endpoint_breakers.lock().await;
            let entry = breakers
                .entry(endpoint_id.to_owned())
                .or_insert_with(|| EndpointBreaker {
                    product,
                    state: BreakerState::default(),
                });
            let breaker = &mut entry.state;
            match breaker.open_until {
                Some(until) if until > Instant::now() => {
                    return Err(AppError::service_unavailable(format!(
                        "Provider untuk {product} sedang tidak tersedia (circuit breaker terbuka). Silakan coba kembali sesaat lagi.",
                        product = product.label_id()
                    )));
                }
                Some(_) => {
                    if breaker.probe_active(Instant::now()) {
                        return Err(AppError::service_unavailable(format!(
                            "Provider untuk {product} sedang diuji kembali (circuit breaker setengah terbuka). Silakan coba kembali sesaat lagi.",
                            product = product.label_id()
                        )));
                    }
                    breaker.probe_since = Some(Instant::now());
                    Admission::Probe
                }
                None => Admission::Normal,
            }
        };

        let queue_wait_ms = self.config().queue_wait_ms;
        match self.semaphores[index]
            .acquire(Duration::from_millis(queue_wait_ms))
            .await
        {
            Some(permit) => Ok(GuardTicket {
                _permit: permit,
                admission,
                endpoint_id: endpoint_id.to_owned(),
                product,
            }),
            None => {
                if admission == Admission::Probe {
                    let mut breakers = self.endpoint_breakers.lock().await;
                    if let Some(entry) = breakers.get_mut(endpoint_id) {
                        entry.state.probe_since = None;
                    }
                }
                Err(AppError::too_many_requests(
                    format!(
                        "Antrean provider untuk {product} penuh. Silakan coba kembali sesaat lagi.",
                        product = product.label_id()
                    ),
                    2,
                ))
            }
        }
    }

    /// Global pacing gate: reserves the next provider-hit start slot and
    /// sleeps until it arrives, so outbound hits stay spaced by
    /// `pace_interval_ms` across all products combined (334 ms = at most
    /// 3 hits/second, the provider's account limit). Callers whose slot is
    /// further out than `pace_max_wait_ms` are rejected with 429 — the queue
    /// sheds load instead of growing without bound. Every provider attempt,
    /// retries included, must pass through here.
    /// Reserve the next start slot for one hit to `host`. The slot clock is
    /// per host (see the module docs): two hosts never block each other,
    /// two hits to the same host are spaced by `pace_interval_ms`.
    pub async fn pace(&self, host: &str) -> Result<(), AppError> {
        let config = self.config();
        if config.pace_interval_ms == 0 {
            return Ok(());
        }
        let interval = Duration::from_millis(config.pace_interval_ms);
        let max_wait = Duration::from_millis(config.pace_max_wait_ms);
        let wait = {
            let now = Instant::now();
            let mut slots = self.pace_slots.lock().expect("pace slot lock");
            slots.retain(|_, slot| *slot > now);
            let key = host.to_ascii_lowercase();
            let slot = slots.get(&key).copied().unwrap_or(now).max(now);
            let wait = slot.saturating_duration_since(now);
            if wait > max_wait {
                return Err(AppError::too_many_requests(
                    "Antrean panggilan ke provider penuh. Silakan coba kembali sesaat lagi.",
                    (wait.as_secs() + 1).min(60),
                ));
            }
            slots.insert(key, slot + interval);
            wait
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        Ok(())
    }

    /// Admin override: force this endpoint's circuit closed and forget its
    /// failure history. Triggered when an admin switches the server on —
    /// the explicit human decision outranks the automatic cooldown, so the
    /// server is usable again immediately, no 30 s wait.
    pub async fn reset_endpoint(&self, endpoint_id: &str) {
        self.endpoint_breakers.lock().await.remove(endpoint_id);
    }

    /// The endpoint answered with a processable response (any normalized outcome).
    pub async fn record_success(&self, ticket: &GuardTicket) {
        let mut breakers = self.endpoint_breakers.lock().await;
        if let Some(entry) = breakers.get_mut(&ticket.endpoint_id) {
            entry.state.consecutive_failures = 0;
            entry.state.open_until = None;
            if ticket.admission == Admission::Probe {
                entry.state.probe_since = None;
            }
        }
    }

    /// The endpoint failed in a way that reflects its health: transport error,
    /// timeout, HTTP 429, or HTTP 5xx (including unreadable/unmappable bodies).
    pub async fn record_failure(&self, ticket: &GuardTicket) {
        let config = self.config();
        let mut breakers = self.endpoint_breakers.lock().await;
        let Some(entry) = breakers.get_mut(&ticket.endpoint_id) else {
            return;
        };
        let breaker = &mut entry.state;
        // AREA 3 trigger (b): alert HANYA pada transisi baru terbuka —
        // circuit yang sudah terbuka tidak mengulang alert tiap failure.
        let was_open = breaker
            .open_until
            .is_some_and(|until| until > Instant::now());
        if ticket.admission == Admission::Probe {
            breaker.probe_since = None;
            breaker.open_until =
                Some(Instant::now() + Duration::from_secs(config.cooldown_seconds.max(1)));
            breaker.consecutive_failures = config.failure_threshold.max(1);
            tracing::warn!(
                product = ticket.product.as_str(),
                endpoint = %ticket.endpoint_id,
                "Probe circuit breaker gagal; circuit dibuka kembali"
            );
            if !was_open {
                crate::alerts::alert(
                    "Circuit breaker provider terbuka",
                    &format!(
                        "Probe ulang untuk {} gagal; circuit dibuka kembali.",
                        ticket.product.as_str()
                    ),
                );
            }
            return;
        }
        breaker.consecutive_failures += 1;
        if breaker.consecutive_failures >= config.failure_threshold.max(1) {
            breaker.open_until =
                Some(Instant::now() + Duration::from_secs(config.cooldown_seconds.max(1)));
            tracing::warn!(
                product = ticket.product.as_str(),
                endpoint = %ticket.endpoint_id,
                failures = breaker.consecutive_failures,
                cooldown_seconds = config.cooldown_seconds,
                "Circuit breaker provider dibuka"
            );
            if !was_open {
                crate::alerts::alert(
                    "Circuit breaker provider terbuka",
                    &format!(
                        "Provider untuk {} tidak tersedia: {} kegagalan beruntun, circuit terbuka selama {} detik.",
                        ticket.product.as_str(),
                        breaker.consecutive_failures,
                        config.cooldown_seconds.max(1)
                    ),
                );
            }
        }
    }

    /// The call ended for a reason unrelated to provider health (client/config
    /// error). Only releases a held probe slot; counters stay untouched.
    pub async fn record_neutral(&self, ticket: &GuardTicket) {
        if ticket.admission == Admission::Probe {
            let mut breakers = self.endpoint_breakers.lock().await;
            if let Some(entry) = breakers.get_mut(&ticket.endpoint_id) {
                entry.state.probe_since = None;
            }
        }
    }

    #[cfg(test)]
    async fn is_open(&self, endpoint_id: &str) -> bool {
        let breakers = self.endpoint_breakers.lock().await;
        breakers.get(endpoint_id).is_some_and(|entry| {
            entry
                .state
                .open_until
                .is_some_and(|until| until > Instant::now())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{default_max_concurrency_pln, ProviderGuard, ProviderGuardConfig};
    use crate::models::ValidationProduct;

    fn guard(threshold: u32, cooldown_seconds: u64, concurrency: u32) -> ProviderGuard {
        ProviderGuard::new(ProviderGuardConfig {
            max_concurrency_per_product: concurrency,
            max_concurrency_pln: default_max_concurrency_pln(),
            queue_wait_ms: 50,
            failure_threshold: threshold,
            cooldown_seconds,
            max_attempts: 2,
            pace_interval_ms: 0,
            pace_max_wait_ms: 10_000,
        })
    }

    fn paced_guard(interval_ms: u64, max_wait_ms: u64) -> ProviderGuard {
        ProviderGuard::new(ProviderGuardConfig {
            pace_interval_ms: interval_ms,
            pace_max_wait_ms: max_wait_ms,
            ..ProviderGuardConfig::default()
        })
    }

    #[tokio::test]
    async fn pacing_spaces_consecutive_hits() {
        let guard = paced_guard(120, 10_000);
        let started = std::time::Instant::now();
        guard
            .pace("tukangcek.id")
            .await
            .expect("first hit is immediate");
        guard
            .pace("tukangcek.id")
            .await
            .expect("second hit waits one interval");
        guard
            .pace("tukangcek.id")
            .await
            .expect("third hit waits another interval");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(230),
            "three hits at 120 ms spacing must take >= ~240 ms, took {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "pacing must not overshoot wildly, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn pacing_rejects_when_backlog_exceeds_max_wait() {
        let guard = paced_guard(5_000, 100);
        guard
            .pace("tukangcek.id")
            .await
            .expect("first hit reserves the slot");
        let rejected = guard.pace("tukangcek.id").await;
        assert!(
            rejected.is_err(),
            "a slot 5 s out with a 100 ms wait budget must be rejected"
        );
    }

    #[tokio::test]
    async fn pacing_disabled_with_zero_interval() {
        let guard = paced_guard(0, 0);
        let started = std::time::Instant::now();
        for _ in 0..5 {
            guard
                .pace("tukangcek.id")
                .await
                .expect("disabled pacing never blocks");
        }
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
    }

    #[tokio::test]
    async fn pacing_is_per_host_not_global() {
        // One host's backlog must never block a different provider account.
        let guard = paced_guard(5_000, 100);
        guard
            .pace("tukangcek.id")
            .await
            .expect("first hit reserves the slot");
        let other = guard.pace("api.cutiezy.id").await;
        assert!(other.is_ok(), "a different host must pace independently");
        let same = guard.pace("tukangcek.id").await;
        assert!(same.is_err(), "the same host must still be spaced");
        let case_insensitive = guard.pace("TUKANGCEK.ID").await;
        assert!(case_insensitive.is_err(), "host keys are case-insensitive");
    }

    #[tokio::test]
    async fn breaker_opens_after_threshold_and_fails_fast() {
        let guard = guard(3, 60, 4);
        for _ in 0..3 {
            let ticket = guard
                .acquire(ValidationProduct::Ewallet, "srv-ewallet")
                .await
                .expect("closed circuit admits");
            guard.record_failure(&ticket).await;
        }
        assert!(guard.is_open("srv-ewallet").await);
        assert!(
            guard
                .acquire(ValidationProduct::Ewallet, "srv-ewallet")
                .await
                .is_err(),
            "open circuit must fail fast"
        );
        assert!(
            guard
                .acquire(ValidationProduct::Ewallet, "srv-ewallet-lain")
                .await
                .is_ok(),
            "server lain produk yang sama tidak ikut tertutup"
        );
    }

    #[tokio::test]
    async fn success_resets_failure_streak() {
        let guard = guard(3, 60, 4);
        for _ in 0..2 {
            let ticket = guard
                .acquire(ValidationProduct::BankAccount, "srv-bank")
                .await
                .unwrap();
            guard.record_failure(&ticket).await;
        }
        let ticket = guard
            .acquire(ValidationProduct::BankAccount, "srv-bank")
            .await
            .unwrap();
        guard.record_success(&ticket).await;
        for _ in 0..2 {
            let ticket = guard
                .acquire(ValidationProduct::BankAccount, "srv-bank")
                .await
                .unwrap();
            guard.record_failure(&ticket).await;
        }
        assert!(!guard.is_open("srv-bank").await);
    }

    #[tokio::test]
    async fn probe_success_closes_circuit_after_cooldown() {
        let guard = guard(1, 1, 4);
        let ticket = guard
            .acquire(ValidationProduct::Whatsapp, "srv-wa")
            .await
            .unwrap();
        guard.record_failure(&ticket).await;
        assert!(guard.is_open("srv-wa").await);
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let probe = guard
            .acquire(ValidationProduct::Whatsapp, "srv-wa")
            .await
            .expect("half-open admits one probe");
        assert!(guard
            .acquire(ValidationProduct::Whatsapp, "srv-wa")
            .await
            .is_err());
        guard.record_success(&probe).await;
        assert!(!guard.is_open("srv-wa").await);
        assert!(
            guard
                .acquire(ValidationProduct::Ewallet, "srv-ewallet-lain")
                .await
                .is_ok(),
            "server lain produk yang sama tidak ikut tertutup"
        );
    }

    #[tokio::test]
    async fn probe_failure_reopens_circuit() {
        let guard = guard(1, 1, 4);
        let ticket = guard
            .acquire(ValidationProduct::BankAccount, "srv-bank")
            .await
            .unwrap();
        guard.record_failure(&ticket).await;
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let probe = guard
            .acquire(ValidationProduct::BankAccount, "srv-bank")
            .await
            .unwrap();
        guard.record_failure(&probe).await;
        assert!(guard.is_open("srv-bank").await);
    }

    #[tokio::test]
    async fn semaphore_rejects_after_queue_wait_when_full() {
        let guard = guard(5, 60, 1);
        let _held = guard
            .acquire(ValidationProduct::Ewallet, "srv-ewallet")
            .await
            .expect("first call takes the only slot");
        let started = std::time::Instant::now();
        let rejected = guard
            .acquire(ValidationProduct::Ewallet, "srv-ewallet")
            .await;
        assert!(rejected.is_err(), "full semaphore must reject after wait");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "rejection must be bounded by queue_wait_ms"
        );
    }

    #[tokio::test]
    async fn reset_endpoint_purges_breaker_entry_for_deleted_endpoint() {
        let guard = guard(1, 600, 4);
        let ticket = guard
            .acquire(ValidationProduct::BankAccount, "srv-hapus")
            .await
            .expect("circuit tertutup menerima");
        guard.record_failure(&ticket).await;
        assert!(guard.is_open("srv-hapus").await);
        // delete_provider_endpoint memakai reset_endpoint sebagai purge-nya.
        guard.reset_endpoint("srv-hapus").await;
        let snapshot = guard.endpoint_snapshot().await;
        assert!(
            !snapshot
                .iter()
                .any(|entry| entry.endpoint_id == "srv-hapus"),
            "entri breaker endpoint yang dihapus harus hilang dari snapshot"
        );
        assert!(!guard.is_open("srv-hapus").await);
    }

    #[tokio::test]
    async fn admin_reset_revives_open_endpoint_immediately() {
        let guard = guard(2, 600, 4);
        for _ in 0..2 {
            let ticket = guard
                .acquire(ValidationProduct::BankAccount, "srv-bank")
                .await
                .unwrap();
            guard.record_failure(&ticket).await;
        }
        assert!(guard.is_open("srv-bank").await);
        assert!(
            guard
                .acquire(ValidationProduct::BankAccount, "srv-bank")
                .await
                .is_err(),
            "open circuit rejects during cooldown"
        );
        guard.reset_endpoint("srv-bank").await;
        assert!(!guard.is_open("srv-bank").await);
        assert!(
            guard
                .acquire(ValidationProduct::BankAccount, "srv-bank")
                .await
                .is_ok(),
            "after an admin reset the endpoint admits at once, no cooldown"
        );
    }

    #[tokio::test]
    async fn neutral_outcome_does_not_trip_breaker() {
        let guard = guard(2, 60, 4);
        for _ in 0..4 {
            let ticket = guard
                .acquire(ValidationProduct::BankAccount, "srv-bank")
                .await
                .unwrap();
            guard.record_neutral(&ticket).await;
        }
        assert!(!guard.is_open("srv-bank").await);
    }

    #[tokio::test]
    async fn config_update_resizes_semaphore_live() {
        let guard = guard(5, 60, 1);
        let _held = guard
            .acquire(ValidationProduct::Ewallet, "srv-ewallet")
            .await
            .unwrap();
        assert!(guard
            .acquire(ValidationProduct::Ewallet, "srv-ewallet")
            .await
            .is_err());
        // Raising the limit must immediately admit another caller.
        let mut config = guard.config();
        config.max_concurrency_per_product = 2;
        guard.update_config(config);
        assert!(guard
            .acquire(ValidationProduct::Ewallet, "srv-ewallet")
            .await
            .is_ok());
        // Lowering it again must not cancel in-flight calls, only block new ones.
        config.max_concurrency_per_product = 1;
        guard.update_config(config);
        assert!(guard
            .acquire(ValidationProduct::Ewallet, "srv-ewallet")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn config_update_changes_breaker_threshold_live() {
        let guard = guard(5, 60, 4);
        let ticket = guard
            .acquire(ValidationProduct::BankAccount, "srv-bank")
            .await
            .unwrap();
        guard.record_failure(&ticket).await;
        assert!(!guard.is_open("srv-bank").await);
        let mut config = guard.config();
        config.failure_threshold = 2;
        guard.update_config(config);
        let ticket = guard
            .acquire(ValidationProduct::BankAccount, "srv-bank")
            .await
            .unwrap();
        guard.record_failure(&ticket).await;
        assert!(guard.is_open("srv-bank").await);
    }

    #[tokio::test]
    async fn pln_has_its_own_concurrency_cap_enforced_on_admission() {
        // B24 trigger: the PLN semaphore used to share the global cap, so
        // 16 concurrent PLN calls could reach one upstream host. With a
        // global cap of 16 and a PLN cap of 3, admission must stop at 3
        // PLN tickets while other products still admit up to 16 — and
        // the status endpoint must report the split.
        let guard = ProviderGuard::new(ProviderGuardConfig {
            max_concurrency_per_product: 16,
            max_concurrency_pln: 3,
            ..ProviderGuardConfig::default()
        });
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(
                guard
                    .acquire(ValidationProduct::Pln, "srv-pln")
                    .await
                    .expect("PLN admits up to its own cap"),
            );
        }
        assert!(
            guard
                .acquire(ValidationProduct::Pln, "srv-pln")
                .await
                .is_err(),
            "a 4th concurrent PLN call must be shed at the PLN cap, not the global cap"
        );
        let statuses = guard.status().await;
        let pln = statuses
            .iter()
            .find(|item| item.product == ValidationProduct::Pln)
            .expect("PLN status row");
        assert_eq!(pln.max_concurrency, 3);
        assert_eq!(pln.in_flight, 3);
        let bank = statuses
            .iter()
            .find(|item| item.product == ValidationProduct::BankAccount)
            .expect("bank status row");
        assert_eq!(bank.max_concurrency, 16);
        // Raising only the PLN cap admits another PLN caller without
        // touching the other products' caps.
        let mut config = guard.config();
        config.max_concurrency_pln = 4;
        guard.update_config(config);
        assert!(guard
            .acquire(ValidationProduct::Pln, "srv-pln")
            .await
            .is_ok());
        let statuses = guard.status().await;
        assert_eq!(
            statuses
                .iter()
                .find(|item| item.product == ValidationProduct::BankAccount)
                .expect("bank status row")
                .max_concurrency,
            16
        );
    }

    #[test]
    fn admin_validation_rejects_out_of_range_values() {
        let mut config = ProviderGuardConfig::default();
        assert!(config.validate_for_admin().is_ok());
        config.max_concurrency_per_product = 0;
        assert!(config.validate_for_admin().is_err());
        config.max_concurrency_per_product = 16;
        config.cooldown_seconds = 0;
        assert!(config.validate_for_admin().is_err());
        config.cooldown_seconds = 30;
        config.queue_wait_ms = 99_999;
        assert!(config.validate_for_admin().is_err());
        config.queue_wait_ms = 2_000;
        config.max_concurrency_pln = 0;
        assert!(config.validate_for_admin().is_err());
        config.max_concurrency_pln = 129;
        assert!(config.validate_for_admin().is_err());
        config.max_concurrency_pln = 3;
        assert!(config.validate_for_admin().is_ok());
    }
}

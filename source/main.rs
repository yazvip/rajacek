use std::{sync::Arc, time::Duration};

use anyhow::Result;
use rajacek_api::{
    api::{build_router, AppState},
    auth::OAuthStateStore,
    config::AppConfig,
    events::build_usage_event_sink,
    idempotency::build_idempotency_coordinator,
    provider::build_provider,
    provider_config::ProviderConfigStore,
    provider_guard::{ProviderGuard, ProviderGuardConfig},
    rate_limit::build_rate_limiter,
    store::AdminStore,
};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Arc::new(AppConfig::from_env()?);
    let store = Arc::new(AdminStore::new(
        config.demo_api_key.as_deref(),
        config.default_rate_limit_per_minute,
    )?);
    let provider_configs = ProviderConfigStore::build(&config).await?;
    // Attach the admin store to the same database so packages, API keys, and
    // quota counters persist across restarts (previously memory-only).
    store.attach_key_cipher(config.api_key_encryption_key.as_deref());
    if let Some(pool) = provider_configs.pool() {
        store.attach_pool(pool);
        store.load_persisted().await;
        // Multi-admin (area 7+8): seed eksplisit — semua email yang
        // sah menurut allowlist lama menjadi owner bila belum punya
        // baris admins (INSERT IGNORE, tidak menimpa peran yang sudah
        // diatur), KECUALI email yang ada di tombstone deleted_admins
        // (dihapus lewat panel, perbaikan R1 — dicek di
        // seed_legacy_admin). Fallback malas di admin_roles.rs tetap
        // berlaku bila seed ini terlewat.

        let legacy_admins: Vec<String> =
            config.admin_google_emails.iter().cloned().collect();
        store.seed_legacy_admins(&legacy_admins).await;
        // Quota snapshots persist through an ordered background writer so
        // validation responses never wait on the quota UPDATE.
        store.start_quota_writer();
    }
    let provider_guard = Arc::new(ProviderGuard::new(ProviderGuardConfig {
        max_concurrency_per_product: config.provider_max_concurrency_per_product,
        // B24: PLN gets its own conservative cap (3) from the start; the
        // env-seeded global cap never applies to it.
        max_concurrency_pln: 3,
        queue_wait_ms: config.provider_queue_wait_ms,
        failure_threshold: config.provider_breaker_failure_threshold,
        cooldown_seconds: config.provider_breaker_cooldown_seconds,
        max_attempts: 2,
        pace_interval_ms: 334,
        pace_max_wait_ms: 10_000,
    }));
    // Panel-saved settings (database) override the env-seeded defaults.
    if let Some(saved) = provider_configs.load_guard_config().await {
        provider_guard.update_config(saved);
    }
    let rate_limiter = build_rate_limiter(
        config.redis_url.as_deref(),
        config.default_rate_limit_per_minute,
    )
    .await?;
    // Panel-saved default rate limit overrides the env seed, live in both the
    // limiter buckets and the store fallback for newly created keys.
    if let Some(saved) = provider_configs
        .load_runtime_setting("rate_limit.default_per_minute")
        .await
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (1..=100_000).contains(value))
    {
        rate_limiter.set_default_limit_per_minute(saved);
        store.set_default_rate_limit_per_minute(saved);
        tracing::info!(
            default_rate_limit = saved,
            "Rate limit bawaan dimuat dari database"
        );
    }
    let state = AppState {
        rate_limiter,
        event_sink: build_usage_event_sink(
            config.redis_url.as_deref(),
            config.event_stream_name.clone(),
        )
        .await?,
        idempotency: build_idempotency_coordinator(
            config.redis_url.as_deref(),
            Duration::from_secs(config.idempotency_ttl_seconds),
        )
        .await?,
        provider: build_provider(&config, provider_configs.clone(), provider_guard.clone()),
        provider_configs,
        provider_guard: if config.is_demo_mode() {
            None
        } else {
            Some(provider_guard)
        },
        oauth_states: Arc::new(OAuthStateStore::new()),
        session_revocation: Arc::new(
            rajacek_api::session_revocation::SessionRevocation::new(
                config.redis_url.as_deref(),
            )
            .await,
        ),
        config: config.clone(),
        store: store.clone(),
    };
    let shutdown_store = store;

    if config.is_demo_mode() {
        tracing::warn!(
            "Rajacek berjalan dalam mode demo. Jangan gunakan mode ini untuk data atau trafik produksi."
        );
    }

    let listener = TcpListener::bind(&config.bind_address).await?;
    tracing::info!(
        address = %config.bind_address,
        provider_mode = if config.is_demo_mode() { "demo" } else { "http" },
        "Rajacek API siap menerima koneksi"
    );

    // Sweep rekonsiliasi order QRIS (tiap menit, di background): order
    // waiting yang lewat expiry dicek statusnya dulu sebelum ditutup,
    // dan order paid yang tertinggal tetap di-grant. Tanpa ini, order
    // yang webhook-nya hilang tidak pernah selesai.
    tokio::spawn(rajacek_api::qris::sweep_loop(
        state.store.clone(),
        state.config.clone(),
    ));

    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Drain any quota snapshots still queued behind the last responses.
    shutdown_store.stop_quota_writer().await;

    tracing::info!("Rajacek API dihentikan dengan aman");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rajacek_api=info,tower_http=info,sqlx=warn,redis=warn".into());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Handler Ctrl+C harus dapat dipasang");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Handler SIGTERM harus dapat dipasang")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

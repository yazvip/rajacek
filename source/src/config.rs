use std::{collections::HashSet, env, str::FromStr};

use anyhow::{bail, Context, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Environment {
    Development,
    Production,
    Test,
}

impl Environment {
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }

    pub fn is_development(&self) -> bool {
        matches!(self, Self::Development)
    }
}

impl FromStr for Environment {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            "test" => Ok(Self::Test),
            _ => bail!("APP_ENV harus bernilai development, production, atau test"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderMode {
    Demo,
    Http,
}

impl FromStr for ProviderMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "demo" => Ok(Self::Demo),
            "http" => Ok(Self::Http),
            _ => bail!("PROVIDER_MODE harus bernilai demo atau http"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub environment: Environment,
    pub bind_address: String,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub provider_mode: ProviderMode,
    pub provider_base_url: Option<String>,
    pub provider_api_key: Option<String>,
    pub provider_credential_key: Option<String>,
    /// Master secret for encrypting member API keys at rest so they can be
    /// shown again from the portal/admin panel. Unset = keys stay
    /// hash-only and cannot be revealed after issuance.
    pub api_key_encryption_key: Option<String>,
    pub provider_allowed_hosts: Vec<String>,
    pub request_timeout_seconds: u64,
    pub default_rate_limit_per_minute: u32,
    pub provider_max_concurrency_per_product: u32,
    pub provider_queue_wait_ms: u64,
    pub provider_breaker_failure_threshold: u32,
    pub provider_breaker_cooldown_seconds: u64,
    pub event_stream_name: String,
    pub idempotency_ttl_seconds: u64,
    pub dashboard_session_secret: Option<String>,
    pub data_fingerprint_secret: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub google_redirect_uri: Option<String>,
    pub google_member_redirect_uri: Option<String>,
    pub admin_google_emails: HashSet<String>,
    pub development_admin_token: Option<String>,
    pub demo_api_key: Option<String>,
    pub allowed_dashboard_origin: Option<String>,
    /// Base URL Cutiezy untuk pembayaran QRIS. Default produksi; env ini
    /// hanya untuk pengujian (mock lokal) dan tidak dipakai member.
    pub qris_base_url: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        // Fail closed (audit 2026-10-25, B7): the old "development"
        // default silently enabled local-login credentials, the dev
        // session-secret fallback, non-Secure cookies and demo mode
        // whenever APP_ENV went missing in production.
        let environment = read_env("APP_ENV")
            .unwrap_or_else(|| "production".to_owned())
            .parse()
            .context("APP_ENV tidak valid")?;

        let provider_mode = read_env("PROVIDER_MODE")
            .unwrap_or_else(|| "demo".to_owned())
            .parse()
            .context("PROVIDER_MODE tidak valid")?;

        let config = Self {
            environment,
            bind_address: read_env("BIND_ADDRESS").unwrap_or_else(|| "0.0.0.0:8080".to_owned()),
            database_url: read_env("DATABASE_URL"),
            redis_url: read_env("REDIS_URL"),
            provider_mode,
            provider_base_url: read_env("PROVIDER_BASE_URL"),
            provider_api_key: read_env("PROVIDER_API_KEY"),
            provider_credential_key: read_env("PROVIDER_CREDENTIAL_KEY"),
            api_key_encryption_key: read_env("API_KEY_ENCRYPTION_KEY"),
            provider_allowed_hosts: parse_list(read_env("PROVIDER_ALLOWED_HOSTS")),
            request_timeout_seconds: parse_env("REQUEST_TIMEOUT_SECONDS", 8)?,
            default_rate_limit_per_minute: parse_env("DEFAULT_RATE_LIMIT_PER_MINUTE", 60)?,
            provider_max_concurrency_per_product: parse_env(
                "PROVIDER_MAX_CONCURRENCY_PER_PRODUCT",
                16,
            )?,
            provider_queue_wait_ms: parse_env("PROVIDER_QUEUE_WAIT_MS", 2_000)?,
            provider_breaker_failure_threshold: parse_env("PROVIDER_BREAKER_FAILURE_THRESHOLD", 5)?,
            provider_breaker_cooldown_seconds: parse_env("PROVIDER_BREAKER_COOLDOWN_SECONDS", 30)?,
            event_stream_name: read_env("EVENT_STREAM_NAME")
                .unwrap_or_else(|| "validation-events".to_owned()),
            idempotency_ttl_seconds: parse_env("IDEMPOTENCY_TTL_SECONDS", 86_400)?,
            dashboard_session_secret: read_env("DASHBOARD_SESSION_SECRET"),
            data_fingerprint_secret: read_env("DATA_FINGERPRINT_SECRET"),
            google_client_id: read_env("GOOGLE_CLIENT_ID"),
            google_client_secret: read_env("GOOGLE_CLIENT_SECRET"),
            google_redirect_uri: read_env("GOOGLE_REDIRECT_URI"),
            google_member_redirect_uri: read_env("GOOGLE_MEMBER_REDIRECT_URI"),
            admin_google_emails: parse_email_set(read_env("ADMIN_GOOGLE_EMAILS")),
            development_admin_token: read_env("DEVELOPMENT_ADMIN_TOKEN"),
            demo_api_key: read_env("DEMO_API_KEY"),
            allowed_dashboard_origin: read_env("ALLOWED_DASHBOARD_ORIGIN"),
            qris_base_url: read_env("CUTIEZY_QRIS_BASE_URL")
                .unwrap_or_else(|| "https://api.cutiezy.id".to_owned()),
        };

        config.validate()?;
        Ok(config)
    }

    pub fn is_demo_mode(&self) -> bool {
        self.provider_mode == ProviderMode::Demo
    }

    pub fn google_login_is_configured(&self) -> bool {
        self.google_client_id.is_some()
            && self.google_client_secret.is_some()
            && self.google_redirect_uri.is_some()
            && self.dashboard_session_secret.is_some()
            && self.redis_url.is_some()
            && self.database_url.is_some()
    }

    /// Redirect URI for the member Google flow: the explicit env value when
    /// set, otherwise derived from the admin redirect URI by swapping its
    /// path (same origin + client). Must be registered in Google Console.
    pub fn member_redirect_uri(&self) -> Option<String> {
        if let Some(uri) = self.google_member_redirect_uri.as_deref() {
            return Some(uri.to_owned());
        }
        let admin = self.google_redirect_uri.as_deref()?;
        let mut url = url::Url::parse(admin).ok()?;
        url.set_path("/v1/auth/google/member/callback");
        Some(url.to_string())
    }

    pub fn google_member_login_is_configured(&self) -> bool {
        self.google_login_is_configured() && self.member_redirect_uri().is_some()
    }

    pub fn dashboard_cookie_secure(&self) -> bool {
        !self.environment.is_development()
    }

    fn validate(&self) -> Result<()> {
        if self.provider_max_concurrency_per_product == 0 {
            bail!("PROVIDER_MAX_CONCURRENCY_PER_PRODUCT harus lebih besar dari 0");
        }
        if self.provider_breaker_failure_threshold == 0 {
            bail!("PROVIDER_BREAKER_FAILURE_THRESHOLD harus lebih besar dari 0");
        }
        if self.provider_breaker_cooldown_seconds == 0 {
            bail!("PROVIDER_BREAKER_COOLDOWN_SECONDS harus lebih besar dari 0");
        }
        if self.request_timeout_seconds == 0 {
            bail!("REQUEST_TIMEOUT_SECONDS harus lebih besar dari 0");
        }

        if self.default_rate_limit_per_minute == 0 {
            bail!("DEFAULT_RATE_LIMIT_PER_MINUTE harus lebih besar dari 0");
        }

        if self.environment.is_production() {
            if self.database_url.is_none() {
                bail!("DATABASE_URL wajib tersedia pada mode production");
            }

            if self.redis_url.is_none() {
                bail!("REDIS_URL wajib tersedia pada mode production");
            }

            if self
                .dashboard_session_secret
                .as_deref()
                .unwrap_or_default()
                .len()
                < 32
            {
                bail!("DASHBOARD_SESSION_SECRET minimal 32 karakter pada mode production");
            }

            if self
                .data_fingerprint_secret
                .as_deref()
                .unwrap_or_default()
                .len()
                < 32
            {
                bail!("DATA_FINGERPRINT_SECRET minimal 32 karakter pada mode production");
            }

            if self.provider_mode == ProviderMode::Demo {
                bail!("PROVIDER_MODE=demo tidak boleh digunakan pada mode production");
            }

            if self.development_admin_token.is_some() {
                bail!("DEVELOPMENT_ADMIN_TOKEN tidak boleh diaktifkan pada mode production");
            }

            if self
                .provider_credential_key
                .as_deref()
                .unwrap_or_default()
                .len()
                < 32
            {
                bail!("PROVIDER_CREDENTIAL_KEY minimal 32 karakter pada mode production");
            }

            // Audit flow B6: the QRIS/webhook cipher falls back to a
            // development key printed in source when this variable is
            // missing, so production must refuse to start without a real
            // one. (The variable is currently set in production, so this
            // validation changes nothing live — it guards the next
            // rebuild/rotation against silently re-encrypting Cutiezy
            // secrets under the fallback key. Member keys are untouched
            // by this path: they already fail closed to hash-only when
            // the cipher is absent.)
            if self
                .api_key_encryption_key
                .as_deref()
                .unwrap_or_default()
                .len()
                < 32
            {
                bail!("API_KEY_ENCRYPTION_KEY minimal 32 karakter pada mode production");
            }

            if self.provider_allowed_hosts.is_empty() {
                bail!("PROVIDER_ALLOWED_HOSTS wajib diisi pada mode production");
            }
        }

        if self.provider_mode == ProviderMode::Http {
            if self.provider_base_url.is_none() {
                bail!("PROVIDER_BASE_URL wajib saat PROVIDER_MODE=http");
            }

            if self.provider_api_key.is_none() {
                bail!("PROVIDER_API_KEY wajib saat PROVIDER_MODE=http");
            }
        }

        Ok(())
    }
}

fn read_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_env<T>(name: &str, default: T) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match read_env(name) {
        Some(value) => value
            .parse::<T>()
            .with_context(|| format!("{name} memiliki nilai yang tidak valid")),
        None => Ok(default),
    }
}

fn parse_list(value: Option<String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|list| list.split(',').map(str::to_owned).collect::<Vec<_>>())
        .map(|item| item.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

fn parse_email_set(value: Option<String>) -> HashSet<String> {
    value
        .into_iter()
        .flat_map(|list| list.split(',').map(str::to_owned).collect::<Vec<_>>())
        .map(|email| email.trim().to_ascii_lowercase())
        .filter(|email| !email.is_empty())
        .collect()
}

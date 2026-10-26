use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use rand::Rng;
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client, StatusCode,
};
use serde::Serialize;
use serde_json::Value;
use tokio::time::Instant;
use url::Url;
use uuid::Uuid;

use crate::{
    bank_codes,
    config::{AppConfig, ProviderMode},
    error::AppError,
    ewallet_codes,
    models::{
        ProviderRequestMode, ProviderValidationRequest, ValidationProduct, ValidationResultData,
        ValidationStatus,
    },
    provider_config::ProviderConfigStore,
    provider_guard::ProviderGuard,
};

#[derive(Clone, Debug, Serialize)]
pub struct RawProviderResponse {
    pub http_status: u16,
    pub body: String,
    pub encoding: &'static str,
    pub truncated: bool,
    /// Which configured server produced this response. Admin-only surface:
    /// the tester shows it so the raw body is never attributed to the wrong
    /// server when several are raced.
    pub server_name: String,
}

#[derive(Clone, Debug)]
pub struct ProviderValidationOutcome {
    pub status: ValidationStatus,
    pub message: String,
    pub result: Option<ValidationResultData>,
    pub provider_name: String,
    pub provider_latency_ms: u64,
    /// Which attempt produced this outcome (1 = first try, no retry happened).
    pub attempts: u32,
}

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    async fn validate(
        &self,
        request: ProviderValidationRequest,
    ) -> Result<ProviderValidationOutcome, AppError>;

    /// Only the authenticated admin tester calls this. Never use it for public validation.
    async fn validate_for_admin(
        &self,
        _request: ProviderValidationRequest,
    ) -> Result<(ProviderValidationOutcome, RawProviderResponse), AppError> {
        Err(AppError::service_unavailable(
            "Respons mentah hanya tersedia untuk provider HTTP",
        ))
    }

    /// Admin tester aimed at one specific server. Providers without endpoint
    /// selection ignore the id and behave like `validate_for_admin`.
    async fn validate_for_admin_at(
        &self,
        _endpoint_id: Uuid,
        request: ProviderValidationRequest,
    ) -> Result<(ProviderValidationOutcome, RawProviderResponse), AppError> {
        self.validate_for_admin(request).await
    }

    fn name(&self) -> &str;
}

pub fn build_provider(
    config: &AppConfig,
    provider_configs: Arc<ProviderConfigStore>,
    guard: Arc<ProviderGuard>,
) -> Arc<dyn ProviderAdapter> {
    match config.provider_mode {
        ProviderMode::Demo => Arc::new(DemoProvider),
        ProviderMode::Http => Arc::new(HttpProvider::new(provider_configs, guard)),
    }
}

/// A deterministic, privacy-conscious development adapter. It never contacts a real data source
/// and exists so frontend, authentication, quotas, and usage flow can be tested safely.
pub struct DemoProvider;

#[async_trait]
impl ProviderAdapter for DemoProvider {
    async fn validate(
        &self,
        request: ProviderValidationRequest,
    ) -> Result<ProviderValidationOutcome, AppError> {
        let started = Instant::now();
        let digest = <sha2::Sha256 as sha2::Digest>::digest(
            format!("{}:{}", request.product.as_str(), request.target).as_bytes(),
        );
        // A tiny bounded delay intentionally reflects an upstream call without making local
        // dashboard/API interaction feel slow.
        tokio::time::sleep(Duration::from_millis(35 + u64::from(digest[0] % 65))).await;

        let selector = digest[1] % 20;
        let (status, message) = match selector {
            0 => (
                ValidationStatus::ProviderError,
                "Provider demo sedang mensimulasikan gangguan sementara.",
            ),
            1 | 2 => (
                ValidationStatus::NotFound,
                "Data tidak ditemukan pada provider demo.",
            ),
            3 => (
                ValidationStatus::Pending,
                "Provider demo memerlukan konfirmasi lanjutan.",
            ),
            _ => (
                ValidationStatus::Valid,
                "Validasi berhasil diproses dalam mode demo.",
            ),
        };

        let result = match status {
            ValidationStatus::Valid => Some(demo_result(&request, &digest)),
            ValidationStatus::NotFound | ValidationStatus::Pending => Some(ValidationResultData {
                account_number: target_fields(request.product, &request.target).0,
                phone_number: target_fields(request.product, &request.target).1,
                service_code: service_code_for(&request),
                bank_name: bank_name_for(&request),
                account_name: None,
                tarif: None,
                daya: None,
                provider: request.provider_hint.clone(),
                registered: Some(false),
                reference: Some(format!("demo-{}", Uuid::now_v7().simple())),
            }),
            _ => None,
        };

        Ok(ProviderValidationOutcome {
            status,
            message: message.to_owned(),
            result,
            provider_name: self.name().to_owned(),
            provider_latency_ms: started.elapsed().as_millis() as u64,
            attempts: 1,
        })
    }

    fn name(&self) -> &str {
        "demo-provider"
    }
}

fn demo_result(request: &ProviderValidationRequest, digest: &[u8]) -> ValidationResultData {
    let account_name = match request.product {
        ValidationProduct::BankAccount | ValidationProduct::Ewallet => {
            let labels = ["Nusantara", "Sentosa", "Pratama", "Kencana", "Mahardika"];
            Some(format!(
                "{} {}",
                labels[(digest[2] as usize) % labels.len()],
                "•••"
            ))
        }
        ValidationProduct::Whatsapp => None,
        // Demo PLN mirrors the live name shape (holder + tariff/power
        // suffix) so the demo path exercises the same result fields.
        ValidationProduct::Pln => Some("PELANGGAN DEMO - R1/1300".to_owned()),
    };

    let (tarif, daya) = match request.product {
        ValidationProduct::Pln => (Some("R1".to_owned()), Some("1300".to_owned())),
        _ => (None, None),
    };

    let (account_number, phone_number) = target_fields(request.product, &request.target);
    ValidationResultData {
        account_number,
        phone_number,
        service_code: service_code_for(request),
        bank_name: bank_name_for(request),
        account_name,
        tarif,
        daya,
        provider: request.provider_hint.clone(),
        registered: Some(true),
        reference: Some(format!(
            "demo-{}-{}",
            request.product.as_str(),
            Utc::now().format("%Y%m%d%H%M%S")
        )),
    }
}

fn target_fields(product: ValidationProduct, target: &str) -> (Option<String>, Option<String>) {
    match product {
        ValidationProduct::BankAccount | ValidationProduct::Ewallet | ValidationProduct::Pln => {
            (Some(target.to_owned()), None)
        }
        ValidationProduct::Whatsapp => (None, Some(target.to_owned())),
    }
}

fn bank_name_for(request: &ProviderValidationRequest) -> Option<String> {
    if request.product != ValidationProduct::BankAccount {
        return None;
    }
    request
        .provider_hint
        .as_deref()
        .and_then(crate::bank_codes::bank_name)
}

fn service_code_for(request: &ProviderValidationRequest) -> Option<String> {
    match request.product {
        ValidationProduct::BankAccount | ValidationProduct::Ewallet => {
            request.provider_hint.clone()
        }
        ValidationProduct::Whatsapp => Some("whatsapp".to_owned()),
        // PLN carries no provider hint (no bank code / wallet slug); the
        // fixed product code plays the same role as "whatsapp" above.
        ValidationProduct::Pln => Some("pln".to_owned()),
    }
}

pub struct HttpProvider {
    client: Client,
    provider_configs: Arc<ProviderConfigStore>,
    guard: Arc<ProviderGuard>,
}

impl HttpProvider {
    fn new(provider_configs: Arc<ProviderConfigStore>, guard: Arc<ProviderGuard>) -> Self {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("rajacek-api/0.1")
            .build()
            .expect("Reqwest client dapat dibuat dengan konfigurasi valid");
        Self {
            client,
            provider_configs,
            guard,
        }
    }

    /// Admission happens per server inside the race (each endpoint has its
    /// own circuit breaker + a product semaphore slot); every attempted
    /// server reports its outcome back to its own breaker exactly once.
    async fn validate_internal(
        &self,
        request: ProviderValidationRequest,
        capture_raw: bool,
    ) -> Result<(ProviderValidationOutcome, Option<RawProviderResponse>), AppError> {
        self.validate_upstream_race(request, capture_raw).await
    }

    /// Report one server's attempt outcome to its own circuit breaker:
    /// success for a processable response, failure only when the upstream
    /// call flagged a provider-health problem, neutral otherwise.
    async fn record_outcome(
        &self,
        ticket: &crate::provider_guard::GuardTicket,
        result: &Result<(ProviderValidationOutcome, Option<RawProviderResponse>), AppError>,
        provider_failure: bool,
    ) {
        match result {
            Ok(_) => self.guard.record_success(ticket).await,
            Err(_) if provider_failure => self.guard.record_failure(ticket).await,
            Err(_) => self.guard.record_neutral(ticket).await,
        }
    }

    /// Admin-tester variant aimed at ONE chosen server (active or not): the
    /// guard still admits and records the outcome exactly once.
    async fn validate_internal_at(
        &self,
        endpoint_id: Uuid,
        request: ProviderValidationRequest,
    ) -> Result<(ProviderValidationOutcome, Option<RawProviderResponse>), AppError> {
        let product = request.product;
        let endpoint = self
            .provider_configs
            .resolve_by_id(endpoint_id)
            .await
            .filter(|endpoint| endpoint.product == product)
            .ok_or_else(|| AppError::not_found("Endpoint provider tidak ditemukan"))?;
        let ticket = self
            .guard
            .acquire(product, &endpoint.id.to_string())
            .await?;
        let (result, provider_failure) = self
            .validate_upstream_endpoint(&endpoint, request, true)
            .await;
        self.record_outcome(&ticket, &result, provider_failure)
            .await;
        result
    }

    /// Fan-out over every ACTIVE server of the product whose own circuit
    /// breaker admits it (a server with an open breaker is skipped, so one
    /// sick server never blocks the healthy ones; only when EVERY server is
    /// blocked does the request fail fast with the breaker error). A single
    /// admitted server keeps the exact historical behavior. With several
    /// admitted they are hit concurrently: the first VALID (found) answer
    /// wins at once; a non-valid answer is held as fallback while other
    /// servers are still outstanding (a slower server may still find the
    /// target); errors never end the race early — only when every
    /// admitted server has failed does the request fail, so the member
    /// always waits for a real answer.
    ///
    /// Fallback ranking (audit 2026-10-25, B1/K4 — ONE ranking, shared by
    /// the whole race; there is no second ranking anywhere): when no leg
    /// returns Valid, the best fallback wins, NOT the first finisher:
    /// Valid > NotKyc > Invalid > NotFound > Pending. This preserves the
    /// user-specified chain Valid > NotKyc > NotFound and the audit rule
    /// that a definitive answer (Invalid/NotFound) beats a hanging Pending.
    /// In particular a NotKyc leg can never beat a Valid leg: a NotKyc
    /// finisher is only a fallback, and the race keeps waiting for the
    /// remaining legs, so a later Valid still wins outright.
    async fn validate_upstream_race(
        &self,
        request: ProviderValidationRequest,
        capture_raw: bool,
    ) -> Result<(ProviderValidationOutcome, Option<RawProviderResponse>), AppError> {
        let endpoints = self.provider_configs.resolve_all(request.product).await;
        if endpoints.is_empty() {
            return Err(AppError::service_unavailable(
                "Endpoint provider untuk produk ini belum aktif atau belum dikonfigurasi",
            ));
        }
        let mut admitted = Vec::new();
        let mut first_block: Option<AppError> = None;
        for endpoint in endpoints {
            match self
                .guard
                .acquire(request.product, &endpoint.id.to_string())
                .await
            {
                Ok(ticket) => admitted.push((endpoint, ticket)),
                Err(error) => {
                    if first_block.is_none() {
                        first_block = Some(error);
                    }
                }
            }
        }
        if admitted.is_empty() {
            return Err(first_block.unwrap_or_else(|| {
                AppError::service_unavailable(
                    "Semua server provider untuk produk ini sedang tidak tersedia",
                )
            }));
        }
        if admitted.len() == 1 {
            let (endpoint, ticket) = admitted.pop().expect("one admitted endpoint");
            let (result, failure) = self
                .validate_upstream_endpoint(&endpoint, request, capture_raw)
                .await;
            self.record_outcome(&ticket, &result, failure).await;
            return result;
        }
        use futures::stream::{FuturesUnordered, StreamExt};
        let mut futures = FuturesUnordered::new();
        for (endpoint, ticket) in admitted {
            let endpoint_request = request.clone();
            futures.push(async move {
                let (result, failure) = self
                    .validate_upstream_endpoint(&endpoint, endpoint_request, capture_raw)
                    .await;
                self.record_outcome(&ticket, &result, failure).await;
                result
            });
        }
        let mut fallback: Option<(ProviderValidationOutcome, Option<RawProviderResponse>)> = None;
        let mut errors: Vec<AppError> = Vec::new();
        while let Some(result) = futures.next().await {
            match result {
                Ok(pair) => {
                    if pair.0.status == ValidationStatus::Valid {
                        // K5, accepted limitation (deliberate, not an
                        // oversight): the remaining legs' futures are
                        // dropped here, so their breaker outcomes are never
                        // recorded — a cancelled leg holding a half-open
                        // probe leaves `probe_since` set until the 120 s
                        // probe lease expires. Clearing it would need the
                        // guard inside the dropped future (or a Drop impl
                        // on the ticket, which cannot take the guard's
                        // async mutex); both were judged riskier than the
                        // bounded 120 s probe delay, and semaphore permits
                        // are still released by Drop. Do not "fix" this
                        // speculatively without that guard plumbing.
                        return Ok(pair);
                    }
                    let better = match &fallback {
                        None => true,
                        Some(current) => {
                            race_fallback_rank(pair.0.status) > race_fallback_rank(current.0.status)
                        }
                    };
                    if better {
                        fallback = Some(pair);
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        if let Some(pair) = fallback {
            return Ok(pair);
        }
        match errors.into_iter().next() {
            Some(error) => Err(error),
            None => Err(AppError::service_unavailable(
                "Semua server provider gagal memberikan respons",
            )),
        }
    }

    /// The per-server attempt loop (historical single-endpoint behavior):
    /// transient failures retry up to the guard maximum; the returned bool
    /// is the breaker classification (true = provider-health failure).
    async fn validate_upstream_endpoint(
        &self,
        endpoint: &crate::provider_config::ResolvedProviderEndpoint,
        request: ProviderValidationRequest,
        capture_raw: bool,
    ) -> (
        Result<(ProviderValidationOutcome, Option<RawProviderResponse>), AppError>,
        bool,
    ) {
        let mut provider_failure = false;
        if endpoint.request_mode == ProviderRequestMode::Cutiezy
            && matches!(request.product, ValidationProduct::Whatsapp | ValidationProduct::Pln)
        {
            return (
                Err(AppError::service_unavailable(
                    "Mode Cutiezy untuk produk ini belum didukung",
                )),
                false,
            );
        }
        let result = async {
            self.provider_configs
                .verify_destination(&endpoint.base_url)
                .await?;
            let prepared = match endpoint.request_mode {
                ProviderRequestMode::Cutiezy => PreparedCall::CutiezyGet,
                ProviderRequestMode::Generic
                    if endpoint.http_method.eq_ignore_ascii_case("GET") =>
                {
                    PreparedCall::GenericGet
                }
                mode => PreparedCall::Json(build_provider_request(
                    &request,
                    mode,
                    &endpoint.service_code_mapping,
                )?),
            };
            let auth_header =
                HeaderName::from_bytes(endpoint.auth_header.as_bytes()).map_err(|_| {
                    AppError::service_unavailable("Header autentikasi provider tidak valid")
                })?;
            let auth_value = if endpoint.auth_header.eq_ignore_ascii_case("authorization") {
                HeaderValue::from_str(&format!("Bearer {}", endpoint.api_key))
            } else {
                HeaderValue::from_str(&endpoint.api_key)
            }
            .map_err(|_| AppError::service_unavailable("Kredensial provider tidak valid"))?;

            // Attempt loop: transient provider failures are retried up to the
            // guard-configured maximum (default 2 total attempts) because a single
            // upstream hiccup — timeout, 429/5xx, malformed body — otherwise fails
            // a validation the provider can often answer on a second hit.
            // Definitive business answers and client/config errors are never
            // retried. The member is still charged at most once: quota capture
            // happens on the final outcome only, outside this loop.
            // Pacing key: the upstream host (= provider account). Parsed once
            // per endpoint call; an unparseable URL falls back to the shared
            // empty-host bucket rather than skipping the gate.
            let pace_host = Url::parse(&endpoint.base_url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_default();
            let max_attempts = self.guard.config().max_attempts.clamp(1, 3);
            let started = Instant::now();
            let mut pace_wait = Duration::ZERO;
            let mut attempt = 0_u32;
            loop {
                attempt += 1;
                // Every attempt — retries included — passes the pacing gate so
                // outbound hits never exceed one provider account's rate limit.
                // The gate is keyed by upstream host (audit 2026-10-25, K6):
                // Cutiezy is paced with its own host bucket like every other
                // provider — the old total exemption is gone. No separate
                // interval exists for Cutiezy, so it shares the configured
                // pace interval (default 334 ms); no new config surface was
                // added. A pacing rejection is our own backpressure, not a
                // provider failure: it returns at once (no retry) and the
                // breaker outcome stays neutral (provider_failure remains
                // false).
                let pace_started = Instant::now();
                self.guard.pace(&pace_host).await?;
                pace_wait += pace_started.elapsed();
                match self
                    .call_provider(
                        endpoint,
                        &auth_header,
                        &auth_value,
                        &request,
                        &prepared,
                        capture_raw,
                    )
                    .await
                {
                    Ok((mut outcome, raw)) => {
                        if let Some(result) = &mut outcome.result {
                            let (account_number, phone_number) =
                                target_fields(request.product, &request.target);
                            if account_number.is_some() {
                                result.account_number = account_number;
                            }
                            if phone_number.is_some() {
                                result.phone_number = phone_number;
                            }
                            if let Some(code) = service_code_for(&request) {
                                result.service_code = Some(code);
                            }
                            if let Some(name) = bank_name_for(&request) {
                                result.bank_name = Some(name);
                            }
                        }
                        outcome.provider_latency_ms =
                            started.elapsed().saturating_sub(pace_wait).as_millis() as u64;
                        outcome.attempts = attempt;
                        return Ok((outcome, raw));
                    }
                    Err(failure) => {
                        provider_failure = failure.provider_failure;
                        if !failure.retryable || attempt >= max_attempts {
                            return Err(failure.error);
                        }
                        tracing::warn!(
                            attempt,
                            max_attempts,
                            product = %request.product.as_str(),
                            "Percobaan ke provider gagal; mencoba lagi"
                        );
                        // Jittered backoff (audit 2026-10-25, K13): a fixed
                        // 250 ms lets retries from many members synchronize
                        // during an upstream outage; 200-500 ms random
                        // spreads them. Only one retry exists (max 2
                        // attempts), so the effect is small by design.
                        let backoff_ms = rand::thread_rng().gen_range(200..=500);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
            }
        }
        .await;
        (result, provider_failure)
    }
    async fn call_provider(
        &self,
        endpoint: &crate::provider_config::ResolvedProviderEndpoint,
        auth_header: &HeaderName,
        auth_value: &HeaderValue,
        request: &ProviderValidationRequest,
        prepared: &PreparedCall,
        capture_raw: bool,
    ) -> Result<(ProviderValidationOutcome, Option<RawProviderResponse>), AttemptError> {
        let timeout = Duration::from_millis(u64::from(endpoint.timeout_ms));
        let response = match prepared {
            PreparedCall::Json(body) => {
                self.client
                    .post(&endpoint.base_url)
                    .timeout(timeout)
                    .header(auth_header.clone(), auth_value.clone())
                    .json(body)
                    .send()
                    .await
            }
            PreparedCall::GenericGet => {
                // Generic GET: the same translated code and account number
                // as the POST body, but as query params with admin-chosen
                // names. The credential travels in the configured auth
                // header and, only when key_param is set, additionally as a
                // query param.
                let url = build_generic_get_url(
                    &endpoint.base_url,
                    request.product,
                    &request.target,
                    request.provider_hint.as_deref(),
                    &endpoint.service_code_mapping,
                    &endpoint.code_param,
                    &endpoint.number_param,
                    endpoint.key_param.as_deref(),
                    &endpoint.api_key,
                )
                .map_err(|error| AttemptError {
                    error,
                    provider_failure: false,
                    retryable: false,
                })?;
                self.client
                    .get(url)
                    .timeout(timeout)
                    .header(auth_header.clone(), auth_value.clone())
                    .send()
                    .await
            }
            PreparedCall::CutiezyGet => {
                // Cutiezy contracts (verified live 22 Oct): GET with the
                // credential as the `apikey` query parameter — no auth
                // header, no body. Bank (…/cek_bank): code = public 3-digit
                // bank code. E-wallet (…/api/check/ewallet): service =
                // wallet slug. user_id is the account number / phone.
                let mut url = Url::parse(&endpoint.base_url).map_err(|_| AttemptError {
                    error: AppError::service_unavailable("URL endpoint provider tidak valid"),
                    provider_failure: false,
                    retryable: false,
                })?;
                let hint = request.provider_hint.as_deref().unwrap_or_default();
                let key_param = match request.product {
                    ValidationProduct::Ewallet => "service",
                    _ => "code",
                };
                let encode = |value: &str| {
                    url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
                };
                url.set_query(Some(&format!(
                    "{}={}&user_id={}&apikey={}",
                    key_param,
                    encode(hint),
                    encode(&request.target),
                    encode(&endpoint.api_key),
                )));
                self.client.get(url).timeout(timeout).send().await
            }
        }
        .map_err(|error| {
            // B2: NEVER log a reqwest::Error with Debug here. Its Debug
            // rendering embeds the full request URL — and Cutiezy (plus any
            // Generic GET with key_param set) carries the provider
            // credential as a query param, so the old `?error` log wrote
            // plaintext credentials to the server journal on every
            // transport failure. Log only the error kind, the upstream
            // host, and the HTTP status (if any). The credential is NOT
            // moved to a header: that contract change is unverified.
            // Coordinator action at deploy (not code): scrub/rotate the
            // journal lines the old log already wrote.
            tracing::warn!(
                kind = transport_error_kind(&error),
                host = %endpoint_host(endpoint),
                status = error.status().map(|status| status.as_u16()),
                "Permintaan ke provider gagal"
            );
            AttemptError {
                error: AppError::service_unavailable(
                    "Provider validasi tidak dapat dihubungi. Silakan ulangi beberapa saat lagi.",
                ),
                provider_failure: true,
                retryable: true,
            }
        })?;

        let status = response.status();
        let (payload, raw) = if capture_raw {
            let mut raw = match read_raw_response(response).await {
                Ok(raw) => raw,
                Err(error) => {
                    return Err(AttemptError {
                        error,
                        provider_failure: true,
                        retryable: true,
                    });
                }
            };
            raw.server_name = endpoint.name.clone();
            let parsed = if status.is_success() {
                Some(
                    serde_json::from_str::<Value>(&raw.body).map_err(|_| AttemptError {
                        error: with_raw_error(
                            AppError::service_unavailable(
                                "Respons provider validasi tidak dapat diproses",
                            ),
                            &raw,
                        ),
                        provider_failure: true,
                        retryable: true,
                    })?,
                )
            } else {
                None
            };
            (parsed, Some(raw))
        } else if status.is_success() {
            let payload = response.json::<Value>().await.map_err(|error| {
                // Same B2 rule as the transport log: no Debug of the error
                // (a decode error can also carry the request URL).
                tracing::warn!(
                    kind = transport_error_kind(&error),
                    host = %endpoint_host(endpoint),
                    "Respons provider bukan JSON yang valid"
                );
                AttemptError {
                    error: AppError::service_unavailable(
                        "Respons provider validasi tidak dapat diproses",
                    ),
                    provider_failure: true,
                    retryable: true,
                }
            })?;
            (Some(payload), None)
        } else {
            (None, None)
        };

        if !status.is_success() {
            let provider_failure =
                status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            // K9: name the endpoint in the HTTP-error log so repeated
            // statuses (notably 422, frequent in the 25 Oct logs) can be
            // attributed to one server instead of floating anonymously.
            // Classification is deliberately UNCHANGED: 422 is not 429/5xx,
            // so it stays non-retryable, neutral for the breaker, and
            // non-billable (generic 503 to the member). Do NOT remap 422
            // to Invalid/NotFound — the upstream contract for 422 is
            // unverified, and a wrong definitive mapping would mischarge
            // members. The endpoint name is an admin-configured label, not
            // a credential or URL, so it is safe to log.
            tracing::warn!(
                status = %status,
                endpoint = %endpoint.name,
                "Provider mengembalikan status HTTP gagal"
            );
            let error = map_provider_http_error(status);
            let error = match raw.as_ref() {
                Some(raw) => with_raw_error(error, raw),
                None => error,
            };
            return Err(AttemptError {
                error,
                provider_failure,
                retryable: provider_failure,
            });
        }

        // PLN has exactly one known upstream contract (Chikamm, flat JSON
        // below), so its mapping is product-level, not per-endpoint: a
        // Generic endpoint configured for PLN is always interpreted with
        // the Chikamm contract, whatever mapping the panel stored for it.
        // Tukangcek/Cutiezy modes never reach here for PLN (rejected
        // above), so this override only ever replaces a Generic mapping.
        let effective_mapping = if request.product == ValidationProduct::Pln {
            chikamm_pln_mapping()
        } else {
            match endpoint.request_mode {
                ProviderRequestMode::Tukangcek => tukangcek_mapping(request.product),
                ProviderRequestMode::Cutiezy => cutiezy_mapping(request.product),
                ProviderRequestMode::Generic => endpoint.response_mapping.clone(),
            }
        };
        // capture_raw is true exactly for the admin tester (see
        // validate_for_admin / validate_for_admin_at); the public/member
        // path always passes false. It doubles as the verbatim-message
        // flag: upstream wording reaches the tester only, never members.
        let (normalized_status, message, result) = normalize_provider_payload(
            request.product,
            &payload.expect("successful response has parsed payload"),
            &effective_mapping,
            &request.target,
            capture_raw,
        )
        .map_err(|error| {
            let error = match raw.as_ref() {
                Some(raw) => with_raw_error(error, raw),
                None => error,
            };
            AttemptError {
                error,
                provider_failure: true,
                retryable: true,
            }
        })?;

        Ok((
            ProviderValidationOutcome {
                status: normalized_status,
                message,
                result,
                provider_name: endpoint.name.clone(),
                // Both set by the attempt loop, which times the whole sequence.
                provider_latency_ms: 0,
                attempts: 1,
            },
            raw,
        ))
    }
}

/// A provider call, prepared per the endpoint's request mode.
enum PreparedCall {
    /// POST with a JSON body and the credential in the configured auth header.
    Json(Value),
    /// Cutiezy-style GET: parameters — credential included — travel in the
    /// query string; built from the request at dispatch time.
    CutiezyGet,
    /// Generic GET: translated code + account number as query params with
    /// admin-chosen names; built from the request at dispatch time.
    GenericGet,
}

/// One failed provider attempt, classified for the retry loop and the guard.
struct AttemptError {
    error: AppError,
    /// Counts against the circuit breaker (transport, 429/5xx, bad payload).
    provider_failure: bool,
    /// A further attempt may succeed (transient classes only).
    retryable: bool,
}

/// Bound only the admin diagnostic capture; do not retain upstream bodies in normal API calls.
const MAX_RAW_RESPONSE_BYTES: usize = 64 * 1024;

async fn read_raw_response(
    mut response: reqwest::Response,
) -> Result<RawProviderResponse, AppError> {
    let http_status = response.status().as_u16();
    let mut bytes = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        AppError::service_unavailable("Respons provider validasi tidak dapat dibaca")
    })? {
        let remaining = MAX_RAW_RESPONSE_BYTES.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            truncated = true;
            break;
        }
        if bytes.len() == MAX_RAW_RESPONSE_BYTES {
            truncated = response
                .chunk()
                .await
                .map_err(|_| {
                    AppError::service_unavailable("Respons provider validasi tidak dapat dibaca")
                })?
                .is_some();
            break;
        }
    }
    let (body, encoding) = match String::from_utf8(bytes.clone()) {
        Ok(body) => (body, "utf-8"),
        Err(_) => (
            base64::engine::general_purpose::STANDARD.encode(bytes),
            "base64",
        ),
    };
    Ok(RawProviderResponse {
        http_status,
        body,
        encoding,
        truncated,
        server_name: String::new(),
    })
}

fn with_raw_error(error: AppError, raw: &RawProviderResponse) -> AppError {
    error.with_details(serde_json::json!({ "upstream_response": raw }))
}

#[derive(Serialize)]
struct GenericProviderRequest<'a> {
    product: ValidationProduct,
    target: &'a str,
    provider_hint: Option<&'a str>,
    request_reference: String,
}

/// Translates a member-facing code through a generic endpoint's custom
/// mapping (e.g. dana -> dana009). Only generic endpoints carry a mapping;
/// Tukangcek/Cutiezy use their built-in translations elsewhere. Unmapped
/// codes and empty values pass through unchanged, preserving the
/// historical behavior for endpoints without a mapping.
fn translate_service_code<'a>(
    mapping: &'a std::collections::HashMap<String, String>,
    code: &'a str,
) -> &'a str {
    mapping
        .get(code)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(code)
}

/// Builds the request URL for a Generic GET endpoint: the translated service
/// code and the account number as query params with admin-chosen names, plus
/// the API key as a query param only when key_param is set. WhatsApp has no
/// service code, so the code param is omitted for it. Existing query pairs
/// on the base URL are preserved; values are percent-encoded.
fn build_generic_get_url(
    base_url: &str,
    product: ValidationProduct,
    target: &str,
    provider_hint: Option<&str>,
    service_code_mapping: &std::collections::HashMap<String, String>,
    code_param: &str,
    number_param: &str,
    key_param: Option<&str>,
    api_key: &str,
) -> Result<Url, AppError> {
    let mut url = Url::parse(base_url)
        .map_err(|_| AppError::service_unavailable("URL endpoint provider tidak valid"))?;
    {
        let mut query = url.query_pairs_mut();
        if product != ValidationProduct::Whatsapp {
            if let Some(hint) = provider_hint {
                query.append_pair(
                    code_param,
                    translate_service_code(service_code_mapping, hint),
                );
            }
        }
        query.append_pair(number_param, target);
        if let Some(key_param) = key_param.filter(|value| !value.trim().is_empty()) {
            query.append_pair(key_param, api_key);
        }
    }
    Ok(url)
}

fn build_provider_request(
    request: &ProviderValidationRequest,
    mode: ProviderRequestMode,
    service_code_mapping: &std::collections::HashMap<String, String>,
) -> Result<Value, AppError> {
    match mode {
        ProviderRequestMode::Generic => serde_json::to_value(GenericProviderRequest {
            product: request.product,
            target: &request.target,
            provider_hint: request
                .provider_hint
                .as_deref()
                .map(|hint| translate_service_code(service_code_mapping, hint)),
            request_reference: Uuid::now_v7().to_string(),
        })
        .map_err(|_| AppError::internal("Request provider tidak dapat dibuat")),
        // Cutiezy calls are GETs built at dispatch time; they never reach
        // this JSON body builder.
        ProviderRequestMode::Cutiezy => {
            Err(AppError::internal("Mode Cutiezy tidak memakai body JSON"))
        }
        ProviderRequestMode::Tukangcek => match request.product {
            ValidationProduct::BankAccount => {
                let public_code = request.provider_hint.as_deref().ok_or_else(|| {
                    AppError::bad_request("code_bank wajib tersedia untuk validasi bank")
                })?;
                let provider_code = bank_codes::tukangcek_code(public_code)?;
                Ok(serde_json::json!({
                    "type": "bank",
                    "target": request.target,
                    "id": provider_code,
                }))
            }
            ValidationProduct::Ewallet => {
                let public_code = request.provider_hint.as_deref().ok_or_else(|| {
                    AppError::bad_request("Kode provider e-wallet wajib tersedia")
                })?;
                let provider_id = ewallet_codes::tukangcek_id(public_code)?;
                Ok(serde_json::json!({
                    "type": "ewallet",
                    "target": request.target,
                    "id": provider_id,
                }))
            }
            ValidationProduct::Whatsapp => Ok(serde_json::json!({
                "target": request.target,
            })),
            // PLN has no Tukangcek contract; its only known upstream is
            // Chikamm (see `chikamm_pln_mapping`), reached via Generic
            // endpoints. Rejecting here mirrors the Cutiezy guard above:
            // a misconfigured endpoint fails as a neutral provider error
            // (no charge), never as a fabricated business answer.
            ValidationProduct::Pln => Err(AppError::service_unavailable(
                "Mode Tukangcek untuk produk ini belum didukung",
            )),
        },
    }
}

/// Host of a configured endpoint, for logs only. Never the full URL: the
/// URL may carry a credential as a query param (Cutiezy, Generic GET with
/// key_param), and full URLs must never reach the server log (B2).
fn endpoint_host(endpoint: &crate::provider_config::ResolvedProviderEndpoint) -> String {
    Url::parse(&endpoint.base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Coarse transport-error class for logs: kind + host + status only, never
/// the Debug rendering (which embeds the request URL, see B2 above).
fn transport_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_request() {
        "request"
    } else {
        "transport"
    }
}

fn map_provider_http_error(status: StatusCode) -> AppError {
    match status {
        StatusCode::UNAUTHORIZED => AppError::service_unavailable(
            "Autentikasi provider ditolak; konfigurasi kredensial perlu diperiksa",
        ),
        StatusCode::BAD_REQUEST => AppError::service_unavailable(
            "Provider menolak parameter request; konfigurasi integrasi perlu diperiksa",
        ),
        StatusCode::TOO_MANY_REQUESTS => AppError::too_many_requests(
            "Provider sedang membatasi permintaan. Silakan coba kembali.",
            30,
        ),
        StatusCode::SERVICE_UNAVAILABLE => AppError::service_unavailable(
            "Layanan provider sedang offline. Silakan coba kembali nanti.",
        ),
        _ if status.is_server_error() => AppError::service_unavailable(
            "Provider mengalami gangguan internal. Silakan coba kembali nanti.",
        ),
        _ => AppError::service_unavailable(
            "Provider validasi sedang tidak tersedia. Silakan ulangi beberapa saat lagi.",
        ),
    }
}

#[async_trait]
impl ProviderAdapter for HttpProvider {
    async fn validate(
        &self,
        request: ProviderValidationRequest,
    ) -> Result<ProviderValidationOutcome, AppError> {
        self.validate_internal(request, false)
            .await
            .map(|(outcome, _)| outcome)
    }

    async fn validate_for_admin(
        &self,
        request: ProviderValidationRequest,
    ) -> Result<(ProviderValidationOutcome, RawProviderResponse), AppError> {
        let (outcome, raw) = self.validate_internal(request, true).await?;
        Ok((
            outcome,
            raw.expect("admin HTTP call captures upstream response"),
        ))
    }

    async fn validate_for_admin_at(
        &self,
        endpoint_id: Uuid,
        request: ProviderValidationRequest,
    ) -> Result<(ProviderValidationOutcome, RawProviderResponse), AppError> {
        let (outcome, raw) = self.validate_internal_at(endpoint_id, request).await?;
        Ok((
            outcome,
            raw.expect("admin HTTP call captures upstream response"),
        ))
    }

    fn name(&self) -> &str {
        "dynamic-http-provider"
    }
}

/// Standard member-facing message per outcome (K7). These strings are
/// authored by Rajacek, never copied from upstream: a generic endpoint's
/// `message_path` may point at vendor wording (vendor names, internal
/// phrasing), and that verbatim text must never reach a member response.
/// The admin tester is the only surface that keeps the verbatim message
/// (see `verbatim_message` on `normalize_provider_payload`).
/// Built-ins already had `message_path: None`, so they never leaked
/// upstream text; for members their message changes from the single
/// generic string below to the per-status standard string — still
/// Rajacek-authored, still no upstream content.
fn canonical_member_message(status: ValidationStatus) -> &'static str {
    match status {
        ValidationStatus::Valid => "Nomor ditemukan dan terdaftar.",
        ValidationStatus::Invalid => "Nomor diperiksa, tetapi tidak valid atau tidak aktif.",
        ValidationStatus::NotFound => "Nomor tidak ditemukan di bank atau layanan tujuan.",
        ValidationStatus::NotKyc => {
            "Akun e-wallet ini belum KYC, sehingga nama pemilik tidak dapat ditampilkan."
        }
        ValidationStatus::Pending => "Hasil akhir belum tersedia; coba lagi nanti.",
        _ => "Respons diterima dari provider validasi.",
    }
}

/// THE central e-wallet "not KYC" detector (audit 2026-10-25, B1). Called
/// from exactly one place — `normalize_provider_payload`, after the holder
/// name is extracted — so Tukangcek, Cutiezy, and any future generic
/// e-wallet mapping all share the rule. It is NEVER called for bank or
/// WhatsApp products (the caller gates on `ValidationProduct::Ewallet`).
///
/// Detection runs on the extracted name, after normalization (trim,
/// collapse whitespace, uppercase for comparison):
/// (a) placeholder: normalized name is "BELUM PREMIUM" (also accepted
///     without the space, "BELUMPREMIUM"), case/whitespace-insensitive;
/// (b) echoed number: the name's digits equal the checked number, with
///     the checked number canonicalized by stripping a leading 0 or 62
///     (input 087812345678 -> canonical 87812345678), in any of the
///     forms canonical / 0+canonical / 62+canonical, OR the canonical
///     number is embedded anywhere inside the name's digits. The
///     canonical number must be at least 8 digits, otherwise short
///     digit runs inside real names would false-positive.
fn ewallet_not_kyc(account_name: Option<&str>, target: &str) -> bool {
    let name = match account_name {
        Some(name) => name,
        None => return false,
    };
    let normalized = name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase();
    if normalized == "BELUM PREMIUM" || normalized == "BELUMPREMIUM" {
        return true;
    }
    let name_digits: String = name.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if name_digits.is_empty() {
        return false;
    }
    let target_digits: String = target.chars().filter(|ch| ch.is_ascii_digit()).collect();
    let canonical = if let Some(stripped) = target_digits.strip_prefix("62") {
        stripped
    } else if let Some(stripped) = target_digits.strip_prefix('0') {
        stripped
    } else {
        target_digits.as_str()
    };
    if canonical.len() < 8 {
        return false;
    }
    name_digits == canonical
        || name_digits == format!("0{canonical}")
        || name_digits == format!("62{canonical}")
        || name_digits.contains(canonical)
}

// Single source of truth for the race fallback order (B1/K4):
// Valid is handled by the early return and never reaches this ranking.
fn race_fallback_rank(status: ValidationStatus) -> u8 {
    match status {
        ValidationStatus::NotKyc => 3,
        ValidationStatus::Invalid => 2,
        ValidationStatus::NotFound => 1,
        ValidationStatus::Pending => 0,
        // Unreachable as a fallback (Valid early-returns; error statuses
        // never arrive here as Ok), ranked lowest defensively.
        _ => 0,
    }
}

fn normalize_provider_payload(
    product: ValidationProduct,
    payload: &Value,
    mapping: &crate::models::ProviderResponseMapping,
    target: &str,
    verbatim_message: bool,
) -> Result<(ValidationStatus, String, Option<ValidationResultData>), AppError> {
    let status_value = json_path(payload, &mapping.status_path)
        .and_then(value_as_text)
        .unwrap_or_default();
    let registered = mapping
        .registered_path
        .as_deref()
        .and_then(|path| json_path(payload, path))
        .and_then(value_as_bool);
    let mut status = map_status(&status_value, registered, mapping).ok_or_else(|| {
        tracing::warn!(status = %status_value, "Nilai status provider tidak cocok dengan mapping");
        AppError::service_unavailable(
            "Status pada respons provider tidak cocok dengan konfigurasi mapping",
        )
    })?;
    let mut message = if verbatim_message {
        mapping
            .message_path
            .as_deref()
            .and_then(|path| json_path(payload, path))
            .and_then(value_as_text)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "Respons diterima dari provider validasi.".to_owned())
    } else {
        canonical_member_message(status).to_owned()
    };

    let mut result = match product {
        ValidationProduct::BankAccount => Some(ValidationResultData {
            account_number: None,
            phone_number: None,
            service_code: None,
            bank_name: None,
            account_name: mapping
                .account_name_path
                .as_deref()
                .and_then(|path| json_path(payload, path))
                .and_then(value_as_text),
            // Never surface an upstream-sourced provider string in a
            // normalized result: public/member responses identify the
            // provider only as "Rajacek" (meta.provider). Raw upstream
            // payloads stay visible in the admin tester only.
            provider: None,
            tarif: None,
            daya: None,
            registered: None,
            reference: mapped_text(payload, mapping.reference_path.as_deref()),
        }),
        ValidationProduct::Ewallet => Some(ValidationResultData {
            account_number: None,
            phone_number: None,
            service_code: None,
            bank_name: None,
            // The name is shown only when the active mapping maps it (the
            // Tukangcek mapping does — its names arrive pre-masked; the
            // generic default mapping leaves the path unset). The raw target
            // and balance are never mapped, so they can never leak here.
            account_name: mapping
                .account_name_path
                .as_deref()
                .and_then(|path| json_path(payload, path))
                .and_then(value_as_text),
            provider: None,
            tarif: None,
            daya: None,
            registered: Some(registered.unwrap_or(status == ValidationStatus::Valid)),
            reference: mapping
                .reference_path
                .as_deref()
                .and_then(|path| json_path(payload, path))
                .and_then(value_as_text),
        }),
        ValidationProduct::Whatsapp => Some(ValidationResultData {
            account_number: None,
            phone_number: None,
            service_code: None,
            bank_name: None,
            account_name: None,
            provider: None,
            tarif: None,
            daya: None,
            registered: Some(registered.unwrap_or(status == ValidationStatus::Valid)),
            reference: mapped_text(payload, mapping.reference_path.as_deref()),
        }),
        ValidationProduct::Pln => {
            let account_name = mapping
                .account_name_path
                .as_deref()
                .and_then(|path| json_path(payload, path))
                .and_then(value_as_text);
            // Tarif/daya are DERIVED from the name suffix only; the name
            // itself is kept whole (never stripped of its suffix), and
            // the member-response uppercasing in api.rs touches only
            // account_name, never these two fields.
            let (tarif, daya) = parse_pln_tarif_daya(account_name.as_deref());
            Some(ValidationResultData {
                account_number: None,
                phone_number: None,
                service_code: None,
                bank_name: None,
                account_name,
                tarif,
                daya,
                // Upstream "provider": "API" is deliberately never mapped
                // (provider_path is None in the Chikamm mapping), exactly
                // like every other product: members only ever see
                // meta.provider "Rajacek".
                provider: None,
                registered: Some(registered.unwrap_or(status == ValidationStatus::Valid)),
                reference: mapped_text(payload, mapping.reference_path.as_deref()),
            })
        }
    };

    // B1, e-wallet only: a placeholder/echoed name is never a holder name
    // and never evidence of a registered account. The placeholder/echo is
    // stripped from the result in every case (never echo it back as a
    // "name"), and a mapped Valid is downgraded to NotKyc with
    // registered=false. A mapped non-Valid keeps its status — it was
    // already not Valid — but still loses the placeholder/echo name.
    // Bank and WhatsApp results never reach this branch: the helper is
    // only consulted for ValidationProduct::Ewallet.
    if product == ValidationProduct::Ewallet {
        if let Some(data) = result.as_mut() {
            if ewallet_not_kyc(data.account_name.as_deref(), target) {
                data.account_name = None;
                data.registered = Some(false);
                if status == ValidationStatus::Valid {
                    status = ValidationStatus::NotKyc;
                    if !verbatim_message {
                        message = canonical_member_message(status).to_owned();
                    }
                }
            }
        }
    }

    Ok((status, message, result))
}

fn map_status(
    raw: &str,
    registered: Option<bool>,
    mapping: &crate::models::ProviderResponseMapping,
) -> Option<ValidationStatus> {
    let value = raw.trim();
    let contains = |items: &[String]| {
        items
            .iter()
            .any(|item| item.trim().eq_ignore_ascii_case(value))
    };
    if contains(&mapping.valid_values) {
        Some(ValidationStatus::Valid)
    } else if contains(&mapping.invalid_values) {
        Some(ValidationStatus::Invalid)
    } else if contains(&mapping.not_found_values) {
        Some(ValidationStatus::NotFound)
    } else if contains(&mapping.pending_values) {
        Some(ValidationStatus::Pending)
    } else {
        registered.map(|value| {
            if value {
                ValidationStatus::Valid
            } else {
                ValidationStatus::NotFound
            }
        })
    }
}

fn mapped_text(payload: &Value, path: Option<&str>) -> Option<String> {
    path.and_then(|path| json_path(payload, path))
        .and_then(value_as_text)
}

fn value_as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value.as_i64().map(|value| value != 0),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "registered" | "active" => Some(true),
            "false" | "0" | "no" | "unregistered" | "inactive" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn json_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.trim().split('.') {
        let mut remainder = segment;
        if let Some(bracket) = remainder.find('[') {
            let field = &remainder[..bracket];
            if !field.is_empty() {
                current = current.get(field)?;
            }
            remainder = &remainder[bracket..];
            while let Some(index_start) = remainder.strip_prefix('[') {
                let end = index_start.find(']')?;
                let index = index_start[..end].parse::<usize>().ok()?;
                current = current.get(index)?;
                remainder = &index_start[end + 1..];
            }
            if !remainder.is_empty() {
                return None;
            }
        } else {
            current = current.get(remainder)?;
        }
    }
    Some(current)
}

/// Chikamm PLN response contract, exactly as probed live (flat JSON, no
/// nested `data` object):
/// `{status: 200, success: bool, request_id, provider: "API",
/// type: "pln", target: echo, name, nickname, created_at}`.
/// - `success: true` → Valid (registered = true, from the status fallback
///   in the Pln result arm); `success: false` → Invalid. There is
///   deliberately NO Invalid-vs-NotFound split for PLN: the failure shape
///   has never been observed, so a failed lookup is one defensive
///   Invalid, never a guessed NotFound.
/// - `name` is the holder name verbatim (the member path uppercases its
///   own copy, like every other product); `nickname` is ignored — it
///   duplicates `name` in the probed shape.
/// - `request_id` is the provider reference.
/// - Upstream `provider` ("API") is NEVER mapped: provider_path is None,
///   so member responses keep provider None and meta.provider "Rajacek".
/// - `target` (echo) and `created_at` are never mapped into the result.
/// A missing/non-boolean `success` does NOT fall through to Invalid: no
/// mapping list matches it, so `map_status` returns None and the call
/// surfaces as a retryable provider error (no charge) — a malformed
/// upstream payload must never be charged to a member as a definitive
/// Invalid, mirroring the existing rule against remapping unverified
/// HTTP statuses to business answers.
fn chikamm_pln_mapping() -> crate::models::ProviderResponseMapping {
    crate::models::ProviderResponseMapping {
        status_path: "success".to_owned(),
        valid_values: vec!["true".to_owned()],
        invalid_values: vec!["false".to_owned()],
        not_found_values: vec![],
        pending_values: vec![],
        message_path: None,
        account_name_path: Some("name".to_owned()),
        provider_path: None,
        registered_path: None,
        reference_path: Some("request_id".to_owned()),
    }
}

/// PLN tariff/power suffix parser. The upstream carries no separate
/// tariff/power fields: both ride in the holder-name suffix
/// `" - TARIF/DAYA"` (e.g. `" - R1/1300"`). Only the suffix AFTER THE
/// LAST `" - "` is considered, so names containing earlier `" - "`
/// separators still parse; the suffix must then split on exactly one
/// `/` into two non-empty parts (trimmed). Anything else — no
/// separator, no slash, an empty side, more than one slash — yields
/// (None, None) and the name stays whole. Values are NOT uppercased
/// here (they already arrive uppercase/numeric); no tariff/power
/// vocabulary is validated, so unseen-but-well-formed variants are not
/// rejected on a guess.
pub(crate) fn parse_pln_tarif_daya(
    account_name: Option<&str>,
) -> (Option<String>, Option<String>) {
    let name = match account_name {
        Some(name) => name,
        None => return (None, None),
    };
    let separator = match name.rfind(" - ") {
        Some(position) => position,
        None => return (None, None),
    };
    let suffix = &name[separator + 3..];
    let (tarif, daya) = match suffix.split_once('/') {
        // Exactly one slash: a second slash in the power side means the
        // suffix is not a TARIF/DAYA pair at all.
        Some((tarif, daya)) if !daya.contains('/') => (tarif.trim(), daya.trim()),
        _ => return (None, None),
    };
    if tarif.is_empty() || daya.is_empty() {
        return (None, None);
    }
    (Some(tarif.to_owned()), Some(daya.to_owned()))
}

/// Cutiezy response contract (bank): `success` flags the outcome, the holder
/// name lives at `data.accountname`. The provider name is never mapped into
/// the result — public responses must not reveal which server answered.
fn cutiezy_mapping(product: ValidationProduct) -> crate::models::ProviderResponseMapping {
    crate::models::ProviderResponseMapping {
        status_path: "success".to_owned(),
        valid_values: vec!["true".to_owned()],
        invalid_values: vec![],
        not_found_values: vec!["false".to_owned()],
        pending_values: vec![],
        message_path: None,
        account_name_path: match product {
            // Live shapes: bank data.accountname, e-wallet data.nickname.
            ValidationProduct::BankAccount => Some("data.accountname".to_owned()),
            ValidationProduct::Ewallet => Some("data.nickname".to_owned()),
            ValidationProduct::Whatsapp => None,
            // Cutiezy mode is rejected for PLN before any mapping is
            // used (see the guard in validate_upstream_endpoint); this
            // arm exists only for exhaustiveness.
            ValidationProduct::Pln => None,
        },
        provider_path: None,
        registered_path: None,
        reference_path: None,
    }
}

fn tukangcek_mapping(product: ValidationProduct) -> crate::models::ProviderResponseMapping {
    match product {
        // Tukangcek mode is rejected for PLN in build_provider_request
        // before any mapping is consulted; this arm exists only for
        // exhaustiveness and is never used for a real PLN call.
        ValidationProduct::Pln => crate::models::ProviderResponseMapping {
            status_path: "found".to_owned(),
            valid_values: vec!["true".to_owned()],
            invalid_values: vec![],
            not_found_values: vec!["false".to_owned()],
            pending_values: vec![],
            message_path: None,
            account_name_path: None,
            provider_path: None,
            registered_path: None,
            reference_path: None,
        },
        ValidationProduct::Whatsapp => crate::models::ProviderResponseMapping {
            status_path: "registered".to_owned(),
            valid_values: vec!["true".to_owned()],
            invalid_values: vec![],
            not_found_values: vec!["false".to_owned()],
            pending_values: vec![],
            message_path: None,
            account_name_path: None,
            provider_path: None,
            registered_path: Some("registered".to_owned()),
            reference_path: None,
        },
        ValidationProduct::BankAccount | ValidationProduct::Ewallet => {
            crate::models::ProviderResponseMapping {
                status_path: "found".to_owned(),
                valid_values: vec!["true".to_owned()],
                invalid_values: vec![],
                not_found_values: vec!["false".to_owned()],
                pending_values: vec![],
                message_path: None,
                // Tukangcek returns the holder name already masked by the
                // provider itself; surface it for bank AND e-wallet.
                account_name_path: Some("name".to_owned()),
                provider_path: None,
                registered_path: matches!(product, ValidationProduct::Ewallet)
                    .then(|| "found".to_owned()),
                reference_path: None,
            }
        }
    }
}

#[cfg(test)]
mod mapping_tests {
    use super::{
        build_provider_request, cutiezy_mapping, map_provider_http_error,
        normalize_provider_payload, read_raw_response, tukangcek_mapping, with_raw_error,
        MAX_RAW_RESPONSE_BYTES,
    };
    use crate::models::{
        ProviderRequestMode, ProviderResponseMapping, ProviderValidationRequest, ValidationProduct,
        ValidationStatus,
    };
    use serde_json::json;

    async fn serve_response(body: Vec<u8>, status: u16) -> reqwest::Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.expect("request");
            let header = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.expect("header");
            stream.write_all(&body).await.expect("body");
        });
        reqwest::get(format!("http://{addr}/"))
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn raw_capture_preserves_original_json_bytes_and_http_error_body() {
        let body = b"{ \"ok\" : false, \"secret\": \"test\" }".to_vec();
        let raw = read_raw_response(serve_response(body.clone(), 401).await)
            .await
            .expect("raw");
        assert_eq!(raw.http_status, 401);
        assert_eq!(raw.body.as_bytes(), body);
        assert_eq!(raw.encoding, "utf-8");
        assert!(!raw.truncated);
        let error = with_raw_error(
            map_provider_http_error(reqwest::StatusCode::UNAUTHORIZED),
            &raw,
        );
        assert_eq!(
            error.details.expect("details")["upstream_response"]["body"],
            raw.body
        );
    }

    #[tokio::test]
    async fn raw_capture_bounds_body_and_encodes_binary() {
        let large = vec![b'x'; MAX_RAW_RESPONSE_BYTES + 10];
        let raw = read_raw_response(serve_response(large, 200).await)
            .await
            .expect("bounded");
        assert_eq!(raw.body.len(), MAX_RAW_RESPONSE_BYTES);
        assert!(raw.truncated);
        let raw = read_raw_response(serve_response(vec![0xff, 0x00], 502).await)
            .await
            .expect("binary");
        assert_eq!(raw.body, "/wA=");
        assert_eq!(raw.encoding, "base64");
    }

    #[test]
    fn bank_mapping_extracts_name_and_status() {
        let mapping = ProviderResponseMapping {
            status_path: "data.status".to_owned(),
            valid_values: vec!["OK".to_owned()],
            invalid_values: vec![],
            not_found_values: vec!["MISSING".to_owned()],
            pending_values: vec![],
            message_path: Some("data.note".to_owned()),
            account_name_path: Some("data.customer.name".to_owned()),
            provider_path: Some("data.bank.code".to_owned()),
            registered_path: None,
            reference_path: Some("meta.reference".to_owned()),
        };
        let payload = json!({"data":{"status":"OK","note":"match","customer":{"name":"BUDI"},"bank":{"code":"BCA"}},"meta":{"reference":"ref-1"}});
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::BankAccount,
            &payload,
            &mapping,
            "1234567890",
            false,
        )
        .expect("mapping valid");
        assert_eq!(status, ValidationStatus::Valid);
        assert_eq!(
            result.expect("result").account_name.as_deref(),
            Some("BUDI")
        );
    }

    #[test]
    fn ewallet_default_mapping_keeps_account_name_empty() {
        let mut mapping = ProviderResponseMapping::default_for(ValidationProduct::Ewallet);
        mapping.status_path = "payload.state".to_owned();
        mapping.registered_path = Some("payload.is_registered".to_owned());
        let payload = json!({"payload":{"state":"unknown","is_registered":true,"account_name":"PRIVATE NAME"}});
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &payload,
            &mapping,
            "081234567890",
            false,
        )
        .expect("mapping valid");
        let result = result.expect("result");
        assert_eq!(status, ValidationStatus::Valid);
        assert_eq!(result.account_name, None);
        assert_eq!(result.registered, Some(true));
        assert_eq!(result.provider, None);
        assert_eq!(result.reference, None);
    }

    #[test]
    fn tukangcek_bank_request_translates_public_bri_code() {
        let request = ProviderValidationRequest {
            product: ValidationProduct::BankAccount,
            provider_hint: Some("002".to_owned()),
            target: "1234567890".to_owned(),
        };
        let body = build_provider_request(
            &request,
            ProviderRequestMode::Tukangcek,
            &std::collections::HashMap::new(),
        )
        .expect("BRI mapping tersedia");
        assert_eq!(
            body,
            json!({"type":"bank","target":"1234567890","id":"BRIC1ID"})
        );
    }

    #[test]
    fn tukangcek_ewallet_request_uses_provider_id() {
        let request = ProviderValidationRequest {
            product: ValidationProduct::Ewallet,
            provider_hint: Some("gopay_driver".to_owned()),
            target: "081234567890".to_owned(),
        };
        assert_eq!(
            build_provider_request(
                &request,
                ProviderRequestMode::Tukangcek,
                &std::collections::HashMap::new(),
            )
            .expect("mapped"),
            json!({"type":"ewallet","target":"081234567890","id":"GOPAY002"})
        );
        let unknown = ProviderValidationRequest {
            provider_hint: Some("unsupported".to_owned()),
            ..request
        };
        assert!(build_provider_request(
            &unknown,
            ProviderRequestMode::Tukangcek,
            &std::collections::HashMap::new(),
        )
        .is_err());
    }

    #[test]
    fn generic_ewallet_request_translates_code_through_endpoint_mapping() {
        let request = ProviderValidationRequest {
            product: ValidationProduct::Ewallet,
            provider_hint: Some("dana".to_owned()),
            target: "081234567890".to_owned(),
        };
        let mut mapping = std::collections::HashMap::new();
        mapping.insert("dana".to_owned(), "dana009".to_owned());
        let body = build_provider_request(&request, ProviderRequestMode::Generic, &mapping)
            .expect("generic body");
        assert_eq!(body["provider_hint"], "dana009");
        // Unmapped codes and empty values pass through unchanged.
        let body = build_provider_request(
            &request,
            ProviderRequestMode::Generic,
            &std::collections::HashMap::new(),
        )
        .expect("generic body");
        assert_eq!(body["provider_hint"], "dana");
        let mut blank = std::collections::HashMap::new();
        blank.insert("dana".to_owned(), "   ".to_owned());
        let body = build_provider_request(&request, ProviderRequestMode::Generic, &blank)
            .expect("generic body");
        assert_eq!(body["provider_hint"], "dana");
        // The member-facing code is untouched by translation: only the
        // upstream payload carries the provider's code.
        assert_eq!(request.provider_hint.as_deref(), Some("dana"));
    }

    #[test]
    fn tukangcek_ewallet_and_whatsapp_contracts_are_normalized() {
        let mapping = tukangcek_mapping(ValidationProduct::Ewallet);
        for (found, expected_status) in [
            (true, ValidationStatus::Valid),
            (false, ValidationStatus::NotFound),
        ] {
            let wallet_payload = json!({"found":found,"name":"PRIVATE","target":"081234567890","channel":"gopay","balance":990});
            let (status, _, wallet) = normalize_provider_payload(
                ValidationProduct::Ewallet,
                &wallet_payload,
                &mapping,
                "081234567890",
                false,
            )
            .expect("wallet response");
            assert_eq!(status, expected_status);
            let wallet = wallet.expect("wallet result");
            assert_eq!(wallet.registered, Some(found));
            // The Tukangcek mapping maps the (provider-masked) holder name.
            assert_eq!(wallet.account_name.as_deref(), Some("PRIVATE"));
            assert_eq!(wallet.provider, None);
            assert_eq!(wallet.reference, None);
            let exposed = serde_json::to_value(&wallet).expect("serialize result");
            let serialized = exposed.to_string();
            // The raw target and balance are never part of the result.
            assert!(!serialized.contains("081234567890"));
            assert!(!serialized.contains("990"));
        }
        assert!(normalize_provider_payload(
            ValidationProduct::Ewallet,
            &json!({"found":null,"name":"PRIVATE"}),
            &mapping,
            "081234567890",
            false,
        )
        .is_err());

        let wa_payload = json!({"registered":false,"target":"6281234567890","balance":980});
        let (status, _, whatsapp) = normalize_provider_payload(
            ValidationProduct::Whatsapp,
            &wa_payload,
            &tukangcek_mapping(ValidationProduct::Whatsapp),
            "6281234567890",
            false,
        )
        .expect("whatsapp response");
        assert_eq!(status, ValidationStatus::NotFound);
        assert_eq!(whatsapp.expect("wa result").registered, Some(false));
    }

    #[test]
    fn cutiezy_bank_contract_is_normalized() {
        // Success shape exactly as the provider documents it.
        let payload = json!({
            "success": true, "ok": true,
            "message": "Mantap, Berhasil mendapatkan data",
            "service": "cek_bank", "category": "bank",
            "data": {
                "brand": "Stalk Rekening Bank", "bank_code": "002",
                "bank_name": "BANK BRI", "accountname": "ANDRIAS SETIAWAN SUB",
                "user_id": "558801014131531"
            }
        });
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::BankAccount,
            &payload,
            &cutiezy_mapping(ValidationProduct::BankAccount),
            "558801014131531",
            false,
        )
        .expect("cutiezy response");
        assert_eq!(status, ValidationStatus::Valid);
        let result = result.expect("bank result");
        assert_eq!(result.account_name.as_deref(), Some("ANDRIAS SETIAWAN SUB"));
        // The answering server's identity never enters the result, and the
        // raw account number is not echoed back either.
        assert_eq!(result.provider, None);
        let serialized = serde_json::to_value(&result)
            .expect("serialize")
            .to_string();
        assert!(!serialized.contains("558801014131531"));
        assert!(!serialized.to_lowercase().contains("cutiezy"));

        let missing =
            json!({"success": false, "ok": false, "message": "Data tidak ditemukan", "data": null});
        let (status, _, _) = normalize_provider_payload(
            ValidationProduct::BankAccount,
            &missing,
            &cutiezy_mapping(ValidationProduct::BankAccount),
            "1234567890",
            false,
        )
        .expect("cutiezy missing response");
        assert_eq!(status, ValidationStatus::NotFound);
    }
}

#[cfg(test)]
mod cutiezy_ewallet_tests {
    use super::{
        canonical_member_message, cutiezy_mapping, ewallet_not_kyc, normalize_provider_payload,
        race_fallback_rank, tukangcek_mapping,
    };
    use crate::models::{ValidationProduct, ValidationStatus};

    #[test]
    fn cutiezy_ewallet_placeholder_nickname_is_not_kyc() {
        // Exact shape probed live from api.cutiezy.id/api/check/ewallet.
        // Audit 2026-10-25, B1: this payload used to normalize to Valid
        // with account_name "Belum Premium" (the old test asserted exactly
        // that). It must now be NotKyc, with NO name echoed back.
        let payload = serde_json::json!({
            "success": true, "ok": true, "service": "dana", "category": "ewallet",
            "data": {"brand": "DANA", "id": "087841903677", "nickname": "Belum Premium"}
        });
        let (status, message, result) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &payload,
            &cutiezy_mapping(ValidationProduct::Ewallet),
            "087841903677",
            false,
        )
        .expect("payload should normalize");
        assert_eq!(status, ValidationStatus::NotKyc);
        assert_eq!(message, canonical_member_message(ValidationStatus::NotKyc));
        let result = result.expect("not_kyc ewallet carries a result");
        assert_eq!(result.account_name, None);
        assert_eq!(result.provider.as_deref(), None);
        assert_eq!(result.registered, Some(false));
        // NotKyc bills like NotFound and answers HTTP 200 like NotFound.
        assert!(status.is_billable());
        assert_eq!(status.as_str(), "not_kyc");
        assert!(!status.is_success());
    }

    #[test]
    fn ewallet_placeholder_variants_are_case_and_whitespace_insensitive() {
        for name in [
            "Belum Premium",
            "BELUM PREMIUM",
            "belum premium",
            "  Belum   Premium  ",
            "BelumPremium",
            "belumpremium",
        ] {
            assert!(
                ewallet_not_kyc(Some(name), "087812345678"),
                "{name} should be detected as not_kyc"
            );
        }
        assert!(!ewallet_not_kyc(Some("BUDI SANTOSO"), "087812345678"));
        assert!(!ewallet_not_kyc(None, "087812345678"));
        assert!(!ewallet_not_kyc(Some(""), "087812345678"));
    }

    #[test]
    fn ewallet_echoed_number_in_all_forms_is_not_kyc() {
        // Checked number 087812345678 -> canonical 87812345678.
        for name in [
            "087812345678",
            "6287812345678",
            "87812345678",
            "Andrias 87812345678 S",
            "  0878 1234 5678  ",
        ] {
            assert!(
                ewallet_not_kyc(Some(name), "087812345678"),
                "{name} should be detected as an echoed number"
            );
        }
        // Same digits checked in international form must match too.
        assert!(ewallet_not_kyc(Some("087812345678"), "6287812345678"));
        assert!(ewallet_not_kyc(Some("87812345678"), "+6287812345678"));
        // Short canonical numbers (< 8 digits) never trigger the embedded
        // rule, so short digit runs inside real names stay Valid.
        assert!(!ewallet_not_kyc(Some("BUDI 812345"), "0812345"));
        assert!(!ewallet_not_kyc(Some("812345"), "0812345"));
    }

    #[test]
    fn ewallet_real_name_stays_valid_across_mappings() {
        // The central helper serves every e-wallet mapping: Cutiezy,
        // Tukangcek, and generic endpoints alike.
        let cutiezy = serde_json::json!({
            "success": true, "data": {"nickname": "BUDI SANTOSO"}
        });
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &cutiezy,
            &cutiezy_mapping(ValidationProduct::Ewallet),
            "087812345678",
            false,
        )
        .expect("cutiezy real name");
        assert_eq!(status, ValidationStatus::Valid);
        assert_eq!(
            result.expect("result").account_name.as_deref(),
            Some("BUDI SANTOSO")
        );

        let tukangcek = serde_json::json!({"found": true, "name": "BUDI SANTOSO"});
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &tukangcek,
            &tukangcek_mapping(ValidationProduct::Ewallet),
            "087812345678",
            false,
        )
        .expect("tukangcek real name");
        assert_eq!(status, ValidationStatus::Valid);
        assert_eq!(
            result.expect("result").account_name.as_deref(),
            Some("BUDI SANTOSO")
        );

        // Generic e-wallet mapping with a placeholder name: also NotKyc,
        // proving the rule is central, not per-provider.
        let mut generic =
            crate::models::ProviderResponseMapping::default_for(ValidationProduct::Ewallet);
        generic.status_path = "state".to_owned();
        generic.account_name_path = Some("name".to_owned());
        let generic_payload = serde_json::json!({"state": "valid", "name": "Belum Premium"});
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &generic_payload,
            &generic,
            "087812345678",
            false,
        )
        .expect("generic placeholder");
        assert_eq!(status, ValidationStatus::NotKyc);
        assert_eq!(result.expect("result").account_name, None);
    }

    #[test]
    fn bank_and_whatsapp_are_untouched_by_the_ewallet_helper() {
        // The same placeholder text on a BANK payload stays Valid: the
        // helper is only consulted on the e-wallet path.
        let bank = serde_json::json!({
            "success": true, "data": {"accountname": "Belum Premium"}
        });
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::BankAccount,
            &bank,
            &cutiezy_mapping(ValidationProduct::BankAccount),
            "1234567890",
            false,
        )
        .expect("bank placeholder untouched");
        assert_eq!(status, ValidationStatus::Valid);
        assert_eq!(
            result.expect("result").account_name.as_deref(),
            Some("Belum Premium")
        );
        // Direct helper gate: bank/WhatsApp callers never invoke it (this
        // documents the call-site contract; the gate itself lives in
        // normalize_provider_payload).
        assert!(!ewallet_not_kyc(None, "081234567890"));
    }

    #[test]
    fn race_fallback_ranking_is_valid_over_not_kyc_over_invalid_over_not_found_over_pending() {
        assert!(
            race_fallback_rank(ValidationStatus::NotKyc)
                > race_fallback_rank(ValidationStatus::Invalid)
        );
        assert!(
            race_fallback_rank(ValidationStatus::Invalid)
                > race_fallback_rank(ValidationStatus::NotFound)
        );
        assert!(
            race_fallback_rank(ValidationStatus::NotFound)
                > race_fallback_rank(ValidationStatus::Pending)
        );
    }

    #[test]
    fn member_message_is_canonical_but_admin_tester_keeps_verbatim() {
        // Generic endpoint whose message_path points at upstream wording
        // mentioning a vendor: members must never see it (K7).
        let mut mapping =
            crate::models::ProviderResponseMapping::default_for(ValidationProduct::Ewallet);
        mapping.status_path = "state".to_owned();
        mapping.message_path = Some("note".to_owned());
        mapping.account_name_path = Some("name".to_owned());
        let payload = serde_json::json!({
            "state": "valid", "name": "BUDI SANTOSO",
            "note": "answered by VENDOR internal system xyz"
        });
        let (_, member_message, _) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &payload,
            &mapping,
            "087812345678",
            false,
        )
        .expect("member message");
        assert_eq!(
            member_message,
            canonical_member_message(ValidationStatus::Valid)
        );
        assert!(!member_message.contains("VENDOR"));
        let (_, tester_message, _) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &payload,
            &mapping,
            "087812345678",
            true,
        )
        .expect("tester message");
        assert_eq!(tester_message, "answered by VENDOR internal system xyz");
    }
}

#[cfg(test)]
mod generic_get_tests {
    use super::build_generic_get_url;
    use crate::models::ValidationProduct;

    fn mapping(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn bank_code_is_translated_and_params_are_named() {
        let url = build_generic_get_url(
            "https://api.provider.example/validate",
            ValidationProduct::BankAccount,
            "1234567890",
            Some("014"),
            &mapping(&[("014", "BCA")]),
            "bank",
            "account",
            None,
            "secret",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.provider.example/validate?bank=BCA&account=1234567890"
        );
    }

    #[test]
    fn unmapped_code_sent_as_is_and_key_param_appended() {
        let url = build_generic_get_url(
            "https://api.provider.example/check?region=id",
            ValidationProduct::Ewallet,
            "081234567890",
            Some("dana"),
            &mapping(&[]),
            "service",
            "user_id",
            Some("apikey"),
            "kunci-uji",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.provider.example/check?region=id&service=dana&user_id=081234567890&apikey=kunci-uji"
        );
    }

    #[test]
    fn whatsapp_omits_code_param_even_with_hint() {
        let url = build_generic_get_url(
            "https://api.provider.example/wa",
            ValidationProduct::Whatsapp,
            "6281234567890",
            Some("whatsapp"),
            &mapping(&[]),
            "code",
            "phone",
            None,
            "secret",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.provider.example/wa?phone=6281234567890"
        );
    }

    #[test]
    fn invalid_base_url_is_rejected() {
        assert!(build_generic_get_url(
            "bukan-url",
            ValidationProduct::BankAccount,
            "123",
            Some("014"),
            &mapping(&[]),
            "code",
            "target",
            None,
            "secret",
        )
        .is_err());
    }
}

#[cfg(test)]
mod pln_tests {
    use super::{chikamm_pln_mapping, normalize_provider_payload, parse_pln_tarif_daya};
    use crate::models::{ValidationProduct, ValidationStatus};

    fn flat_pln_payload(success: bool) -> serde_json::Value {
        // Flat Chikamm shape exactly as probed live: no nested `data`.
        serde_json::json!({
            "status": 200,
            "success": success,
            "request_id": "REQ-PLN-1",
            "provider": "API",
            "type": "pln",
            "target": "12345678901",
            "name": "PELANGGAN CONTOH - R1/1300",
            "nickname": "PELANGGAN CONTOH - R1/1300",
            "created_at": "2026-10-26T00:00:00Z"
        })
    }

    #[test]
    fn chikamm_success_maps_to_valid_with_tarif_and_daya() {
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::Pln,
            &flat_pln_payload(true),
            &chikamm_pln_mapping(),
            "12345678901",
            false,
        )
        .expect("success payload normalizes");
        assert_eq!(status, ValidationStatus::Valid);
        let result = result.expect("valid PLN carries a result");
        // The holder name stays whole — the suffix is NOT stripped.
        assert_eq!(
            result.account_name.as_deref(),
            Some("PELANGGAN CONTOH - R1/1300")
        );
        assert_eq!(result.tarif.as_deref(), Some("R1"));
        assert_eq!(result.daya.as_deref(), Some("1300"));
        assert_eq!(result.registered, Some(true));
        assert_eq!(result.reference.as_deref(), Some("REQ-PLN-1"));
        // Upstream "provider": "API" never reaches the member result.
        assert_eq!(result.provider, None);
        let serialized = serde_json::to_value(&result).expect("serialize").to_string();
        assert!(serialized.contains("\"tarif\":\"R1\""));
        assert!(serialized.contains("\"daya\":\"1300\""));
        assert!(!serialized.contains("\"provider\""));
    }

    #[test]
    fn chikamm_failure_maps_to_defensive_invalid_not_not_found() {
        // The failure shape was never observed, so there is no
        // Invalid-vs-NotFound split for PLN: any success=false is one
        // defensive Invalid (which shares the free-invalid pool).
        let mut payload = flat_pln_payload(false);
        payload.as_object_mut().unwrap().remove("name");
        payload.as_object_mut().unwrap().remove("nickname");
        let (status, _, result) = normalize_provider_payload(
            ValidationProduct::Pln,
            &payload,
            &chikamm_pln_mapping(),
            "12345678901",
            false,
        )
        .expect("failure payload normalizes");
        assert_eq!(status, ValidationStatus::Invalid);
        assert!(status.is_invalid_pool());
        assert!(status.is_billable());
        let result = result.expect("invalid PLN carries a result");
        assert_eq!(result.account_name, None);
        assert_eq!(result.tarif, None);
        assert_eq!(result.daya, None);
        assert_eq!(result.registered, Some(false));
        assert_eq!(result.reference.as_deref(), Some("REQ-PLN-1"));
    }

    #[test]
    fn chikamm_nickname_is_ignored_and_provider_label_discarded() {
        let mut payload = flat_pln_payload(true);
        payload["name"] = serde_json::json!("NAMA ASLI - R1/900");
        payload["nickname"] = serde_json::json!("NICK BERBEDA");
        let (_, _, result) = normalize_provider_payload(
            ValidationProduct::Pln,
            &payload,
            &chikamm_pln_mapping(),
            "12345678901",
            false,
        )
        .expect("payload normalizes");
        let result = result.expect("result");
        assert_eq!(result.account_name.as_deref(), Some("NAMA ASLI - R1/900"));
        let serialized = serde_json::to_value(&result).expect("serialize").to_string();
        assert!(!serialized.contains("NICK BERBEDA"));
        assert!(!serialized.contains("\"provider\""));
    }

    #[test]
    fn chikamm_missing_success_is_a_provider_error_not_a_charged_invalid() {
        let mut payload = flat_pln_payload(true);
        payload.as_object_mut().unwrap().remove("success");
        assert!(normalize_provider_payload(
            ValidationProduct::Pln,
            &payload,
            &chikamm_pln_mapping(),
            "12345678901",
            false,
        )
        .is_err());
    }

    #[test]
    fn tarif_daya_parsing_rules() {
        let cases: [(Option<&str>, Option<&str>, Option<&str>); 10] = [
            (Some("PELANGGAN - R1/1300"), Some("R1"), Some("1300")),
            // Only the suffix after the LAST " - " counts.
            (Some("PT ANEKA - JAYA - R1/2200"), Some("R1"), Some("2200")),
            // Whitespace around the parts is trimmed.
            (Some("PELANGGAN - R1 / 1300"), Some("R1"), Some("1300")),
            (Some("PELANGGAN TANPA SUFIKS"), None, None),
            (Some("PELANGGAN - TANPASLASH"), None, None),
            (Some("PELANGGAN - R1/"), None, None),
            (Some("PELANGGAN - /1300"), None, None),
            (Some("PELANGGAN - R1/1300/X"), None, None),
            (Some("PELANGGAN - "), None, None),
            (None, None, None),
        ];
        for (name, tarif, daya) in cases {
            assert_eq!(
                parse_pln_tarif_daya(name),
                (tarif.map(str::to_owned), daya.map(str::to_owned)),
                "name {name:?} must parse to tarif={tarif:?} daya={daya:?}"
            );
        }
    }

    #[test]
    fn other_products_serialize_without_tarif_or_daya() {
        // Bank (Cutiezy), e-wallet (Tukangcek) and WhatsApp (Tukangcek)
        // results must be byte-shape-identical to before: the new fields
        // are skipped when None, so the keys never appear.
        let bank = serde_json::json!({
            "success": true,
            "data": {"accountname": "BUDI SANTOSO"}
        });
        let (_, _, bank_result) = normalize_provider_payload(
            ValidationProduct::BankAccount,
            &bank,
            &super::cutiezy_mapping(ValidationProduct::BankAccount),
            "1234567890",
            false,
        )
        .expect("bank normalizes");
        let ewallet = serde_json::json!({"found": true, "name": "BUDI SANTOSO"});
        let (_, _, ewallet_result) = normalize_provider_payload(
            ValidationProduct::Ewallet,
            &ewallet,
            &super::tukangcek_mapping(ValidationProduct::Ewallet),
            "081234567890",
            false,
        )
        .expect("ewallet normalizes");
        let whatsapp = serde_json::json!({"registered": true});
        let (_, _, whatsapp_result) = normalize_provider_payload(
            ValidationProduct::Whatsapp,
            &whatsapp,
            &super::tukangcek_mapping(ValidationProduct::Whatsapp),
            "6281234567890",
            false,
        )
        .expect("whatsapp normalizes");
        for result in [bank_result, ewallet_result, whatsapp_result] {
            let result = result.expect("result");
            assert_eq!(result.tarif, None);
            assert_eq!(result.daya, None);
            let serialized = serde_json::to_value(&result).expect("serialize").to_string();
            assert!(!serialized.contains("tarif"));
            assert!(!serialized.contains("daya"));
        }
    }
}

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, MySqlPool};
use tokio::{net::lookup_host, sync::RwLock};
use url::Url;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    error::AppError,
    models::{
        ProviderEndpoint, ProviderRequestMode, ProviderResponseMapping,
        UpdateProviderEndpointRequest, ValidationProduct,
    },
};

#[derive(Clone, Debug)]
pub struct ResolvedProviderEndpoint {
    pub id: Uuid,
    pub product: ValidationProduct,
    pub name: String,
    pub base_url: String,
    pub api_key: String,
    pub timeout_ms: u32,
    pub request_mode: ProviderRequestMode,
    pub auth_header: String,
    /// Admin-only: bila true, endpoint tetap di-admit meski circuit
    /// breaker-nya terbuka (bypass HANYA breaker; pacer/semaphore/
    /// antrean tetap berlaku, hasil tetap dicatat ke breaker).
    pub force_on: bool,
    pub response_mapping: ProviderResponseMapping,
    pub service_code_mapping: std::collections::HashMap<String, String>,
    pub http_method: String,
    pub code_param: String,
    pub number_param: String,
    pub key_param: Option<String>,
}

#[derive(Clone, Debug)]
struct ProviderEndpointRecord {
    endpoint: ProviderEndpoint,
    api_key: String,
}

pub struct ProviderConfigStore {
    /// Every configured third-party server, keyed by endpoint id. A product
    /// may have several servers; validations race the active ones.
    entries: RwLock<HashMap<Uuid, ProviderEndpointRecord>>,
    pool: Option<MySqlPool>,
    cipher: CredentialCipher,
    production: bool,
    allowed_hosts: Vec<String>,
}

impl ProviderConfigStore {
    /// The shared MySQL pool, when a database is configured. Other stores
    /// attach to the same pool for their own persistence.
    pub fn pool(&self) -> Option<MySqlPool> {
        self.pool.clone()
    }

    pub async fn build(config: &AppConfig) -> anyhow::Result<Arc<Self>> {
        let cipher = CredentialCipher::new(config.provider_credential_key.as_deref());
        let pool = match config.database_url.as_deref() {
            Some(url) => Some(
                crate::database::Database::connect(url)
                    .await?
                    .pool()
                    .clone(),
            ),
            None => None,
        };
        let store = Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
            pool,
            cipher,
            production: config.environment.is_production(),
            allowed_hosts: config.provider_allowed_hosts.clone(),
        });

        store.load_persisted().await?;
        if store.entries.read().await.is_empty() {
            if let (Some(base_url), Some(api_key)) = (
                config.provider_base_url.as_deref(),
                config.provider_api_key.as_deref(),
            ) {
                validate_endpoint_url(base_url, store.production, &store.allowed_hosts, false)?;
                let tukangcek = Url::parse(base_url)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
                    .is_some_and(|host| host == "tukangcek.id" || host.ends_with(".tukangcek.id"));
                let now = Utc::now();
                let mut entries = store.entries.write().await;
                for product in [
                    ValidationProduct::BankAccount,
                    ValidationProduct::Ewallet,
                    ValidationProduct::Whatsapp,
                ] {
                    let record = ProviderEndpointRecord {
                        endpoint: ProviderEndpoint {
                            id: Uuid::now_v7(),
                            product,
                            name: format!("HTTP {}", product.label_id()),
                            base_url: if tukangcek {
                                match product {
                                    ValidationProduct::Whatsapp => {
                                        "https://tukangcek.id/api/check-wa".to_owned()
                                    }
                                    _ => "https://tukangcek.id/api/check".to_owned(),
                                }
                            } else {
                                base_url.to_owned()
                            },
                            timeout_ms: (config.request_timeout_seconds * 1_000).clamp(100, 60_000)
                                as u32,
                            active: true,
                            force_on: false,
                            request_mode: if tukangcek {
                                ProviderRequestMode::Tukangcek
                            } else {
                                ProviderRequestMode::Generic
                            },
                            auth_header: if tukangcek {
                                "X-API-Key".to_owned()
                            } else {
                                "Authorization".to_owned()
                            },
                            api_key_configured: true,
                            service_code_mapping: std::collections::HashMap::new(),
                            response_mapping: if tukangcek {
                                tukangcek_response_mapping(product)
                            } else {
                                ProviderResponseMapping::default_for(product)
                            },
                            http_method: "POST".to_owned(),
                            code_param: "code".to_owned(),
                            number_param: "target".to_owned(),
                            key_param: None,
                            updated_at: now,
                        },
                        api_key: api_key.to_owned(),
                    };
                    entries.insert(record.endpoint.id, record);
                }
            }
        }

        let now = Utc::now();
        let mut entries = store.entries.write().await;
        for product in [
            ValidationProduct::BankAccount,
            ValidationProduct::Ewallet,
            ValidationProduct::Whatsapp,
        ] {
            if !entries
                .values()
                .any(|record| record.endpoint.product == product)
            {
                let record = ProviderEndpointRecord {
                    endpoint: ProviderEndpoint {
                        id: Uuid::now_v7(),
                        product,
                        name: format!("Provider {}", product.label_id()),
                        base_url: String::new(),
                        timeout_ms: 8_000,
                        active: false,
                        force_on: false,
                        request_mode: ProviderRequestMode::Generic,
                        auth_header: "Authorization".to_owned(),
                        api_key_configured: false,
                        service_code_mapping: std::collections::HashMap::new(),
                        response_mapping: ProviderResponseMapping::default_for(product),
                        http_method: "POST".to_owned(),
                        code_param: "code".to_owned(),
                        number_param: "target".to_owned(),
                        key_param: None,
                        updated_at: now,
                    },
                    api_key: String::new(),
                };
                entries.insert(record.endpoint.id, record);
            }
        }
        drop(entries);
        Ok(store)
    }

    pub async fn list(&self) -> Vec<ProviderEndpoint> {
        let entries = self.entries.read().await;
        let mut endpoints = entries
            .values()
            .map(|record| record.endpoint.clone())
            .collect::<Vec<_>>();
        endpoints.sort_by(|left, right| {
            left.product
                .as_str()
                .cmp(right.product.as_str())
                .then_with(|| left.name.cmp(&right.name))
        });
        endpoints
    }

    fn resolved(record: &ProviderEndpointRecord) -> ResolvedProviderEndpoint {
        ResolvedProviderEndpoint {
            id: record.endpoint.id,
            product: record.endpoint.product,
            name: record.endpoint.name.clone(),
            base_url: record.endpoint.base_url.clone(),
            api_key: record.api_key.clone(),
            timeout_ms: record.endpoint.timeout_ms,
            request_mode: record.endpoint.request_mode,
            auth_header: record.endpoint.auth_header.clone(),
            force_on: record.endpoint.force_on,
            response_mapping: record.endpoint.response_mapping.clone(),
            service_code_mapping: record.endpoint.service_code_mapping.clone(),
            http_method: record.endpoint.http_method.clone(),
            code_param: record.endpoint.code_param.clone(),
            number_param: record.endpoint.number_param.clone(),
            key_param: record.endpoint.key_param.clone(),
        }
    }

    /// Every ACTIVE server for a product, in stable name order — the set a
    /// validation races.
    pub async fn resolve_all(&self, product: ValidationProduct) -> Vec<ResolvedProviderEndpoint> {
        let entries = self.entries.read().await;
        let mut endpoints = entries
            .values()
            .filter(|record| record.endpoint.product == product && record.endpoint.active)
            .map(Self::resolved)
            .collect::<Vec<_>>();
        endpoints.sort_by(|left, right| left.name.cmp(&right.name));
        endpoints
    }

    /// One specific server regardless of its active flag (admin tester and
    /// destination checks target a server before it is activated).
    pub async fn resolve_by_id(&self, id: Uuid) -> Option<ResolvedProviderEndpoint> {
        self.entries.read().await.get(&id).map(Self::resolved)
    }

    fn validate_endpoint_fields(
        &self,
        product: ValidationProduct,
        name: &str,
        base_url: &str,
        timeout_ms: u32,
        mapping: &ProviderResponseMapping,
        request_mode: crate::models::ProviderRequestMode,
        auth_header: &str,
    ) -> Result<String, AppError> {
        if name.is_empty() || name.len() > 160 {
            return Err(AppError::bad_request(
                "Nama endpoint wajib diisi dan maksimal 160 karakter",
            ));
        }
        if !(100..=60_000).contains(&timeout_ms) {
            return Err(AppError::bad_request(
                "Timeout provider harus berada antara 100 dan 60000 milidetik",
            ));
        }
        validate_endpoint_url(base_url, self.production, &self.allowed_hosts, false)?;
        validate_response_mapping(product, mapping)?;
        // B5: an empty auth header is allowed ONLY for Generic endpoints —
        // it means "send no auth header at all". Other modes keep
        // requiring a valid header name.
        validate_auth_header(
            auth_header,
            request_mode == crate::models::ProviderRequestMode::Generic,
        )
    }

    async fn persist_endpoint(
        &self,
        endpoint: &ProviderEndpoint,
        api_key: &str,
    ) -> Result<(), AppError> {
        if let Some(pool) = &self.pool {
            let encrypted = self.cipher.encrypt(api_key)?;
            sqlx::query(
                r#"
                INSERT INTO third_party_endpoints (
                    id, product_code, name, base_url, credential_ciphertext,
                    timeout_ms, request_mode, auth_header, active, force_on, response_mapping, service_code_mapping,
                    http_method, code_param, number_param, key_param, updated_at
                ) VALUES (UUID_TO_BIN(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    name = VALUES(name), base_url = VALUES(base_url),
                    credential_ciphertext = VALUES(credential_ciphertext),
                    timeout_ms = VALUES(timeout_ms), request_mode = VALUES(request_mode),
                    auth_header = VALUES(auth_header), active = VALUES(active), force_on = VALUES(force_on),
                    response_mapping = VALUES(response_mapping),
                    service_code_mapping = VALUES(service_code_mapping),
                    http_method = VALUES(http_method), code_param = VALUES(code_param),
                    number_param = VALUES(number_param), key_param = VALUES(key_param),
                    updated_at = VALUES(updated_at)
                "#,
            )
            .bind(endpoint.id.to_string())
            .bind(endpoint.product.as_str())
            .bind(&endpoint.name)
            .bind(&endpoint.base_url)
            .bind(encrypted)
            .bind(endpoint.timeout_ms)
            .bind(match endpoint.request_mode {
                ProviderRequestMode::Generic => "generic",
                ProviderRequestMode::Tukangcek => "tukangcek",
                ProviderRequestMode::Cutiezy => "cutiezy",
            })
            .bind(&endpoint.auth_header)
            .bind(endpoint.active)
            .bind(endpoint.force_on)
            .bind(
                serde_json::to_string(&endpoint.response_mapping).map_err(|_| {
                    AppError::internal("Mapping respons provider tidak dapat diserialisasi")
                })?,
            )
            .bind(
                serde_json::to_string(&endpoint.service_code_mapping).map_err(|_| {
                    AppError::internal("Mapping kode pihak ketiga tidak dapat diserialisasi")
                })?,
            )
            .bind(&endpoint.http_method)
            .bind(&endpoint.code_param)
            .bind(&endpoint.number_param)
            .bind(&endpoint.key_param)
            .bind(endpoint.updated_at)
            .execute(pool)
            .await
            .map_err(|error| {
                tracing::error!(error = ?error, "Gagal menyimpan endpoint provider");
                AppError::internal("Endpoint provider tidak dapat disimpan")
            })?;
        }
        Ok(())
    }

    pub async fn create(
        &self,
        input: crate::models::CreateProviderEndpointRequest,
    ) -> Result<ProviderEndpoint, AppError> {
        let product = input.product;
        let name = input.name.trim();
        let auth_header = self.validate_endpoint_fields(
            product,
            name,
            input.base_url.trim(),
            input.timeout_ms,
            &input.response_mapping,
            input.request_mode,
            &input.auth_header,
        )?;
        validate_service_code_mapping(product, &input.service_code_mapping)?;
        let (http_method, code_param, number_param, key_param) = validate_http_params(
            &input.http_method,
            &input.code_param,
            &input.number_param,
            input.key_param.as_deref(),
        )?;
        // K6: PLN Generic endpoints must match the known Chikamm
        // contract at save time, so a misconfigured-but-active PLN
        // endpoint can never silently fail every check.
        validate_pln_generic_contract(
            product,
            input.request_mode,
            &http_method,
            &number_param,
            key_param.as_deref(),
        )?;
        let api_key = match input.api_key.as_deref().map(str::trim) {
            Some(value) if !value.is_empty() => {
                if value.len() > 4_096 {
                    return Err(AppError::bad_request("Kredensial provider terlalu panjang"));
                }
                value.to_owned()
            }
            _ => {
                return Err(AppError::bad_request(
                    "Kredensial provider wajib diisi saat endpoint dibuat",
                ))
            }
        };
        let endpoint = ProviderEndpoint {
            id: Uuid::now_v7(),
            product,
            name: name.to_owned(),
            base_url: input.base_url.trim().to_owned(),
            timeout_ms: input.timeout_ms,
            active: input.active,
            force_on: input.force_on,
            request_mode: input.request_mode,
            auth_header,
            api_key_configured: true,
            response_mapping: input.response_mapping,
            service_code_mapping: input.service_code_mapping,
            http_method,
            code_param,
            number_param,
            key_param,
            updated_at: Utc::now(),
        };
        self.persist_endpoint(&endpoint, &api_key).await?;
        self.entries.write().await.insert(
            endpoint.id,
            ProviderEndpointRecord {
                endpoint: endpoint.clone(),
                api_key,
            },
        );
        Ok(endpoint)
    }

    pub async fn update_by_id(
        &self,
        id: Uuid,
        input: UpdateProviderEndpointRequest,
    ) -> Result<ProviderEndpoint, AppError> {
        let existing = self
            .entries
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| AppError::not_found("Endpoint provider tidak ditemukan"))?;
        let product = existing.endpoint.product;
        let name = input.name.trim();
        let auth_header = self.validate_endpoint_fields(
            product,
            name,
            input.base_url.trim(),
            input.timeout_ms,
            &input.response_mapping,
            input.request_mode,
            &input.auth_header,
        )?;
        validate_service_code_mapping(product, &input.service_code_mapping)?;
        let (http_method, code_param, number_param, key_param) = validate_http_params(
            &input.http_method,
            &input.code_param,
            &input.number_param,
            input.key_param.as_deref(),
        )?;
        // K6: same save-time Chikamm contract check as create; it never
        // blocks clearing the auth header (B5) — the two checks are
        // independent, and an empty header stays allowed for Generic.
        validate_pln_generic_contract(
            product,
            input.request_mode,
            &http_method,
            &number_param,
            key_param.as_deref(),
        )?;
        let api_key = match input.api_key.as_deref().map(str::trim) {
            Some(value) if !value.is_empty() => {
                if value.len() > 4_096 {
                    return Err(AppError::bad_request("Kredensial provider terlalu panjang"));
                }
                value.to_owned()
            }
            _ => {
                if existing.api_key.is_empty() {
                    return Err(AppError::bad_request(
                        "Kredensial provider wajib diisi saat endpoint pertama kali dibuat",
                    ));
                }
                existing.api_key.clone()
            }
        };
        let endpoint = ProviderEndpoint {
            id,
            product,
            name: name.to_owned(),
            base_url: input.base_url.trim().to_owned(),
            timeout_ms: input.timeout_ms,
            active: input.active,
            force_on: input.force_on,
            request_mode: input.request_mode,
            auth_header,
            api_key_configured: true,
            response_mapping: input.response_mapping,
            service_code_mapping: input.service_code_mapping,
            http_method,
            code_param,
            number_param,
            key_param,
            updated_at: Utc::now(),
        };
        self.persist_endpoint(&endpoint, &api_key).await?;
        self.entries.write().await.insert(
            id,
            ProviderEndpointRecord {
                endpoint: endpoint.clone(),
                api_key,
            },
        );
        Ok(endpoint)
    }

    pub async fn set_active(&self, id: Uuid, active: bool) -> Result<ProviderEndpoint, AppError> {
        let existing = self
            .entries
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| AppError::not_found("Endpoint provider tidak ditemukan"))?;
        let mut endpoint = existing.endpoint.clone();
        endpoint.active = active;
        endpoint.updated_at = Utc::now();
        self.persist_endpoint(&endpoint, &existing.api_key).await?;
        self.entries.write().await.insert(
            id,
            ProviderEndpointRecord {
                endpoint: endpoint.clone(),
                api_key: existing.api_key.clone(),
            },
        );
        Ok(endpoint)
    }

    /// Admin toggle paksa ON (PATCH force-on): hanya membalik flag,
    /// tanpa menyentuh breaker — SENGAJA tidak memanggil
    /// reset_breaker_on_activation. Berbeda dengan aktivasi
    /// nonaktif->aktif (K34) yang me-reset breaker, toggle paksa
    /// on/off harus membiarkan state breaker apa adanya: hasil yang
    /// tercatat selama paksa ON tetap berlaku saat paksa dimatikan.
    pub async fn set_force_on(
        &self,
        id: Uuid,
        force_on: bool,
    ) -> Result<ProviderEndpoint, AppError> {
        let existing = self
            .entries
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| AppError::not_found("Endpoint provider tidak ditemukan"))?;
        let mut endpoint = existing.endpoint.clone();
        endpoint.force_on = force_on;
        endpoint.updated_at = Utc::now();
        self.persist_endpoint(&endpoint, &existing.api_key).await?;
        self.entries.write().await.insert(
            id,
            ProviderEndpointRecord {
                endpoint: endpoint.clone(),
                api_key: existing.api_key.clone(),
            },
        );
        Ok(endpoint)
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        if self.entries.write().await.remove(&id).is_none() {
            return Err(AppError::not_found("Endpoint provider tidak ditemukan"));
        }
        if let Some(pool) = &self.pool {
            sqlx::query("DELETE FROM third_party_endpoints WHERE id = UUID_TO_BIN(?)")
                .bind(id.to_string())
                .execute(pool)
                .await
                .map_err(|error| {
                    tracing::error!(error = ?error, "Gagal menghapus endpoint provider");
                    AppError::internal("Endpoint provider tidak dapat dihapus")
                })?;
        }
        Ok(())
    }

    pub async fn verify_destination(&self, base_url: &str) -> Result<(), AppError> {
        validate_endpoint_url(base_url, self.production, &self.allowed_hosts, true)?;
        let parsed = Url::parse(base_url)
            .map_err(|_| AppError::bad_request("URL endpoint provider tidak valid"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| AppError::bad_request("Host endpoint provider wajib tersedia"))?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addresses = lookup_host((host, port)).await.map_err(|error| {
            tracing::warn!(host, error = ?error, "DNS provider tidak dapat diverifikasi");
            AppError::service_unavailable("DNS endpoint provider tidak dapat diverifikasi")
        })?;
        let mut found = false;
        for address in addresses {
            found = true;
            if self.production && !is_public_ip(address.ip()) {
                return Err(AppError::bad_request(
                    "Endpoint provider mengarah ke jaringan privat atau alamat terlarang",
                ));
            }
        }
        if !found {
            return Err(AppError::service_unavailable(
                "Endpoint provider tidak memiliki alamat DNS yang dapat digunakan",
            ));
        }
        Ok(())
    }

    /// Durable member validation history from `validation_requests` (written by
    /// the worker). Returns None when no database is attached or the query
    /// fails, so the caller can fall back to the in-memory history.
    /// Member-portal aggregates from the durable history: checks today (WIB),
    /// checks in the last 30 days, and per-day per-product counts for the
    /// last 14 days (WIB dates). Returns None when no database is attached.
    pub async fn member_usage_from_db(
        &self,
        prefixes: &[String],
    ) -> Option<crate::models::MemberUsageData> {
        if prefixes.is_empty() {
            return None;
        }
        let pool = self.pool.as_ref()?;
        // All three aggregates span the member's prefixes (see F15).
        let mut today_builder =
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM validation_requests WHERE ");
        today_builder.push("api_key_prefix IN (");
        let mut separated = today_builder.separated(", ");
        for prefix in prefixes {
            separated.push_bind(prefix);
        }
        separated.push_unseparated(")");
        today_builder.push(
            " AND DATE(CONVERT_TZ(occurred_at, '+00:00', '+07:00')) = DATE(CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+07:00'))",
        );
        let today: i64 = today_builder
            .build_query_scalar()
            .fetch_one(pool)
            .await
            .ok()?;
        let mut last_30_builder =
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM validation_requests WHERE ");
        last_30_builder.push("api_key_prefix IN (");
        let mut separated = last_30_builder.separated(", ");
        for prefix in prefixes {
            separated.push_bind(prefix);
        }
        separated.push_unseparated(")");
        last_30_builder.push(" AND occurred_at >= UTC_TIMESTAMP() - INTERVAL 30 DAY");
        let last_30_days: i64 = last_30_builder
            .build_query_scalar()
            .fetch_one(pool)
            .await
            .ok()?;
        let mut rows_builder = sqlx::QueryBuilder::new(
            "SELECT DATE_FORMAT(CONVERT_TZ(occurred_at, '+00:00', '+07:00'), '%Y-%m-%d') AS day, \
             product_code, COUNT(*) AS total FROM validation_requests WHERE ",
        );
        rows_builder.push("api_key_prefix IN (");
        let mut separated = rows_builder.separated(", ");
        for prefix in prefixes {
            separated.push_bind(prefix);
        }
        separated.push_unseparated(")");
        rows_builder.push(
            " AND occurred_at >= UTC_TIMESTAMP() - INTERVAL 14 DAY \
             GROUP BY day, product_code ORDER BY day",
        );
        let rows: Vec<(String, String, i64)> = rows_builder
            .build_query_as()
            .fetch_all(pool)
            .await
            .ok()?;
        Some(crate::models::MemberUsageData {
            checks_today: today,
            checks_last_30_days: last_30_days,
            daily: rows
                .into_iter()
                .map(|(date, product, count)| crate::models::MemberDailyCount {
                    date,
                    product,
                    count,
                })
                .collect(),
        })
    }

    pub async fn validation_history_from_db(
        &self,
        filters: &crate::models::ValidationHistoryFilters,
        limit: u32,
        offset: u32,
    ) -> Option<(Vec<crate::models::ValidationHistoryItem>, u64, u64, u64)> {
        let pool = self.pool.as_ref()?;
        fn apply_filters<'a>(
            mut builder: sqlx::QueryBuilder<'a, sqlx::MySql>,
            filters: &'a crate::models::ValidationHistoryFilters,
        ) -> sqlx::QueryBuilder<'a, sqlx::MySql> {
            if let Some(product) = filters.product {
                builder.push(" AND product_code = ");
                builder.push_bind(product.as_str());
            }
            if let Some(outcome) = &filters.outcome {
                builder.push(" AND outcome = ");
                builder.push_bind(outcome.clone());
            }
            if let Some(prefixes) = &filters.api_key_prefixes {
                // Member-wide view: exact matches across all of the
                // member's prefixes (current + regenerated + revoked).
                builder.push(" AND api_key_prefix IN (");
                let mut first = true;
                for prefix in prefixes {
                    if !first {
                        builder.push(", ");
                    }
                    first = false;
                    builder.push_bind(prefix.clone());
                }
                builder.push(")");
            } else if let Some(prefix) = &filters.api_key_prefix {
                builder.push(" AND api_key_prefix LIKE ");
                builder.push_bind(format!(
                    "{}%",
                    crate::models::escape_like(prefix)
                ));
            }
            // AREA 5: kata kunci + rentang tanggal admin. LIKE di-escape
            // (escape_like) supaya `_`/`%` dari input tidak melebar jadi
            // wildcard; perbandingan tanggal memakai kolom UTC apa adanya.
            if let Some(q) = &filters.q {
                let pattern = format!("%{}%", crate::models::escape_like(q));
                builder.push(" AND (api_key_prefix LIKE ");
                builder.push_bind(pattern.clone());
                builder.push(" OR request_id LIKE ");
                builder.push_bind(pattern.clone());
                builder.push(" OR target_masked LIKE ");
                builder.push_bind(pattern);
                builder.push(")");
            }
            if let Some(from) = &filters.from {
                builder.push(" AND occurred_at >= ");
                builder.push_bind(from.naive_utc());
            }
            if let Some(to) = &filters.to_exclusive {
                builder.push(" AND occurred_at < ");
                builder.push_bind(to.naive_utc());
            }
            builder
        }
        let mut count_builder = apply_filters(
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM validation_requests WHERE 1 = 1"),
            filters,
        );
        let total: i64 = match count_builder.build_query_scalar().fetch_one(pool).await {
            Ok(total) => total,
            Err(error) => {
                tracing::warn!(error = ?error, "Hitung riwayat validasi gagal");
                return None;
            }
        };
        // Riwayat ADMIN: member_code di-resolve di query yang sama
        // (migration 0025), bukan N+1 query per baris: prefix kunci unik
        // di admin_api_keys, jadi LEFT JOIN ini tidak pernah menggandakan
        // baris. LEFT JOIN (bukan INNER): kunci seed env / kunci terhapus
        // tetap tampil dengan member_code NULL, bukan hilang/error.
        // Nama endpoint sumber (migration 0033) di-resolve dengan pola
        // yang sama: te.id adalah PK sehingga JOIN ini juga tidak pernah
        // menggandakan baris; baris lama (provider_endpoint_id NULL)
        // tetap tampil dengan nama NULL. Hanya NAMA yang diambil —
        // tidak pernah URL/host/kredensial endpoint.
        // Kolom filter apply_filters tetap tak-ambigu: hanya
        // validation_requests yang punya product_code/outcome/
        // api_key_prefix/request_id/target_masked/occurred_at.
        #[derive(sqlx::FromRow)]
        struct HistoryRow {
            request_id: String,
            api_key_prefix: String,
            product_code: String,
            outcome: String,
            target_masked: String,
            target_raw: Option<String>,
            account_name: Option<String>,
            provider_reference: Option<String>,
            provider_hint: Option<String>,
            provider_latency_ms: u64,
            rajacek_processing_ms: Option<u64>,
            total_latency_ms: Option<u64>,
            attempts: Option<u32>,
            occurred_at: chrono::NaiveDateTime,
            channel: String,
            member_code: Option<String>,
            provider_endpoint_name: Option<String>,
        }
        let mut rows_builder = apply_filters(
            sqlx::QueryBuilder::new(
                "SELECT vr.request_id, vr.api_key_prefix, vr.product_code, vr.outcome, vr.target_masked, vr.target_raw, vr.account_name, vr.provider_reference, vr.provider_hint, vr.provider_latency_ms, vr.rajacek_processing_ms, vr.total_latency_ms, vr.attempts, vr.occurred_at, vr.channel, m.member_code, te.name AS provider_endpoint_name FROM validation_requests vr LEFT JOIN admin_api_keys k ON k.prefix = vr.api_key_prefix LEFT JOIN members m ON m.id = k.member_id LEFT JOIN third_party_endpoints te ON te.id = vr.provider_endpoint_id WHERE 1 = 1",
            ),
            filters,
        );
        rows_builder.push(" ORDER BY occurred_at DESC LIMIT ");
        rows_builder.push_bind(i64::from(limit));
        rows_builder.push(" OFFSET ");
        rows_builder.push_bind(i64::from(offset));
        let rows: Vec<HistoryRow> = match rows_builder.build_query_as().fetch_all(pool).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(error = ?error, "Kueri riwayat validasi gagal");
                return None;
            }
        };
        let items = rows
            .into_iter()
            .filter_map(
                |row| {
                    let Some(product) = parse_product(row.product_code.as_str()) else {
                        return None;
                    };

                    Some(crate::models::ValidationHistoryItem {
                        request_id: row.request_id,
                        api_key_prefix: row.api_key_prefix,
                        member_code: row.member_code,
                        product,
                        outcome: row.outcome,
                        target_masked: row.target_masked,
                        target_raw: row.target_raw,
                        account_name: row.account_name,
                        provider_endpoint_name: row.provider_endpoint_name,
                        provider_hint_display: crate::models::provider_hint_display(
                            product,
                            row.provider_hint.as_deref(),
                        ),
                        provider_reference: row.provider_reference,
                        provider_latency_ms: row.provider_latency_ms,
                        rajacek_processing_ms: row.rajacek_processing_ms,
                        total_latency_ms: row.total_latency_ms,
                        attempts: row.attempts,
                        occurred_at: chrono::DateTime::from_naive_utc_and_offset(
                            row.occurred_at,
                            chrono::Utc,
                        ),
                        channel: row.channel,
                    })
                },
            )
            .collect();
        // Rolling-window hit counts with the same filters, for the admin
        // recap (average hits per second / per minute). occurred_at is UTC.
        let window_count = |seconds: i64| {
            let mut builder = apply_filters(
                sqlx::QueryBuilder::new("SELECT COUNT(*) FROM validation_requests WHERE 1 = 1"),
                filters,
            );
            builder.push(format!(
                " AND occurred_at >= UTC_TIMESTAMP() - INTERVAL {seconds} SECOND"
            ));
            builder
        };
        let hits_last_60s: i64 = match window_count(60).build_query_scalar().fetch_one(pool).await {
            Ok(count) => count,
            Err(_) => 0,
        };
        let hits_last_3600s: i64 = match window_count(3600)
            .build_query_scalar()
            .fetch_one(pool)
            .await
        {
            Ok(count) => count,
            Err(_) => 0,
        };
        Some((
            items,
            total.max(0) as u64,
            hits_last_60s.max(0) as u64,
            hits_last_3600s.max(0) as u64,
        ))
    }

    /// Generic single-value runtime settings (see migration 0005). Used for
    /// small admin-tunable numbers such as the default rate limit.
    pub async fn load_runtime_setting(&self, key: &str) -> Option<String> {
        let pool = self.pool.as_ref()?;
        sqlx::query_scalar::<_, String>(
            "SELECT setting_value FROM runtime_settings WHERE setting_key = ?",
        )
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
    }

    pub async fn save_runtime_setting(&self, key: &str, value: &str) -> bool {
        let Some(pool) = self.pool.as_ref() else {
            return false;
        };
        sqlx::query(
            "INSERT INTO runtime_settings (setting_key, setting_value) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .is_ok()
    }

    /// Loads panel-saved provider guard settings, if a database is attached and
    /// a complete set was stored. Anything incomplete or unparsable is ignored so
    /// a bad row can never wedge startup; the env-seeded values stay in effect.
    pub async fn load_guard_config(&self) -> Option<crate::provider_guard::ProviderGuardConfig> {
        let pool = self.pool.as_ref()?;
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT setting_key, setting_value FROM runtime_settings WHERE setting_key LIKE 'provider_guard.%'",
        )
        .fetch_all(pool)
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "Pengaturan provider guard tidak dapat dimuat");
            error
        })
        .ok()?;
        fn lookup<T: std::str::FromStr>(rows: &[(String, String)], key: &str) -> Option<T> {
            rows.iter()
                .find(|(stored, _)| stored == key)
                .and_then(|(_, value)| value.parse().ok())
        }
        let config = crate::provider_guard::ProviderGuardConfig {
            max_concurrency_per_product: lookup(
                &rows,
                "provider_guard.max_concurrency_per_product",
            )?,
            // Rows saved before the PLN cap existed fall back to the
            // conservative PLN default instead of wedging startup.
            max_concurrency_pln: lookup(&rows, "provider_guard.max_concurrency_pln")
                .unwrap_or(3),
            queue_wait_ms: lookup(&rows, "provider_guard.queue_wait_ms")?,
            failure_threshold: lookup(&rows, "provider_guard.failure_threshold")?,
            cooldown_seconds: lookup(&rows, "provider_guard.cooldown_seconds")?,
            // Saved before this setting existed: fall back to the default.
            max_attempts: lookup(&rows, "provider_guard.max_attempts").unwrap_or(2),
            pace_interval_ms: lookup(&rows, "provider_guard.pace_interval_ms").unwrap_or(334),
            pace_max_wait_ms: lookup(&rows, "provider_guard.pace_max_wait_ms").unwrap_or(10_000),
        };
        if config.validate_for_admin().is_err() {
            tracing::warn!("Pengaturan provider guard tersimpan di luar rentang; diabaikan");
            return None;
        }
        tracing::info!("Pengaturan provider guard dimuat dari database");
        Some(config)
    }

    /// Persists provider guard settings. Returns false when no database is
    /// attached (values then live only in process memory) or the write failed.
    pub async fn save_guard_config(
        &self,
        config: &crate::provider_guard::ProviderGuardConfig,
    ) -> bool {
        let Some(pool) = self.pool.as_ref() else {
            return false;
        };
        let entries = [
            (
                "provider_guard.max_concurrency_per_product",
                config.max_concurrency_per_product.to_string(),
            ),
            (
                "provider_guard.max_concurrency_pln",
                config.max_concurrency_pln.to_string(),
            ),
            (
                "provider_guard.queue_wait_ms",
                config.queue_wait_ms.to_string(),
            ),
            (
                "provider_guard.failure_threshold",
                config.failure_threshold.to_string(),
            ),
            (
                "provider_guard.cooldown_seconds",
                config.cooldown_seconds.to_string(),
            ),
            (
                "provider_guard.max_attempts",
                config.max_attempts.to_string(),
            ),
            (
                "provider_guard.pace_interval_ms",
                config.pace_interval_ms.to_string(),
            ),
            (
                "provider_guard.pace_max_wait_ms",
                config.pace_max_wait_ms.to_string(),
            ),
        ];
        for (key, value) in entries {
            let result = sqlx::query(
                "INSERT INTO runtime_settings (setting_key, setting_value) VALUES (?, ?)                  ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await;
            if let Err(error) = result {
                tracing::warn!(error = ?error, key, "Pengaturan provider guard gagal disimpan");
                return false;
            }
        }
        true
    }

    async fn load_persisted(&self) -> anyhow::Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let rows = sqlx::query_as::<_, ProviderEndpointRow>(
            r#"
            SELECT BIN_TO_UUID(id) AS id, product_code, name, base_url,
                   credential_ciphertext, timeout_ms, request_mode, auth_header,
                   active, force_on, CAST(response_mapping AS CHAR) AS response_mapping,
                   CAST(service_code_mapping AS CHAR) AS service_code_mapping,
                   http_method, code_param, number_param, key_param, updated_at
            FROM third_party_endpoints
            "#,
        )
        .fetch_all(pool)
        .await?;
        let mut entries = self.entries.write().await;
        for row in rows {
            let Some(product) = parse_product(&row.product_code) else {
                tracing::warn!(product = %row.product_code, "Konfigurasi provider memiliki produk tidak dikenal");
                continue;
            };
            let api_key = self.cipher.decrypt(&row.credential_ciphertext)?;
            let endpoint_id = Uuid::parse_str(&row.id)?;
            let record = ProviderEndpointRecord {
                endpoint: ProviderEndpoint {
                    id: endpoint_id,
                    product,
                    name: row.name,
                    base_url: row.base_url,
                    timeout_ms: row.timeout_ms,
                    active: row.active,
                    force_on: row.force_on,
                    request_mode: match row.request_mode.as_str() {
                        "tukangcek" => ProviderRequestMode::Tukangcek,
                        "cutiezy" => ProviderRequestMode::Cutiezy,
                        _ => ProviderRequestMode::Generic,
                    },
                    auth_header: row.auth_header,
                    api_key_configured: !api_key.is_empty(),
                    response_mapping: parse_stored_mapping(&row.response_mapping)?,
                    service_code_mapping: parse_stored_service_mapping(
                        row.service_code_mapping.as_deref(),
                    ),
                    http_method: normalize_http_method(&row.http_method),
                    code_param: normalize_param_name(&row.code_param, "code"),
                    number_param: normalize_param_name(&row.number_param, "target"),
                    key_param: row
                        .key_param
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned),
                    updated_at: row.updated_at,
                },
                api_key,
            };
            entries.insert(endpoint_id, record);
        }
        Ok(())
    }
}

/// Parses a stored response mapping. The column is MySQL JSON and is read
/// through a CAST to text; tolerate a double-encoded JSON string from older
/// writers by unwrapping one string layer when the direct parse fails.
/// Parses a stored service-code mapping. NULL (pre-migration rows) and
/// malformed values both mean "no mapping" rather than failing the whole
/// endpoint load: an unmapped code is sent as-is, the historical behavior.
fn parse_stored_service_mapping(text: Option<&str>) -> std::collections::HashMap<String, String> {
    let Some(text) = text else {
        return std::collections::HashMap::new();
    };
    match serde_json::from_str::<std::collections::HashMap<String, String>>(text) {
        Ok(mapping) => mapping,
        Err(error) => {
            tracing::warn!(error = ?error, "Mapping kode pihak ketiga tersimpan tidak valid; diabaikan");
            std::collections::HashMap::new()
        }
    }
}

fn parse_stored_mapping(text: &str) -> Result<ProviderResponseMapping, serde_json::Error> {
    if let Ok(mapping) = serde_json::from_str::<ProviderResponseMapping>(text) {
        return Ok(mapping);
    }
    let inner: String = serde_json::from_str(text)?;
    serde_json::from_str(&inner)
}

#[derive(FromRow)]
struct ProviderEndpointRow {
    id: String,
    product_code: String,
    name: String,
    base_url: String,
    credential_ciphertext: Vec<u8>,
    timeout_ms: u32,
    request_mode: String,
    auth_header: String,
    active: bool,
    force_on: bool,
    response_mapping: String,
    service_code_mapping: Option<String>,
    http_method: String,
    code_param: String,
    number_param: String,
    key_param: Option<String>,
    updated_at: DateTime<Utc>,
}

/// Stored method is normalized defensively: anything but GET becomes POST,
/// the pre-migration default.
fn normalize_http_method(value: &str) -> String {
    if value.trim().eq_ignore_ascii_case("GET") {
        "GET".to_owned()
    } else {
        "POST".to_owned()
    }
}

fn normalize_param_name(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[derive(Clone)]
pub(crate) struct CredentialCipher {
    cipher: Aes256Gcm,
    /// True when no secret was configured (or it was empty), so the
    /// constructor fell back to the development key printed in source.
    /// Decrypting legacy data with a fallback cipher still works, but
    /// NEW secrets must never be encrypted under it (audit flow B6).
    from_fallback: bool,
}

impl CredentialCipher {
    pub(crate) fn new(secret: Option<&str>) -> Self {
        use sha2::{Digest, Sha256};
        let from_fallback = secret.is_none_or(|value| value.is_empty());
        let material = secret.unwrap_or("development-only-provider-credential-key");
        let key = Sha256::digest(material.as_bytes());
        Self {
            cipher: Aes256Gcm::new_from_slice(&key).expect("SHA-256 selalu menghasilkan 32 byte"),
            from_fallback,
        }
    }

    /// Whether this cipher was built without a configured secret.
    pub(crate) fn is_fallback(&self) -> bool {
        self.from_fallback
    }

    pub(crate) fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, AppError> {
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut output = nonce_bytes.to_vec();
        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .map_err(|_| AppError::internal("Kredensial provider tidak dapat dienkripsi"))?;
        output.extend(encrypted);
        Ok(output)
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<String> {
        anyhow::ensure!(
            ciphertext.len() > 12,
            "Ciphertext kredensial provider rusak"
        );
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&ciphertext[..12]), &ciphertext[12..])
            .map_err(|_| anyhow::anyhow!("Kredensial provider tidak dapat didekripsi"))?;
        Ok(String::from_utf8(plaintext)?)
    }
}

fn validate_endpoint_url(
    value: &str,
    production: bool,
    allowed_hosts: &[String],
    runtime_check: bool,
) -> Result<(), AppError> {
    if value.len() > 2_048 {
        return Err(AppError::bad_request(
            "URL endpoint provider terlalu panjang",
        ));
    }
    let url = Url::parse(value)
        .map_err(|_| AppError::bad_request("URL endpoint provider tidak valid"))?;
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err(AppError::bad_request(
            "URL provider tidak boleh memuat userinfo atau fragment",
        ));
    }
    if production && url.scheme() != "https" {
        return Err(AppError::bad_request(
            "Endpoint provider production wajib menggunakan HTTPS",
        ));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::bad_request(
            "Endpoint provider hanya mendukung HTTP atau HTTPS",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::bad_request("Host endpoint provider wajib tersedia"))?
        .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        if production {
            return Err(AppError::bad_request(
                "Endpoint localhost tidak diizinkan pada production",
            ));
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if production && !is_public_ip(ip) {
            return Err(AppError::bad_request(
                "Alamat IP privat atau lokal tidak diizinkan pada production",
            ));
        }
    }
    if production
        && !allowed_hosts
            .iter()
            .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
    {
        return Err(AppError::bad_request(
            "Host endpoint tidak terdapat dalam PROVIDER_ALLOWED_HOSTS",
        ));
    }
    if runtime_check && url.query().is_some() {
        tracing::debug!("Endpoint provider menggunakan query statis yang telah disetujui admin");
    }
    Ok(())
}

fn tukangcek_response_mapping(product: ValidationProduct) -> ProviderResponseMapping {
    match product {
        ValidationProduct::Whatsapp => ProviderResponseMapping {
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
        ValidationProduct::BankAccount | ValidationProduct::Ewallet => ProviderResponseMapping {
            status_path: "found".to_owned(),
            valid_values: vec!["true".to_owned()],
            invalid_values: vec![],
            not_found_values: vec!["false".to_owned()],
            pending_values: vec![],
            message_path: None,
            account_name_path: Some("name".to_owned()),
            provider_path: None,
            registered_path: matches!(product, ValidationProduct::Ewallet)
                .then(|| "found".to_owned()),
            reference_path: None,
        },
        // PLN tidak pernah lewat Tukangcek (ditolak sebelum mapping ini
        // dipakai); arm hanya untuk exhaustiveness.
        ValidationProduct::Pln => ProviderResponseMapping {
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
    }
}

fn validate_auth_header(value: &str, allow_empty: bool) -> Result<String, AppError> {
    let value = value.trim();
    // B5: Generic endpoints may opt out of auth headers entirely — an
    // empty name means "send no header at all" at dispatch time. A
    // whitespace-only or invalid name is still rejected everywhere.
    if value.is_empty() {
        if allow_empty {
            return Ok(String::new());
        }
        return Err(AppError::bad_request(
            "Nama header autentikasi provider tidak valid",
        ));
    }
    if value.len() > 80
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::bad_request(
            "Nama header autentikasi provider tidak valid",
        ));
    }
    Ok(value.to_owned())
}

/// K6: save-time contract check for PLN Generic endpoints (Chikamm).
/// Only PLN + Generic is gated: other products and other request modes
/// keep their existing behavior, and the auth header is deliberately
/// NOT part of this check (B5: clearing it must never be blocked here).
fn validate_pln_generic_contract(
    product: ValidationProduct,
    request_mode: crate::models::ProviderRequestMode,
    http_method: &str,
    number_param: &str,
    key_param: Option<&str>,
) -> Result<(), AppError> {
    if product != ValidationProduct::Pln
        || request_mode != crate::models::ProviderRequestMode::Generic
    {
        return Ok(());
    }
    if !http_method.eq_ignore_ascii_case("GET") {
        return Err(AppError::bad_request(
            "Endpoint PLN (Chikamm) harus memakai metode GET — POST mengirim body JSON ke URL yang mengharapkan query string",
        ));
    }
    if number_param != "target" {
        return Err(AppError::bad_request(
            "Endpoint PLN (Chikamm) harus memakai nama param nomor 'target'",
        ));
    }
    if key_param != Some("api_key") {
        return Err(AppError::bad_request(
            "Endpoint PLN (Chikamm) harus memakai nama param kunci 'api_key'",
        ));
    }
    Ok(())
}

fn validate_response_mapping(
    product: ValidationProduct,
    mapping: &ProviderResponseMapping,
) -> Result<(), AppError> {
    let paths = [
        Some(mapping.status_path.as_str()),
        mapping.message_path.as_deref(),
        mapping.account_name_path.as_deref(),
        mapping.provider_path.as_deref(),
        mapping.registered_path.as_deref(),
        mapping.reference_path.as_deref(),
    ];
    for path in paths.into_iter().flatten() {
        if !is_valid_json_path(path) {
            return Err(AppError::bad_request(
                "Path JSON hanya boleh berisi nama field dan indeks array, misalnya data.account.name atau data.items[0].status",
            ));
        }
    }
    if mapping.valid_values.is_empty() {
        return Err(AppError::bad_request(
            "Mapping status valid harus memiliki minimal satu nilai",
        ));
    }
    if mapping
        .valid_values
        .iter()
        .chain(&mapping.invalid_values)
        .chain(&mapping.not_found_values)
        .chain(&mapping.pending_values)
        .any(|value| value.trim().is_empty() || value.len() > 100)
    {
        return Err(AppError::bad_request(
            "Nilai mapping status tidak boleh kosong dan maksimal 100 karakter",
        ));
    }
    // E-wallet results carry the holder name like bank results do; only
    // WhatsApp is name-less (its normalizer never surfaces a name anyway).
    Ok(())
}

/// Custom e-wallet code mapping for generic third-party endpoints: the
/// member-facing code (key) translated to the code that provider expects
/// (value), e.g. dana -> dana009. Only e-wallet endpoints may carry one;
/// Tukangcek/Cutiezy endpoints keep their built-in mappings. Empty values
/// and unknown keys are rejected so a misconfiguration fails at save time,
/// never silently at request time.
fn validate_service_code_mapping(
    product: ValidationProduct,
    mapping: &std::collections::HashMap<String, String>,
) -> Result<(), AppError> {
    if mapping.is_empty() {
        return Ok(());
    }
    // Mapping keys are always member-facing codes; WhatsApp has no service
    // code so a mapping is meaningless for it.
    let supported = |code: &str| match product {
        ValidationProduct::Ewallet => crate::ewallet_codes::list()
            .iter()
            .any(|(supported, _)| *supported == code),
        ValidationProduct::BankAccount => crate::bank_codes::list()
            .iter()
            .any(|bank| bank.code_bank.as_str() == code),
        ValidationProduct::Whatsapp => false,
        // PLN tidak punya service-code mapping, seperti WhatsApp.
        ValidationProduct::Pln => false,
    };
    if product == ValidationProduct::Whatsapp {
        return Err(AppError::bad_request(
            "Mapping kode pihak ketiga tidak tersedia untuk WhatsApp",
        ));
    }
    for (code, target) in mapping {
        if !supported(code) {
            return Err(AppError::bad_request(
                "Kode pada mapping tidak didukung untuk produk ini",
            ));
        }
        if target.trim().is_empty() || target.len() > 100 {
            return Err(AppError::bad_request(
                "Kode pihak ketiga tidak boleh kosong dan maksimal 100 karakter",
            ));
        }
    }
    Ok(())
}

/// Validates the Generic GET/POST options. Returns normalized values: method
/// uppercased, param names trimmed, empty key param as None. Only used for
/// request_mode='generic'; other modes store the values but ignore them.
fn validate_http_params(
    http_method: &str,
    code_param: &str,
    number_param: &str,
    key_param: Option<&str>,
) -> Result<(String, String, String, Option<String>), AppError> {
    let method = http_method.trim().to_ascii_uppercase();
    if method != "GET" && method != "POST" {
        return Err(AppError::bad_request(
            "Metode HTTP endpoint harus GET atau POST",
        ));
    }
    let check_param = |label: &str, value: &str| -> Result<String, AppError> {
        let value = value.trim();
        let valid = !value.is_empty()
            && value.len() <= 80
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
        if !valid {
            return Err(AppError::bad_request(format!(
                "Nama parameter {label} hanya boleh 1-80 karakter huruf, angka, _, - atau ."
            )));
        }
        Ok(value.to_owned())
    };
    let code = check_param("kode", code_param)?;
    let number = check_param("nomor", number_param)?;
    let key = match key_param.map(str::trim) {
        Some(value) if !value.is_empty() => Some(check_param("kunci", value)?),
        _ => None,
    };
    Ok((method, code, number, key))
}

fn is_valid_json_path(path: &str) -> bool {
    let path = path.trim();
    !path.is_empty()
        && path.len() <= 240
        && path.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '[' | ']')
        })
        && !path.starts_with('.')
        && !path.ends_with('.')
        && !path.contains("..")
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
                || (ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19)))
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn parse_product(value: &str) -> Option<ValidationProduct> {
    match value {
        "bank_account" => Some(ValidationProduct::BankAccount),
        "ewallet" => Some(ValidationProduct::Ewallet),
        "whatsapp" => Some(ValidationProduct::Whatsapp),
        "pln" => Some(ValidationProduct::Pln),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_public_ip, parse_product, validate_auth_header, validate_endpoint_url,
        validate_http_params, validate_pln_generic_contract, validate_service_code_mapping,
    };

    use crate::models::ValidationProduct;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn empty_auth_header_allowed_only_for_generic() {
        // B5 trigger: saving a Generic endpoint with no header used to
        // fail validation, so every Generic GET always sent a header.
        assert_eq!(
            validate_auth_header("", true).unwrap(),
            "",
            "empty header must be storable for Generic"
        );
        assert_eq!(
            validate_auth_header("   ", true).unwrap(),
            "",
            "whitespace-only header normalizes to empty for Generic"
        );
        assert!(validate_auth_header("", false).is_err());
        assert!(validate_auth_header("Authorization", false).is_ok());
        assert!(validate_auth_header("X-API-Key", true).is_ok());
        assert!(validate_auth_header("Bad Header!", true).is_err());
    }

    #[test]
    fn pln_generic_contract_rejected_at_save_time() {
        use crate::models::ProviderRequestMode;
        // K6 trigger: a PLN Generic endpoint that looks active but can
        // never succeed (POST body to a GET-query upstream, or renamed
        // params) must be rejected here, not discovered per-check.
        assert!(validate_pln_generic_contract(
            ValidationProduct::Pln,
            ProviderRequestMode::Generic,
            "GET",
            "target",
            Some("api_key"),
        )
        .is_ok());
        assert!(validate_pln_generic_contract(
            ValidationProduct::Pln,
            ProviderRequestMode::Generic,
            "POST",
            "target",
            Some("api_key"),
        )
        .is_err());
        assert!(validate_pln_generic_contract(
            ValidationProduct::Pln,
            ProviderRequestMode::Generic,
            "GET",
            "number",
            Some("api_key"),
        )
        .is_err());
        assert!(validate_pln_generic_contract(
            ValidationProduct::Pln,
            ProviderRequestMode::Generic,
            "GET",
            "target",
            None,
        )
        .is_err());
        assert!(validate_pln_generic_contract(
            ValidationProduct::Pln,
            ProviderRequestMode::Generic,
            "GET",
            "target",
            Some("key"),
        )
        .is_err());
        // Other products and other modes are untouched by this gate.
        assert!(validate_pln_generic_contract(
            ValidationProduct::BankAccount,
            ProviderRequestMode::Generic,
            "POST",
            "number",
            None,
        )
        .is_ok());
        assert!(validate_pln_generic_contract(
            ValidationProduct::Pln,
            ProviderRequestMode::Cutiezy,
            "POST",
            "number",
            None,
        )
        .is_ok());
    }

    #[test]
    fn service_code_mapping_for_ewallet_and_bank_with_supported_codes() {
        let mut mapping = std::collections::HashMap::new();
        mapping.insert("dana".to_owned(), "dana009".to_owned());
        assert!(validate_service_code_mapping(ValidationProduct::Ewallet, &mapping).is_ok());
        let mut bank_mapping = std::collections::HashMap::new();
        bank_mapping.insert("014".to_owned(), "BCA".to_owned());
        assert!(
            validate_service_code_mapping(ValidationProduct::BankAccount, &bank_mapping).is_ok()
        );
        let mut bad_bank = std::collections::HashMap::new();
        bad_bank.insert("999".to_owned(), "XXX".to_owned());
        assert!(
            validate_service_code_mapping(ValidationProduct::BankAccount, &bad_bank).is_err()
        );
        assert!(
            validate_service_code_mapping(ValidationProduct::Whatsapp, &mapping).is_err()
        );
        let mut bad = std::collections::HashMap::new();
        bad.insert("doku".to_owned(), "DOKU001".to_owned());
        assert!(validate_service_code_mapping(ValidationProduct::Ewallet, &bad).is_err());
        let mut blank = std::collections::HashMap::new();
        blank.insert("dana".to_owned(), "  ".to_owned());
        assert!(validate_service_code_mapping(ValidationProduct::Ewallet, &blank).is_err());
        assert!(validate_service_code_mapping(
            ValidationProduct::Ewallet,
            &std::collections::HashMap::new()
        )
        .is_ok());
    }

    #[test]
    fn history_product_mapping_keeps_every_product_including_pln() {
        for (code, expected) in [
            ("bank_account", ValidationProduct::BankAccount),
            ("ewallet", ValidationProduct::Ewallet),
            ("whatsapp", ValidationProduct::Whatsapp),
            ("pln", ValidationProduct::Pln),
        ] {
            assert_eq!(parse_product(code), Some(expected), "{code} must map");
        }
        assert_eq!(parse_product("tidak_dikenal"), None);
    }

    #[test]
    fn http_params_normalize_and_reject_bad_names() {

        let (method, code, number, key) =
            validate_http_params("get", " bank ", "user_id", Some(" apikey ")).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(code, "bank");
        assert_eq!(number, "user_id");
        assert_eq!(key.as_deref(), Some("apikey"));
        assert!(validate_http_params("PUT", "code", "target", None).is_err());
        assert!(validate_http_params("GET", "a b", "target", None).is_err());
        assert!(validate_http_params("GET", "code", "", None).is_err());
        let (_, _, _, key) = validate_http_params("POST", "code", "target", Some("  ")).unwrap();
        assert!(key.is_none());
    }

    #[test]
    fn production_rejects_private_destinations() {
        let allowed = vec!["example.com".to_owned()];
        assert!(validate_endpoint_url("http://example.com/check", true, &allowed, false).is_err());
        assert!(validate_endpoint_url("https://127.0.0.1/check", true, &allowed, false).is_err());
        assert!(validate_endpoint_url("https://example.com/check", true, &allowed, false).is_ok());
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}

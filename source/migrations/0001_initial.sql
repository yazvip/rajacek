-- Rajacek MySQL 8 baseline schema.
-- Apply through `sqlx migrate run` only after reviewing provider, billing, and retention requirements.
-- IDs are UUID values stored as BINARY(16); public APIs must expose UUID strings, never sequence IDs.

CREATE TABLE users (
    id BINARY(16) NOT NULL PRIMARY KEY,
    google_subject VARCHAR(255) NOT NULL,
    email VARCHAR(320) NOT NULL,
    display_name VARCHAR(255) NULL,
    avatar_url VARCHAR(2048) NULL,
    status ENUM('active', 'suspended', 'deleted') NOT NULL DEFAULT 'active',
    last_login_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_users_google_subject (google_subject),
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_status_created_at (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE organizations (
    id BINARY(16) NOT NULL PRIMARY KEY,
    owner_user_id BINARY(16) NOT NULL,
    name VARCHAR(160) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    billing_email VARCHAR(320) NULL,
    status ENUM('active', 'suspended', 'deleted') NOT NULL DEFAULT 'active',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_organizations_slug (slug),
    KEY idx_organizations_owner (owner_user_id),
    CONSTRAINT fk_organizations_owner FOREIGN KEY (owner_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE organization_members (
    organization_id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    role ENUM('owner', 'admin', 'member', 'support', 'finance') NOT NULL DEFAULT 'member',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (organization_id, user_id),
    KEY idx_organization_members_user (user_id),
    CONSTRAINT fk_organization_members_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT fk_organization_members_user FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE products (
    id BINARY(16) NOT NULL PRIMARY KEY,
    code VARCHAR(80) NOT NULL,
    name VARCHAR(160) NOT NULL,
    description TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    provider_route VARCHAR(160) NOT NULL,
    base_price_idr BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_products_code (code),
    CONSTRAINT chk_products_price CHECK (base_price_idr > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE packages (
    id BINARY(16) NOT NULL PRIMARY KEY,
    name VARCHAR(160) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    highlighted BOOLEAN NOT NULL DEFAULT FALSE,
    rate_limit_per_minute INT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_packages_slug (slug),
    CONSTRAINT chk_packages_rpm CHECK (rate_limit_per_minute > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE package_prices (
    id BINARY(16) NOT NULL PRIMARY KEY,
    package_id BINARY(16) NOT NULL,
    currency CHAR(3) NOT NULL DEFAULT 'IDR',
    amount_idr BIGINT UNSIGNED NOT NULL,
    included_hits BIGINT UNSIGNED NOT NULL,
    effective_from DATETIME(6) NOT NULL,
    effective_until DATETIME(6) NULL,
    created_by_user_id BINARY(16) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_package_prices_effectivity (package_id, effective_from, effective_until),
    CONSTRAINT fk_package_prices_package FOREIGN KEY (package_id) REFERENCES packages (id),
    CONSTRAINT fk_package_prices_user FOREIGN KEY (created_by_user_id) REFERENCES users (id),
    CONSTRAINT chk_package_prices_amount CHECK (amount_idr > 0),
    CONSTRAINT chk_package_prices_hits CHECK (included_hits > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE package_products (
    package_id BINARY(16) NOT NULL,
    product_id BINARY(16) NOT NULL,
    PRIMARY KEY (package_id, product_id),
    CONSTRAINT fk_package_products_package FOREIGN KEY (package_id) REFERENCES packages (id),
    CONSTRAINT fk_package_products_product FOREIGN KEY (product_id) REFERENCES products (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE subscriptions (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    package_id BINARY(16) NOT NULL,
    package_price_id BINARY(16) NOT NULL,
    status ENUM('active', 'expired', 'cancelled', 'suspended') NOT NULL DEFAULT 'active',
    starts_at DATETIME(6) NOT NULL,
    ends_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY idx_subscriptions_organization_status (organization_id, status, ends_at),
    CONSTRAINT fk_subscriptions_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT fk_subscriptions_package FOREIGN KEY (package_id) REFERENCES packages (id),
    CONSTRAINT fk_subscriptions_package_price FOREIGN KEY (package_price_id) REFERENCES package_prices (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE balances (
    organization_id BINARY(16) NOT NULL PRIMARY KEY,
    available_hits BIGINT NOT NULL DEFAULT 0,
    reserved_hits BIGINT NOT NULL DEFAULT 0,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_balances_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT chk_balances_available CHECK (available_hits >= 0),
    CONSTRAINT chk_balances_reserved CHECK (reserved_hits >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE api_keys (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    created_by_user_id BINARY(16) NULL,
    name VARCHAR(160) NOT NULL,
    key_prefix VARCHAR(80) NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    scopes JSON NOT NULL,
    status ENUM('active', 'revoked', 'expired', 'suspended') NOT NULL DEFAULT 'active',
    rate_limit_per_minute INT UNSIGNED NOT NULL,
    expires_at DATETIME(6) NULL,
    last_used_at DATETIME(6) NULL,
    revoked_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_api_keys_prefix (key_prefix),
    KEY idx_api_keys_organization_status (organization_id, status),
    CONSTRAINT fk_api_keys_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT fk_api_keys_user FOREIGN KEY (created_by_user_id) REFERENCES users (id),
    CONSTRAINT chk_api_keys_rpm CHECK (rate_limit_per_minute > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE rate_limit_policies (
    id BINARY(16) NOT NULL PRIMARY KEY,
    name VARCHAR(160) NOT NULL,
    scope ENUM('global', 'api_key', 'ip', 'package', 'endpoint') NOT NULL,
    target VARCHAR(255) NOT NULL,
    requests_per_minute INT UNSIGNED NOT NULL,
    burst INT UNSIGNED NOT NULL,
    concurrency_limit INT UNSIGNED NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by_user_id BINARY(16) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY idx_rate_limit_policies_scope_active (scope, active),
    CONSTRAINT fk_rate_limit_policies_user FOREIGN KEY (created_by_user_id) REFERENCES users (id),
    CONSTRAINT chk_rate_limit_policy_rpm CHECK (requests_per_minute > 0),
    CONSTRAINT chk_rate_limit_policy_burst CHECK (burst > 0),
    CONSTRAINT chk_rate_limit_policy_concurrency CHECK (concurrency_limit > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE provider_configs (
    id BINARY(16) NOT NULL PRIMARY KEY,
    product_id BINARY(16) NOT NULL,
    route_name VARCHAR(160) NOT NULL,
    base_url VARCHAR(2048) NOT NULL,
    credential_ciphertext MEDIUMBLOB NOT NULL,
    credential_key_version VARCHAR(80) NOT NULL,
    timeout_ms INT UNSIGNED NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_provider_configs_route (route_name),
    KEY idx_provider_configs_product_active (product_id, active),
    CONSTRAINT fk_provider_configs_product FOREIGN KEY (product_id) REFERENCES products (id),
    CONSTRAINT chk_provider_configs_timeout CHECK (timeout_ms BETWEEN 100 AND 60000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE usage_reservations (
    id BINARY(16) NOT NULL PRIMARY KEY,
    idempotency_key_hash BINARY(32) NOT NULL,
    api_key_id BINARY(16) NOT NULL,
    organization_id BINARY(16) NOT NULL,
    product_id BINARY(16) NULL,
    request_id VARCHAR(64) NOT NULL,
    status ENUM('reserved', 'captured', 'released', 'expired') NOT NULL DEFAULT 'reserved',
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_usage_reservations_idempotency (idempotency_key_hash),
    UNIQUE KEY uq_usage_reservations_request (request_id),
    KEY idx_usage_reservations_status_expiry (status, expires_at),
    CONSTRAINT fk_usage_reservations_api_key FOREIGN KEY (api_key_id) REFERENCES api_keys (id),
    CONSTRAINT fk_usage_reservations_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT fk_usage_reservations_product FOREIGN KEY (product_id) REFERENCES products (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE validation_requests (
    id BINARY(16) NOT NULL PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    event_id BINARY(16) NOT NULL,
    api_key_prefix VARCHAR(80) NOT NULL,
    product_code VARCHAR(80) NOT NULL,
    outcome ENUM('valid', 'invalid', 'not_found', 'pending', 'provider_error', 'rate_limited', 'quota_exhausted') NOT NULL,
    target_fingerprint CHAR(64) NOT NULL,
    target_masked VARCHAR(120) NOT NULL,
    provider_reference VARCHAR(255) NULL,
    provider_latency_ms BIGINT UNSIGNED NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_validation_requests_event (event_id),
    KEY idx_validation_requests_request_id (request_id),
    KEY idx_validation_requests_occurred_at (occurred_at),
    KEY idx_validation_requests_api_product (api_key_prefix, product_code, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE usage_ledger (
    id BINARY(16) NOT NULL PRIMARY KEY,
    event_id BINARY(16) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    api_key_prefix VARCHAR(80) NOT NULL,
    product_code VARCHAR(80) NOT NULL,
    operation ENUM('charge', 'refund', 'adjustment') NOT NULL,
    outcome ENUM('valid', 'invalid', 'not_found', 'pending', 'provider_error', 'rate_limited', 'quota_exhausted') NOT NULL,
    quantity BIGINT NOT NULL,
    amount_idr BIGINT NOT NULL DEFAULT 0,
    price_snapshot_id BINARY(16) NULL,
    occurred_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_usage_ledger_event (event_id),
    KEY idx_usage_ledger_api_key_time (api_key_prefix, occurred_at),
    KEY idx_usage_ledger_request_id (request_id),
    KEY idx_usage_ledger_occurred_at (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE webhook_endpoints (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    event_types JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY idx_webhook_endpoints_organization_active (organization_id, active),
    CONSTRAINT fk_webhook_endpoints_organization FOREIGN KEY (organization_id) REFERENCES organizations (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE webhook_deliveries (
    id BINARY(16) NOT NULL PRIMARY KEY,
    endpoint_id BINARY(16) NOT NULL,
    event_id BINARY(16) NOT NULL,
    status ENUM('pending', 'delivered', 'failed', 'dead_letter') NOT NULL DEFAULT 'pending',
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    response_status SMALLINT UNSIGNED NULL,
    next_attempt_at DATETIME(6) NULL,
    delivered_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_webhook_deliveries_endpoint_event (endpoint_id, event_id),
    KEY idx_webhook_deliveries_pending (status, next_attempt_at),
    CONSTRAINT fk_webhook_deliveries_endpoint FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE admin_audit_logs (
    id BINARY(16) NOT NULL PRIMARY KEY,
    actor_user_id BINARY(16) NULL,
    actor_email VARCHAR(320) NOT NULL,
    action VARCHAR(160) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id BINARY(16) NULL,
    request_id VARCHAR(64) NULL,
    before_json JSON NULL,
    after_json JSON NULL,
    ip_address VARCHAR(45) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_admin_audit_logs_actor_created (actor_email, created_at),
    KEY idx_admin_audit_logs_resource (resource_type, resource_id, created_at),
    CONSTRAINT fk_admin_audit_logs_actor FOREIGN KEY (actor_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

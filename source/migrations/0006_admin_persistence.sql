-- Fase 0 (member platform): persist the admin store's packages, rate-limit
-- policies, and API keys (including quota counters and package/member
-- ownership) in MySQL so restarts no longer reset them. Previously these
-- lived only in process memory and every restart re-seeded quota.

CREATE TABLE IF NOT EXISTS admin_packages (
    id CHAR(36) NOT NULL PRIMARY KEY,
    name VARCHAR(191) NOT NULL,
    slug VARCHAR(191) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    price_idr BIGINT UNSIGNED NOT NULL,
    included_hits BIGINT UNSIGNED NOT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    highlighted TINYINT(1) NOT NULL DEFAULT 0,
    products TEXT NOT NULL,
    rate_limit_per_minute INT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL
);

-- NOTE: `rate_limit_policies` is intentionally NOT created here — the table
-- already exists from the initial schema (BINARY(16) ids, scope enum). The
-- store's policy persistence adapts to that shape instead.

CREATE TABLE IF NOT EXISTS admin_api_keys (
    id CHAR(36) NOT NULL PRIMARY KEY,
    prefix VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(191) NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    scopes TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    rate_limit_per_minute INT UNSIGNED NOT NULL,
    quota_total BIGINT UNSIGNED NOT NULL,
    quota_remaining BIGINT UNSIGNED NOT NULL,
    expires_at DATETIME(6) NULL,
    package_id CHAR(36) NULL,
    member_id CHAR(36) NULL,
    last_used_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);

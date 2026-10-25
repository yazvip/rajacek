-- Fase 1 (member platform): Google-signed member accounts and one-time
-- trial grants. Members own admin_api_keys rows via member_id; the trial
-- grant ledger is keyed by Google subject so a trial can never be re-issued
-- to the same Google account, even if the member row is recreated.

CREATE TABLE IF NOT EXISTS members (
    id CHAR(36) NOT NULL PRIMARY KEY,
    google_sub VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(191) NOT NULL,
    name VARCHAR(191) NULL,
    picture_url TEXT NULL,
    plan_kind VARCHAR(32) NOT NULL DEFAULT 'trial',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at DATETIME(6) NOT NULL,
    last_login_at DATETIME(6) NULL
);

CREATE TABLE IF NOT EXISTS trial_grants (
    google_sub VARCHAR(255) NOT NULL PRIMARY KEY,
    member_id CHAR(36) NOT NULL,
    email VARCHAR(191) NOT NULL,
    quota_hits BIGINT UNSIGNED NOT NULL,
    granted_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL
);

-- Runtime-managed third-party validation endpoints.
-- Credentials are encrypted by the API before insertion and are never returned by admin reads.

CREATE TABLE third_party_endpoints (
    id BINARY(16) NOT NULL PRIMARY KEY,
    product_code ENUM('bank_account', 'ewallet', 'whatsapp') NOT NULL,
    name VARCHAR(160) NOT NULL,
    base_url VARCHAR(2048) NOT NULL,
    credential_ciphertext MEDIUMBLOB NOT NULL,
    timeout_ms INT UNSIGNED NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_third_party_endpoints_product (product_code),
    KEY idx_third_party_endpoints_active (active, product_code),
    CONSTRAINT chk_third_party_endpoints_timeout CHECK (timeout_ms BETWEEN 100 AND 60000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

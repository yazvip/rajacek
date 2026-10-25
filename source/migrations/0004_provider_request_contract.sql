-- Selectable outbound request contract and credential header for third-party endpoints.

ALTER TABLE third_party_endpoints
    ADD COLUMN request_mode ENUM('generic', 'tukangcek') NOT NULL DEFAULT 'generic' AFTER timeout_ms,
    ADD COLUMN auth_header VARCHAR(80) NOT NULL DEFAULT 'Authorization' AFTER request_mode;

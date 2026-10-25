-- Fase pembelian paket mandiri (QRIS Cutiezy): pesanan member + pengaturan
-- pembayaran admin. Order adalah sumber kebenaran status pembayaran; grant
-- kuota dilakukan atomik bersama perubahan status order (lihat
-- store::grant_package_order) sehingga tidak ada grant ganda.
-- Token/QRIS string Cutiezy hanya dipakai server (tidak pernah dikirim ke
-- klien member); gambar QR disajikan lewat proxy endpoint kita sendiri.

CREATE TABLE IF NOT EXISTS package_orders (
    id CHAR(36) NOT NULL PRIMARY KEY,
    member_id CHAR(36) NOT NULL,
    key_id CHAR(36) NULL,
    package_id CHAR(36) NOT NULL,
    package_name VARCHAR(191) NOT NULL,
    price_idr BIGINT UNSIGNED NOT NULL,
    quota_hits BIGINT UNSIGNED NOT NULL,
    rate_limit_per_minute INT UNSIGNED NOT NULL,
    valid_days INT NOT NULL,
    amount_idr BIGINT UNSIGNED NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'waiting_payment',
    qris_token VARCHAR(64) NULL,
    qris_string TEXT NULL,
    qris_image_url TEXT NULL,
    qris_expires_at DATETIME(6) NULL,
    paid_at DATETIME(6) NULL,
    granted_at DATETIME(6) NULL,
    granted_quota BIGINT UNSIGNED NULL,
    granted_expires_at DATETIME(6) NULL,
    mutation_ref VARCHAR(191) NULL,
    last_error TEXT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_package_orders_member_status (member_id, status),
    INDEX idx_package_orders_status_created (status, created_at),
    INDEX idx_package_orders_token (qris_token)
);

-- Satu baris pengaturan QRIS (id = 1). Kredensial terenkripsi AES-256-GCM
-- (pola yang sama dengan kredensial provider); knob non-rahasia polos.
CREATE TABLE IF NOT EXISTS qris_settings (
    id TINYINT NOT NULL PRIMARY KEY DEFAULT 1,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    expiry_minutes INT NOT NULL DEFAULT 15,
    valid_days INT NOT NULL DEFAULT 30,
    source_id INT NULL,
    api_key_ciphertext BLOB NULL,
    webhook_secret_ciphertext BLOB NULL,
    last_error TEXT NULL,
    last_cutiezy_remaining INT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);

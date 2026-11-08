-- 0042: layanan cek ID game (Cutiezy) + kuota game terpisah per paket.
-- Satu pembelian = satu bucket yang membawa DUA kuota: hit validasi
-- (total_hits/remaining_hits) dan hit game (game_total_hits/
-- game_remaining_hits). Keduanya FIFO + expiry sama; game tidak pernah
-- memotong kuota validasi dan sebaliknya. Trial memberi 0 hit game
-- (member harus beli paket yang berisi hit game).
-- game_services di-seed NONAKTIF semua: admin mengaktifkan per game
-- setelah respons nyata per game terverifikasi (dokumen Cutiezy hanya
-- memuat contoh resmi untuk region-ml; field game lain ilustratif).
CREATE TABLE IF NOT EXISTS game_services (
    code VARCHAR(64) NOT NULL PRIMARY KEY,
    service VARCHAR(64) NOT NULL,
    name VARCHAR(191) NOT NULL,
    needs_zone TINYINT(1) NOT NULL DEFAULT 0,
    param_kind VARCHAR(16) NOT NULL DEFAULT 'user_id',
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    verified_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);
INSERT INTO game_services (code, service, name, needs_zone, param_kind, enabled, created_at) VALUES
    ('region-ml', 'region-ml', 'Mobile Legends — Region', 1, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('mlbb-bundle', 'mlbb-bundle', 'Mobile Legends — Bundle', 1, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('mlcreate', 'mlcreate', 'Mobile Legends — Umur Akun', 1, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('first-topup', 'first-topup', 'Mobile Legends — First Top Up', 1, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('first-mcgg', 'first-mcgg', 'Magic Chess — First Top Up', 1, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('mcgg', 'mcgg', 'Magic Chess Go Go', 1, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('undawn', 'undawn', 'Garena Undawn', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('free-fire', 'free-fire', 'Free Fire', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('pubg', 'pubg', 'PUBG Mobile', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('codm', 'codm', 'Call of Duty Mobile', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('zenless', 'zenless', 'Zenless Zone Zero', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('hok', 'hok', 'Honor of Kings', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('blood-strike', 'blood-strike', 'Blood Strike', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('valorant', 'valorant', 'Valorant', 0, 'riot_id', 0, UTC_TIMESTAMP(6)),
    ('genshin', 'genshin', 'Genshin Impact', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('hsr', 'hsr', 'Honkai Star Rail', 0, 'user_id', 0, UTC_TIMESTAMP(6)),
    ('roblox', 'roblox', 'Roblox', 0, 'username', 0, UTC_TIMESTAMP(6));

-- Pengaturan games (pola qris_settings): satu baris; API key Cutiezy
-- untuk games terenkripsi AES-256-GCM (CredentialCipher), tidak pernah
-- tampil polos di log/respons.
CREATE TABLE IF NOT EXISTS games_settings (
    id TINYINT NOT NULL PRIMARY KEY DEFAULT 1,
    api_key_ciphertext BLOB NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);

ALTER TABLE admin_packages ADD COLUMN game_hits BIGINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE quota_buckets ADD COLUMN game_total_hits BIGINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE quota_buckets ADD COLUMN game_remaining_hits BIGINT UNSIGNED NOT NULL DEFAULT 0;

-- Pool gratis game terpisah dari pool validasi (cerminan
-- invalid_free_daily): 100 hasil NotFound game pertama per kunci per
-- hari WIB gratis; selebihnya memotong 1 hit game.
CREATE TABLE IF NOT EXISTS game_invalid_free_daily (
    api_key_prefix VARCHAR(64) NOT NULL,
    wib_date DATE NOT NULL,
    free_used INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (api_key_prefix, wib_date)
);

ALTER TABLE package_orders ADD COLUMN game_hits BIGINT UNSIGNED NOT NULL DEFAULT 0;

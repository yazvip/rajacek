-- Multi-admin dengan peran (area 7+8, 2026-10-25). ADDITIVE saja:
-- tabel baru, tidak mengubah tabel yang sudah ada.
--
-- Mekanisme identitas admin HARI INI (dibaca dari src/auth.rs +
-- src/config.rs, bukan ditebak):
--   * Google OAuth: callback hanya menerima email yang ada di
--     ADMIN_GOOGLE_EMAILS (env, diparse jadi HashSet lowercase di
--     AppConfig::admin_google_emails); sesi JWT berisi role="admin"
--     generik tanpa peran bertingkat.
--   * Token pengembangan (non-production): header x-admin-token yang
--     cocok dengan DEVELOPMENT_ADMIN_TOKEN -> principal email
--     "admin@local.dev".
--   * Login lokal (development saja): satu akun admin lokal.
-- SEED: setiap email yang lolos cek lama di atas adalah owner sampai
-- ada baris admins-nya (lihat src/admin_roles.rs: fallback). Seed
-- eksplisit juga dijalankan saat startup (main.rs memanggil
-- seed_legacy_admins dengan isi ADMIN_GOOGLE_EMAILS) dan secara malas
-- saat resolusi peran pertama kali; keduanya INSERT IGNORE sehingga
-- tidak pernah menimpa peran yang sudah diatur owner.
--
-- CATATAN KEAMANAN: baris di tabel ini TIDAK membuka login. Sesi
-- tetap harus lolos cek lama (allowlist Google / token dev / login
-- lokal); tabel ini hanya menentukan PERAN sesi yang sudah sah.
-- Admin baru yang dibuat owner lewat API baru bisa masuk setelah
-- emailnya juga ditambahkan ke ADMIN_GOOGLE_EMAILS (atau lewat jalur
-- dev yang berlaku). Mengubah ini (allowlist diganti tabel) adalah
-- keputusan koordinator, bukan patch ini.
CREATE TABLE IF NOT EXISTS admins (
    id CHAR(36) NOT NULL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    created_by VARCHAR(255) NULL,
    INDEX idx_admins_role (role),
    INDEX idx_admins_active (active)
);

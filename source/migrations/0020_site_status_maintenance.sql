-- AREA 6: halaman status publik, pengumuman, dan mode maintenance.
--
-- PENYIMPANGAN DARI SPESIFIKASI AWAL (disengaja, aditif): tabel
-- `runtime_settings` SUDAH ADA sejak migrasi 0005 dengan kolom
-- `setting_key` / `setting_value` / `updated_at` — membuat tabel baru
-- bernama sama dengan kolom `key` / `value` akan menabrak tabel itu
-- dan memecahkan pemakai lamanya (provider guard, trial settings).
-- Maka migrasi ini TIDAK membuat tabel baru; ia hanya:
--   1. menambahkan kolom `updated_by` (email admin, nullable);
--   2. melebarkan `setting_value` dari VARCHAR(255) menjadi TEXT agar
--      teks pengumuman/banner tidak terpotong di 255 karakter;
--   3. men-seed lima kunci area ini (INSERT IGNORE, tidak menimpa
--      nilai yang sudah diatur admin).
-- Semua perubahan bersifat aditif: tidak ada kolom/tabel yang dihapus.
ALTER TABLE runtime_settings ADD COLUMN updated_by VARCHAR(255) NULL AFTER setting_value;
ALTER TABLE runtime_settings MODIFY COLUMN setting_value TEXT NOT NULL;
INSERT IGNORE INTO runtime_settings (setting_key, setting_value) VALUES
    ('announcement_text', ''),
    ('announcement_active', '0'),
    ('maintenance_banner_text', ''),
    ('maintenance_banner_active', '0'),
    ('maintenance_block_validations', '0');

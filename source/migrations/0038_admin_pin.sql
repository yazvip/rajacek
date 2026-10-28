-- Login administrator dengan email + PIN (28 Okt 2026).
--
-- admin_pin_settings: satu baris (id=1) untuk PIN administrator global.
-- - pin_hash: hash format `sha256$salt$digest` (pola yang sama dengan
--   hash kunci API di store.rs). Hash PIN AWAL TIDAK ADA di file ini:
--   baris di-seed sekali saat deploy lewat SQL perintah, bukan migrasi.
-- - is_default: 1 selama PIN masih bernilai awal (panel menampilkan
--   banner peringatan); 0 setelah PIN diganti dari panel.
-- Tanpa baris (belum di-seed / mode memory-only), login PIN fail-closed.
CREATE TABLE IF NOT EXISTS admin_pin_settings (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
  pin_hash VARCHAR(255) NOT NULL,
  is_default TINYINT(1) NOT NULL DEFAULT 1,
  updated_at DATETIME(6) NOT NULL
);

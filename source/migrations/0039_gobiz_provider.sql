-- Provider QRIS Gobiz — satu-satunya provider QRIS Rajacek (31 Okt 2026).
--
-- Menggantikan Cutiezy sepenuhnya (keputusan 31 Okt 2026): Cutiezy dihapus
-- dari kode; kolom Cutiezy lama di qris_settings (api_key_ciphertext,
-- webhook_secret_ciphertext, last_cutiezy_remaining, source_id) SENGAJA
-- TIDAK di-drop — dibiarkan mati di DB sebagai data rollback. Kode baru
-- tidak membaca/menulis kolom itu lagi.
--
-- qris_settings:
-- - gobiz_base_url: default URL worker Gobiz produksi (URL layanan
--   publik, bukan secret). Di-trim trailing '/' oleh klien.
-- - gobiz_callback_url: default endpoint webhook Gobiz Rajacek; dikirim
--   per payment sebagai callback_url (pola AI Gateway).
-- - gobiz_api_key_ciphertext / gobiz_webhook_secret_ciphertext: pola
--   enkripsi yang sama dengan kredensial lama (CredentialCipher).
--
-- package_orders:
-- - provider_order_id: id pembayaran di sisi Gobiz (id `pay_...`).
-- - expected_amount: nominal bayar SESUAI RESPON GOBIZ (harga paket +
--   sufiks unik); verifikasi grant mencocokkan nilai ini, bukan harga
--   paket mentah.
-- - Index provider_order_id untuk lookup dari webhook/sweep.
--
-- CATATAN DEPLOY: migrasi ini TIDAK auto-apply di produksi
-- (AUTO_MIGRATE=false). Terapkan manual SEBELUM restart binary baru:
-- binary baru gagal jelas bila kolom Gobiz belum ada (tidak ada fallback
-- ke provider lama — Cutiezy sudah tidak ada). Binary lama tidak
-- terpengaruh kolom tambahan ini.
ALTER TABLE qris_settings
  ADD COLUMN gobiz_base_url VARCHAR(512) NULL DEFAULT 'https://gobiz-payment-v2.andrias.workers.dev',
  ADD COLUMN gobiz_callback_url VARCHAR(512) NULL DEFAULT 'https://www.rajacek.com/v1/payments/qris/webhook/gobiz',
  ADD COLUMN gobiz_api_key_ciphertext BLOB NULL,
  ADD COLUMN gobiz_webhook_secret_ciphertext BLOB NULL;

ALTER TABLE package_orders
  ADD COLUMN provider_order_id VARCHAR(128) NULL,
  ADD COLUMN expected_amount BIGINT UNSIGNED NULL,
  ADD INDEX idx_package_orders_provider_order (provider_order_id);

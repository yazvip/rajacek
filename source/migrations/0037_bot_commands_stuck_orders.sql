-- Perintah bot Telegram (webhook) + alert order macet — 28 Okt 2026.
--
-- telegram_settings:
-- - webhook_secret_ciphertext: secret header X-Telegram-Bot-Api-Secret-Token
--   terenkripsi (digenerate acak saat aktivasi perintah bot; token bot
--   TIDAK PERNAH ditaruh di URL webhook agar tidak bocor di log).
-- - webhook_active: hasil setWebhook terakhir (false = belum aktif atau
--   setWebhook terakhir gagal; panel menampilkan tombol retry).
--
-- package_orders:
-- - stuck_notified_at: penanda anti-duplikat alert B1 (dibayar tapi belum
--   grant). Ditulis HANYA bila kirim sukses (WHERE NULL + rows==1);
--   gagal kirim → NULL tetap, dicoba lagi tick berikut.
ALTER TABLE telegram_settings
    ADD COLUMN webhook_secret_ciphertext BLOB NULL AFTER chat_id,
    ADD COLUMN webhook_active TINYINT(1) NOT NULL DEFAULT 0 AFTER webhook_secret_ciphertext;
ALTER TABLE package_orders
    ADD COLUMN stuck_notified_at DATETIME(6) NULL AFTER updated_at;

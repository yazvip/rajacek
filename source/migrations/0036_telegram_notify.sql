-- Notifikasi bot Telegram admin: (1) member baru, (2) member beli paket,
-- (3) paket hampir kedaluwarsa (24 jam).
--
-- Pengaturan bot disimpan di tabel khusus (pola qris_settings): token
-- terenkripsi AES-256-GCM (CredentialCipher), chat ID plaintext (bukan
-- kredensial — tanpa token, chat ID saja tidak bisa dipakai mengirim).
-- Panel tidak pernah menampilkan token (hanya status terisi + 4 akhir).
--
-- expiry_notified_at: penanda anti-spam job kedaluwarsa. NULL = belum
-- pernah diberitahu. Diisi saat pesan terkirim; bucket yang gagal kirim
-- tetap NULL sehingga dicoba lagi pada tick berikutnya (6 jam).
-- Tidak ada backfill: baris lama tetap NULL (benar — belum diberitahu).
CREATE TABLE IF NOT EXISTS telegram_settings (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    bot_token_ciphertext BLOB NULL,
    chat_id VARCHAR(64) NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);
ALTER TABLE quota_buckets
    ADD COLUMN expiry_notified_at DATETIME(6) NULL;

-- Notifikasi member via bot Telegram yang sama dengan bot admin (3 Nov 2026).
--
-- Bot, token, dan webhook TIDAK berubah: tabel ini hanya mencatat tautan
-- chat member + preferensi per member + log pengiriman (dedupe).
-- - member_telegram_links: satu member = satu chat; satu chat = satu member
--   (UNIQUE chat_id). Chat ID disimpan sebagai string, sama seperti
--   telegram_settings.chat_id; nilainya TIDAK PERNAH dikirim ke portal
--   maupun panel (hanya status tertaut + tanggal tautan).
-- - member_notification_prefs: opt-in eksplisit; default SEMUA MATI.
-- - member_telegram_link_codes: kode sekali pakai 12 karakter, berlaku
--   15 menit, dipakai lewat /start <kode> di bot.
-- - member_notification_log: dedupe keras via UNIQUE(kind, ref_key);
--   ref_key selalu memuat identitas pemilik (order/bucket/member) agar
--   tidak bertabrakan antar member.
CREATE TABLE IF NOT EXISTS member_telegram_links (
    member_id CHAR(36) NOT NULL PRIMARY KEY,
    chat_id VARCHAR(64) NOT NULL,
    linked_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_member_telegram_links_chat (chat_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS member_notification_prefs (
    member_id CHAR(36) NOT NULL PRIMARY KEY,
    notify_expiry TINYINT(1) NOT NULL DEFAULT 0,
    notify_admin TINYINT(1) NOT NULL DEFAULT 0,
    notify_purchase TINYINT(1) NOT NULL DEFAULT 0,
    notify_recap TINYINT(1) NOT NULL DEFAULT 0,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS member_telegram_link_codes (
    code VARCHAR(32) NOT NULL PRIMARY KEY,
    member_id CHAR(36) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_member_telegram_link_codes_member (member_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS member_notification_log (
    id CHAR(36) NOT NULL PRIMARY KEY,
    member_id CHAR(36) NOT NULL,
    kind VARCHAR(64) NOT NULL,
    ref_key VARCHAR(191) NOT NULL,
    status VARCHAR(16) NOT NULL,
    error VARCHAR(500) NULL,
    sent_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_member_notification_log_kind_ref (kind, ref_key),
    INDEX idx_member_notification_log_member (member_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

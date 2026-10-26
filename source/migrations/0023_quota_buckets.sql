-- Fase bucket FIFO kuota member: tiap pembelian (grant/assign-add) menjadi
-- satu bucket dengan sisa + expiry sendiri; pemotongan selalu dari bucket
-- paling cepat kedaluwarsa dulu (FIFO). Kolom agregat di admin_api_keys
-- (quota_total, quota_remaining, expires_at) DIPERTAHANKAN sebagai cache
-- tampilan; sumber kebenaran pemotongan adalah baris-baris tabel ini.
--
-- package_id dicatat per bucket agar tampilan API dapat menyebut nama
-- paket bucket itu (di-resolve dari admin_packages saat dibaca); NULL
-- untuk bucket manual/trial tanpa paket. order_id NULL untuk bucket
-- backfill/assign/adjust (hanya grant pembelian yang mengisinya).
--
-- Backfill satu kali: tiap kunci yang masih bisa diaktifkan kembali
-- (status active ATAU disabled — set_member_status mengembalikan kunci
-- disabled menjadi active saat member diaktifkan lagi) mendapat satu
-- bucket dari agregatnya saat ini. Kunci revoked TIDAK ikut: saldonya
-- sudah pindah ke kunci pengganti saat regenerasi, dan kunci revoked
-- tidak pernah bisa validasi lagi. Kunci tanpa kuota (0/0) tetap
-- mendapat bucket 0/0 agar invarian "satu kunci aktif = >=1 bucket"
-- berlaku seragam; bucket 0 tidak pernah bisa dipotong.
CREATE TABLE IF NOT EXISTS quota_buckets (
    id CHAR(36) NOT NULL PRIMARY KEY,
    key_id CHAR(36) NOT NULL,
    member_id CHAR(36) NULL,
    order_id CHAR(36) NULL,
    package_id CHAR(36) NULL,
    total_hits BIGINT UNSIGNED NOT NULL,
    remaining_hits BIGINT UNSIGNED NOT NULL,
    expires_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    INDEX idx_quota_buckets_key_expiry (key_id, expires_at),
    INDEX idx_quota_buckets_member (member_id)
);

INSERT INTO quota_buckets
    (id, key_id, member_id, order_id, package_id, total_hits, remaining_hits, expires_at, created_at)
SELECT
    UUID(), id, member_id, NULL, package_id,
    quota_total, quota_remaining, expires_at, UTC_TIMESTAMP(6)
FROM admin_api_keys
WHERE status IN ('active', 'disabled');

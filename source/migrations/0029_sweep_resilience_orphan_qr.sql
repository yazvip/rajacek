-- Fase 1 (audit flow 2026-10-26): ketahanan sweep + QR yatim yang bisa
-- di-resolve.
--
-- 1. B13: `package_orders.check_fail_count` — hitung gagal check-status
--    berturut-turut per order. Sweep rutin mengkarantina order yang
--    mencapai 5 (tidak lagi menjadi kandidat sweep) agar order "racun"
--    tidak memblokir order paid yang lebih baru tanpa batas; karantina
--    dibuka lewat resolve admin (tombol panel) atau verify ulang yang
--    sukses (menghitung ulang dari 0). Kolom ini TIDAK masuk
--    ORDER_COLUMNS (struct PackageOrderRow tidak berubah) — sweep
--    hanya memakainya di WHERE/UPDATE.
--
-- 2. K26: `orphan_qr` — QR Cutiezy yang sudah terbit tapi gagal
--    dibatalkan (cancel ikut gagal) sehingga menjadi QR berbayar tanpa
--    baris order. Dulu yang tersisa hanya log error; kini barisnya
--    tersimpan agar admin bisa me-resolve-berbukti (cocokkan RRN +
--    nominal lewat check-status) dan meng-grant paket yang dipilih
--    admin. Token disimpan seperti baris package_orders (server-only,
--    tidak pernah dikirim ke klien).
--
-- Idempotensi (dua lapis, seperti migrasi 0028):
--   1. sqlx::migrate! mencatat versi di _sqlx_migrations, jadi migrasi
--      tidak dijalankan ulang oleh proses deploy berikutnya.
--   2. CREATE TABLE IF NOT EXISTS aman dijalankan ulang (no-op).
--   Untuk kolom baru, MySQL tidak punya ADD COLUMN IF NOT EXISTS:
--   guard-nya adalah (1) — migrasi hanya berjalan sekali per database.
--   Jangan jalankan ALTER ini manual di luar migrasi (lihat pelajaran
--   migrasi 0011: ALTER manual + file migrasi = duplicate column).
ALTER TABLE package_orders ADD COLUMN check_fail_count INT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS orphan_qr (
    id CHAR(36) NOT NULL PRIMARY KEY,
    member_id CHAR(36) NOT NULL,
    qris_token VARCHAR(64) NOT NULL,
    amount_idr BIGINT UNSIGNED NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    resolved_order_id CHAR(36) NULL,
    note TEXT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_orphan_qr_member_status (member_id, status),
    INDEX idx_orphan_qr_token (qris_token)
);

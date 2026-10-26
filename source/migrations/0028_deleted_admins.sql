-- Tombstone penghapusan admin (perbaikan R1, audit 2026-10-26).
--
-- Masalah: DELETE FROM admins menghapus baris, tetapi resolve_admin_role
-- dan seed startup memperlakukan "tanpa baris" sebagai admin lama yang
-- berhak fallback Owner + INSERT IGNORE baris owner baru. Akibatnya
-- penghapusan admin allowlist lewat panel dibatalkan pada request
-- berikutnya (bahkan menaikkan Viewer menjadi Owner).
--
-- Perbaikan: penghapusan kini juga menulis satu baris ke tabel ini.
-- resolve_admin_role dan seed_legacy_admin memeriksa tabel ini
-- SEBELUM fallback/seed, sehingga email yang sengaja dihapus ditolak
-- 403 dan tidak pernah di-seed kembali — termasuk setelah restart.
-- Email yang belum pernah punya baris DAN belum pernah dihapus tidak
-- ada di tabel ini, jadi fallback Owner untuk admin lama tetap jalan.
--
-- Revive yang sah: membuat ulang email yang sama lewat endpoint tambah
-- admin (create_admin_account) menghapus baris tombstone-nya, karena
-- saat itu owner secara eksplisit menghendaki email itu aktif lagi.
--
-- Idempotensi (dua lapis):
--   1. sqlx::migrate! mencatat versi di _sqlx_migrations, jadi migrasi
--      tidak dijalankan ulang oleh proses deploy berikutnya.
--   2. CREATE TABLE IF NOT EXISTS aman dijalankan ulang (no-op).
CREATE TABLE IF NOT EXISTS deleted_admins (
    email VARCHAR(255) NOT NULL PRIMARY KEY,
    deleted_at DATETIME(6) NOT NULL,
    deleted_by VARCHAR(255) NULL,
    INDEX idx_deleted_admins_deleted_at (deleted_at)
);

-- AREA 3 — Pencatatan refund admin (SATU-SATUNYA migrasi area ini).
-- ADDITIVE saja: tabel baru, tidak mengubah tabel yang sudah ada.
--
-- BATASAN YANG MENGIKAT (lihat qris.rs, modul refund-record):
-- - Tabel ini HANYA pencatatan. Tidak ada endpoint refund uang yang
--   terverifikasi di klien Cutiezy pohon ini (hanya create,
--   check-status, cancel), jadi pengembalian uang dilakukan admin
--   secara manual lewat dashboard provider, lalu dicatat di sini.
-- - Tidak ada pergerakan kuota lewat tabel ini; `compensation_note`
--   hanya catatan bebas (kompensasi kuota lewat jalur adjust kuota
--   area lain). Tidak ada kolom yang mengubah status order/kuota.
-- - Aturan di level aplikasi (bukan constraint DB, agar pesan error
--   tetap ramah): order harus pernah lunas (paid_at NOT NULL),
--   nominal > 0, alasan wajib, dan total kumulatif refund per order
--   tidak boleh melebihi nominal order (refund parsial bertahap
--   diizinkan; refund penuh kedua otomatis tertolak oleh cap ini).
CREATE TABLE IF NOT EXISTS refund_records (
    id CHAR(36) NOT NULL PRIMARY KEY,
    order_id CHAR(36) NOT NULL,
    amount_idr BIGINT UNSIGNED NOT NULL,
    reason VARCHAR(500) NOT NULL,
    external_ref VARCHAR(191) NULL,
    compensation_note VARCHAR(500) NULL,
    recorded_by VARCHAR(255) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_refund_records_order FOREIGN KEY (order_id) REFERENCES package_orders (id),
    INDEX idx_refund_records_order (order_id)
);

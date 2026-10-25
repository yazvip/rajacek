-- Jejak audit aksi admin yang persisten (audit 2026-10-25, B12).
-- Sebelumnya record_admin_activity hanya menulis ke vektor in-memory
-- (cap 16 entri, hilang saat restart) dan panel hanya menampilkan
-- riwayat validasi dari validation_requests. Tabel ini adalah sumber
-- kebenaran untuk GET /v1/admin/activity; mirror in-memory tetap ada
-- sebagai fallback saat database tidak terhubung.
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id CHAR(36) NOT NULL PRIMARY KEY,
    occurred_at DATETIME(6) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(120) NOT NULL,
    detail TEXT NOT NULL,
    entity_type VARCHAR(60) NULL,
    entity_id VARCHAR(64) NULL,
    INDEX idx_admin_audit_occurred (occurred_at),
    INDEX idx_admin_audit_action (action),
    INDEX idx_admin_audit_actor (actor)
);

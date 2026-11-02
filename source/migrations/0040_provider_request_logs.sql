-- Tab Logs di detail riwayat validasi admin (31 Okt 2026).
--
-- provider_request_logs: satu baris per dispatch HTTP ke provider yang
-- tercatat selama validasi (pemenang balapan, leg yang kalah, retry,
-- dan gagal transport tanpa body). Ditulis worker dari field
-- `provider_attempt_logs` di UsageEvent, dalam transaksi yang sama
-- dengan baris riwayat (atomik); gagal tulis log HANYA diperingatkan,
-- tidak pernah menggagalkan riwayat/ledger (diagnostik, bukan billing).
--
-- KEAMANAN (fail-closed, lihat provider.rs):
-- - request_redacted TIDAK PERNAH berisi host/URL mentah atau nilai
--   kredensial: query/body di-mask di provider.rs SEBELUM masuk event.
-- - response_body ter-cap 64 KiB dan ikut disikat nilai kredensialnya.
-- - Yang disimpan hanya NAMA endpoint (label konfigurasi admin), bukan
--   host — konsisten dengan aturan riwayat (migrasi 0033).
--
-- RETENSI 48 JAM: job worker (pola K48) menghapus permanen baris dengan
-- created_at lebih tua dari 48 jam, tiap jam, batch 1.000. Yang dihapus
-- HANYA tabel ini; baris validation_requests (riwayat cek) TIDAK
-- disentuh. created_at diisi worker dari occurred_at event (waktu cek),
-- sehingga retensi diukur dari waktu cek, bukan waktu tulis ulang
-- (mis. replay DLQ).
--
-- CATATAN DEPLOY: migrasi ini TIDAK auto-apply di produksi
-- (AUTO_MIGRATE=false). Terapkan manual SEBELUM restart binary baru
-- agar log mulai tercatat sejak awal; binary lama tidak terpengaruh
-- tabel baru ini (tidak dibaca kode lama). Bila tabel belum ada saat
-- binary baru jalan, tulis log hanya diperingatkan (worker tetap
-- mengomit riwayat/ledger) — bukan gagal keras.
CREATE TABLE IF NOT EXISTS provider_request_logs (
    id BINARY(16) NOT NULL PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    endpoint_name VARCHAR(255) NOT NULL,
    method VARCHAR(16) NOT NULL,
    request_redacted TEXT NOT NULL,
    response_status SMALLINT UNSIGNED NULL,
    response_body MEDIUMTEXT NULL,
    truncated TINYINT(1) NOT NULL DEFAULT 0,
    latency_ms BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_provider_request_logs_request (request_id, created_at),
    KEY idx_provider_request_logs_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

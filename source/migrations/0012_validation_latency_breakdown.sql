-- Rincian latensi per riwayat validasi: proses internal Rajacek dan total
-- sampai respons member, agar gap terhadap latensi provider terlihat di
-- panel admin. Kolom nullable: baris lama sebelum migrasi ini tidak punya
-- datanya dan ditampilkan apa adanya (kosong).
ALTER TABLE validation_requests
    ADD COLUMN rajacek_processing_ms BIGINT UNSIGNED NULL AFTER provider_latency_ms,
    ADD COLUMN total_latency_ms BIGINT UNSIGNED NULL AFTER rajacek_processing_ms,
    ADD COLUMN attempts INT UNSIGNED NULL AFTER total_latency_ms;

-- Riwayat admin: target utuh + nama pemegang untuk audit admin saja.
--
-- Dua kolom NULLABLE di validation_requests, diisi worker dari UsageEvent
-- untuk cek baru (target_raw = target mentah dari request; account_name =
-- nama apa adanya dari upstream — tersamar untuk Tukangcek, nickname /
-- accountname apa adanya untuk Cutiezy, NULL untuk WhatsApp dan untuk
-- e-wallet NotKyc). TIDAK ADA backfill: baris lama tidak pernah menyimpan
-- nama, dan target utuh tidak bisa diturunkan dari target_fingerprint
-- (hash satu arah), jadi baris lama tetap NULL. Sisi member TIDAK
-- membaca kolom ini (respons member hanya memakai target_masked).
ALTER TABLE validation_requests
    ADD COLUMN target_raw VARCHAR(120) NULL AFTER target_masked,
    ADD COLUMN account_name VARCHAR(255) NULL AFTER target_raw;

-- Perluasan enum outcome untuk status not_kyc (integrasi fitur admin, 2026-10-25).
--
-- Latar: sejak status not_kyc diperkenalkan (audit-flow), worker menulis
-- validation_requests + usage_ledger dengan outcome 'not_kyc', tetapi kedua
-- kolom ENUM di migrasi 0001 tidak memuat nilai itu — baris yang ditulis
-- lewat INSERT IGNORE tidak tersimpan sebagai not_kyc (ledger tidak lengkap
-- untuk hasil Belum KYC, dan agregasi analitik membaca 0 untuk not_kyc).
--
-- Aditif saja: hanya menambah satu nilai enum di akhir daftar; nilai lama
-- tidak diubah, tidak dihapus, dan tidak ada baris yang dimigrasi ulang.
ALTER TABLE validation_requests
    MODIFY COLUMN outcome ENUM('valid', 'invalid', 'not_found', 'pending', 'provider_error', 'rate_limited', 'quota_exhausted', 'not_kyc') NOT NULL;
ALTER TABLE usage_ledger
    MODIFY COLUMN outcome ENUM('valid', 'invalid', 'not_found', 'pending', 'provider_error', 'rate_limited', 'quota_exhausted', 'not_kyc') NOT NULL;

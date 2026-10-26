-- Anti-farming trial (dipilih user 27 Okt 2026, jalur monitoring +
-- throttle — bukan verifikasi nomor HP): catat IP signup di tiap
-- grant trial agar grant per IP per 24 jam bisa dibatasi.
--
-- signup_ip NULL = baris lama pra-fitur (tidak pernah dihitung ke
-- batas IP mana pun, karena perbandingan `signup_ip = ?` tidak cocok
-- dengan NULL). Default NULL (bukan string kosong) agar baris lama
-- tidak tiba-tiba membentuk satu "IP" raksasa.
ALTER TABLE trial_grants
    ADD COLUMN signup_ip VARCHAR(45) NULL;
CREATE INDEX idx_trial_grants_signup_ip_granted
    ON trial_grants (signup_ip, granted_at);

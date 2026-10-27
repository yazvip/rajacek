-- Kode bank / slug e-wallet yang diinput member di Detail validasi (admin).
-- Baris riwayat menyimpan provider_hint apa adanya dari request yang
-- dinormalisasi: kode bank publik 3 digit untuk bank_account, atau slug
-- e-wallet publik untuk ewallet. NULL untuk produk lain (PLN, WhatsApp)
-- dan untuk baris lama pra-fitur.
--
-- NULL = baris lama pra-fitur — popup menampilkan "tidak tercatat
-- (data lama)" untuk produk bank/ewallet tanpa hint. Nama bank /
-- e-wallet di-resolve saat baca dari katalog publik (bukan disimpan
-- di sini), supaya ganti nama katalog tetap tercermin; kode upstream
-- (tukangcek_code) TIDAK PERNAH disimpan di kolom ini.
-- Tidak ada backfill: hint baris lama tidak dapat dipulihkan dari
-- target_fingerprint yang di-salt secret (audit 2026-10-27) — kolom
-- ini hanya terisi untuk validasi baru ke depan.
ALTER TABLE validation_requests
    ADD COLUMN provider_hint VARCHAR(48) NULL;

-- Kode member admin-only (RC + 6 digit) untuk kolom "MEMBER" di riwayat admin.
--
-- Latar: kolom riwayat admin selama ini menampilkan api_key_prefix (prefix
-- kunci API, mis. rv_live_...), bukan identitas member. Satu member bisa
-- punya beberapa kunci, dan id member adalah UUID terpisah di tabel
-- members — jadi riwayat admin butuh kode pendek yang stabil per member.
-- Kode ini ADMIN-ONLY: tidak pernah diserialisasi ke respons member
-- (lihat MemberAccount.member_code yang skip_serializing + view admin
-- eksplisit di api.rs, dan ValidationHistoryItem.member_code yang
-- skip_serializing + AdminValidationHistoryItem).
--
-- Kolom NULLABLE + UNIQUE: MySQL mengizinkan banyak NULL dalam unique
-- index, jadi backfill di bawah aman — dan baris yang (karena suatu
-- keadaan) belum berkode tidak akan memblokir insert lain.
ALTER TABLE members
    ADD COLUMN member_code VARCHAR(8) NULL;

-- Backfill berurutan dari member terdaftar paling awal: RC000001,
-- RC000002, ... Urutan deterministik: created_at ASC, tie-break id ASC.
-- ROW_NUMBER() butuh MySQL 8 (live: 8.0.x, terverifikasi).
UPDATE members m
JOIN (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at ASC, id ASC) AS rn
    FROM members
) AS ranked ON ranked.id = m.id
SET m.member_code = CONCAT('RC', LPAD(ranked.rn, 6, '0'));

ALTER TABLE members
    ADD UNIQUE KEY uq_members_member_code (member_code);

-- Counter persisten untuk pembuatan member baru. Satu baris, dikunci
-- dengan SELECT ... FOR UPDATE di dalam transaksi pembuatan member
-- (store::create_member), jadi dua sign-in bersamaan tidak pernah
-- mendapat nomor yang sama — TIDAK PERNAH dihitung dari COUNT(*).
-- next_value = nomor BERIKUTNYA yang akan dipakai (bukan yang terakhir
-- dipakai), di-seed dari kode terbesar hasil backfill.
CREATE TABLE IF NOT EXISTS member_code_counter (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    next_value BIGINT UNSIGNED NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO member_code_counter (id, next_value)
SELECT 1, COALESCE(MAX(CAST(SUBSTRING(member_code, 3) AS UNSIGNED)), 0) + 1
FROM members
WHERE NOT EXISTS (SELECT 1 FROM member_code_counter WHERE id = 1);

-- Jatah gratis hasil tidak valid (aturan billing 2026-10-25): 100 hasil
-- final Invalid/NotFound pertama per kunci API per hari kalender WIB
-- gratis; selebihnya memotong 1 hit. Satu pool bersama untuk Invalid dan
-- NotFound. Satu baris per (kunci, hari); klaim memakai UPDATE kondisional
-- (free_used < 100) sehingga dua klaim konkuren di batas pool tepat satu
-- yang menang. Hari WIB dihitung di kode (+7 tetap, tanpa DST), bukan
-- CONVERT_TZ, jadi kolomnya DATE polos. Tabel ini tumbuh ~1 baris per
-- kunci per hari; prune berkala bisa ditambahkan bila diperlukan.
CREATE TABLE IF NOT EXISTS invalid_free_daily (
    api_key_prefix VARCHAR(64) NOT NULL,
    wib_date DATE NOT NULL,
    free_used INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (api_key_prefix, wib_date)
);

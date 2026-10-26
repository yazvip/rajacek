-- Paksa ON endpoint (admin): satu server bisa ditandai agar TETAP
-- di-admit meski circuit breaker-nya terbuka. Flag ini persisten di DB
-- sampai admin mematikannya — itulah "terus"-nya.
--
-- Cakupan bypass: HANYA admission breaker. Pacer (jarak antar hit),
-- semaphore konkurensi, antrean, dan rate limit TETAP berlaku untuk
-- endpoint paksa ON, dan hasil (sukses/gagal) tetap dicatat ke breaker
-- seperti biasa — jadi saat paksa dimatikan, breaker langsung kembali
-- ke perilaku normal dari state yang tercatat, tanpa ada state yang
-- disembunyikan. Toggle paksa on/off TIDAK me-reset breaker (berbeda
-- dengan aktivasi nonaktif->aktif yang me-reset per K34).
--
-- Default 0 = perilaku lama untuk semua baris yang sudah ada; tidak
-- ada endpoint yang tiba-tiba jadi paksa ON karena migrasi ini.
ALTER TABLE third_party_endpoints
    ADD COLUMN force_on TINYINT(1) NOT NULL DEFAULT 0;

-- Izinkan produk PLN di kolom product_code tabel third_party_endpoints.
--
-- Latar: varian produk "pln" sudah ada di enum Rust + parse_product, dan panel
-- admin sudah menampilkan grup PLN + tombol Tambah Server, tetapi kolom ini
-- masih ENUM('bank_account','ewallet','whatsapp') sehingga INSERT server PLN
-- dari panel admin ditolak MySQL. Tanpa migrasi ini, langkah "buat server
-- Chikamm" tidak bisa jalan.
--
-- Keamanan pernyataan: semua nilai yang sudah ada (ketiga produk lama) adalah
-- subset dari ENUM baru, jadi tidak ada baris yang berubah atau gagal.
--
-- Idempotensi (dua lapis):
--   1. sqlx::migrate! mencatat versi di _sqlx_migrations, jadi migrasi
--      tidak dijalankan ulang oleh proses deploy berikutnya.
--   2. Pernyataan MODIFY ke definisi yang sama aman dijalankan ulang (no-op).
ALTER TABLE third_party_endpoints
    MODIFY product_code ENUM('bank_account', 'ewallet', 'whatsapp', 'pln') NOT NULL;

-- PLN masuk ke semua paket AKTIF yang produknya belum memuat "pln".
--
-- Bentuk penyimpanan: admin_packages.products adalah TEXT berisi array JSON
-- string produk (mis. ["bank_account","ewallet","whatsapp"]), dibaca lewat
-- serde Vec<ValidationProduct> di store::into_package. TIDAK ada tabel
-- package_products terpisah — satu-satunya tempat daftar produk paket.
--
-- Definisi "paket aktif" yang dipakai migrasi ini: kolom active = 1.
-- Itu satu-satunya penanda status paket: highlighted hanya penanda tampilan
-- (paket unggulan), dan filter harga > 0 di landing/portal member hanya
-- filter tampil/beli, bukan status aktif. Paket active = 0 TIDAK diubah.
--
-- Idempotensi (dua lapis):
--   1. sqlx::migrate! mencatat versi di _sqlx_migrations, jadi migrasi
--      tidak dijalankan ulang oleh proses deploy berikutnya.
--   2. Pernyataan ini sendiri aman dijalankan dua kali: guard
--      NOT JSON_CONTAINS(products, '"pln"') membuat run kedua mengubah
--      0 baris — tidak pernah menduplikasi "pln" di dalam satu array.
-- Guard JSON_VALID + JSON_TYPE = 'ARRAY' menjaga baris berformat liar
-- (bukan array JSON valid) tidak diubah dan tidak menggagalkan statement
-- untuk baris lain; nilai seperti itu tidak ada di live saat migrasi
-- ditulis (3/3 baris aktif lolos predikat ini pada dry-run read-only).
--
-- updated_at SENGAJA tidak disentuh: ini migrasi data, bukan edit admin.
--
-- PERINGATAN URUTAN DEPLOY (wajib dibaca koordinator): migrasi ini HANYA
-- boleh naik bersamaan dengan kode yang mengenal varian produk "pln"
-- (ValidationProduct::Pln di models.rs, pekerjaan worker lain). Alasannya:
-- store::into_package mem-parse products sebagai Vec<ValidationProduct>
-- dan load_persisted MEMBUANG baris yang gagal parse (filter_map .ok()).
-- Bila 0026 naik SEBELUM varian itu ada, paket yang baru ditambahi "pln"
-- akan hilang dari daftar in-memory (landing + portal member) sampai kode
-- baru deploy + restart. Jangan pernah deploy 0026 sendirian.
--
-- Migrasi ini HANYA data produk paket: tidak mengubah skema apa pun,
-- tidak menyentuh invalid_free_daily, quota_buckets, atau tabel lain.
UPDATE admin_packages
SET products = JSON_ARRAY_APPEND(products, '$', 'pln')
WHERE active = 1
  AND JSON_VALID(products)
  AND JSON_TYPE(products) = 'ARRAY'
  AND NOT JSON_CONTAINS(products, '"pln"');

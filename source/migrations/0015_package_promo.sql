-- Promo per paket (Paket A): persen potongan + tanggal berakhir wajib
-- bila promo aktif. Harga yang tampil selalu sama dengan harga yang
-- ditagih: harga bayar dihitung dari kolom-kolom ini di server
-- (lihat models::effective_price), bukan dari input klien.
ALTER TABLE admin_packages
  ADD COLUMN promo_percent TINYINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN promo_ends_at DATETIME(6) NULL;

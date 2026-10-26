-- K22 (audit flow 2026-10-26): guard database untuk "satu waiting per
-- member". Sebelumnya invarian ini hanya dijaga mutex dalam proses
-- (CREATE_ORDER_LOCK) + cek SELECT di create_member_order — bila
-- deployment direplikasi, dua create bersamaan dari dua replika bisa
-- sama-sama lolos dan menerbitkan dua QR Cutiezy.
--
-- Guard: kolom generated STORED yang bernilai member_id HANYA saat
-- status = 'waiting_payment', NULL untuk status lain. Unique index di
-- atasnya menegakkan maksimal satu baris waiting per member (MySQL
-- mengizinkan banyak NULL dalam unique index, jadi order paid /
-- granted / expired / canceled tidak saling menghalangi). Saat order
-- keluar dari waiting (lunas/kedaluwarsa/batal), guard otomatis NULL
-- dan member boleh membeli lagi — perilaku yang sudah ada tidak
-- berubah: paket sama -> order waiting itu dikembalikan; paket beda ->
-- 409 dengan pesan yang sudah ada (lihat create_member_order).
--
-- KEAMANAN MIGRASI: bila sudah ada DUA baris waiting untuk member yang
-- sama (duplikat historis), ADD UNIQUE KEY GAGAL dan migrasi berhenti
-- — itu disengaja (fail-closed, bukan menghapus order diam-diam).
-- Pemeriksaan pra-deploy wajib: SELECT member_id, COUNT(*) FROM
-- package_orders WHERE status = 'waiting_payment' GROUP BY member_id
-- HAVING COUNT(*) > 1; bila ada baris, selesaikan manual dulu (satu
-- order dipertahankan, sisanya dibatalkan lewat jalur cancel yang
-- sudah ada) sebelum deploy migrasi ini.
ALTER TABLE package_orders
    ADD COLUMN waiting_guard VARCHAR(36)
        GENERATED ALWAYS AS (
            CASE WHEN status = 'waiting_payment' THEN member_id ELSE NULL END
        ) STORED,
    ADD UNIQUE KEY uq_package_orders_waiting_guard (waiting_guard);

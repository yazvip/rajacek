-- Sumber endpoint pemenang di Detail validasi (admin): baris riwayat
-- menyimpan id endpoint yang jawabannya ditampilkan, agar popup Detail
-- bisa menyebut nama server sumbernya.
--
-- NULL = baris lama pra-fitur (atau jalur tanpa endpoint, mis. demo) —
-- popup menampilkan "tidak tercatat (data lama)" untuk Valid tanpa id.
-- Nama di-resolve saat baca (JOIN ke third_party_endpoints), bukan
-- disimpan di sini, supaya ganti nama endpoint tetap tercermin.
-- Tidak ada baris yang tiba-tiba berubah maknanya karena migrasi ini.
ALTER TABLE validation_requests
    ADD COLUMN provider_endpoint_id BINARY(16) NULL;

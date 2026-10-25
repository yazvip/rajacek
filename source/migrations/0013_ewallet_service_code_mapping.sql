-- Mapping kode layanan e-wallet per endpoint pihak ketiga: kode member
-- (mis. dana) diterjemahkan ke kode yang dipakai pihak ketiga tersebut
-- (mis. dana009) sebelum request dikirim. NULL = tanpa mapping, kode
-- dikirim apa adanya seperti perilaku lama. Hanya berlaku untuk endpoint
-- e-wallet mode generic; mode Tukangcek/Cutiezy memakai mapping bawaannya.
ALTER TABLE third_party_endpoints
    ADD COLUMN service_code_mapping JSON NULL AFTER response_mapping;

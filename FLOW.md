# FLOW PROYEK RAJACEK

Dokumen alur lengkap. Snapshot: 25 Oktober 2026 malam.
Binary live: api `ffa14f52…`, worker `7bc1a330…`, migrasi s/d `0022`.
Produksi: https://rajacek.com (+ www) — VPS 43.157.205.163, Ubuntu 24.04.
Admin UI terakhir diperbarui 26 Okt 2026 (CSS `?v=20261026-6`), deploy file web tanpa restart; backup: `/opt/rajacek/backups/admin-ui-20261026-005359`.

```
Internet → Cloudflare → nginx (TLS Let's Encrypt) → API 127.0.0.1:8080
                                                              ├─ MySQL 8  (rajacek)
                                                              └─ Redis 7 (Streams)
rajacek-api     : HTTP API + panel admin + portal member + landing + docs
rajacek-worker  : migrasi DB saat start + worker Redis Streams + sweep QRIS
```

Layout repo: `Cargo.toml`, `src/*.rs` (api, store, provider, provider_guard,
provider_config, qris, member, auth, session_revocation, analytics, alerts,
admin_roles, database, models, …), `src/bin/worker.rs`, `web/` (index.html =
panel admin, member.html, landing.html, docs.html, app.js), `migrations/`
0001–0022, `openapi/` (json + yaml).

Jam server VPS = UTC+8 (WIB+1). Semua tanggal bisnis (hari jatah gratis,
promo, expiry) dihitung dalam WIB (UTC+7 tetap).

---

## 1. FLOW VALIDASI (API member)

Endpoint: `GET/POST /api/v3/validate` (bank / e-wallet / WhatsApp / PLN; satu endpoint, produk dipilih lewat `code`).
Auth: header `x-api-key` atau `Authorization: Bearer`, atau `api_key` lewat query (GET) / field body (POST); bila lebih dari satu sumber ada dan nilainya berbeda → 401.

```
Request
  → Auth kunci (hash sha256$salt$digest; kunci revoked/disabled → 401;
    expired tetap boleh beli paket untuk perpanjangan)
  → Idempotency-Key POST saja (opsional; kosong → server generate UUID v7 + echo header; GET tidak idempotent — setiap GET adalah cek baru);
    kiriman klien divalidasi 8–200 karakter; replay TIDAK potong kuota 2x)
  → Rate limit kunci (default 60/menit, bisa override per member;
    sliding-window 60 detik sejak Fase 4, K7 — bukan bucket menit kalender)
  → X-Request-Id (opsional; kosong → server generate 10 char [A-Za-z0-9];
    kiriman klien > 64 char DITOLAK 400, bukan dipotong diam-diam — Fase 4, B25)
  → Reserve 1 hit (kuota 0 → 402 sebelum validasi jalan)
  → Balapan provider (lihat bawah)
  → Mapping hasil member-safe (lihat bawah)
  → Keputusan billing (lihat tabel) → commit/refund reserve
  → Response + tulis ledger (usage_ledger, validation_requests)
```

### Balapan provider (race)

- Provider aktif per produk: bank = Tukangcek + Cutiezy; e-wallet = Tukangcek +
  Cutiezy; WhatsApp = Tukangcek. Allowlist host: tukangcek.id, api.cutiezy.id.
- Guard per server: circuit breaker (threshold 5 gagal, cooldown 30 detik,
  max_attempts 2), semaphore 16/produk, pacer 334 ms per-host (semua provider,
  termasuk Cutiezy). Pengecualian: PLN memakai cap semaphore sendiri
  (Fase 2, B24) — `max_concurrency_pln`, default 3, kolom terpisah di
  panel provider-guard, tersimpan sebagai
  `runtime_settings.provider_guard.max_concurrency_pln`; baris guard lama
  yang belum punya kunci itu memakai default 3. Nilai per produk yang
  berlaku terlihat di status guard panel (maks per produk).
- Peringkat agregat: `Valid > not_kyc > Invalid > NotFound > Pending`.
  Leg `not_kyc` tidak pernah menang atas Valid. Leg yang dibatalkan tidak
  `record_outcome` (keterbatasan yang didokumentasikan, ditanggung lease).
- Satu validasi = maksimal 1 hit, berapa pun provider yang dicoba.
- Biaya fan-out (Fase 4, K12 — DOKUMENTASI, tanpa perubahan kode): balapan
  memanggil SEMUA server aktif produk itu sekaligus, jadi satu cek member
  menghabiskan N hit upstream (N = jumlah server aktif) + retry tiap leg.
  Kuota member tetap 1 hit; pengalinya menimpa tagihan upstream Rajacek.
  Hari ini N = 1 per produk sehingga biayanya nol — SEBELUM mengaktifkan
  server kedua untuk redundansi, pertimbangkan mode sequential-fallback
  (server utama dulu, fallback hanya bila gagal) agar biaya tidak berlipat
  tanpa peringatan di panel.
- Admission fail-fast (Fase 4, K46): balapan mencoba semua endpoint TANPA
  menunggu dulu; server yang antreannya penuh di-skip seketika (bukan
  menahan percobaan ke server sehat sampai 2 detik per server). Hanya
  bila TIDAK ADA endpoint yang langsung lolos, balapan kembali menunggu
  berurutan seperti dulu — server tunggal yang antre-penuh berperilaku
  persis sama (tunggu, lalu 429).

### Mapping hasil (member-safe — ATURAN STRUKTURAL)

- Permukaan publik/member TIDAK PERNAH menampilkan nama/URL/kode provider:
  `meta.provider` konstan `"Rajacek"`, field `provider` hasil = None, payload
  mentah upstream hanya ada di Tester admin.
- `account_name` member selalu HURUF BESAR (satu titik: `validation_response()`).
- Bank + e-wallet menampilkan nama pemilik (tersamar untuk bank); WhatsApp
  hanya status Terdaftar/Tidak Terdaftar. Riwayat menyimpan `target_masked` saja.
- **Aturan e-wallet "belum KYC"** (helper sentral, semua endpoint e-wallet):
  nama = `"BELUM PREMIUM"` (case/whitespace-insensitive) ATAU nama sama dengan /
  mengandung nomor yang dicek (bentuk 0, 62, maupun terselip; kanonik ≥8 digit)
  → status `not_kyc`, `account_name = None`, `registered = false`.
  Pesan member: "Akun e-wallet ini belum KYC, sehingga nama pemilik tidak
  dapat ditampilkan."
- Pesan error member memakai kalimat baku per status; pesan verbatim upstream
  tidak pernah diteruskan ke member.

### Tabel billing (per kunci API, per hari kalender WIB)

| Hasil | Potongan |
|---|---|
| Valid | 1 hit |
| not_kyc (Belum KYC) | 1 hit |
| Invalid + NotFound (satu pool) | GRATIS 100 pertama/hari, mulai ke-101 → 1 hit |
| Pending / ProviderError / RateLimited / QuotaExhausted | 0, tidak makan jatah |
| Idempotent replay | 0, tidak makan jatah |

- Jatah gratis dicatat di tabel `invalid_free_daily` (kunci, tanggal WIB,
  `free_used`), klaim atomik (`INSERT IGNORE` + `UPDATE ... WHERE free_used
  < 100`, fail-closed ke penagihan bila DB error). Klaim pool + refund
  1 hit-nya adalah SATU transaksi (Fase 1, K2): proses mati di antaranya
  tidak boleh menghilangkan 1 hit + 1 slot sekaligus; bila tidak ada
  bucket aktif yang bisa menampung refund, slot tidak dikonsumsi
  (hasil tetap berbayar).
- Pool TERIKAT PREFIX kunci, bukan member, by design (K15): regenerasi
  menerbitkan prefix baru → jatah hari itu dimulai baru untuk kunci baru;
  jatah kunci lama tidak terbawa dan tidak terlihat di overview kunci baru.
- Kunci bersaldo 0 tetap 402 sebelum validasi (reserve gagal) — jatah gratis
  hanya terpakai selama saldo > 0.
- Kuota ditulis background writer FIFO (channel mpsc 8192); mutasi + snapshot
  HARUS di bawah data lock yang sama (invarian kritis). Channel penuh =
  DROP dengan warning, bukan stall (Fase 4, K17): dulu writer yang penuh
  membuat pengirim menunggu sambil memegang data lock sehingga SEMUA
  validasi stall; snapshot yang di-drop bersifat absolut dan self-healing
  pada gerakan berikutnya. Urutan sync agregat dari bucket SEBELUM snapshot
  tidak diubah — snapshot yang terkirim selalu memuat agregat terbaru.
- Rate limit sliding-window (Fase 4, K7): jendela berjalan 60 detik (log
  timestamp per kunci/IP/global di Redis sorted set), bukan bucket menit
  kalender — burst 2x di perbatasan menit tidak lagi mungkin. Request yang
  ditolak tidak mengonsumsi bucket mana pun. Limit per menit, penolakan di
  atas limit, dan bentuk respons tidak berubah.
- Request ID (Fase 4, B25/K47): ID server selalu 10 char `[A-Za-z0-9]`
  (juga untuk sandbox portal — dulu UUID 36 char). ID klien > 64 char
  DITOLAK 400 karena kolom DB hanya 64 char (dulu dipotong diam-diam
  lewat `INSERT IGNORE`: respons menampilkan ID penuh, DB menyimpan 64
  char pertama, pencarian support gagal). Header `X-Request-Id` /
  `Idempotency-Key` non-ASCII (bukan UTF-8 valid) DITOLAK 400 dengan
  pesan generik yang sudah ada — dulu diabaikan diam-diam sehingga retry
  klien tidak me-replay tanpa klien tahu.

---

## 2. FLOW MEMBER & KUNCI

### Pendaftaran / login

- Login Google member → callback `/v1/auth/google/member/callback`
  (CATATAN OPERASIONAL: redirect URI ini harus ditambahkan di Google Console;
  tanpa itu pendaftaran Google member gagal).
- Login Google admin → callback `/admin` (gerbang login menyembunyikan shell
  panel sampai sesi valid).
- Trial: 10 hit / 7 hari, kunci tampil sekali saat dibuat.
- Satu orang dua akun Google = dua trial (Fase 4, K31 — DITERIMA sebagai
  keterbatasan, tanpa perubahan kode, keputusan D4): email member tidak
  unik (hanya `google_sub` yang UNIQUE), jadi tidak ada dedup manusia
  lintas akun Google. Diterima sebagai biaya akuisisi; jangan "memperbaiki"
  diam-diam tanpa keputusan baru.
- Login dengan API key juga bisa (sesi `source = "api_key"`).

### Kunci API

- Prefix CSPRNG acak (bukan turunan UUID lagi). Kunci baru: plaintext
  terenkripsi AES-256-GCM, reveal lewat ikon mata (tercatat di log aktivitas).
  Kunci lama hash-only perlu regenerasi sekali.
- Status: active / disabled / revoked. Revoked/disabled diblokir di portal +
  QRIS; expired tetap boleh beli untuk perpanjangan.
- Regenerasi memakai lock per-member (tidak boleh dua kunci aktif dari race).
- Sesi member TERIKAT ke `key_prefix`: regenerasi memaksa login ulang sekali;
  sesi curian tidak selamat dari regenerasi. Sesi memakai `jti + source`
  (produksi menolak source lain); cookie `Domain=.rajacek.com`.
  Logout admin mengembalikan JSON `{revoked, warning}` (jujur bila revocasi
  gagal); sesi kedaluwarsa 12 jam.
- Assign paket admin: member disabled → 409; `plan_kind` tidak boleh drift
  diam-diam.

### Sandbox portal member ("Coba Cek Live")

- Memakai handler validasi yang sama dengan API → aturan billing yang sama
  (sandbox MEMOTONG kuota). Portal: Ringkasan / Penggunaan / Info Kunci /
  Beli Paket / Coba Cek Live / Riwayat, auto-refresh 5 detik.
- Submit ulang sandbox memakai kunci idempotensi yang SAMA dari state
  halaman per (produk+target+provider) sehingga retry setelah error/
  timeout me-replay, bukan menagih cek baru; kunci dihapus begitu submit
  berhasil (Fase 1, K11). Server memakai kunci klien bila dikirim, dan
  hanya menggenerate bila tidak ada.

---

## 3. FLOW PEMBELIAN QRIS (paket mandiri)

Katalog paket: harga dari `effective_price` = katalog × (100 − persen promo),
promo 100% → harga 0 → tidak bisa dibeli; promo butuh persen + tanggal
berakhir, kedaluwarsa auto-nonaktif. Beli lagi = kuota DITAMBAH (bukan
diganti); expiry = (expiry lama bila future, else now) + valid_days (default
30 hari); rate = max(rate aktif, rate paket baru).

```
Portal member: pilih paket → preview (harga diskon dikunci saat order dibuat)
  → create order (syarat: 1 order waiting per (member, paket);
    rate limit = semua create sukses 1 jam terakhir, maks 5/jam)
  → QR diproksi via /v1/member/orders/:id/qr
    (token/QRIS string/URL Cutiezy TIDAK PERNAH ke klien member)
  → QR berlaku 15 menit
  → Member klik "Saya sudah bayar" → check-status Cutiezy (GRATIS)
    ATAU webhook qris.payment (HANYA pemicu sweep, bukan bukti grant)
  → Sweep worker (tiap menit): check-status + cocokkan nominal
  → Grant atomik CAS paid → granted (SEKALI saja; cek rows_affected == 0,
    karena UPDATE multi-tabel MySQL melaporkan 2 baris untuk grant normal)
  → Bila nominal mismatch → needs_review (TANPA grant)
  → Bila order expired/canceled tapi terbukti lunas → jalur pemulihan
    (resolve dengan bukti lunas)
```

- Admin resolve: `POST /v1/admin/orders/:id/resolve` — HANYA dengan bukti
  lunas (`paid_at` terisi, atau check-status Paid + nominal cocok); mismatch
  → 409; member nonaktif → 409. Respons membawa field `outcome`
  (granted / already_granted / needs_review / rejected) — pemanggil WAJIB cek
  `outcome`, bukan status HTTP (resolve mengembalikan 200 untuk semua outcome).
  Panel menampilkan tombol resolve juga untuk order `expired`/`canceled`
  (Fase 1, B10: bayar telat — server re-check Cutiezy dulu, grant hanya
  bila terbukti Paid + nominal cocok; `rejected` berarti terbukti belum
  lunas, status terminal tidak berubah).
- Resolve MENOLAK bila order sudah refund penuh (Fase 1, B14): cek
  kumulatif `refund_records` ≥ nominal dilakukan sebelum grant dan diulang
  persis sebelum grant; refund parsial tidak memblokir grant. Koreksi
  refund-record yang salah masih manual di DB (tidak ada endpoint koreksi).
- Sweep berketahanan (Fase 1, B12/B13, migrasi 0029): tiap menit, 4 pass
  masing-masing LIMIT 20 (paid tertua → waiting melewati expiry lokal →
  waiting segar berumur >120 detik → expired/canceled 24 jam terakhir) +
  sweep webhook LIMIT 50. Order yang check-nya gagal berturut-turut
  ≥5 kali dikarantina (`check_fail_count`, tidak lagi diproses) + satu
  alert admin; order paid yang lebih baru tidak pernah tersumbat antrean
  poison tanpa batas.
- QR yatim (Fase 1, K26, tabel `orphan_qr` migrasi 0029): QR Cutiezy yang
  gagal dibatalkan saat create order gagal, lalu dibayar member, dicatat
  (token tidak pernah ke panel). Panel orders menampilkan daftarnya +
  form resolve-berbukti (`POST /v1/admin/orphan-qr/:id/resolve`, peran
  Support, body `package_id` + `mutation_ref` opsional): server memverifikasi
  Paid + nominal persis + RRN bila kedua nilai ada, lalu membuat order
  `paid` dan meng-grant; grant conflict → order diparkir `needs_review`
  dan QR tertaut ke order itu (lanjutkan lewat tombol resolve order).
- Refund: Cutiezy TIDAK punya endpoint refund uang (terverifikasi dari kode).
  Maka refund = pencatatan admin (jumlah, alasan, referensi eksternal,
  kumulatif ≤ nominal, wajib bukti lunas) + kompensasi kuota opsional lewat
  adjust kuota beraudit. Uang dikembalikan manual lewat dashboard Cutiezy.
  Pencatatan memakai row lock pada baris order (Fase 1, B11): dua pencatatan
  bersamaan tidak bisa melampaui nominal. Order lunas tapi `paid_at` NULL
  (string `paid_at` Cutiezy gagal diparse) tetap bisa dicatat refund-nya
  bila statusnya `paid`/`granted` (Fase 1, K23) — bukti alternatifnya
  check-status Paid + nominal cocok.
- Guard database satu waiting (Fase 4, K22, migrasi 0031): kolom generated
  `package_orders.waiting_guard` (= member_id hanya saat status
  `waiting_payment`, NULL untuk status lain) + unique index — maksimal
  satu order waiting per member walau deployment direplikasi (dulu hanya
  mutex dalam proses + cek SELECT). Perilaku tidak berubah: paket sama →
  order waiting itu dikembalikan; paket beda → 409 dengan pesan yang sudah
  ada. Bila balapan antar replika kalah di INSERT, QR pemenang-dingin
  dibatalkan best-effort lalu hasil re-read yang dipakai.
- Halaman beli berhenti polling saat countdown habis (Fase 4, K27):
  countdown 0 → satu refresh final → bila masih waiting, tampilkan status
  akhir "menunggu konfirmasi kedaluwarsa" dan SEMUA timer berhenti (dulu
  polling berputar tiap detik selamanya sampai sweep menandai expired).
  Tombol manual "Saya sudah bayar"/"Batalkan" tetap jalan.
- Webhook ack ≤ 5 detik dijamin (Fase 4, K24): secret webhook terdekripsi
  di-cache di memori proses API; jalur ack hanya verifikasi HMAC (in-memory)
  → balas 200 → sweep di background (spawn, tidak ditunggu). DB hanya
  disentuh pada cold path (cache kosong / rotasi secret di luar panel).
  HMAC gagal tetap 401; pemrosesan background tetap lewat sweep + verify
  idempoten sehingga tidak ada grant ganda. Cache dikosongkan setiap kali
  pengaturan QRIS disimpan lewat panel.
- Kill switch off (Fase 3, B15/D3) → tombol beli hilang DAN semua order
  waiting yang BELUM dibayar DIBATALKAN saat itu juga (cancel massal
  saat toggle dimatikan + gerbang di `verify_and_grant` untuk yang
  terlewat — mencakup tombol member, sweep, dan webhook). QR Cutiezy
  dibatalkan best-effort (endpoint cancel Cutiezy DIDUKUNG; gagal
  cancel tidak menggagalkan pembatalan lokal). Pengecualian keras:
  order yang SUDAH terbayar TETAP di-grant (cancel hanya menyasar
  waiting + `paid_at` NULL lewat CAS; yang keburu lunas lolos lewat
  CAS dan di-grant). Order yang dibatalkan kill switch ditandai kolom
  `package_orders.kill_switch_canceled` (migrasi 0030): re-check
  terminal B10 TIDAK auto-grant order bertanda ini — pembayaran yang
  telanjur masuk hanya bisa di-grant lewat resolve-berbukti admin
  (K26). Webhook URL: https://www.rajacek.com/v1/payments/qris/webhook
  (event asli `qris.payment`; balas 200 ≤5 detik via background).
- Pengaturan produksi saat snapshot: enabled=1, expiry 15 menit, valid 30
  hari, source_id NULL (create sukses dengan source_id NULL pada 25 Okt
  20:13 WIB; klaim "terblokir" terbantahkan).

---

## 4. FLOW ADMIN

Panel: `/admin` (halaman dari disk, `app.js` + `styles.css` ber-pinned `?v=`).

Peran (hierarki viewer < support < manager < owner), ditegakkan SERVER-SIDE
di tiap handler (UI saja tidak cukup):

| Peran | Boleh |
|---|---|
| viewer | GET / baca saja (kecuali pengecualian berpokok di bawah) |
| support | resolve order, status member, rate-limit member, refund-record, rekonsiliasi keuangan |
| manager | produk, endpoint provider, tester, guard, paket, rate-limit, api-keys, reveal/regenerate kunci, trial, QRIS, site-settings, adjust kuota, assign paket, export CSV, replay DLQ |
| owner | kelola admin saja (di atas semua) |

Matriks peran Fase 3 (K40 — selaras ke sisi yang lebih ketat; aturan dasar
"semua GET = Viewer" dengan pengecualian yang didokumentasikan, bukan
diam-diam): site-settings GET = Manager (konfigurasi situs, bukan data);
daftar refund-record + rekonsiliasi = Support (angka keuangan, sekeluarga
dengan pencatatan refund — daftar/detail order biasa tetap Viewer);
detail member = Viewer TETAPI field `google_sub` hanya untuk Manager+;
export CSV = Manager (B23, bacaan massal 10.000 baris termasuk email);
assign paket = Manager + cap kuota manual 10.000.000/assign (B20, sama
dengan batas adjust).

- Baris `admins` TIDAK membuka login — email baru tetap harus masuk
  `ADMIN_GOOGLE_EMAILS` dulu. Tidak boleh nonaktifkan/demot/hapus diri sendiri
  atau owner aktif terakhir (→ 409). Akun nonaktif → 403 di semua endpoint.
- Jejak aktivitas admin PERSISTEN di DB (`admin_audit_log`, migrasi 0017)
  + filter (admin, aksi, rentang tanggal). Semua aksi sensitif (adjust kuota,
  refund-record, failover, ubah peran, maintenance, pengumuman) beraudit.
- Analitik: `GET /v1/admin/analytics` (pendapatan nyata dari package_orders,
  hit/hari, success rate per produk, cache 60 detik).
- Monitor provider: `GET /v1/admin/providers/health` (guard in-memory +
  ledger 24 jam; latensi per rute = null karena validation_requests tidak
  menyimpan id rute — ditulis eksplisit, bukan ditebak).
- Monitor stream + DLQ (Fase 3, B22/B26): `GET /v1/admin/stream-health`
  (panjang stream + DLQ live dari Redis, breaker terbuka dari guard,
  status pengiriman alert) + `GET /v1/admin/dlq` (daftar DLQ, terbaru
  dulu, maks 100, tanpa target mentah) + `POST /v1/admin/dlq/:id/replay`
  dan `POST /v1/admin/dlq/replay-all` (Manager; persist ulang lewat
  `persist_usage_event` yang sama dengan worker sehingga idempotent —
  INSERT IGNORE — lalu XDEL hanya bila sukses; yang gagal
  persist/parse dipertahankan). Indikator DLQ tidak kosong + stream
  melewati ambang 80.000 tampil di panel monitor TANPA bergantung pada
  Telegram; worker juga meng-alert SEKALI saat DLQ bertransisi kosong →
  tidak kosong (bukan tiap menit).
- Status alert (Fase 3, K35): `GET /v1/admin/alerts/status` melaporkan
  kesehatan pengiriman NYATA proses API (`delivery_state`:
  `never_attempted` = belum pernah mengirim sejak proses berjalan —
  panel menulis ini eksplisit, bukan "aktif" yang menyesatkan;
  `last_sent` / `last_failed` + waktu + judul upaya terakhir). Upaya
  kirim proses worker tidak tercakup di sini (restart proses
  mengosongkan rekaman) — tetapi indikator stream/DLQ panel dibaca
  langsung dari Redis, jadi tidak ada yang hilang.
- Export CSV: `GET /v1/admin/export/:kind` (orders/usage/members, cap 10.000
  baris + header penanda terpotong; tanpa key/plaintext). Minimal
  Manager sejak Fase 3 (B23, D2); percobaan Viewer yang ditolak tercatat
  di log aktivitas (jejak probing peran).
- Site settings: `GET/PUT /v1/admin/site-settings` (pengumuman maks 2000
  karakter, sakelar maintenance). Maintenance default TIDAK memblokir;
  bila `maintenance_block_validations` = "1"/"true" (case-insensitive,
  K42), gate di puncak validasi mengembalikan 503 sebelum kuota
  tersentuh. Penyimpanan LIMA kunci kini SATU transaksi (K42): gagal di
  tengah = tidak ada yang terapan. Nilai flag tak dikenal yang tak
  kosong dicatat sebagai peringatan (bukan diam-diam nonaktif).
  Tester admin JUGA diblokir saat maintenance aktif (K41); resolve
  order dan grant webhook tetap berjalan (bukan validasi — uang yang
  sudah dibayar harus tetap bisa di-grant).
- Revokasi sesi fail-CLOSED (Fase 3, B19/D1): bila Redis terkonfigurasi
  tapi pemeriksaan revocasi tidak bisa dipastikan, token admin DAN
  member DITOLAK (503) — login mati saat Redis down, demi keamanan.
  Tanpa URL Redis sama sekali (mode memory-only/dev), revocasi tidak
  ada sehingga pemeriksaan melaporkan jelas (bukan fail-closed palsu).
- Reveal satu-kali (Fase 3, K33): `POST /v1/member/reveal-key` dengan
  token di body JSON — GET query URL DIHAPUS (token tidak lagi muncul
  di log akses/proxy). Portal member mengirim POST; kontrak member
  lain tidak berubah.
- Status publik: `GET /status` (HTML) + `GET /v1/status` (JSON, tanpa login):
  overall operational/degraded + per produk, tanpa nama provider.
- Detail member: `GET /v1/admin/members/:id/detail` (profil, semua kunci,
  order, pemakaian tertagih 30 hari). Adjust kuota: `POST
  /v1/admin/members/:id/keys/:key_id/adjust` — HANYA delta relatif
  (≠0, |delta| ≤ 10.000.000, alasan 5–500 karakter, member disabled → 409,
  kunci non-active → 409, kunci bukan milik member → 404). Adjust positif
  tanpa bucket aktif membuat bucket baru berexpiry now+30 hari (Fase 1,
  B7 — bukan NULL abadi); bucket + agregat + snapshot ditulis dalam satu
  transaksi (B9); refund kuota kembali ke bucket ASAL bila masih aktif,
  bila tidak ke bucket aktif terdekat yang masih punya ruang, bila tidak
  ada bucket aktif sama sekali refund dicatat hilang di log (K1/K13).
  Semua mutasi kuota (assign, regenerasi, grant, reserve, refund, adjust)
  terserialisasi lewat lock per-member lalu data lock, urutan yang sama
  di semua jalur (Fase 1, B6); regenerasi all-or-nothing — gagal di tengah
  = kunci lama utuh (K32).
- Produk: kartu produk TIDAK menampilkan harga rupiah per hit (dihapus
  25 Okt malam; kolom DB `base_price_idr` dibiarkan, tidak dipakai billing).
  Harga yang sah dalam rupiah: harga PAKET (per paket) + nominal order.

## 5. FLOW WORKER & REDIS

- Stream `validation-events`: `XADD MAXLEN ~100000` (pemangkas mandiri).
  Worker: `XAUTOCLAIM` tiap 60 detik (idle ≥5 menit, COUNT 32), consumer
  stabil `rajacek-worker-1`.
- Persist ledger gagal → retry maks 5x → DLQ + ACK (tidak menyumbat ledger).
  Probe liveness `SELECT 1` membedakan DB mati vs event beracun.
  DLQ bisa dilihat + di-replay dari panel monitor (Fase 3, B26) dan
  worker meng-alert sekali saat DLQ bertransisi kosong → tidak kosong.
- Alert fire-and-forget (timeout HTTP 3 detik, tidak memblokir jalur utama):
  needs_review, circuit breaker baru terbuka, XLEN ≥ 80.000. Bila
  `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` belum di-set, alert jatuh ke log
  + aktivitas admin.
- Migrasi: backend worker AUTO-APPLY file `migrations/` saat start (tracking
  `_sqlx_migrations`, versi = integer prefix). JANGAN jalankan ALTER manual
  untuk migrasi yang sudah ada sebagai file.
- Retensi target mentah 90 hari (Fase 4, K48, keputusan D5): worker
  menjalankan prune sekali saat startup lalu tiap 24 jam — per tick maks
  10 batch × 1.000 baris, `UPDATE validation_requests SET target_raw =
  NULL, account_name = NULL WHERE ... AND created_at < UTC_TIMESTAMP(6)
  - INTERVAL 90 DAY`. BARIS DIPERTAHANKAN (produk/outcome/latensi/
  request_id tetap); hanya kolom personal yang dihapus. Prune idempotent
  (baris yang sudah NULL tidak terhitung lagi). Salinan Redis stream +
  DLQ TIDAK ikut prune — keduanya mengandalkan cap yang sudah ada
  (stream MAXLEN ~100.000, DLQ cap lokal 10.000). Verifikasi: `SELECT
  COUNT(*) FROM validation_requests WHERE (target_raw IS NOT NULL OR
  account_name IS NOT NULL) AND created_at < UTC_TIMESTAMP(6) - INTERVAL
  90 DAY;` harus 0 setelah satu tick prune (kecuali backlog > 10.000
  baris, yang terkikis satu tick per hari); log worker memuat baris
  "Prune retensi target mentah K48" per batch.

## 6. MODEL DATA (tabel inti)

```
members, admins, admin_api_keys, api_keys (legacy),
packages, package_products, package_prices, products,
package_orders, refund_records, qris_settings,
admin_audit_log (+ admin_audit_logs legacy),
invalid_free_daily, validation_requests, usage_ledger, usage_reservations,
runtime_settings, provider_configs, third_party_endpoints,
rate_limit_policies, trial_grants, balances, subscriptions,
organizations, organization_members, users (legacy),
webhook_endpoints, webhook_deliveries, _sqlx_migrations
```

## 7. ATURAN KEAMANAN (ringkas)

- Kredensial HANYA lewat env server (`/etc/rajacek/rajacek.env`, 600, root);
  tidak pernah di kode, log, dump, atau ZIP ini (file env SENGAJA tidak
  termasuk — salin manual saat restore).
- Validasi produksi mewajibkan `API_KEY_ENCRYPTION_KEY` ≥32 karakter;
  fallback dev tidak bisa dipakai di production.
- CSRF: origin check; reveal kunci lewat POST (bukan GET).
- Log transport tidak memuat kredensial (hanya kind+host+status).
- Sesi lama tanpa klaim `key_prefix` ditolak (login ulang sekali).

## 8. DEPLOY & RESTORE

Prosedur deploy (yang terbukti): backup timestamped → upload sumber → md5
lokal=server → build di server sebagai user ubuntu (`~/.cargo/bin/cargo
build --release`, tangkap BUILD_EXIT eksplisit, TANPA `| tail`) → verifikasi
hash binary baru BERBEDA sebelum restart → stop API (worker juga bila
hash-nya berubah) → cp binary → start worker dulu (migrasi) → sleep ±12
detik → start API → verifikasi active, NRestarts=0, health 200, log error
kosong. File web saja (app.js/css/html) = disk-only, tanpa restart, tapi
pin `?v=` WAJIB naik.

Restore dari ZIP ini:
1. Buat DB MySQL kosong → import `database/rajacek.sql`
   (berisi `_sqlx_migrations` s/d 0022, jadi skema ikut).
2. Salin `source/` ke direktori kerja, `cargo build --release --bins`.
3. Salin file env (`/etc/rajacek/rajacek.env`) dari backup server secara
   manual — file ini TIDAK ada di ZIP demi keamanan.
4. Jalankan worker dulu (migrasi), lalu API. Verifikasi health + login admin.

---

## 9. PLN (Chikamm)

- Produk: kode `pln`, label `PLN`. Target = ID pelanggan PLN numerik
  11–12 digit. Permukaan member hanya mengenal kode `pln` — nama/URL/
  kode provider upstream tidak pernah tampil di JSON member, portal,
  maupun docs (meta.provider tetap `Rajacek`, field provider None;
  payload mentah hanya di Tester admin).
- Provider: upstream Chikamm (pengetahuan admin saja). Respons upstream
  berbentuk datar: status + success + request_id + nama; tidak ada
  field tarif/daya terpisah.
- Konfigurasi endpoint Generic PLN (Fase 2): header auth boleh kosong —
  header kosong berarti TIDAK ADA header auth yang dikirim sama sekali
  (B5; panel menampilkan "tanpa header auth", pratinjau request ikut
  menandainya). Endpoint yang sudah ada tidak diubah otomatis; admin
  yang mengosongkan header PLN lewat Kelola bila diinginkan.
- Validasi save-time kontrak Chikamm (Fase 2, K6): menyimpan endpoint
  PLN mode Generic ditolak bila metode bukan GET, nama param nomor
  bukan `target`, atau nama param kunci bukan `api_key` — produk tidak
  boleh tampak aktif sementara setiap cek gagal diam-diam. Validasi ini
  hanya untuk PLN Generic dan tidak menghalangi pengosongan header (B5).
- Generic GET tidak menduplikasi param (Fase 2, K5): bila base URL sudah
  memuat nama param yang akan ditambahkan (target/api_key/dll.), nilai
  base URL dipertahankan dan param tambahan itu dilewati.
- Mapping hasil: `success` true → `valid`; selain itu → `invalid`
  (defensif — bentuk gagal untuk ID tidak valid belum teramati saat
  probe, disempurnakan setelah probe ID invalid bila perlu).
  `request_id` upstream dipakai sebagai referensi provider.
- Parsing tarif/daya: nama upstream menggabungkan nama pelanggan dan
  sufiks ` - <TARIF>/<DAYA>` (mis. pola ` - R1/1300`); sufiks itu
  dipecah menjadi field member opsional `tarif` dan `daya` (hanya
  untuk PLN, hanya bila tersedia). Nama pelanggan tetap dinormalisasi
  huruf besar semua seperti produk lain.
- Billing: ikut pool penagihan yang sama dengan produk lain — valid
  memotong 1 hit; hasil tidak-valid masuk pool gratis harian yang sama
  (per kunci, WIB). Aturan potong/pool selengkapnya ikut §1/§3.
- Paket: PLN bisa dipilih di form paket admin (checkbox produk),
  sehingga paket yang memuat `pln` memberi akses produk ini; kartu
  paket memakai label `PLN` dari `productLabel` yang sama dengan
  riwayat, analitik, dan grup provider.
- `meta.expires_at` pada respons validasi member (2026-10-26): masa aktif
  agregat live, definisi sama persis dengan overview member (live_view →
  bucket_aggregate: expiry bucket aktif terdekat; null = tidak pernah
  kedaluwarsa). SEJAK Fase 4 (K14, keputusan D6): bila TIDAK ADA bucket
  aktif bersisa (saldo habis / semua lewat expiry), expiry = NULL — bukan
  tanggal bucket pertama (dulu MIN semua bucket, menyesatkan: member
  membaca "sudah kedaluwarsa" padahal masalahnya saldo habis; sinyal
  saldo habis sudah ada di `remaining_quota = 0`). Kasus normal tidak
  berubah (bucket aktif terdekat tetap dipakai bila ada yang bersisa;
  bucket tanpa tanggal tetap null). Replay idempotensi menyegarkan tanggal dari agregat live,
  bukan tanggal basi tersimpan. Semantik beli ulang: pembelian = bucket
  baru (expiry = beli + valid_days), bucket lama tidak diperpanjang;
  agregat bisa maju lebih awal bila paket baru lebih cepat kedaluwarsa
  (dipakai dulu secara FIFO), lalu kembali ke paket lama setelah paket
  baru habis/lewat; kunci mati hanya bila SEMUA bucket lewat expiry.

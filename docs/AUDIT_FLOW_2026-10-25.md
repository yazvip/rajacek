# AUDIT MENYELURUH FLOW RAJACEK — 2026-10-25

**Ruang lingkup:** seluruh flow produksi Rajacek (validasi bank/e-wallet/WhatsApp, member, pembelian QRIS, admin, lintas/infrastruktur).
**Kode yang diaudit:** `~/workspace/rajacek-fixed/` (Rust Axum + Tokio, sqlx MySQL, Redis Streams).
**Produksi saat audit:** `https://rajacek.com`, VPS 43.157.205.163, `rajacek-api` + `rajacek-worker` keduanya `active`, `NRestarts=0`, `/health/live` → `ok`, `/health/ready` → `ready`, `provider_mode=http`.
**Metode:** 5 auditor area paralel (validasi, member, QRIS, admin, lintas), semuanya READ-ONLY: baca kode, SELECT read-only via SSH keypair, `journalctl`/`systemctl` read-only, endpoint publik. **Tidak dilakukan:** tidak ada perbaikan, deploy, restart, tulis DB, aksi berbayar, cek validasi live yang memotong kuota, login dengan kredensial siapa pun, pemakaian API key member, dan `cargo build/test` (dihindari agar tidak berebut lock target/ antar auditor). Tidak ada nilai kredensial, token, atau key yang disalin ke laporan ini.
**Pembanding:** `AUDIT_2026-10-25.md` (audit sebelumnya). Bug yang sudah diperbaiki di sana tidak dilaporkan ulang, kecuali bila masih ada.

## Ringkasan

| Severity | Jumlah |
|---|---|
| KRITIS | 0 |
| BESAR | 15 |
| KECIL | 36 |

**Tidak ada temuan KRITIS baru.** Kelima area sepakat: tidak ada bypass auth jarak jauh, tidak ada kebocoran kredensial ke member, dan tidak ada jalur member yang bisa mencetak kuota/uang tanpa bayar.

**Temuan BESAR (15):** B1 semantik e-wallet Cutiezy "Belum Premium" · B2 kredensial provider di log server · B3 sesi member tidak terikat ke kunci · B4 regenerasi konkuren bisa menghasilkan dua kunci aktif · B5 revocasi sesi fail-open + logout selalu lapor sukses · B6 secret QRIS/webhook terenkripsi kunci fallback dev bila env hilang · B7 resolve admin bisa meng-grant order yang belum terbukti lunas · B8 rate limit create QRIS 5/jam mati total · B9 satu order waiting mengabaikan `package_id` · B10 order expired/canceled yang ternyata lunas tanpa jalur pemulihan · B11 `source_id` NULL sehingga pembelian baru terblokir · B12 jejak audit admin tidak tampil dan hilang saat restart · B13 hapus paket yang gagal di DB disembunyikan · B14 stream Redis tak pernah dipangkas (noeviction) · B15 worker tersumbat pesan gagal-persist tanpa DLQ.

**Deduplikasi:** temuan yang muncul di beberapa area digabung menjadi satu (grant untuk kunci `disabled` muncul di 3 area; kontrak resolve 200 muncul di 2 area; boolean `set_order_status` yang dibuang muncul di 2 area). Bukti yang konvergen dari beberapa area justru memperkuat temuan tersebut.

**Prioritas perbaikan yang disarankan:**
1. B7 (bukti lunas pada resolve) + B10 (jalur pemulihan expired/canceled terbukti lunas) — keduanya soal integritas pembayaran, satu pola verifikasi yang sama.
2. B11 (isi `source_id` + retest) — pembelian baru saat ini tidak jalan sama sekali (operasional, bukan kode).
3. B14 (trim stream Redis) — satu-satunya temuan dengan tanggal kedaluwarsa yang dapat diprediksi.
4. B1 (keputusan user dulu — mengubah jawaban berbayar) + B2 (sapu/rotasi log + strip kredensial dari log).
5. B3 + B4 (ikat sesi ke kunci; serialisasi regenerasi) — keduanya menyangkut efektivitas regenerasi sebagai respons insiden.
6. B5, B6, B8, B9, B12, B13, B15, lalu seluruh KECIL bertahap.

## Verifikasi perbaikan grant QRIS (bukan temuan baru)

Bug yang baru diperbaiki — transaksi grant memakai UPDATE multi-tabel yang dicek `rows_affected() != 1` padahal MySQL melaporkan 2 — **terverifikasi benar dan sudah live**, oleh dua area independen:

- **Kode:** `src/store.rs:grant_package_order` kini memakai `rows_affected() == 0` sebagai satu-satunya kondisi gagal (dengan komentar yang menjelaskan semantik ROW_COUNT multi-tabel), rollback + baca ulang status di luar transaksi (`granted` → `AlreadyGranted`), lalu `UPDATE members SET plan_kind='package'` masih di dalam transaksi yang sama sebelum commit, dan pembaruan memori + `persist_key_quota` dilakukan setelah commit di bawah `data` write-lock yang sama.
- **Analisis kasus:** 2 baris (normal) lolos dan commit; 1 baris degeneratif (mis. nilai kunci tak berubah) tetap lolos dengan benar — perbaikan ini robust, bukan sekadar mengganti 1 menjadi 2; 0 baris → rollback + re-read.
- **Bukti live:** md5 `qris.rs`, `store.rs`, `models.rs` di server identik dengan file lokal; DB hanya punya 1 order paket total dan statusnya kini `granted` dengan catatan "Grant ulang oleh admin" — klik Grant ulang admin setelah deploy perbaikan berhasil, padahal sebelumnya setiap grant normal di-rollback sebagai konflik. Kuota kunci terkait: total 5.010.000, `granted_quota` 4.979.746, remaining saat audit 4.979.730 (selisih 16 = pemakaian pasca-grant).
- **Batasan verifikasi:** delta +10.000 tidak dibuktikan secara independen (tidak ada snapshot kuota sebelum grant); grant baru ujung-ke-ujung dengan snapshot sebelum/sesudah masih perlu dibuktikan live. Bug lama ini TIDAK dihitung sebagai temuan audit ini.
- **Pemeriksaan sejenis:** seluruh pengecekan `rows_affected` eksplisit lain sudah diperiksa satu per satu (lihat tabel di akhir laporan) — **tidak ditemukan bug sejenis di tempat lain**.

## Temuan BESAR

### B1 — [BESAR] E-wallet Cutiezy: nomor tak dikenal dijawab `valid=true` + nama "BELUM PREMIUM", dan balapan langsung memenangkannya
- **Deskripsi:** mapping e-wallet Cutiezy menganggap `success:true` sebagai Valid dan memakai `data.nickname` sebagai nama pemilik. Payload dengan nickname placeholder ("Belum Premium") dinormalisasi menjadi `valid:true, registered:true, account_name:"BELUM PREMIUM"` (setelah uppercase). Balapan mengembalikan Valid pertama tanpa menunggu server lain, jadi jawaban Cutiezy yang cepat mengalahkan `not_found` Tukangcek yang lebih lambat.
- **Bukti:** `src/provider.rs:1120-1138` (mapping: `status_path: "success"`, `valid_values: ["true"]`, `account_name_path: "data.nickname"`); `src/provider.rs:360-375` (Valid pertama langsung menang); unit test `src/provider.rs:1454-1471` membuktikan payload tersebut menjadi `ValidationStatus::Valid`.
- **Dampak:** member membayar 1 hit dan menerima jawaban positif palsu untuk nomor e-wallet yang belum tentu terdaftar. Ini bukan sekadar soal balapan: bahkan single-server Cutiezy pun menghasilkan jawaban yang sama.
- **Verifikasi:** HANYA DARI KODE + dokumen probe lama. Premis "nomor tak dikenal pun dijawab `success:true`" berasal dari probe live yang didokumentasikan di `FIX_2026-10-21.md:362` — **tidak diverifikasi ulang secara live dalam audit ini** (cek live dilarang karena memotong kuota). Jadi premis tersebut adalah FAKTA DOKUMEN LAMA, bukan verifikasi live baru.
- **Rekomendasi:** perlakukan nickname placeholder ("Belum Premium" dan variannya, case-insensitive) sebagai `NotFound`, bukan `Valid`; atau ubah balapan e-wallet menjadi "tunggu semua server, Valid dari server mana pun menang atas NotFound, tapi placeholder tidak dihitung Valid". **Perlu keputusan user dulu** karena mengubah jawaban berbayar (keputusan ini tercatat belum diputuskan sebelumnya).

### B2 — [BESAR] Kredensial provider tertulis di log server saat Cutiezy gagal transport
- **Deskripsi:** URL Cutiezy dibangun dengan kredensial sebagai query param, lalu kegagalan `send()` di-log dengan format Debug `reqwest::Error` yang menyertakan URL lengkap termasuk query.
- **Bukti:** `src/provider.rs:594-606` (Cutiezy GET, URL dengan kredensial sebagai query, `tracing::warn!(error = ?error, ...)`); pola yang sama untuk endpoint Generic GET bila `key_param` diset (`src/provider.rs:540-566`).
- **Dampak:** setiap timeout/kegagalan koneksi ke Cutiezy menulis kredensial provider dalam bentuk plaintext ke journald VPS (dapat dibaca siapa pun yang punya akses log, dan ikut terbawa bila log di-forward/diarsipkan). Ini bukan bocor ke member, tapi bocor kredensial pihak ketiga ke permukaan log.
- **Verifikasi:** TERVERIFIKASI LIVE via `journalctl -u rajacek-api` (struktur URL + parameter kredensial terlihat di baris log; nilainya sengaja tidak disalin ke sini).
- **Rekomendasi:** log hanya kind/host/status dari error transport (tanpa Debug URL, atau strip query sebelum log); sapu/rotasi kredensial yang sudah tertulis di journal lama; pertimbangkan memindahkan kredensial Cutiezy dari query ke header bila kontraknya mengizinkan (belum diverifikasi — jangan diasumsikan).

### B3 — [BESAR] Sesi member-id tidak terikat ke kunci — sesi curian selamat dari regenerasi dan bisa me-reveal kunci BARU
- **Deskripsi:** sesi member-id hanya memegang `member.id`; setiap request mengambil kunci terbaru lewat `member_key()`. Klaim sesi tidak memuat `key_id`/`prefix`.
- **Bukti:** `src/member.rs:156` (`resolve_session` → `member_key(id)` → `prefix: summary.prefix`); `src/member.rs:237` (`issue_member_session`, klaim hanya `sub/exp/iat/jti/source`); `src/member.rs:965` (`reveal_own_key` memakai `session.prefix` hasil resolve).
- **Dampak (FAKTA dari kode):** bila cookie sesi member bocor (XSS/perangkat), lalu admin melakukan regenerasi sebagai respons insiden, sesi lama TIDAK mati: resolve berikutnya mengarah ke kunci baru, dan tombol mata menampilkan plaintext kunci baru itu ke pemegang sesi curian. Regenerasi hanya membunuh kunci lama yang bocor, bukan sesi yang bocor. Berbeda dengan revoke (sesi ikut terblokir karena `member_key` mengembalikan kunci revoked → 401).
- **Verifikasi:** HANYA DARI KODE (tidak diuji live — butuh login, dilarang).
- **Rekomendasi:** ikat sesi member-id ke prefix/kunci saat diterbitkan dan tolak resolve bila kunci saat ini berbeda (pengguna login ulang setelah regenerasi; grant/assign tidak mengganti prefix, jadi hanya regenerasi yang memaksa login ulang). Alternatif: registrasi sesi per member agar regenerasi bisa mem-blocklist semua `jti` aktif member tersebut.

### B4 — [BESAR] Regenerasi tanpa serialisasi bisa menghasilkan dua kunci aktif + kuota ganda
- **Deskripsi:** kunci lama ditandai revoked di bawah lock sesaat, lock dilepas, lalu persist + penerbitan kunci baru berjalan tanpa lock/marker. Tidak ada yang menegakkan satu kunci aktif: `member_key()` hanya memilih `max_by_key((status != "revoked", created_at))`, dan skema hanya UNIQUE di `prefix`, tanpa constraint unik `(member_id, status aktif)`.
- **Bukti:** `src/store.rs:1852` (`regenerate_member_key`); `src/store.rs:1490` (`member_key()`); `migrations/0006_admin_persistence.sql` (UNIQUE hanya `prefix`).
- **Dampak:** regenerasi A dan B konkuren (klik ganda admin / retry setelah timeout) sama-sama menangkap kunci lama yang sama sebelum kunci baru pertama tersisip → masing-masing menerbitkan kunci baru dengan sisa kuota yang sama. Hasil: 2 kunci aktif, total kuota yang bisa dipakai ≈ 2× sisa lama, dan semua tampilan (portal, panel admin, preview, grant, assign) hanya melihat yang terbaru — kunci satunya tidak terlihat tapi tetap valid untuk API. Regenerasi sekuensial aman.
- **Verifikasi:** HANYA DARI KODE + live DB menegaskan saat ini 0 member multi-aktif (laten, bukan kondisi live). Skenario interleaving adalah DUGAAN yang dimungkinkan kode, bukan kejadian live yang teramati.
- **Rekomendasi:** serialisasi per member untuk `regenerate_member_key` (mutex per member-id atau lock global store selama seluruh fungsi), atau guard DB (klaim regenerasi atomik). Audit berkala: SELECT member dengan >1 kunci `active`.

### B5 — [BESAR] Revokasi sesi fail-open + bisa nonaktif permanen sejak boot, sementara logout selalu lapor sukses
- **Deskripsi:** pemeriksaan revocasi gagal Redis → `false` (fail-open); `revoke()` gagal Redis hanya di-log, caller tetap lanjut; bila pembuatan `ConnectionManager` gagal saat boot, seluruh pemeriksaan/revoke menjadi no-op sampai restart proses. Logout member dan admin selalu mengembalikan 204 + hapus cookie walau `revoke()` gagal.
- **Bukti:** `src/session_revocation.rs:66` (`is_revoked` fail-open + warn); `:47` (`revoke` best-effort); `:24` (`new` → `connection: None` tanpa retry); `src/member.rs:392` dan `src/api.rs:759` (logout selalu sukses).
- **Dampak (FAKTA dari kode):** selama Redis tidak terjangkau, logout TIDAK benar-benar membatalkan token: token curian tetap valid sampai `exp` (12 jam member / 8 jam admin). Ini trade-off yang ditulis eksplisit di komentar kode ("fail-open by design"), tapi dikombinasikan dengan logout yang diam-diam sukses, pengguna/admin mendapat rasa aman palsu.
- **Verifikasi:** HANYA DARI KODE (Redis tidak pernah dimatikan untuk pengujian — dilarang mengubah state).
- **Rekomendasi:** minimal: logout mengembalikan peringatan bila `revoke` gagal; retry/reconnect `SessionRevocation` berkala bila `connection: None` (bukan no-op permanen). Opsi kuat: fail-closed untuk pemeriksaan revocasi pada endpoint sensitif (reveal, sandbox, pembelian) saat Redis down; alarm pada warn fail-open.

### B6 — [BESAR, laten — saat ini aman di produksi] Secret QRIS/webhook terenkripsi kunci fallback dev bila env tidak ter-set; validasi produksi tidak mewajibkannya
- **Deskripsi:** konstruktor cipher QRIS memakai kunci fallback yang tercetak di source code bila `API_KEY_ENCRYPTION_KEY` tidak ter-set. Jalur QRIS memakai konstruktor ini langsung, bukan jalur aman yang dipakai kunci member. Validasi produksi mewajibkan beberapa secret lain ≥32 karakter, tetapi TIDAK mewajibkan variabel ini.
- **Bukti:** `src/provider_config.rs:1027` (`CredentialCipher::new`: fallback → SHA-256 sebagai kunci AES-256-GCM); pemakaian di `src/api.rs:2466` (simpan pengaturan QRIS), `src/api.rs:2583` (dekripsi webhook secret), `src/member.rs:1438` (cancel order), `src/qris.rs:972` (`cipher_or_unavailable`); validasi produksi di `src/config.rs` (tidak mencakup variabel ini).
- **Dampak (FAKTA kode + cek live):** bila variabel itu hilang saat rebuild/rotasi env, API key Cutiezy + webhook secret yang disimpan admin akan terenkripsi dengan kunci yang tercetak di source code — siapa pun yang mendapat dump DB + source dapat mendekripsinya (webhook secret sendiri dampaknya terbatas karena webhook hanya memicu sweep, tapi API key Cutiezy bisa dipakai membuat/membatalkan QRIS). **Kunci member TIDAK terkena jalur ini** (member memakai jalur aman: env kosong → cipher `None` → kunci hash-only, reveal 404 — fail-closed). Cek live: variabel ter-set di produksi, jadi ini laten, bukan kebocoran live.
- **Verifikasi:** HANYA DARI KODE + cek keberadaan env live (aman saat ini).
- **Rekomendasi:** tambahkan ke validasi produksi: variabel wajib ≥32 karakter (gagal start bila kosong), atau tolak simpan pengaturan QRIS bila cipher fallback aktif. Pisahkan kunci enkripsi per keperluan (member vs provider vs QRIS) bila memungkinkan.

### B7 — [BESAR] Resolve admin bisa meng-grant order yang BELUM PERNAH terbukti lunas
- **Deskripsi:** satu-satunya penolak resolve adalah string `last_error` mengandung "Nominal bayar tidak sama" dan member harus aktif. Setelah itu order di-reset `needs_review→paid` lalu di-grant — **tanpa satu pun panggilan check-status Cutiezy**.
- **Bukti:** `src/qris.rs:resolve_needs_review_order` (mulai baris 1301; penolak di ~1318-1324; reset + `grant_row` setelahnya).
- **Jalur masuknya (FAKTA dari kode):** `verify_and_grant` memindahkan order ke `needs_review` bukan hanya saat sudah lunas, tapi juga saat member dinonaktifkan (baris ~1159-1184), padahal order itu masih `waiting_payment` dan belum dibayar. Alurnya: member nonaktif → verify menahan order ke `needs_review` → member diaktifkan lagi → admin klik "Grant ulang" → kuota ter-grant **tanpa pembayaran**.
- **Dampak:** pemberian kuota gratis lewat satu klik admin yang tampilannya menyiratkan order tersebut "sudah lunas tapi tertahan". Membutuhkan aksi admin (bukan eksploitasi jarak jauh oleh member), tapi ini pelanggaran integritas pembayaran.
- **Verifikasi:** HANYA DARI KODE (tidak dipicu live, dan memang dilarang).
- **Rekomendasi:** resolve wajib membuktikan lunas dulu: panggil `check-status` bila order belum pernah mencapai `paid` (atau bila tidak ada bukti bayar yang terekam), dan tolak grant bila hasilnya bukan `Paid` dengan nominal cocok. Minimal, bedakan `needs_review` "terbukti lunas" vs "ditahan non-pembayaran" (kolom/tanda terpisah), dan tampilkan pembeda itu di panel admin sebelum tombol Grant ulang.

### B8 — [BESAR] Rate limit create QRIS 5/jam MATI TOTAL (tidak pernah bisa tercapai)
- **Deskripsi:** urutan create: (1) bila ada order `waiting_payment`, langsung kembalikan order itu (sebelum rate limit dicek); (2) hitung `SELECT COUNT(*) ... WHERE status='waiting_payment' AND created_at > ... - INTERVAL 1 HOUR`; (3) tolak bila `>= 5`.
- **Bukti:** `src/qris.rs:create_member_order` (mulai baris 991).
- **Dampak:** karena hanya boleh ada satu order waiting dan hitungan itu hanya menghitung order waiting, nilai hitungan pada titik pengecekan selalu 0 (bila tidak ada waiting) atau tidak pernah dicapai (bila ada waiting, sudah early-return). Member bisa mengulang create→cancel tanpa batas, dan tiap create sukses memotong 6 hit kuota akun Cutiezy — satu member bisa menguras kuota Cutiezy hingga pembelian semua member lain ikut gagal. Ini efek samping dari perbaikan audit sebelumnya yang mengubah hitungan menjadi "hanya waiting" tanpa mengubah ambang/logikanya.
- **Verifikasi:** HANYA DARI KODE (logikanya deterministik; live hanya ada 1 order sehingga tidak ada data perilaku).
- **Rekomendasi:** hitung **semua create yang sukses dalam 1 jam terakhir** (butuh kolom/tabel jejak create, atau hitung order dengan status apa pun yang dibuat dalam 1 jam — dengan catatan order lama yang granted dalam 1 jam ikut terhitung, jadi ambang mungkin perlu disesuaikan), atau simpan counter create per member per jam. Pindahkan pengecekan sebelum early-return waiting bila memakai definisi baru.

### B9 — [BESAR] Satu order waiting per member MENGABAIKAN `package_id`: klik paket B bisa mengembalikan QR paket A
- **Deskripsi:** pencarian order waiting memfilter hanya `member_id` + `status='waiting_payment'`, dan create mengembalikannya apa adanya tanpa membandingkan `package_id` yang diminta. Handler juga tidak membandingkan.
- **Bukti:** `src/qris.rs` (`waiting_order_for_member`, `create_member_order`); `src/member.rs:create_order` (baris 1344).
- **Dampak:** member yang sudah punya waiting order paket A lalu mengonfirmasi pembelian paket B akan menerima QR/nominal/kuota paket A. Mitigasi yang ada: portal menampilkan `package_name`/`amount_idr` dari order yang dikembalikan, jadi member yang teliti bisa melihat ketidakcocokan sebelum memindai — tapi tidak ada penolakan atau peringatan eksplisit, dan member yang tidak teliti akan membayar paket yang salah.
- **Catatan terkait (KECIL, jalur yang sama):** pengecekan `package.active` dan `effective == 0` terjadi **sebelum** pengecekan waiting — jadi bila paket A dinonaktifkan/dijadikan promo 100% setelah waiting dibuat, klik Beli lagi mengembalikan error, bukan order waiting yang masih bisa dibayar lewat daftar order/QR proxy.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** batasi waiting per `(member_id, package_id)`, atau kembalikan 409 eksplisit "selesaikan/batalkan order menunggu paket A dulu" bila paket yang diminta berbeda.

### B10 — [BESAR] Order `expired`/`canceled` yang ternyata lunas TIDAK PUNYA jalur pemulihan produk
- **Deskripsi:** `verify_and_grant` melakukan early-return `Expired`/`Canceled` **tanpa** memeriksa ulang Cutiezy. Resolve menolak semua status selain `needs_review`. Tidak ada endpoint refund uang QRIS sama sekali.
- **Bukti:** `src/qris.rs:verify_and_grant` (mulai baris 1140); `src/qris.rs:resolve_needs_review_order` (menolak non-`needs_review`); grep `refund` di `api.rs`/`member.rs` hanya menemukan `refund_quota` untuk hit validasi, bukan uang.
- **Dampak:** balapan nyata — member membayar tepat saat sweep menutup order (sweep hanya memeriksa Cutiezy sekali, lalu menandai expired) atau tepat saat cancel sukses (cancel sukses berarti Cutiezy menyatakan belum lunas *pada saat itu*) — uang member sudah berpindah, order tidak akan pernah ter-grant, dan admin tidak punya tombol apa pun selain intervensi DB manual. Probabilitas rendah, dampak tinggi (jendela balapan hitungan detik).
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** (a) izinkan resolve untuk `expired`/`canceled` **hanya** setelah re-verifikasi check-status membuktikan `Paid` + nominal cocok; atau (b) tambahkan status `paid_late` + alur admin yang sama dengan resolve. Jangan izinkan grant tanpa bukti bayar (lihat B7).

### B11 — [BESAR, operasional live — bukan bug kode] Pembelian baru saat ini terblokir: `source_id` NULL padahal pembelian aktif
- **Deskripsi:** pengaturan QRIS live: `enabled=1`, expiry 15 menit, valid 30 hari, `source_id=NULL`. Kode create mengirim `source_id` apa adanya (None = field dihilangkan).
- **Bukti:** `src/qris.rs:create` (baris 473+); SELECT live `qris_settings`.
- **Dampak (berdasar diagnosa 25 Okt malam yang tercatat, bukan re-verifikasi live oleh auditor — membuat order dilarang):** Cutiezy menolak create dinamis tanpa QRIS sumber dengan 409 `QRIS_SOURCE_REQUIRED`. Selama NULL, setiap klik Beli baru gagal. Pesan ke member pun generik, dan pencatat error create tidak pernah dipanggil di jalur mana pun, jadi `last_error` panel admin tidak ikut mencatat kegagalan create — admin hanya bisa melihatnya dari log server.
- **Verifikasi:** TERVERIFIKASI LIVE untuk nilai settings; prediksi 409 berdasar diagnosa tercatat (bukan retest live).
- **Rekomendasi:** upload QRIS sumber di dashboard Cutiezy, isi `source_id` di panel admin, lalu retest satu create nyata (butuh keputusan admin — bukan oleh auditor). Terpisah dari itu: panggil pencatat error pada kegagalan create dan petakan 409 sumber ke pesan admin yang spesifik (bukan ke member, agar tidak membocorkan detail provider).

### B12 — [BESAR] Jejak audit admin tidak tampil di panel saat DB terhubung, hilang total saat restart, dan isinya generik
- **Deskripsi:** `record_admin_activity` hanya menulis ke vektor in-memory (cap 16 entri), tidak pernah INSERT ke DB. Namun bila DB terhubung, overview mengambil `recent_activities` dari DB — yang dibangun dari `validation_requests`, bukan dari aksi admin. Panel hanya merender `overview.recent_activities`; tidak ada endpoint `/v1/admin/activity`.
- **Bukti:** `src/api.rs:2116` (`record_admin_activity` → `append_activity`); `src/store.rs:2141-2153` (insert + truncate 16; tidak ada INSERT aktivitas); `src/store.rs:623-624` (bila `db_overview` ada, aktivitas dari DB); `src/store.rs:820-841` (aktivitas DB = riwayat validasi, LIMIT 8); `web/app.js:368,816` (panel hanya merender overview); tidak ada rute `/v1/admin/activity` di `src/api.rs:80-216`.
- **Dampak:** di produksi, view "Aktivitas" panel menampilkan riwayat validasi saja. Grant ulang, reveal kunci, revoke, perubahan paket/settings — semua yang dicatat — tidak terlihat admin di panel, dan lenyap saat proses restart. Jejak forensik aksi sensitif praktis tidak ada di UI. Ditambah: isi log yang ada generik (tanpa ID/nama: revoke kunci, hapus paket, hapus kebijakan, hapus endpoint) dan login/logout admin (sukses maupun gagal) serta percobaan auth gagal tidak dicatat; reveal kunci oleh member sendiri hanya `tracing::info!`, bukan baris aktivitas persisten.
- **Verifikasi:** HANYA DARI KODE (alurnya deterministik; tampilan panel live tidak bisa dicek tanpa login admin, yang dilarang).
- **Rekomendasi:** buat tabel `admin_audit_log` persisten + endpoint `GET /v1/admin/activity` (paginasi, filter aksi/aktor); sertakan ID/nama objek di setiap detail log; catat login/logout/gagal-auth admin; tulis self-reveal ke log persisten, bukan hanya tracing.

### B13 — [BESAR] Hapus paket: gagal hapus di DB disembunyikan, paket bisa "bangkit" setelah restart
- **Deskripsi:** `delete_package` menghapus dari memori lalu memanggil helper DB yang menelan error; handler tetap mengembalikan 204.
- **Bukti:** `src/store.rs:1053-1063` (hapus memori, lalu `delete_package_row`, `Ok(())`); `src/store.rs:371-380` (`delete_package_row` hanya warn bila DELETE gagal; tidak ada propagasi error); `src/api.rs:1649-1665` (`delete_package` → `NO_CONTENT` tanpa memeriksa hasil hapus DB). Pola yang sama ada di `delete_policy_row` (`src/store.rs:404-413`, warn-only). Berbeda dengan `delete_provider_endpoint` (`src/provider_config.rs:487+`) yang mengembalikan error bila DELETE DB gagal, dan dengan `persist_key` yang sengaja mengembalikan error.
- **Dampak:** bila DELETE `admin_packages` gagal sesaat (mis. gangguan DB), admin mengira paket terhapus, padahal setelah restart paket dimuat lagi dari DB dan bisa dibeli lagi. Ini persis pola divergensi memori/DB yang sudah diperbaiki di jalur lain.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** samakan dengan `persist_key`: `delete_package_row` mengembalikan `Result`, handler gagal bila DB gagal (atau hapus DB dulu, baru memori — konsisten dengan pola DB-first di assign).

### B14 — [BESAR] Stream Redis `validation-events` tidak pernah dipangkas; dengan `maxmemory-policy noeviction` ini menjadi outage total jalur berbayar di masa depan
- **Deskripsi:** `XADD` tanpa `MAXLEN`/`MINID`; tidak ada `XTRIM`/`XDEL` di codebase. Worker hanya `XACK`, tidak pernah `XDEL`.
- **Bukti:** `src/events.rs:57` (`XADD` tanpa batas); grep `XTRIM|XDEL|MAXLEN` di `src/` = tidak ada hasil.
- **Bukti live:** `XLEN validation-events` = **29.633**, `max-deleted-entry-id 0-0`, `entries-added 29633`, `used_memory 21,33 MB` dari `maxmemory 256 MB`, `maxmemory-policy noeviction`. `validation_requests` = 29.633 dan `usage_ledger` = 29.633 — persis sama dengan panjang stream, jadi sejauh ini belum ada kehilangan (FAKTA), tapi stream hanya tumbuh.
- **Dampak:** saat Redis penuh, `XADD` gagal → `enqueue()` 503 → validasi berbayar digagalkan + kuota di-refund. Ini fail-closed (tidak ada kuota gratis), tapi berubah menjadi outage total validasi berbayar. Pada laju ±29 ribu entri sejak ~21 Okt, ini soal minggu–bulan, bukan tahun (DUGAAN laju — angka pasti per hari tidak dihitung).
- **Verifikasi:** TERVERIFIKASI LIVE (angka Redis).
- **Rekomendasi:** `XADD … MAXLEN` (atau `XTRIM` berkala oleh worker setelah ACK) dengan retensi yang masih mencakup jendela reclaim; pantau `XLEN` + `used_memory` sebagai alarm. Jangan ubah policy ke eviction sembarangan — eviction bisa menghapus PEL/rate-limit/idempotency.

### B15 — [BESAR] Worker: pesan yang gagal persist ke DB tidak punya batas retry/DLQ dan memblokir seluruh ledger (head-of-line blocking)
- **Deskripsi:** hanya payload malformed yang di-DLQ (bukan string, tidak ditemukan, JSON tidak valid → DLQ + ACK). Sebaliknya error persist DB memakai `?`: error menggagalkan sesi consumer, loop luar tidur 3 detik dan mulai ulang; loop utama selalu membaca pending sendiri dulu sebelum fresh, jadi **satu pesan yang gagal-persist selamanya akan dicoba ulang selamanya dan event fresh tidak pernah diproses**.
- **Bukti:** `src/bin/worker.rs` (`process_reply`, `run_consumer_session`, loop baca pending dulu).
- **Dampak:** setelah DB pulih pun, satu event "beracun" di level DB (mis. nilai melebihi lebar kolom — DUGAAN pemicu, bukan kasus teramati) menghentikan seluruh histori/ledger, bukan hanya event itu. Kuota member tidak hilang (reserve sudah di memori API), tapi `validation_requests`/`usage_ledger`/riwayat berhenti bertambah. Yang teramati live: `XPENDING = 0`, DLQ = 0 — saat ini bersih, ini risiko laten, bukan insiden berjalan.
- **Verifikasi:** HANYA DARI KODE + status live bersih (XPENDING/DLQ nol).
- **Rekomendasi:** hitung percobaan persist per stream-id; setelah N kali gagal, pindahkan ke DLQ + ACK seperti payload malformed, dengan alarm. Bedakan error koneksi DB (retry, benar) dari error per-event (DLQ).

## Temuan KECIL

### K1 — [KECIL] Grant mengizinkan kunci `disabled` dan tidak memeriksa status member di dalam fungsi (temuan gabungan 3 area)
- **Deskripsi:** `grant_package_order` hanya menolak `status == "revoked"` (CAS `k.status != 'revoked'`) dan tidak memeriksa `members.status`. Komentar resolve mengklaim kunci revoked/disabled ditahan — klaim untuk `disabled` ini TIDAK BENAR di kode.
- **Bukti:** `src/store.rs:1705` (CAS); `src/store.rs:1634` (tidak ada cek member); `src/qris.rs:1335` (komentar yang salah); `src/qris.rs:980` (`ensure_key_buyable` menolak revoked DAN disabled saat beli — inkonsisten dengan grant).
- **Dampak (terbatas):** kuota mendarat di kunci yang sedang dinonaktifkan — tidak bisa dipakai sampai diaktifkan lagi, jadi bukan kuota gratis dan bukan kehilangan uang; member yang membayar lalu kuncinya dinonaktifkan di jendela verifikasi akan melihat order `granted` tapi tetap tidak bisa cek sampai admin mengaktifkan. Jalur normal terlindungi sebagian: `verify_and_grant` dan resolve memeriksa `member.status == 'active'` dari DB, dan kunci disabled hanya muncul berpasangan dengan member disabled (via `set_member_status` transaksional). Pola yang sama di `assign_plan_to_member_key` (hanya menolak `revoked`) lebih rendah risikonya karena itu aksi admin eksplisit.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** ubah CAS grant menjadi `k.status = 'active'` (kunci kedaluwarsa tetap berstatus `active` dengan `expires_at` lewat, jadi perpanjangan tidak pecah) dan tambahkan cek `members.status == 'active'` di dalam `grant_package_order`; selaraskan komentar resolve.

### K2 — [KECIL] Kontrak endpoint resolve menyesatkan bagi pemanggil API (temuan gabungan 2 area; panel sudah jujur)
- **Deskripsi:** handler resolve selalu mengembalikan `Json(MemberOrderView)` 200, termasuk saat grant mengembalikan order ke `needs_review`. Tidak ada field `outcome` — satu-satunya sinyal adalah `view.status`. Log aktivitas admin pun mencatat "di-grant ulang (hasil: NeedsReview)" seolah grant terjadi.
- **Bukti:** `src/api.rs:2522-2540` (`resolve_admin_order` → `Ok(Json(view))` apa pun outcome); `src/qris.rs:1387-1400` (`grant_row` → `Ok((view, VerifyOutcome::NeedsReview))`); panel sudah diperbaiki (`web/app.js:1032-1050`, memeriksa `result.status`).
- **Dampak:** konsumen API non-panel yang hanya memeriksa status HTTP akan salah mengira grant berhasil. Risiko terbatas karena satu-satunya konsumen yang diketahui adalah panel yang sudah memeriksa `status`.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** tambahkan field `outcome` eksplisit pada respons resolve (atau status HTTP non-2xx untuk outcome gagal-grant), dan perbaiki teks log aktivitas agar membedakan granted vs ditahan.

### K3 — [KECIL] Nilai balik `set_order_status` (bool CAS) diabaikan di 8 dari 9 call site → verdict bisa salah pada race (temuan gabungan 2 area)
- **Deskripsi:** primitifnya BENAR (`rows_affected() == 1`), tetapi pemanggil membuang bool: member dinonaktifkan → `needs_review`, member tidak ditemukan → `needs_review`, nominal tidak sama → `needs_review`, pending + lewat expiry → `expired`, Cutiezy expired → `expired`, canceled → `canceled`, not-found + lewat expiry → `expired`, konflik grant `paid` → `needs_review`. Hanya resolve yang memeriksa bool.
- **Bukti:** `src/qris.rs:954` (primitif); call site di `src/qris.rs:1163, 1176, 1209, 1259, 1267, 1272, 1285, 1392`; pola yang benar dipakai di `src/qris.rs:1233-1250` (mark-paid).
- **Dampak (terbatas, FAKTA dari alur kode):** bila verifikator lain mengubah status di antara `get_order()` dan CAS ini, CAS gagal (0 baris) tetapi kode tetap me-re-read baris lalu mengembalikan verdict lama (mis. baris sudah `granted` tapi verdict `NeedsReview`/`Expired`). Sweep/webhook mengabaikan verdict sehingga tidak ada efek uang; yang kena adalah tombol "cek" manual member/admin yang bisa menampilkan verdict menyesatkan padahal barisnya benar.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** bila `set_order_status` mengembalikan `false`, turunkan verdict dari `row.status` hasil re-read (pola yang sudah benar di cabang mark-paid).

### K4 — [KECIL] Fallback balapan = finisher non-Valid pertama, bukan jawaban paling definitif
- **Deskripsi:** bila tidak ada Valid, balapan mengembalikan finisher non-Valid pertama apa adanya.
- **Bukti:** `src/provider.rs:365-380` (`if fallback.is_none() { fallback = Some(pair); }`).
- **Dampak:** bila Cutiezy `NotFound` finis dulu dan Tukangcek `Invalid` finis kemudian (atau sebaliknya), member menerima klasifikasi finisher pertama. Tagihan sama-sama billable (`Valid|Invalid|NotFound`), jadi dampaknya klasifikasi jawaban, bukan double-charge. `Pending` sebagai fallback pertama juga bisa mengalahkan `Invalid`/`NotFound` yang datang kemudian (tidak ditagih karena non-billable, tapi member mendapat jawaban menggantung padahal ada jawaban definitif).
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** beri peringkat fallback: `Invalid`/`NotFound` mengalahkan `Pending`; bila dua jawaban definitif berbeda, pilih berdasarkan prioritas server yang dikonfigurasi admin (atau kembalikan yang paling dulu hanya di antara jawaban definitif).

### K5 — [KECIL] Leg balapan yang dibatalkan tidak pernah `record_outcome`
- **Deskripsi:** saat Valid pertama menang, fungsi `return` dan future leg lain di-drop; `record_outcome` hanya dipanggil di dalam future tiap leg, jadi leg yang di-drop tidak mencatat sukses/gagal ke breaker-nya.
- **Bukti:** `src/provider.rs:360-375` (early-return); `src/provider.rs:254-267` (`record_outcome` di dalam future leg).
- **Dampak:** statistik breaker server yang kalah balapan tidak diperbarui (kegagalan diam-diam hilang). Permit semaphore tetap dilepas lewat `Drop`, jadi tidak ada kebocoran slot. Untuk probe half-open, `probe_since` tertinggal sampai lease 120 detik sehingga probe berikutnya tertunda hingga 120 detik.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** pada early-return balapan, batalkan leg lain secara eksplisit dan bersihkan `probe_since` bila leg yang dibatalkan memegang probe (atau terima sebagai keterbatasan yang didokumentasikan — dampaknya kecil).

### K6 — [KECIL] Cutiezy dibebaskan total dari pacer, bukan diberi bucket per-host sendiri
- **Deskripsi:** pacer dilewati sepenuhnya untuk mode Cutiezy, padahal pacer sendiri per-host sehingga Cutiezy sebenarnya bisa punya bucket sendiri di host-nya.
- **Bukti:** `src/provider.rs:462` (`if endpoint.request_mode != ProviderRequestMode::Cutiezy { self.guard.pace(...) }`); `src/provider_guard.rs:470-520` (pacer per-host, kunci host lowercase).
- **Dampak:** satu-satunya pembatas laju ke Cutiezy adalah semaphore 16/produk + rate limit member. Pada 16 slot bersamaan × 2 produk (bank+e-wallet berbagi host Cutiezy), laju puncak ke satu akun Cutiezy bisa melampaui pola 3 hit/detik yang diterapkan ke Tukangcek. **DUGAAN** (bukan fakta): apakah Cutiezy punya rate limit akun sendiri tidak diketahui dari kode — bila ada, exemption ini yang akan pertama kali menabraknya (gejala: 429 upstream → retry → breaker per-server).
- **Verifikasi:** HANYA DARI KODE (exemption-nya fakta; ada/tidaknya limit Cutiezy dugaan).
- **Rekomendasi:** pace Cutiezy dengan bucket host-nya sendiri (interval terpisah yang bisa diset admin), bukan exemption; atau dokumentasikan secara eksplisit bahwa Cutiezy terbukti tanpa limit.

### K7 — [KECIL] Pesan upstream mengalir verbatim ke member lewat `message_path` generik
- **Deskripsi:** `message` diambil dari `mapping.message_path` bila ada; default generik memakai field `message`. Untuk built-in, `message_path: None` sehingga member hanya menerima default generik — aman. Risikonya hanya endpoint mode Generic.
- **Bukti:** `src/provider.rs:987-997`; default generik `src/models.rs:410` (`message_path: Some("message")`); built-in `message_path: None` (Tukangcek `src/provider.rs:1140+`, Cutiezy `src/provider.rs:1120+`); `provider_path` di mapping sengaja diabaikan (`provider: None` di `src/provider.rs:1013-1031`).
- **Dampak:** bila pesan upstream menyebut nama/kode vendor atau kalimat internal vendor, teks itu sampai ke JSON member tanpa sanitasi. Jalur nama provider via field terpisah sudah ditutup, tapi jalur pesan belum.
- **Verifikasi:** HANYA DARI KODE (isi pesan upstream aktual tidak diperiksa — butuh payload live).
- **Rekomendasi:** untuk respons member, ganti pesan generik dengan pesan baku per status (seperti default saat ini), atau filter pesan upstream terhadap daftar nama/kode vendor; biarkan pesan verbatim hanya di tester admin.

### K8 — [KECIL] Penolakan guard terjadi setelah reserve: kuota kembali, slot rate-limit hangus
- **Deskripsi:** urutan: idempotensi → rate limit (`admit`) → `reserve_quota` → `provider.validate()`. Bila provider gagal (breaker terbuka, semaphore penuh, pacer shed), cabang Err me-refund kuota dan me-abandon idempotensi, tetapi tidak ada mekanisme pengembalian slot rate limit (skrip Lua menaikkan semua bucket sebelum memeriksa batas).
- **Bukti:** `src/api.rs:886-968` (urutan); `src/provider_guard.rs:360-420,470-520` (penolakan guard); `src/api.rs:957-967` (refund); `src/rate_limit.rs:17-45` (Lua).
- **Dampak:** saat provider sedang bermasalah, member yang me-retry akan menghabiskan budget rate-limit-nya sendiri walau kuotanya utuh. Bukan double-charge kuota, tapi mempercepat 429 member di tengah outage.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** terima sebagai trade-off yang didokumentasikan, atau pisahkan: pindahkan pemeriksaan guard ringan (breaker terbuka) sebelum reserve — tidak mengubah perilaku antrean penuh/pacer yang memang harus dinilai setelah reserve.

### K9 — [KECIL] HTTP 422 upstream berulang: netral, non-billable, 503 generik, tanpa atribusi endpoint
- **Deskripsi:** 422 bukan 429/5xx → `retryable: false`, `provider_failure: false` → `record_neutral`, tidak menambah hitungan breaker. 422 dipetakan ke default generik 503. Log hanya mencatat status, bukan endpoint.
- **Bukti:** `src/provider.rs:654-670` (klasifikasi); `src/provider.rs:888-911` (pemetaan 422 → 503 generik).
- **Dampak:** member tidak ditagih (benar bila 422 memang bukan jawaban definitif) tapi selalu menerima "tidak tersedia" tanpa jalan keluar, dan breaker tidak pernah bereaksi terhadap pola 422 sistematis.
- **Verifikasi:** TERVERIFIKASI LIVE untuk frekuensi (tinggi di log 25 Okt malam) + klasifikasi; makna 422 HANYA DUGAAN (tidak bisa disimpulkan dari kode/log; butuh kontrak upstream).
- **Rekomendasi:** tentukan kontrak 422 per upstream (bila definitif → petakan ke `Invalid`/`NotFound` di mapping; bila konfigurasi → alert admin); tambahkan nama endpoint ke log HTTP-error agar 422 bisa diatribusikan.

### K10 — [KECIL] Timeout nginx 30 detik < worst-case validasi di bawah backlog pace
- **Deskripsi:** nginx `proxy_read_timeout 30s`. Worst-case satu leg Tukangcek live: 2 attempt × (pace wait maks 10 detik + timeout 8 detik) = 36 detik. Pada beban normal pace wait ≈ 0–1 detik sehingga total ≈ 16–18 detik (< 30 detik) — skenario 36 detik hanya terjadi saat backlog pace penuh.
- **Bukti:** nginx live (TERVERIFIKASI LIVE); `src/provider.rs:449-465`, `src/provider_guard.rs` (nilai live: pace wait maks 10 detik, timeout endpoint 8 detik).
- **Dampak:** bila 504 nginx terjadi saat API masih memproses, member menerima 504 (bukan error Rajacek), kuota sudah ter-reserve, dan: retry dengan kunci idempotensi yang sama akan me-replay setelah selesai (aman, TTL 24 jam), tetapi retry tanpa header — jalur default yang menghasilkan UUID baru per request (`src/api.rs:2240-2260`) — akan mengeksekusi ulang dan menagih kedua kalinya.
- **Verifikasi:** TERVERIFIKASI LIVE untuk angka nginx + timeout endpoint; skenario backlog adalah perhitungan dari kode, bukan kejadian yang diamati.
- **Rekomendasi:** naikkan `proxy_read_timeout` nginx ke ≥ 60 detik, atau turunkan `pace_max_wait_ms` agar worst-case satu leg selalu < 30 detik; dan dorong klien API memakai `Idempotency-Key` sendiri (portal sandbox saat ini tidak mengembalikan kunci generated-nya — lihat K11).

### K11 — [KECIL] Dua celah idempotensi di jalur gagal (bukan di jalur normal)
- **Deskripsi:** (a) bila `idempotency.complete()` gagal, respons tetap dikembalikan dan dicatat error; entri tetap in-flight sampai TTL 300 detik, setelah itu retry kunci yang sama akan `Execute` + reserve + tagih ulang untuk satu permintaan logis yang sama. (b) Sandbox portal memanggil `execute_validation` langsung dengan kunci `portal-<uuid>` acak dan tidak mengembalikannya ke klien, sehingga retry sandbox tidak pernah bisa replay.
- **Bukti:** `src/api.rs:1055-1075` (complete gagal); `src/idempotency.rs:24` (TTL in-flight 300 detik); `src/member.rs:1094-1109` (sandbox, kunci tidak dikembalikan).
- **Dampak:** (a) hanya terjadi bila Redis gagal/hilang tepat di `complete` DAN respons awal hilang di jaringan DAN klien me-retry setelah 300 detik — rantai langka, tapi konsekuensinya double-charge. (b) Dampak praktis kecil (klik ganda manual di portal), tapi berarti sandbox tidak mendapat perlindungan yang dimiliki API publik.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** (a) terima + dokumentasikan, atau simpan respons ke antrean pemulihan saat `complete` gagal; (b) kembalikan kunci sandbox di header respons seperti jalur API publik.

### K12 — [KECIL] Backpressure writer kuota menahan lock data; window SIGKILL tetap diakui
- **Deskripsi:** saat channel penuh (8192), `persist_key_quota` memakai `send().await` (bukan tulis langsung — perbaikan lama, benar secara FIFO) sambil pemanggil masih memegang `data` write lock. Drain shutdown 30 detik; komentar di sana mengakui SIGKILL mid-validasi tetap bisa menghilangkan snapshot.
- **Bukti:** `src/store.rs:559-586` (backpressure); `src/store.rs:2048-2075` (reserve), `2082-2105` (refund) di bawah lock; `src/store.rs:537-556` (drain 30 detik + komentar SIGKILL).
- **Dampak:** DB lambat/mati = semua reserve/refund validasi ikut stall (bukan korupsi — ini trade-off yang dipilih secara sadar di komentar kode). Restart paksa di tengah validasi = 1 hit hilang dari DB + gap riwayat, tanpa job rekonsiliasi.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** tidak ada perbaikan mendesak; pertimbangkan job rekonsiliasi berkala (kuota memori vs `admin_api_keys.quota_remaining` + `usage_ledger`) bila window SIGKILL dianggap material.

### K13 — [KECIL] Retry memakai backoff tetap 250 ms tanpa jitter
- **Deskripsi:** sleep 250 ms tetap di antara attempt (maks 2 attempt).
- **Bukti:** `src/provider.rs:502-516`.
- **Dampak:** DUGAAN — saat outage upstream, retry dari banyak member cenderung tersinkronisasi; dengan hanya 1 retry, dampaknya kecil.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** tambahkan jitter (mis. 200–500 ms acak) bila pola retry terbukti memperparah 429 upstream.

### K14 — [KECIL] IP klien diambil dari entri PERTAMA `X-Forwarded-For` → throttle login per-IP dan bucket IP rate-limit bisa di-spoof
- **Deskripsi:** bila peer loopback, IP diambil dari entri pertama `X-Forwarded-For`. Dipakai throttle login member dan bucket `rl:ip:`.
- **Bukti:** `src/api.rs:809` (`effective_client_ip`: `X-Forwarded-For.split(',').next()`); `src/member.rs:292` (throttle login); `src/rate_limit.rs:126` (bucket IP); nginx live append (`$proxy_add_x_forwarded_for`), peer selalu loopback (nginx → `127.0.0.1:8080`).
- **Dampak (FAKTA kode + nginx live; kaki Cloudflare tidak diverifikasi dari header live):** dalam rantai append, entri pertama adalah yang paling mudah dipalsukan penyerang; dengan memutar nilai XFF, penyerang dapat mengganti kunci throttle/bucket IP sesuka hati. Dampak dibatasi: secret kunci 48 hex membuat brute-force tetap tidak layak, dan bucket per-API-key tetap berlaku — yang jebol hanya kontrol berbasis IP dan atribusi IP di log.
- **Verifikasi:** HANYA DARI KODE + konfigurasi nginx TERVERIFIKASI LIVE.
- **Rekomendasi:** percayai `CF-Connecting-IP` (ditimpa Cloudflare, bukan append) atau entri tepercaya terakhir dari rantai proxy, bukan entri pertama.

### K15 — [KECIL] Login Google pertama yang konkuren → dua kunci aktif (trial + kosong), kuota trial terdampar; trial bisa hangus/ganda pada gagal DB
- **Deskripsi:** balapan `create_member` — yang kalah mengadopsi baris member dengan `is_new=false`, lalu bila `needs_key` masih benar (kunci pemenang belum terbit saat pengecekan) ia menerbitkan kunci KOSONG, bukan trial kedua. Member kini punya 2 kunci aktif; portal hanya menampilkan yang terbaru (kosong, 0 hit) sementara kuota trial terdampar di kunci lama. `record_trial_grant` mengembalikan `false` untuk SEMUA error (bukan hanya duplikat PK): bila gagal non-duplikat, kunci trial langsung dicabut dan login berikutnya memberi kunci kosong — trial hangus permanen untuk akun itu (hanya bisa dipulihkan assign admin). Bila revoke pecundang itu sendiri gagal (hanya warn), kunci trial pecundang tetap aktif dan bisa di-reveal lewat tombol mata portal.
- **Bukti:** `src/member.rs:775` (`google_callback`, balapan `create_member`); `src/member.rs:880` (kunci kosong); `src/member.rs:871` (cabut kunci trial); `src/store.rs:1935` (`record_trial_grant` false untuk semua error).
- **Dampak:** jendela balapan milidetik; tidak direproduksi live. Terkait B4 (invarian satu kunci aktif) tetapi jalur berbeda (login pertama, bukan regenerasi).
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** bedakan error duplikat vs error DB di `record_trial_grant` (jangan cabut kunci pada error transient; tandai trial pending untuk retry). Serialisasi provisioning kunci pertama per `google_sub` (atau jadikan `needs_key` + penerbitan satu transaksi logis). Perbaiki bersama B4 karena sama-sama soal invarian satu-kunci-aktif.

### K16 — [KECIL] Assign paket admin tidak memeriksa status member; `plan_kind` bisa drift diam-diam
- **Deskripsi:** handler assign tidak memeriksa `member.status`; assign hanya menolak kunci revoked. `set_member_plan_kind` gagal hanya di-warn dan nilai baliknya diabaikan pemanggil.
- **Bukti:** `src/api.rs:1825` (handler assign); `src/store.rs:1550` (`assign_plan_to_member_key`); `src/store.rs:1457` (`set_member_plan_kind` warn-only).
- **Dampak:** admin bisa meng-assign paket ke member disabled (kuota bertambah, `plan_kind` berubah menjadi `package`/`manual`, akun tetap disabled — membingungkan saat diaktifkan kembali). `plan_kind` sendiri hanya display (tidak ada gating logika yang membacanya — diverifikasi via grep), jadi dampaknya kosmetik/operasional, bukan keamanan.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** tolak assign untuk member disabled (atau beri peringatan eksplisit di panel), dan surface error `set_member_plan_kind` ke handler.

### K17 — [KECIL] Inkonsistensi audit reveal: admin reveal tanpa gate status; self-reveal member hanya tracing, bukan baris aktivitas persisten
- **Deskripsi:** reveal admin tidak memeriksa status kunci sama sekali — plaintext kunci revoked/disabled/expired tetap bisa ditampilkan admin — sementara self-reveal member memblokir kunci non-aktif/expired. Self-reveal hanya `tracing::info!`, bukan `record_admin_activity`; feed aktivitas admin sendiri hanya memori (cap 16 entri, hilang saat restart).
- **Bukti:** `src/api.rs:1978` (`reveal_member_key` admin, tanpa gate status); `src/member.rs:965` (`reveal_own_key` memblokir non-aktif/expired); `src/store.rs:2141` (`append_activity` memori).
- **Dampak:** admin adalah pihak tepercaya sehingga reveal admin bukan kebocoran akses; yang hilang adalah konsistensi dan jejak audit yang tahan restart untuk peristiwa sensitif (melihat plaintext kunci).
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** samakan gate status di reveal admin (atau dokumentasikan pengecualian admin), dan tulis self-reveal ke log aktivitas persisten (DB), bukan hanya tracing. Lihat juga B12.

### K18 — [KECIL] Endpoint start OAuth tanpa throttle; cap state 1000 memakai eviksi (flood bisa mengusir login sah)
- **Deskripsi:** cap 1000 dengan eviksi entri paling cepat kedaluwarsa; tidak ada throttle per-IP di `google_start` (admin maupun member). State in-memory: restart proses membunuh login yang sedang berjalan.
- **Bukti:** `src/auth.rs` (`OAuthStateStore::issue`, cap + eviksi; tidak ada throttle per-IP di start).
- **Dampak:** banjir request start (masing-masing hanya butuh GET anonim) dapat mengusir state login sah → korban harus retry. Risiko DoS login, bukan bypass auth (state tetap sekali pakai, TTL 10 menit, dan callback butuh kode Google valid).
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** throttle ringan per-IP di endpoint start (atau naikkan cap + eviksi berbasis LRU per-IP), dan pertimbangkan state di Redis bila multi-replika kelak.

### K19 — [KECIL, DUGAAN — butuh uji browser] Header clear varian host-only tidak membawa flag `Secure`
- **Deskripsi:** header clear (`Max-Age=0`) tidak membawa `; Secure`, sementara cookie domain menyertakan `Secure` di produksi.
- **Bukti:** `src/member.rs:272` (`host_only_clear_header`) dan clear legacy admin di `src/auth.rs`.
- **Dampak (DUGAAN, bukan fakta terverifikasi):** bila cookie host-only lama tersimpan sebagai Secure, belum dipastikan apakah clear tanpa flag ini benar-benar menghapusnya di semua browser. Dampaknya terbatas pada sesi lama pra-perbaikan 24 Okt.
- **Verifikasi:** HANYA DARI KODE; verifikasi browser di luar wewenang audit ini.
- **Rekomendasi:** samakan flag `Secure` pada header clear dengan cookie yang dihapus, lalu uji hapus cookie lama di browser.

### K20 — [KECIL] Gagal parsing respons create meninggalkan QR yatim yang tidak bisa dibatalkan
- **Deskripsi:** bila Cutiezy menjawab 2xx tapi bodi non-JSON, field hilang (`token`/`amount` wajib), `ok`/`success` keduanya absen/false, atau `amount != order`, fungsi mengembalikan `Unexpected` **tanpa token** — sehingga create tidak bisa memanggil `cancel` (berbeda dengan jalur gagal-insert yang memang membatalkan QR yatim). QR sudah terbit di Cutiezy, tidak terlihat member, tidak bisa di-grant.
- **Bukti:** `src/qris.rs:QrisClient::create` (baris 473+); `src/qris.rs:create_member_order` (tidak ada token untuk dibatalkan pada jalur ini).
- **Dampak:** terbatas pada biaya hit Cutiezy + QR yatim di sisi provider; member tidak bisa membayarnya karena tidak pernah menerima QR-nya. Anomali "2xx bodi non-JSON" ini sudah pernah teramati pada diagnosa sebelumnya — polanya konsisten dengan kode ini.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** pada jalur `amount` mismatch dan parse parsial, kembalikan token bila berhasil diparsing agar pemanggil bisa membatalkan; untuk 2xx non-JSON, catat bodi terpotong ke log admin (bukan ke member) agar mudah didiagnosis.

### K21 — [KECIL] Status check-status yang tak dikenal dipetakan diam-diam ke `NotFound`
- **Deskripsi:** `match` hanya menangani `paid`/`pending`/`expired`/`canceled`; sisanya menjadi `NotFound`. Cabang `NotFound` di verify menunggu sampai expiry lokal lalu menandai `expired` — tanpa pernah menjadi `needs_review`.
- **Bukti:** `src/qris.rs:check` (baris 545+).
- **Dampak:** bila Cutiezy memakai kosakata status lain (mis. varian sukses), order yang sebenarnya lunas akan kedaluwarsa diam-diam dan jatuh ke lubang B10. Ini **DUGAAN risiko kosakata**, bukan fakta — kosakata Cutiezy yang sesungguhnya tidak diverifikasi dari dokumen provider dalam audit ini.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** perlakukan status tak dikenal sebagai error (log warn + 502 yang bisa di-retry sweep berikutnya), bukan `NotFound`.

### K22 — [KECIL] Update paket yang GAGAL validasi tetap mengubah paket di memori (divergen dari DB)
- **Deskripsi:** mutasi dilakukan langsung pada `data.packages.get_mut()` di bawah write-lock, sedangkan `validate_promo(...)` baru dipanggil di akhir. Bila validasi gagal (mis. persen > 0 tanpa tanggal, atau > 100%), fungsi mengembalikan error **tanpa** mengembalikan mutasi dan **tanpa** `persist_package` — memori divergen dari DB sampai restart.
- **Bukti:** `src/store.rs:update_package` (baris 983+; mutasi dulu, validasi di ~1045).
- **Dampak:** efek praktisnya mengarah aman (promo tidak valid → `promo_active` false → harga katalog), tapi panel admin membaca memori sehingga admin melihat promo yang ditolak seolah sudah tersimpan, sementara penagihan memakai harga katalog. Jalur create paket sudah benar: validasi sebelum insert.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** validasi di atas klon paket dulu, atau kembalikan nilai lama bila validasi gagal, sebelum lock dilepas.

### K23 — [KECIL] Landing: "masa aktif 30 hari" di-hardcode; kartu Rp0 untuk promo 100% masih tampil
- **Deskripsi:** landing menulis literal `per paket · masa aktif 30 hari` dan footer "Semua paket berlaku 30 hari"; `public_landing` hanya memfilter `active`, tidak memfilter `effective_price > 0` (berbeda dengan daftar paket member yang memfilter keduanya).
- **Bukti:** `src/api.rs:render_landing` (literal 30 hari); `src/api.rs:public_landing` (filter `active` saja); `src/member.rs:purchase_packages` (filter `active` + `effective_price > 0`).
- **Dampak saat ini NIHIL secara live** (TERVERIFIKASI LIVE: `valid_days=30`, tidak ada paket promo 100%; harga landing Starter Rp4.500 / Growth Rp379.050 / Scale Rp1.499.000 persis sama dengan `effective_price` dari DB). Risikonya laten: bila admin mengubah `valid_days` atau mengaktifkan promo 100%, landing berbohong sementara penagihan tetap benar.
- **Verifikasi:** TERVERIFIKASI LIVE untuk kondisi saat ini; risiko laten HANYA DARI KODE.
- **Rekomendasi:** render masa aktif dari `qris_settings.valid_days` (atau dari paket) dan filter kartu `effective_price == 0` di landing seperti di portal member.

### K24 — [KECIL] Proxy QR tanpa allowlist URL / batas ukuran
- **Deskripsi:** proxy melakukan GET ke `image_url` dari Cutiezy (reqwest mengikuti redirect bawaan), hanya memeriksa prefix `image/` pada content-type, tanpa batas ukuran.
- **Bukti:** `src/qris.rs:fetch_qr_png` (baris 641+).
- **Dampak terbatas:** URL berasal dari respons Cutiezy, bukan input member, sehingga ini bukan SSRF yang bisa dipicu member; risikonya hanya bila respons provider dikompromikan/dipalsukan. Tetap layak diperketat (allowlist host Cutiezy + batas byte).
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** allowlist host Cutiezy + batas ukuran respons.

### K25 — [KECIL] Banjir webhook bisa men-spawn banyak sweep bersamaan tanpa dedup
- **Deskripsi:** setiap event pembayaran yang lolos HMAC men-spawn sweep (hingga 50 order terbuka per spawn). Tidak ada throttle/dedup antar-spawn.
- **Bukti:** `src/api.rs:qris_webhook` (`tokio::spawn(sweep_open_orders_now)`); `src/qris.rs` sweep (baris 1432+, LIMIT 50).
- **Dampak terbatas:** check-status diklaim gratis dan CAS membuat grant ganda mustahil, jadi ini soal beban/kompetisi DB, bukan kebenaran uang. Sweep rutin 60 detik tetap menjadi backstop bila satu pass gagal.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** dedup/throttle spawn sweep (mis. satu sweep berjalan max, atau debounce singkat).

### K26 — [KECIL] `paid_at` Cutiezy yang gagal diparsing menjadi NULL tanpa jejak
- **Deskripsi:** parser hanya menerima format `%Y-%m-%d %H:%M:%S` lalu digeser −7 jam; bila format berbeda, `Paid.paid_at = None` tetapi grant tetap berjalan (kolom `paid_at` diikat sebagai NULL).
- **Bukti:** `src/qris.rs:parse_cutiezy_paid_at` (format tunggal + geser −7 jam).
- **Dampak:** hanya jejak audit (jam lunas hilang), bukan uang — grant tidak bergantung pada `paid_at`. Perlu dicatat karena diagnosis "Lunas 26 Okt" sebelumnya berakar pada penanganan zona waktu kolom ini.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** terima juga format ISO-8601 dan log warn bila parsing gagal pada status `paid`.

### K27 — [KECIL] Daftar order admin di-hardcode limit 100 tanpa paginasi; panel tidak punya tombol hapus paket
- **Deskripsi:** `list_admin_orders` di-hardcode limit 100 tanpa paginasi. Panel hanya punya filter status. Bila order >100, order tertua tidak bisa dijangkau dari panel sama sekali. Terpisah: endpoint `DELETE /v1/admin/packages/:id` ada tetapi panel tidak punya tombol hapus paket — kartu paket hanya Edit/Duplikasi. Menghapus paket hanya bisa lewat API langsung.
- **Bukti:** `src/api.rs:2490-2500` (`list_orders_admin(..., 100)`); `web/app.js:940` (filter status saja); `src/api.rs:148-151` (rute DELETE ada); `web/app.js:731` (kartu paket tanpa hapus).
- **Dampak:** bukan bug keamanan, tapi inkonsistensi UI vs API dan keterbatasan jangkauan panel.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** tambah paginasi/offset ke `GET /v1/admin/orders` + panel; putuskan sengaja apakah hapus paket memang disembunyikan dari panel (bila ya, dokumentasikan; bila tidak, tambah tombol + konfirmasi).

### K28 — [KECIL] Gagal muat dashboard non-auth menjatuhkan admin ke layar login
- **Deskripsi:** `loadDashboard` memakai `Promise.all` atas 7 panggilan inti tanpa `.catch` per panggilan (hanya guard dan rate-default yang diberi `.catch(() => null)`); bila salah satunya gagal non-401/403, `initialize` tetap memanggil `showLoginOnly()`.
- **Bukti:** `web/app.js:300-322` (`loadDashboard`); `web/app.js:1710-1730` (`initialize`: `catch` → toast bila bukan 401/403, lalu `showLoginOnly()` tanpa syarat).
- **Dampak:** gangguan sesaat pada satu endpoint (mis. `/v1/admin/banks`) membuat sesi admin yang valid tampak seperti belum login; admin harus login ulang padahal masalahnya bukan sesi. Bukan kebocoran, tapi penanganan error yang tidak jujur.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** bedakan kegagalan sesi (401/403 → login) dari kegagalan data (tampilkan toast + shell dengan view error, tanpa `showLoginOnly`).

### K29 — [KECIL] Aksi destruktif tanpa konfirmasi: toggle provider & toggle status member
- **Deskripsi:** dua aksi satu klik tanpa `window.confirm`, padahal aksi destruktif lain punya konfirmasi.
- **Bukti:** tanpa konfirmasi: `web/app.js:1505-1518` (toggle provider → PATCH `/active` langsung) dan `web/app.js:1884-1898` (tombol status member → POST `/status` langsung). Dengan konfirmasi: hapus server, hapus kebijakan, cabut kunci, regenerasi kunci.
- **Dampak (FAKTA, dengan batas):** server-side kedua aksi ini aman dan reversibel: toggle endpoint tercatat di log aktivitas; `set_member_status` transaksional dan tercatat, dan mengaktifkan kembali member mengembalikan kunci non-revoked ke aktif. Jadi risikonya salah klik + gangguan sesaat, bukan kehilangan data. **DUGAAN (bukan fakta):** mematikan satu-satunya server aktif suatu produk kemungkinan membuat validasi produk itu gagal sampai diaktifkan lagi — perilaku zero-active-endpoint belum diverifikasi dari kode provider selection dalam audit ini, jadi jangan jadikan itu dasar keputusan sebelum dicek.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** tambah konfirmasi untuk toggle provider (setidaknya bila itu satu-satunya server aktif produk tersebut) dan untuk penonaktifan member.

### K30 — [KECIL] Hapus paket tanpa proteksi referensi: `package_id` menggantung, kuota existing tidak hilang
- **Deskripsi:** tidak ada FK dari `admin_api_keys.package_id` ke `admin_packages` (kolom `CHAR(36) NULL` tanpa constraint), dan `delete_package` tidak memeriksa member/order yang merujuk paket itu.
- **Bukti:** `migrations/0006_admin_persistence.sql:6-42` (tanpa FK); `delete_package` tanpa pemeriksaan referensi.
- **Dampak (FAKTA, dibatasi):** ini TIDAK menghapus kuota member — kuota/masa aktif sudah termaterialisasi di baris kunci saat assign/grant. Yang rusak hanya provenance: kunci member menunjuk `package_id` yang tak ada (assign ulang paket itu akan 404 "Paket tidak ditemukan"), dan order lama hanya tersisa snapshot nama/harga. Tidak ada endpoint hapus member sama sekali (grep tidak menemukan rute DELETE member) — yang ada hanya penonaktifan — itu bersih.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** sebelum hapus paket, tolak bila masih ada kunci aktif dengan `package_id` itu, atau null-kan `package_id` kunci tersebut dalam transaksi yang sama dan catat di log. Lihat juga B13 (hapus paket yang gagal di DB disembunyikan).

### K31 — [KECIL] CSRF: origin check ada, tapi tanpa token dan membolehkan Origin kosong/tak-terurai; reveal kunci lewat GET
- **Deskripsi:** `csrf_origin_check` dipasang global untuk POST/PUT/PATCH/DELETE: bila Origin/Referer tidak ada atau gagal di-parse, permintaan diloloskan; hanya host yang jelas-jelas berbeda yang ditolak 403. Komentar kode sendiri mengakui non-browser diloloskan. Cookie admin `SameSite=Lax` adalah pertahanan utama; tidak ada token CSRF per-permintaan. Reveal kunci adalah GET, sehingga tidak tercakup origin check sama sekali.
- **Bukti:** `src/api.rs:623-656` (origin check); `:239` (pemasangan global); `src/auth.rs:618-621` (SameSite=Lax); `GET /v1/admin/members/:id/api-key/reveal` (`src/api.rs:175`) dan `GET /v1/member/api-key/reveal` (`src/member.rs:1005+`); `referrer-policy: no-referrer` (`src/api.rs:658+`); webhook QRIS sengaja lolos dari skema ini tetapi dilindungi HMAC (signature wajib, tanpa secret → 503) — itu bersih dan bukan bagian temuan.
- **Dampak (FAKTA, dibatasi):** untuk CSRF klasik dari situs jahat, browser selalu mengirim Origin pada POST sehingga akan ditolak bila host berbeda, dan Lax memblokir pengiriman cookie lintas situs pada POST — jadi celahnya sempit, bukan bypass terbuka. Kelemahannya adalah defense-in-depth: Origin kosong/tak-terurai yang diloloskan + tidak adanya token berarti perlindungan bertumpu pada perilaku browser, bukan pada bukti eksplisit per permintaan.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** pertimbangkan token CSRF (atau header kustom wajib) untuk aksi tulis admin; pindahkan reveal kunci ke POST, atau minimal catat bahwa GET-reveal diterima sebagai pengecualian sadar.

### K32 — [KECIL] View Kunci API tanpa kolom pemilik (kunci member bisa tercabut tanpa sadar)
- **Deskripsi:** `list_api_keys` mengembalikan SEMUA baris `admin_api_keys` termasuk kunci member, dan panel merendernya tanpa kolom pemilik (hanya nama, prefix, scope, RPM, terakhir dipakai, status, tombol Cabut). Kunci member memang bernama `Kunci member <email>`, jadi pemiliknya masih bisa ditebak dari nama — tetapi konfirmasi cabut hanya menampilkan nama tanpa peringatan "ini kunci member berbayar".
- **Bukti:** `src/store.rs:1166-1175` (list tanpa filter `member_id`); `web/app.js:800-815` (render tanpa pemilik); `src/store.rs:1512-1513` (penamaan kunci member); `web/app.js:1696` (konfirmasi hanya nama).
- **Dampak (FAKTA, dibatasi):** admin bisa mencabut kunci member dari view Kunci API; member itu lalu terkunci dari portal (sesi menolak kunci revoked) sampai admin meregenerasi — kuota/masa aktif dipertahankan saat regenerasi. Ini kemampuan admin yang sah, bukan IDOR; risikonya salah klik karena tidak ada penanda pemilik yang eksplisit. Sebaliknya, pemisahan kuncinya sendiri bersih: admin tidak pernah memakai kunci member untuk apa pun (tester memakai endpoint provider, bukan kunci member; `reveal_member_key` mengambil kunci lewat `member_key(member_id)` yang memfilter `member_id`, jadi tidak bisa dipakai mengambil prefix sembarang).
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** tambah kolom Pemilik (member/standalone) di view Kunci API dan peringatan di dialog cabut bila kunci milik member.

### K33 — [KECIL] Tanggal: jalur utama bersih; satu kerapuhan di `relativeTime`
- **Deskripsi:** semua jalur tanggal order yang diperiksa konsisten UTC: penulisan dari `Utc::now().naive_utc()` dan `UTC_TIMESTAMP(6)`; `paid_at` Cutiezy digeser −7 jam WIB→UTC; pembacaan admin (`NaiveDateTime` + `formatDate` menambahkan `Z` pada nilai tanpa zona) benar karena nilai itu UTC; pembacaan member (`DateTime<Utc>` + `fmtDate` dengan `timeZone: 'Asia/Jakarta'` eksplisit; tanggal harian riwayat memakai `+07:00` eksplisit sejalan dengan `wib_date` backend). Tanggal admin lain (`promo_ends_at`, `expires_at`, `last_used_at`, `created_at`, `updated_at`) bertipe `DateTime<Utc>` berzona, sehingga `formatDate` membiarkannya apa adanya dan countdown promo benar; round-trip input promo benar dalam satu browser.
- **Bukti:** `src/qris.rs:1067+` (penulisan order); `src/qris.rs:832-854` (AdminOrderView naive); `web/app.js:120-133` (formatDate + Z); `src/qris.rs:735-762` (MemberOrderView naive→UTC); `web/member.html:847-849` (fmtDate), `:1040,1059` (tanggal harian +07:00); `src/member.rs:454+` (wib_date).
- **Verifikasi:** kode + satu baris DB live (order `granted`: `created_at` 13:13 UTC dan `paid_at` 13:14 UTC — selaras dengan jam 20:13/20:14 WIB yang dikenal, jadi konversi WIB→UTC dan tampilan konsisten; tidak ada lagi selisih 7 jam pada baris ini). Backfill baris lama lain tidak bisa diverifikasi karena hanya ada satu baris order di DB saat ini.
- **Kerapuhan:** `relativeTime` (`web/app.js:138-150`) TIDAK menambahkan `Z`. Saat ini aman karena dua pemakainya menerima nilai berzona (`activity.occurred_at` dan `policy.updated_at`, keduanya `DateTime<Utc>`), tetapi bila suatu hari field naive `AdminOrderView` dilewatkan ke sana, tampilannya akan meleset −7 jam. Ini kerapuhan, bukan bug aktif.
- **Rekomendasi:** buat `relativeTime` memanggil normalisasi zona yang sama dengan `formatDate`, atau beri nama/parameter eksplisit "hanya terima nilai berzona".

### K34 — [KECIL] Quota writer mengabaikan `rows_affected = 0` (snapshot hilang diam-diam bila baris prefix tidak ada di DB)
- **Deskripsi:** writer dan jalur direct tidak memeriksa baris: `Ok` dengan 0 baris = snapshot hilang diam-diam; error hanya warn-only.
- **Bukti:** `src/store.rs:514` (writer) dan `:596` (direct).
- **Dampak:** baris yang terhapus manual dari DB tidak punya jalur dalam aplikasi (revoke hanya mengubah status, bukan DELETE — tidak ada `DELETE FROM admin_api_keys` di kode), sehingga ini hanya tercapai lewat intervensi DB manual. Bila terjadi, memori dan DB divergen sampai restart; dan `load_persisted` akan menulis ulang kunci in-memory yang tidak ada di DB sebagai seed, sehingga kunci yang "dihapus manual" bisa bangkit lagi saat restart — DUGAAN yang mengikuti langsung dari alur seed, belum diuji live dan tidak boleh diuji di produksi.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** log warn bila writer mendapat 0 baris, dan jangan pernah menghapus baris kunci langsung dari DB; revoke adalah jalur yang didukung.

### K35 — [KECIL] `set_member_status` dan update metadata mengembalikan sukses walau 0 baris berubah; `cancel_order` mengabaikan hasil CAS (jinak)
- **Deskripsi:** `set_member_status` (UPDATE members + UPDATE kunci) tanpa cek hasil, lalu `Ok(())`; admin yang menonaktifkan member-id yang tidak ada (atau yang sudah berstatus sama) mendapat respons sukses yang sama. Sama untuk `touch_member_login`, `update_member_profile`, `set_member_plan_kind` (warn-only). Terpisah: `cancel_order` mengabaikan hasil CAS (`UPDATE ... WHERE status='waiting_payment'`), tetapi re-read menyelamatkannya: bila sweep sudah meng-grant di antara panggilan cancel Cutiezy dan UPDATE ini, member melihat status benar (`granted`/`paid`), bukan `canceled` palsu.
- **Bukti:** `src/store.rs:1812,1822` (set_member_status); `:1422,1444,1459` (metadata); `src/member.rs:1452` (cancel + re-read).
- **Dampak:** rendah; status yang diinginkan memang sudah tercapai bila baris sudah berstatus itu (idempotent), dan metadata bukan uang. Cancel: BENAR secara hasil akhir berkat re-read, tapi rapuh — sebaiknya ditegaskan eksplisit.
- **Verifikasi:** HANYA DARI KODE.
- **Rekomendasi:** kembalikan 404 bila `set_member_status` mengubah 0 baris members; tegaskan eksplisit pola cancel (cek hasil CAS + re-read).

### K36 — [KECIL, DUGAAN — belum terbukti dapat dicapai] Cek "nominal tidak sama" di resolve berada di luar CAS
- **Deskripsi:** resolve membaca `order.last_error` lalu menolak bila mengandung "Nominal bayar tidak sama", baru kemudian CAS `needs_review → paid`. Pengecekan dan CAS tidak atomik.
- **Bukti:** `src/qris.rs` resolve (baca `last_error`, lalu `set_order_status` di `:1345`).
- **Kualifikasi:** di jalur kode yang ditemukan, tidak ada penulis ke `needs_review` selain cabang konflik grant (yang mensyaratkan status `paid`, bukan `needs_review`) dan `verify_and_grant` yang early-return untuk `needs_review` — jadi race yang mengubah alasan menjadi mismatch di jendela ini tidak terlihat dapat dicapai dari jalur aplikasi. Jangan diperlakukan sebagai bug terbukti.
- **Verifikasi:** HANYA DARI KODE (teoretis).
- **Rekomendasi (murah):** pindahkan guard mismatch ke dalam CAS (`WHERE status='needs_review' AND last_error NOT LIKE '%Nominal bayar tidak sama%'`) atau cek ulang setelah reset.

## Area yang diperiksa dan dinyatakan BERSIH (dengan bukti)

### Validasi
- Circuit breaker **per server** (bukan per produk) — status dari server yang sama tidak meluap ke produk lain; semaphore **per produk** (16, antre 2 detik); pacer **per host** kecuali Cutiezy (K6).
- Idempotensi jalur normal: kunci prefix-scoped, fingerprint mencakup `provider_hint`, `begin` sebelum rate limit, replay tidak memanggil provider dan tidak menyentuh kuota, TTL in-flight 300 detik, TTL replay 24 jam.
- Urutan rate-limit → reserve → provider dengan fail-closed saat Redis gagal; satu reserve di luar loop provider dengan refund tepat-satu-kali (capped di `quota_total`).
- Tidak ada kebocoran nama/URL/kode provider ke member (kecuali risiko pesan verbatim di K7); uppercase `account_name` lewat satu titik `validation_response()` untuk live, replay, dan sandbox; timeout/retry per attempt (retry hanya: transport/timeout/429/5xx/bodi tak terbaca).

### Member
- **K1 prefix (perbaikan lama, terverifikasi ulang):** `generate_key_prefix` memakai 8 byte CSPRNG (64-bit, bukan turunan timestamp); `persist_new_key` adalah INSERT polos (duplikat → error, bukan upsert timpa); `issue_api_key` memeriksa tabrakan di memori (32 percobaan) + retry DB 3×, dan menghapus rekaman memori pada gagal apa pun (fail-closed). Secret yang sama dipakai ulang antar retry prefix — tidak masalah karena plaintext percobaan gagal tidak pernah dikembalikan.
- OAuth state & sesi lama: state sekali pakai, TTL 10 menit, binding `purpose` (admin vs member), PKCE S256, `email_verified` wajib, profil via userinfo (bukan percaya `id_token`), lookup member via `google_sub`. Klaim ketat produksi: admin menolak `source != "google"`, member menolak selain `"google"/"api_key"` — sesi pra-audit tanpa source/jti ditolak di produksi; `APP_ENV=production` terverifikasi live; default `APP_ENV` kini `production`.
- Fallback dev tidak terjangkau di produksi: login lokal 404 di luar dev, token dev ditolak saat `production` (validasi bail bila `DEVELOPMENT_ADMIN_TOKEN` di-set), fallback secret sesi hanya untuk dev, cookie `Secure` di non-dev, `PROVIDER_MODE=demo` ditolak start di produksi.
- Status kunci di sesi: `resolve_session` memblokir revoked/disabled di jalur member-id maupun prefix; kunci expired tetap resolve (sengaja, agar bisa beli perpanjangan) tetapi sandbox dan API publik menolak expired — matriks ini konsisten di semua jalur yang diperiksa.
- Pembelian: `ensure_key_buyable` menolak revoked/disabled sebelum bayar di preview maupun create; kunci expired tetap boleh beli; endpoint admin resolve `needs_review` ada; grant menolak nominal mismatch.
- Login kunci revoked-only: login Google memberi kunci KOSONG (bukan trial kedua) bila satu-satunya kunci revoked; trial hanya sekali per `google_sub` (PK `trial_grants` + `is_new` + `needs_key`). Pengecualian: multi-akun Google berbeda = trial baru per akun — itu kebijakan per-akun, bukan bug kode.
- Kuota: assign DB-first dengan error dikembalikan (bukan warn-only); quota writer retry backoff tanpa drop; backpressure (bukan tulis langsung) saat channel penuh.
- Kuota + expiry + plan_kind: `compute_grant_effect` — beli lagi = tambah (saturating), expiry dari expiry lama bila future else now, rate = max; grant atomik CAS + `plan_kind='package'` dalam satu transaksi; assign `add`/`replace` sesuai spesifikasi; transisi `trial → package → manual` hanya lewat grant/assign; regenerasi mempertahankan kuota/expiry/rate/package tanpa mengubah `plan_kind`.
- Fingerprint B1 (perbaikan lama): `provider_hint` (bank_code/slug) masuk hash fingerprint — relevan untuk sandbox member yang memakai pipeline sama.
- CSRF: middleware global untuk POST/PUT/PATCH/DELETE membandingkan Origin/Referer vs Host; CORS tanpa `allow_credentials` (cookie tidak terkirim lintas origin); tidak ada mutasi GET (kecuali reveal — lihat K31).
- Kebingungan peran token: secret sesi dipakai bersama admin+member, tetapi `SessionClaims` mewajibkan `email/name/role` sehingga token member gagal decode sebagai admin; token admin sebagai cookie member gagal resolve (sub bukan UUID maupun prefix). Tidak ada jalur sesi tanpa source/jti yang lolos di produksi.
- Throttle login lokal: 10 percobaan/5 menit per email + per-IP untuk login member; login member kini menerima `x-api-key` maupun `Bearer`.
- **Sengaja tidak diubah (dari audit sebelumnya, tetap berlaku):** oracle 401 vs 403 (`authenticate_api_key`: prefix tak dikenal → 401, kunci non-aktif/kedaluwarsa → 403) — risiko rendah, prefix 64-bit acak bukan rahasia dan tidak dapat dienumerasi.

### QRIS
- Satu sumber harga bayar: `effective_price` dipakai daftar paket member, preview, create, landing + JSON-LD price range; kalkulasi ulang JS di panel admin dan portal hanya untuk tampilan badge, bukan penagihan; promo 100% → 0 → ditolak di preview dan create, disembunyikan dari daftar beli; promo kedaluwarsa/tanpa tanggal → `promo_active` false; persen > 0 tanpa tanggal ditolak `validate_promo` di create dan update.
- Preview vs create TOCTOU: preview murni komputasi (non-binding), create menghitung ulang dari paket + settings saat itu lalu mengunci snapshot (harga/kuota/rate/`valid_days`) ke order; risiko TOCTOU dimitigasi UI (portal menampilkan hasil create sebelum member memindai QR, jadi perubahan harga antara preview dan create masih terlihat sebelum bayar); risiko sisanya adalah B9 (order waiting lama dikembalikan), bukan preview itu sendiri.
- Webhook tidak pernah langsung grant: HMAC wajib — tanpa secret → 503, tanpa header → 401, signature salah → 401; HMAC manual lolos uji RFC 4231 dan menerima hex dan base64; event `qris.payment` dan `qris.payment.success` keduanya diterima; payload tidak membawa token order sehingga webhook hanya men-spawn sweep; grant tetap diputuskan `verify_and_grant` lewat check-status + kecocokan nominal.
- Tombol "saya sudah bayar": check-status gratis → nominal harus cocok persis (`amount != order.amount_idr` → `needs_review`, tanpa grant); `Paid.amount` yang hilang dipetakan ke 0 sehingga pasti mismatch (fail-closed); order `paid` yang tertinggal langsung di-grant (pemulihan crash); cancel yang dijawab "sudah lunas" beralih ke `verify_and_grant`; kegagalan cancel lain tidak mengubah status lokal (fail-closed).
- Kill switch: create, preview, daftar paket memeriksa `settings.enabled`; webhook, sweep, check, cancel, resolve SENGAJA tidak memeriksanya — order yang sudah lunas tetap bisa ter-grant saat pembelian baru dimatikan. Benar.
- Token tidak bocor ke member: `MemberOrderView` tidak membawa token Cutiezy/QRIS string/URL; gambar QR hanya lewat proxy order (hanya order sendiri + status waiting + `Cache-Control: private, no-store`); `AdminOrderView` membawa token, tapi hanya untuk admin.
- Sweep: rutin tiap 60 detik (waiting lewat expiry: cek Cutiezy dulu — lunas→grant, sisanya→expired) + order `paid` tertinggal, LIMIT 20 tertua dulu, error per-order di-log dan dilewati (tanpa head-of-line blocking).
- Cancel/expired: gagal insert setelah 3× retry → QR dibatalkan best-effort dan error dikembalikan keras ke member; cancel sukses → status lokal diubah dengan CAS `waiting_payment`; order `Pending` lewat expiry lokal ditutup menjadi `expired` oleh verify/sweep, tidak menggantung di balik aturan satu-waiting.
- Bayar setelah expiry lokal tapi sebelum sweep: cabang `Paid` tidak memeriksa expiry lokal, jadi tetap di-grant — benar (uang sudah diterima).
- Refund: tidak ada endpoint refund uang QRIS. `refund_quota` adalah refund hit validasi untuk hasil non-billable, capped di `min(quota_total)` sehingga tidak bisa melebihi total dan tidak mencetak hit gratis; tidak tersentuh alur cancel order (cancel sebelum bayar tidak mengubah kuota, karena kuota hanya bertambah saat grant).

### Admin
- Otorisasi semua rute `/v1/admin/*`: setiap handler memanggil `require_admin` terlebih dahulu (diperiksa handler per handler).
- Kualitas `require_admin`: cookie terpisah `rv_admin_session`, `role == "admin"` + allowlist `ADMIN_GOOGLE_EMAILS`, produksi menolak `source != "google"`, token yang sudah logout ditolak lewat cek revocasi, token dev hanya non-produksi, login lokal 404 di luar development.
- Gerbang login admin: shell disembunyikan sampai sesi admin terverifikasi, `role !== "admin"` ditolak, 401/403 → `showLoginOnly()`, modal tidak bisa ditutup selama gerbang aktif. Gerbang ini CSS-only, tetapi shell tidak memuat data sensitif sebelum auth — catat sebagai keterbatasan yang diterima, bukan kebocoran.
- Member IDOR: order selalu difilter `id` + `member_id`; list/history/QR/check/cancel lewat `resolve_order_member` + `resolve_session`; prefix riwayat dari sesi; token reveal sekali pakai terikat member+prefix; reveal sendiri memblokir kunci revoked/disabled/expired.
- Pemisahan kunci admin/member: struktur klaim berbeda (JWT member tidak punya email/role sehingga gagal decode sebagai `SessionClaims`; JWT admin yang disalin ke cookie member gagal `resolve_session` — analisis kode, DUGAAN KUAT, bukan uji live karena pengujian butuh kredensial).
- Aksi panel yang jujur (selain K2/K28): konfirmasi pada hapus/regenerasi, `handleApiError` + toast, field QRIS kosong berarti "pertahankan nilai lama", tombol "Test" per-endpoint hanya memverifikasi DNS/host.
- Aksi destruktif yang dilindungi server-side: soft revoke, `set_member_status` transaksional, resolve menolak mismatch/member non-aktif, tidak ada endpoint hapus member.
- Kesehatan live: `GET /health/live` → 200, `provider_mode: http`; `GET /v1/admin/orders` dan `/v1/admin/members` tanpa sesi → 401 (TERVERIFIKASI LIVE); SELECT read-only: 1 order paket `granted`, 3 baris `admin_packages`.

### Lintas
- **Migrasi:** migrasi 0001–0016 semuanya ter-apply di `_sqlx_migrations` (bukan `schema_migrations`), semua `success=1`, terbaru 0016 terpasang 2026-10-25 13:41:24; tidak ada migrasi tertunda/duplikat yang terdeteksi. Hanya worker yang menjalankan migrasi (`AUTO_MIGRATE=1` di env worker; API tidak pernah migrasi). **Tidak terverifikasi:** checksum migrasi lokal-vs-DB tidak dibandingkan (butuh build/check, dihindari dalam audit ini); perilaku sqlx bila dua worker bermigrasi bersamaan tidak diverifikasi.
- **Restart/recovery:** paket, kunci, kuota, member — BERTAHAN (DB) lewat `load_persisted`. Kuota di antrean writer (channel 8192) — graceful: drain maks 30 detik; SIGKILL: hilang → DB melebihkan sisa kuota (hit gratis) — window yang sudah diakui audit sebelumnya, tidak bisa ditutup dari dalam proses. Sesi JWT — BERTAHAN (stateless) kecuali revocasi di Redis. Blocklist revocasi — bertahan selama Redis hidup; HILANG bila Redis restart/flush (persistensi Redis tidak terverifikasi). State OAuth (login dalam proses) — HILANG (in-memory, TTL 10 menit, cap 1000) — login dalam proses gagal, pengguna retry (jinak). Bucket rate-limit, idempotensi — BERTAHAN (Redis). Guard provider (breaker, pacing 334 ms, semaphore) — HILANG (in-memory) — breaker menutup lagi, pacing mulai dari nol → burst sesaat ke provider yang sedang gagal setelah restart. Statistik/aktivitas in-memory — sebagian hilang; overview dashboard sudah DB-first. Throttle login lokal — HILANG (dev-only, tidak relevan di produksi). Sweep QRIS (tiap 60 detik, LIMIT 20; webhook sweep LIMIT 50) — aman restart; backlog >20 terkuras bertahap. PEL worker di Redis — BERTAHAN; reclaim setelah idle 5 menit; live `XPENDING = 0`.
- **Asumsi single-process yang pecah bila direplikasi** (FAKTA dari kode; dampak lintas-replika adalah DUGAAN mengikuti desain): `OAuthStateStore`, `CREATE_ORDER_LOCK`, `ProviderGuard` (pacing/breaker per proses — agregat melebihi 3 hit/detik/host, breaker tidak tersinkronisasi), writer kuota FIFO per proses (snapshot basi lintas proses bisa menimpa yang lebih baru — persis bug yang diperbaiki di dalam satu proses), lock store `data`, throttle login lokal. Yang sudah benar lintas-replika: rate limit Redis, idempotensi Redis, CAS grant DB, PK trial.
- **Fail-open vs fail-closed:** revocasi sesi — FAIL-OPEN by design + terdokumentasi (lihat B5). Rate limiter / idempotensi / event sink (error Redis saat operasi) — FAIL-CLOSED: 503, validasi dibatalkan + refund — aman. Fallback lokal (tanpa `redis_url`) — hanya tercapai bila `redis_url` kosong; validasi produksi menolak konfigurasi tanpa Redis — bukan fail-open produksi, tapi footgun bila `APP_ENV` diubah. Fallback kredensial dev — FAIL-CLOSED di produksi (APP_ENV default production, `PROVIDER_MODE=demo` ditolak, `DEVELOPMENT_ADMIN_TOKEN` ditolak, secret sesi dev hanya non-produksi, login lokal hanya `is_development`); live `APP_ENV=production`, `PROVIDER_MODE=http`. Guard provider saat DB/Redis mati — guard in-memory, tidak bergantung pada keduanya untuk acquire/pace/breaker; `ProviderConfigStore::build` gagal total bila DB tidak terjangkau saat boot (fail-closed saat boot), tetapi saat runtime DB mati validasi tetap jalan dari memori + antrean kuota — akuntansi menumpuk di antrean, tidak berhenti — observasi, bukan bug: pantau antrean writer saat DB mati. Writer kuota saat DB mati — retry selamanya + backoff maks 30 detik; antrean penuh → `persist_key_quota` beralih ke send blokir **sambil memegang lock `data`** → semua operasi kuota stall (fail-closed tapi stall berantai, bukan korupsi) — KECIL–SEDANG: outage DB panjang = stall API, bukan korupsi; per pilihan desain lama (stall lebih baik daripada korupsi). `load_persisted` gagal baca DB saat boot — warn + lanjut dengan seed memori (fail-open ringan saat boot) — KECIL: seed bisa menimpa state DB bila DB pulih — sudah didokumentasikan sebagai pengecualian seed.
- **Log error (journalctl, 25 Okt, terfilter):** noise provider (bukan sinyal bug): banjir WARN 422 dari provider (puluhan, sepanjang hari), timeout koneksi Cutiezy dengan retry attempt 1/2, warn varian nama bank ganda (mis. kode 013 PERMATA/PERMATA SYARIAH, 542 JAGO/BANK JAGO SYARIAH). Dikenal, bukan baru: create QRIS gagal 409 `QRIS_SOURCE_REQUIRED` (19:07 waktu VPS) dan satu `Unexpected("expected value at line 1 column 1")` → 500 (19:10 waktu VPS), selaras dengan diagnosa QRIS malam sebelumnya. **Tidak ada** error grant/konflik, writer kuota, persist worker, atau migrasi sejak restart grantfix (~20:51 WIB).

## Tabel pengecekan `rows_affected` (seluruh codebase, satu per satu)

| Lokasi | Perilaku | Penilaian |
|---|---|---|
| `src/store.rs:1729` (grant) | UPDATE multi-tabel, `WHERE o.status='paid' AND k.status!= 'revoked'`; sukses normal = 2 (1 kunci + 1 order); 1 bila nilai kunci tak berubah; cek `== 0` → rollback + re-read (`granted` → AlreadyGranted) | **BENAR** (perbaikan grantfix; robust untuk kasus 1 baris) |
| `src/store.rs:1956` (trial) | INSERT `trial_grants` (PK `google_sub` = klaim atomik); sukses 1; duplikat → Err, bukan 0; cek `> 0` | **BENAR** (redundan tapi benar; pecundang race → false) |
| `src/qris.rs:954` (`set_order_status`) | UPDATE satu tabel, `WHERE id=? AND status=?`; sukses 1 (dari ≠ ke di semua call site); cek `== 1` | **BENAR sebagai primitif**; masalahnya pemanggil membuang bool (K3) |
| `src/qris.rs:1233` (mark paid) | UPDATE satu tabel, `WHERE status='waiting_payment'`; sukses 1; cek `!= 1` → re-read; `granted` → AlreadyGranted, `paid` → jalankan grant (anti-ganda lewat CAS grant) | **BENAR** |
| `src/store.rs:1746` (grant: `plan_kind`) | `UPDATE members SET plan_kind='package'` di dalam transaksi grant | **BENAR secara hasil** (tidak ada keputusan yang bergantung padanya; 0 baris bila sudah `package` tetap benar) |
| `src/store.rs:514,596` (writer kuota / direct) | Tanpa cek baris | **KECIL** (K34) |
| `src/store.rs:1812,1822` (`set_member_status`) | Tanpa cek hasil | **KECIL** (K35) |
| `src/store.rs:1422,1444,1459` (login/profile/plan_kind metadata) | Warn-only | Diterima, bukan uang |
| `src/store.rs:347,385,424,459` (persist paket/kebijakan/kunci, INSERT … ON DUPLICATE KEY UPDATE) | Error dipropagasi/dilog; 0 baris = nilai sudah sama = state yang diinginkan | **BENAR** |
| `src/store.rs:373,406` (hapus baris paket/kebijakan, DELETE) | Diterima (state akhir yang diinginkan adalah "hilang") | Diterima — tapi lihat B13 untuk memori vs DB |
| `src/provider_config.rs:273,787,879` (persist endpoint/runtime setting) | Error dipropagasi atau bool dikembalikan | **BENAR** |
| `src/provider_config.rs:492` (hapus endpoint, setelah hapus dari map memori, 404 bila hilang) | 0 baris = sudah hilang | **BENAR** |
| `src/qris.rs:201,223,234` (upsert qris_settings) | Error dipropagasi; `record_*` telemetri best-effort | **BENAR** |
| `src/qris.rs:1074` (INSERT order, id `Uuid::now_v7`) | Retry 3×, gagal → batalkan QR agar tidak yatim | **BENAR** |
| `src/member.rs:1452` (cancel) | 0 baris diabaikan, tapi re-read menyelamatkan | Jinak (K35) |
| `src/database.rs:74,107` (ledger worker, INSERT IGNORE) | 0 baris = duplikat redelivery, bukan error | **BENAR** by design |
| `src/store.rs:1400` (INSERT member) | Error dipropagasi | **BENAR** |

Semantik MySQL yang terverifikasi: UPDATE satu tabel yang nilainya tidak berubah melaporkan 0 (tanpa `CLIENT_FOUND_ROWS`) — tidak memengaruhi keempat pengecekan di atas karena suatu kolom selalu berubah (status) di tiap kasus. `ROW_COUNT` multi-tabel menjumlahkan semua tabel — persis sumber bug grant lama, dan tidak ada UPDATE multi-tabel lain (hanya `store.rs:1700`).

Ringkasan CAS lain: grant multi-tabel (`store.rs:1700`) — `paid` + `!= revoked`, dalam transaksi, 0 baris → rollback + re-read → AlreadyGranted — serial di dalam proses lewat lock `data`; lintas proses tidak ada (single-process) — **BENAR kecuali celah `disabled` (K1)**. Mark paid (`qris.rs:1223`) — `waiting_payment` — re-read + cabang `paid` → re-grant (aman ganda) — **BENAR**. `set_order_status` generik — parameter `from_status` — atomik per statement; kelemahan di pemanggil (K3) — primitif **BENAR**. Reset resolve (`qris.rs:1345`) — `needs_review` → `paid`, bool dicek — konflik → pesan "reload" — **BENAR (minus K36 teoretis)**. Fallback grant (`qris.rs:1392`) — `paid` → `needs_review` — bool dibuang; re-read dipakai untuk verdict — **KECIL (K3)**. Cancel (`member.rs:1452`) — `waiting_payment` — re-read menyelamatkan — jinak (K35). Trial grant — PK `google_sub` — pecundang dapat false — **BENAR**. Idempotensi/rate-limit — Lua atomik / SET NX — **BENAR**. Create order satu-waiting — cek DB `waiting_order_for_member` + `CREATE_ORDER_LOCK` lokal-proses — TOCTOU lintas replika: dua replika bisa sama-sama lolos cek dan membuat 2 QR (biaya Cutiezy ganda) — **KECIL saat ini (satu replika)**, pecah bila direplikasi. Reserve/refund kuota — lock memori `data` (bukan CAS DB) — writer FIFO + snapshot absolut; refund capped di total — **BENAR dalam satu proses**.

## Yang TIDAK diverifikasi dalam audit ini (jujur)

- Tidak ada pengujian live atas grant, cancel, resolve, atau pesan beracun worker (dilarang).
- Checksum migrasi lokal-vs-DB tidak dibandingkan (butuh build/check, dihindari).
- Perilaku sqlx bila dua worker bermigrasi bersamaan tidak diverifikasi.
- Premis e-wallet Cutiezy "nomor tak dikenal → `success:true`" tidak diverifikasi ulang secara live (berdasar probe lama yang didokumentasikan).
- Kosakata status Cutiezy yang sesungguhnya tidak diverifikasi dari dokumen provider (risiko K21 bersifat dugaan).
- Apakah URI redirect member turunan sudah didaftarkan di Google Console tidak dapat diverifikasi tanpa mencoba login (dilarang) — tetap sebagai follow-up operasional, bukan temuan kode.
- Apakah `GOOGLE_MEMBER_REDIRECT_URI` sudah diisi eksplisit: live tidak di-set eksplisit, sehingga URI member diturunkan dari URI admin (`src/config.rs:member_redirect_uri()`).
- Tidak ada kredensial/token/key yang disalin atau ditampilkan dalam laporan ini; nilai-nilai di log server tidak direproduksi.

## Urutan perbaikan yang disarankan (ringkas)

1. **B7 + B10** — bukti lunas pada resolve + jalur pemulihan expired/canceled terbukti lunas (satu pola verifikasi yang sama).
2. **B11** — isi `source_id` + retest satu create nyata (aksi admin, bukan auditor).
3. **B14** — trim stream Redis + alarm `XLEN`/`used_memory`.
4. **B1** (setelah keputusan user) + **B2** (strip kredensial dari log + sapu/rotasi log lama).
5. **B3 + B4 + K15** — ikat sesi ke kunci; serialisasi regenerasi dan provisioning kunci pertama.
6. **B5, B6, B8, B9, B12, B13, B15**, lalu KECIL bertahap (K1–K3 bergabung dengan butir BESAR di atas; K31/K33/K34/K35 sebagai hardening audit dan konsistensi data).

*Laporan ini bersifat read-only dan tidak mengubah apa pun di produksi. Perbaikan diputuskan user setelah membaca.*

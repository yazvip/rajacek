# Peta runtime VPS: Go APIValidasi + Rust Rajacek

Status diverifikasi 31 Oktober 2026. Dokumen ini sengaja tidak memuat credential, token, PIN, DSN, maupun private key. Live server adalah sumber kebenaran; file konfigurasi di repository adalah template.

## Identitas source dan GitHub

| Bagian | Go — APIValidasi | Rust — Rajacek |
|---|---|---|
| Repository | [yazvip/apivalidasi-v4](https://github.com/yazvip/apivalidasi-v4), `main` | [yazvip/rajacek](https://github.com/yazvip/rajacek), `main` |
| Checkout lokal | `E:\PROJEK\golangapi` | `E:\PROJEK\rajacek-deploy-audit` |
| Source aplikasi | Backend `.go` di root; `admin-frontend/src/`, `member-frontend/src/` | `source/src/`, `source/web/`, `source/migrations/` |
| Snapshot commit remote sebelum pembaruan map ini | `2fb0929` | `f4eb97b` (perbaikan source pada `8beb9b3`) |
| Panduan source | `SOURCE_GUIDE.md`, `PROJECT_MAP.md`, `PROJECT_HANDOFF_VPS.md` | `source/README.md`, map ini, template `ops/vps/` |

Commit di atas adalah snapshot, bukan versi yang akan berlaku selamanya. Verifikasi `git rev-parse HEAD` dan `git ls-remote origin refs/heads/main` setiap rilis. **Push GitHub tidak otomatis deploy VPS.** Binary Go live belum dibuktikan identik dengan commit `2fb0929` melalui build provenance; jangan menyimpulkan demikian hanya karena health sehat.

Folder `/opt/rajacek/repo/` di VPS berasal dari arsip source, bukan Git checkout; jangan menjalankan `git pull` di sana. Sebagian web Rust ditanam ke binary, tetapi admin/static juga memakai `web/`, sehingga binary dan aset harus satu versi.

Go saat ini masih memiliki hasil build `deploy/` yang tracked secara historis. Commit `2fb0929` membawa perubahan source/tests/dokumentasi/aset pendukung, bukan perubahan hasil build yang tertinggal di worktree. Jangan `git add .` atau menghapus perubahan pengguna untuk membersihkannya.

## Jalur trafik

```text
app.apivalidasi.my.id
  → Cloudflare → aaPanel Nginx go_ewalletproxy.conf → 127.0.0.1:8090
  → Go binary /www/wwwroot/ewallet-proxy/ewallet-proxy
  → aaPanel MySQL 5.7 :3306 + provider bank/e-wallet/GTC/PLN/game/QRIS/Telegram

rajacek.com / www.rajacek.com
  → Cloudflare → aaPanel Nginx rajacek.conf → 127.0.0.1:8091
  → Rust rajacek-api.service → MySQL 8 Docker :3307 + Redis logical DB 1
  → rajacek-worker.service consumes validation-events from Redis
```

Kedua API publik bind loopback dan menerima trafik melalui Nginx/TLS. MySQL 8 Rust terpisah dari aaPanel MySQL 5.7 Go. Redis tersedia sebagai daemon VPS dan dipakai Rajacek pada DB index 1 dengan autentikasi; source Go yang diperiksa tidak memiliki dependensi Redis. Container MySQL 8 bernama `rajacek-mysql8`, volume persisten `rajacek-mysql8-data`, restart policy `unless-stopped`. Jangan hapus volume atau memakai migrasi/config satu proyek untuk proyek lain.

## Server locations and service ownership

| Project | Source/runtime | Process owner | Public hostname and port | Data |
|---|---|---|---|---|
| Go production | `/www/wwwroot/ewallet-proxy/` (binary, `.env.runtime`, `admin-dist/`, `member-dist/`) | Proses 8090; kini cgroup cron; periksa sebelum restart | `app.apivalidasi.my.id` → 8090 | MySQL 5.7 :3306 |
| Go legacy/other instance | `/www/wwwroot/go/ewallet-proxy` | `ewallet-proxy.service` | Separate Nginx mapping, process listens :8080 | Do not assume same DB/config |
| Rust API + worker | `/opt/rajacek/repo/source/` (release binaries under `target/release/`) | `rajacek-api`, `rajacek-worker` systemd units; user `rajacek` | `rajacek.com`, `www.rajacek.com` → 8091 | MySQL 8 :3307, Redis DB 1 |
| Rust secrets/backups | `/opt/rajacek/.env`, `/opt/rajacek/mysql8-root-password`, `/opt/rajacek/backups/` | root-only secrets/backup | Never public | daily systemd timer, 30-day local retention |

**Peringatan Go:** pemeriksaan terbaru menunjukkan proses publik 8090 berada di `/system.slice/cron.service`, **bukan** `ewallet-proxy.service`. Pada audit sebelumnya proses berada di login-session cgroup; proses telah berubah, tetapi supervisor/autostart yang sebenarnya belum dipastikan. Unit `ewallet-proxy.service` tetap menunjuk `/www/wwwroot/go/ewallet-proxy` pada 8080. Jangan memakai restart unit itu untuk memperbarui 8090. Identifikasi PID, executable, cwd, cgroup, dan pengelola proses terbaru; buat unit khusus hanya dalam perubahan terpisah yang diotorisasi. Jangan hardcode PID atau reset/push worktree Go sebagai bagian rilis Rajacek.

Nginx Go: `/www/server/panel/vhost/nginx/go_ewalletproxy.conf` → 8090. Nginx Rust: `/www/server/panel/vhost/nginx/rajacek.conf` → 8091. TLS Rust: `/etc/letsencrypt/live/rajacek.com/`; TLS Go: `/www/server/panel/vhost/cert/ewalletproxy/`. Jangan menimpa vhost/certificate proyek lain.

## Rust deploy/update flow

1. Use a clean Rajacek checkout/branch; inspect `git status` and protect `.env`, SQL dumps, backups, and credentials. Do not copy Go’s files or config.
2. Run Rust tests and `cargo build --locked --release --bins`. On this 1.8 GiB VPS, build with bounded Docker memory/CPU or build elsewhere and upload tested Linux binaries; avoid unbounded parallel compilation.
3. Back up `/opt/rajacek/backups/` and record current binary hashes. Stage source/assets and both binaries before replacing live files.
4. Database migration: `AUTO_MIGRATE=false` is intentional. The imported DB records migration 38, but historical migration 5 checksum differs from the checked-out source. Never edit `_sqlx_migrations` checksums or turn auto-migrate on blindly. Compare schema and migration history, then apply a reviewed forward-only migration with an explicit DB backup/restore plan.
5. Install staged source/binaries atomically, verify ownership/modes, run `nginx -t`, and restart only `rajacek-api` / `rajacek-worker` when their artifacts or config changed. Upload binary/config wajib diikuti restart proses yang benar; push Git saja tidak cukup. Nginx reload only if its config changed.
6. Verify both units active, logs clean, `https://www.rajacek.com/health/live`, `/health/ready`, `/v1/status`, one public page, MySQL/Redis connectivity, then verify Go health at `https://app.apivalidasi.my.id/`.
7. Bila health regress, hentikan worker/API yang gagal, pulihkan source dan binary yang hash-nya dicatat, restart unit Rust, lalu cek Go lagi. Jangan restore dump DB lama di atas database live tanpa keputusan pemulihan eksplisit.
8. Setelah deploy VPS berhasil dan smoke test lulus, commit lalu push perubahan source dan template operasional yang memang perlu dipelihara ke `yazvip/rajacek`. Untuk perubahan Go gunakan `yazvip/apivalidasi-v4`, bukan repo Rajacek. Verifikasi SHA commit remote sama dengan commit lokal. Jangan push secret, `.env`, database dump, backup, build artifacts, atau helper yang berisi kredensial. Jika deploy gagal, rollback dahulu; jangan menandai perubahan sebagai rilis berhasil. Perubahan dokumentasi saja tidak memerlukan deploy/restart.


Rust unit controls:

```sh
systemctl status rajacek-api rajacek-worker
journalctl -u rajacek-api -u rajacek-worker -n 100 --no-pager
systemctl restart rajacek-api rajacek-worker   # only after Rust release/config deployment
systemctl status rajacek-backup.timer certbot.timer
```

Daily database backup runs via `rajacek-backup.timer`; current backups are local to the same VPS, so configure and periodically test an encrypted offsite copy before treating disaster recovery as complete. TLS uses Certbot; its deploy hook tests and reloads Nginx after renewal.

Backup tanggal 30 dan 31 Oktober teramati tersedia. Timer VPS memakai zona waktu server CST (UTC+8), bukan WIB; lihat `systemctl list-timers` untuk waktu eksekusi aktual. Keberhasilan backup/gzip bukan bukti restore berhasil.

## Go deploy/restart guardrail

Go production code is separate from Rajacek. Before any Go restart, check `systemctl show ewallet-proxy -p ExecStart`, `ss -ltnp`, process cwd, and the Nginx upstream. The known unit targets legacy 8080, while public Nginx targets 8090. Never replace `/www/wwwroot/ewallet-proxy/.env.runtime`; deploy only explicitly built Go artifacts and preserve current UI/runtime files. A dedicated supervisor for 8090 is a follow-up reliability task, not silently changed by the Rajacek release.

## Current limitations to clear before calling DR/production fully proven

- Google OAuth, paid-provider transactions, and recovery from an offsite backup have not been exercised end-to-end.
- Historical SQLx migration checksum drift requires an approved reconciliation before future migrations.
- The 8090 Go process supervisor/autostart path must be made deterministic in a separate change.
- Local backup is not offsite disaster recovery.
- Health HTTP 200 tidak membuktikan OAuth, provider, debit/kuota, dan callback QRIS end-to-end. Pemeriksaan terbaru: Go `/healthz` dan Rust `/health/ready` sama-sama 200, Rust API/worker, MySQL 8, backup timer dan certbot timer aktif.
- Catat commit/base source, perubahan lokal, hash binary, dan aset setiap deploy agar hubungan GitHub dengan runtime dapat ditelusuri. Jangan deploy ulang otomatis hanya untuk menyamakan snapshot Git tanpa otorisasi rilis.

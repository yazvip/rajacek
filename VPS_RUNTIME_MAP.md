# Peta runtime VPS: Go APIValidasi + Rust Rajacek

Status diverifikasi 31 Oktober 2026. Dokumen ini sengaja tidak memuat credential, token, PIN, DSN, maupun private key. Live server adalah sumber kebenaran; file konfigurasi di repository adalah template.

## Jalur trafik

```text
app.apivalidasi.my.id
  → Cloudflare → aaPanel Nginx go_ewalletproxy.conf → 127.0.0.1:8090
  → Go binary /www/wwwroot/ewallet-proxy/ewallet-proxy
  → aaPanel MySQL 5.7 :3306 + Redis :6379

rajacek.com / www.rajacek.com
  → Cloudflare → aaPanel Nginx rajacek.conf → 127.0.0.1:8091
  → Rust rajacek-api.service → MySQL 8 Docker :3307 + Redis logical DB 1
  → rajacek-worker.service consumes validation-events from Redis
```

Both APIs bind to loopback. Public traffic goes through Nginx/TLS. Rust’s MySQL 8 is isolated from Go’s aaPanel MySQL 5.7. Redis daemon is shared, but Rajacek uses DB index 1. MySQL 8 container is `rajacek-mysql8`, persistent Docker volume `rajacek-mysql8-data`, restart policy `unless-stopped`.

## Server locations and service ownership

| Project | Source/runtime | Process owner | Public hostname and port | Data |
|---|---|---|---|---|
| Go production | `/www/wwwroot/ewallet-proxy/` (binary, `.env.runtime`, `admin-dist/`, `member-dist/`) | Current 8090 process; inspect before restart | `app.apivalidasi.my.id` → 8090 | MySQL 5.7 :3306, Redis :6379 |
| Go legacy/other instance | `/www/wwwroot/go/ewallet-proxy` | `ewallet-proxy.service` | Separate Nginx mapping, process listens :8080 | Do not assume same DB/config |
| Rust API + worker | `/opt/rajacek/repo/source/` (release binaries under `target/release/`) | `rajacek-api`, `rajacek-worker` systemd units; user `rajacek` | `rajacek.com`, `www.rajacek.com` → 8091 | MySQL 8 :3307, Redis DB 1 |
| Rust secrets/backups | `/opt/rajacek/.env`, `/opt/rajacek/mysql8-root-password`, `/opt/rajacek/backups/` | root-only secrets/backup | Never public | daily systemd timer, 30-day local retention |

Important Go caveat: during this audit, public 8090 was an orphan process in a login-session cgroup, **not** `ewallet-proxy.service`. That service points to `/www/wwwroot/go/ewallet-proxy` and port 8080. Do not restart `ewallet-proxy.service` as a way to restart public 8090. First identify its current supervisor and establish a dedicated, tested systemd unit in a separately approved change. The Go worktree may contain user edits; never reset or push it as part of a Rajacek deployment.

## Rust deploy/update flow

1. Use a clean Rajacek checkout/branch; inspect `git status` and protect `.env`, SQL dumps, backups, and credentials. Do not copy Go’s files or config.
2. Run Rust tests and `cargo build --locked --release --bins`. On this 1.8 GiB VPS, build with bounded Docker memory/CPU or build elsewhere and upload tested Linux binaries; avoid unbounded parallel compilation.
3. Back up `/opt/rajacek/backups/` and record current binary hashes. Stage source/assets and both binaries before replacing live files.
4. Database migration: `AUTO_MIGRATE=false` is intentional. The imported DB records migration 38, but historical migration 5 checksum differs from the checked-out source. Never edit `_sqlx_migrations` checksums or turn auto-migrate on blindly. Compare schema and migration history, then apply a reviewed forward-only migration with an explicit DB backup/restore plan.
5. Install staged source/binaries atomically, verify ownership/modes, run `nginx -t`, and restart only `rajacek-api` / `rajacek-worker` when their artifacts or config changed. Nginx reload only if its config changed.
6. Verify both units active, logs clean, `https://www.rajacek.com/health/live`, `/health/ready`, `/v1/status`, one public page, MySQL/Redis connectivity, then verify Go health at `https://app.apivalidasi.my.id/`.
7. If health regresses, stop the failed worker/API, restore the recorded binaries/source and `.env` backup, restart the Rust units, and verify Go again. Do not restore an old DB backup over live data without an explicit recovery decision.

Rust unit controls:

```sh
systemctl status rajacek-api rajacek-worker
journalctl -u rajacek-api -u rajacek-worker -n 100 --no-pager
systemctl restart rajacek-api rajacek-worker   # only after Rust release/config deployment
systemctl status rajacek-backup.timer certbot.timer
```

Daily database backup runs via `rajacek-backup.timer`; current backups are local to the same VPS, so configure and periodically test an encrypted offsite copy before treating disaster recovery as complete. TLS uses Certbot; its deploy hook tests and reloads Nginx after renewal.

## Go deploy/restart guardrail

Go production code is separate from Rajacek. Before any Go restart, check `systemctl show ewallet-proxy -p ExecStart`, `ss -ltnp`, process cwd, and the Nginx upstream. The known unit targets legacy 8080, while public Nginx targets 8090. Never replace `/www/wwwroot/ewallet-proxy/.env.runtime`; deploy only explicitly built Go artifacts and preserve current UI/runtime files. A dedicated supervisor for 8090 is a follow-up reliability task, not silently changed by the Rajacek release.

## Current limitations to clear before calling DR/production fully proven

- Google OAuth, paid-provider transactions, and recovery from an offsite backup have not been exercised end-to-end.
- Historical SQLx migration checksum drift requires an approved reconciliation before future migrations.
- The 8090 Go process supervisor/autostart path must be made deterministic in a separate change.
- Local backup is not offsite disaster recovery.

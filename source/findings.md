## Phase 19 — aaPanel deployment documentation — 2026-10-21
- `.gitignore` previously ignored `Cargo.lock`, which conflicts with shipping binaries and with `COPY Cargo.toml Cargo.lock* ./` in the Dockerfile. The ignore rule was removed so the locked dependency graph can be committed for reproducible server builds.
- `EnvironmentFile=` is processed after `Environment=` in systemd units, so a value in `.env` overrides `Environment=`. The guide therefore keeps `AUTO_MIGRATE` out of `.env` and sets it in the unit file / Compose `environment:` block instead.
- `dotenvy` does not override variables already present in the process environment, so the systemd/Compose-provided values win over `.env` for the same key; the guide still avoids duplicate definitions to prevent confusion.
- `readiness_health` only asserts that `DATABASE_URL` and `REDIS_URL` are configured in production; it does not ping MySQL or Redis. Real dependency health must be observed via worker logs, process status, and direct database queries.
- Both `RedisRateLimiter` and `RedisStreamEventSink` fail closed with `503` when Redis is unreachable, so Redis is a hard runtime dependency for validation traffic rather than a cache that can silently degrade.
- `OAuthStateStore` keeps PKCE `code_verifier` state in process memory with a 10-minute TTL, so the API must run as a single replica and an API restart invalidates in-flight Google logins.
- Three directories are embedded at compile time with `include_str!`: `web/landing.html` (`src/api.rs`), `openapi/openapi.yaml` (`src/api.rs`), and `data/bank_codes.json` (`src/bank_codes.rs`). The original Dockerfile builder stage copied only `Cargo.toml`, `src`, and `migrations`; `COPY web ./web`, `COPY openapi ./openapi`, and `COPY data ./data` were added before `cargo build --release --bins`.
- Production startup is gated by `AppConfig::validate()`: `DATABASE_URL`, `REDIS_URL`, three >=32-character secrets (`DASHBOARD_SESSION_SECRET`, `DATA_FINGERPRINT_SECRET`, `PROVIDER_CREDENTIAL_KEY`), `PROVIDER_MODE` other than `demo`, absent `DEVELOPMENT_ADMIN_TOKEN`, and a non-empty `PROVIDER_ALLOWED_HOSTS`. `PROVIDER_MODE=http` additionally requires `PROVIDER_BASE_URL` and `PROVIDER_API_KEY`.
- Dashboard session cookies are `Secure` whenever the environment is not development, so HTTPS through the aaPanel Nginx proxy is mandatory for admin login.
- Static dashboard assets are served from the relative `web/` directory at runtime, so any systemd or container working directory must contain `web/`.
- Migrations are executed only by the worker path (`AUTO_MIGRATE=true`), not by the API executable; the Compose production profile therefore enables it on the worker and disables it on the API.
- `AdminStore` keeps products, packages, rate-limit policies, and API keys in process memory, so API keys created from the dashboard do not survive a restart. This remains the main blocker for declaring the deployment production-ready and is documented as such.
- aaPanel-specific guidance recorded: panel hardening, MySQL 8.0 requirement for `utf8mb4_0900_ai_ci` and CHECK constraints, Redis `requirepass`, loopback-only API binding (`127.0.0.1:8080`), reverse proxy with SSL and Force HTTPS, and Google redirect URI alignment.

## Phase 18 recovery — 2026-10-21
- The nine public e-wallet slugs are translated into Tukangcek IDs in `src/ewallet_codes.rs`; Tukangcek request builder and two focused provider tests are already present.
- HTTP validation uses a Tukangcek-specific built-in response mapping regardless of the editable persisted mapping; `found` drives e-wallet status/registered while result fields intentionally omit name, target, channel, balance, and account metadata.
- Bootstrap config includes a `found`/registered mapping; existing persisted mappings may still be displayed as configured even though Tukangcek overrides them at runtime.
- README still documents an outdated e-wallet request ID (`dana`); docs and broader tests need finishing. Git diff unavailable because this workspace is not a Git repository.
- Attempt to insert into empty findings using apply_diff failed (empty search is forbidden); created the file content with write_to_file instead.
## Admin dashboard UX redesign — 2026-10-26
- Admin pages are the views inside `source/web/index.html`; `source/web/app.js` owns the existing rendering and event wiring; `source/web/styles.css` is the shared visual layer.
- Keep IDs/data attributes and route behavior stable because the UI is a large static SPA whose renderers target these selectors directly.
- The public docs stylesheet is separate; this task targets admin views only.
- Existing project files include duplicate legacy root-level Rust files; the admin UI source of truth is `source/web/`.
- Admin UX refresh applies a shared CSS system in `source/web/styles.css`, concise operational copy in each of the 13 admin view headings, and a stylesheet cache-version bump in `source/web/index.html`. The notification icon and placeholder help affordance had no meaningful action; they were removed, and the hard-coded all-systems-normal message was replaced by a neutral “Panel administrasi” context label.

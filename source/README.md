# Rajacek

Rajacek is a Rust service for validating Indonesian bank accounts, e-wallet accounts, and WhatsApp numbers through approved providers. The root route is a public Indonesian landing page; the administrative dashboard is available separately at `/admin`.

The MVP includes:

- An Axum/Tokio REST API with a stable JSON error envelope.
- A responsive public landing page with SEO metadata and a separate Indonesian admin dashboard served by the API.
- Demo-provider support for safe local development.
- API-key authentication, scope checks, rate-limit foundations, and idempotent paid validation requests.
- MySQL migrations and a Redis Streams worker for durable, asynchronous usage/audit persistence.
- An OpenAPI 3.1 contract at [`openapi/openapi.yaml`](openapi/openapi.yaml).

> **Compliance notice:** Account numbers, phone numbers, and e-wallet identifiers are sensitive personal data. Use only approved provider APIs and process data only when an appropriate lawful basis and user consent apply. The demo provider is for local integration work only.

All local accounts, passwords, API keys, sample requests, provider placeholders, products, packages, and rate-limit seed values are centralized in [`DUMMY_DATA.md`](DUMMY_DATA.md).

## Project layout

```text
rajacek/
|-- migrations/             # MySQL schema migrations
|-- openapi/
|   `-- openapi.yaml        # OpenAPI 3.1 source contract
|-- src/
|   |-- bin/worker.rs       # Redis Streams usage/audit worker
|   `-- main.rs             # API executable entry point
|-- web/                    # Static Indonesian admin dashboard
|-- .env.example            # Environment variable template
|-- compose.yaml            # Full local MySQL + Redis + API + worker stack
|-- Dockerfile              # Production-style multi-stage image
|-- DEPLOY_AAPANEL.md       # Indonesian aaPanel installation and deployment guide
`-- Cargo.toml              # Rust package and executable definitions
```

For server deployment on aaPanel (panel installation, MySQL/Redis preparation, production `.env` rules, Docker Compose or systemd, Nginx reverse proxy with SSL, Google OAuth, verification, updates, and troubleshooting), see [`DEPLOY_AAPANEL.md`](DEPLOY_AAPANEL.md).

## Prerequisites

### Verified Windows development path

The dependency-free demo path has been verified on Windows 11 with:

- Rust/Cargo 1.99.1 installed through Rustup.
- Microsoft Visual Studio 2022 Build Tools with the C++ build-tools workload, which provides the MSVC linker required by the default Rust target.
- Node.js, used only for the static JavaScript syntax check.
- `curl.exe`, included with current Windows installations.

Open a **x64 Native Tools Command Prompt for Visual Studio**, or load the Visual Studio developer environment before invoking Cargo:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64
```

The standard Rust commands below were verified from that environment:

```bat
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
node --check web\app.js
```

### Full-stack Docker path

The full-stack path additionally needs Docker Desktop (or compatible Docker Engine with Compose). Docker was **not installed in the verification environment**, so the Compose instructions below are configuration-checked but not executed there.

## Fast local demo (verified)

This route starts the API with the in-memory/demo fallbacks. It does **not** start MySQL, Redis, the worker, migrations, Redis Lua rate limiting, or Redis Streams persistence.

From a Windows `cmd.exe` terminal in the project root, load the Visual Studio environment and start the API:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 && ^
set "APP_ENV=development" && ^
set "PROVIDER_MODE=demo" && ^
set "BIND_ADDRESS=127.0.0.1:18080" && ^
set "DATABASE_URL=" && ^
set "REDIS_URL=" && ^
set "DEVELOPMENT_ADMIN_TOKEN=replace-with-a-local-only-token" && ^
set "DEMO_API_KEY=rv_live_local_0123456789abcdef0123456789abcdef0123456789abcdef" && ^
set "RUST_LOG=rajacek_api=info,tower_http=info" && ^
cargo run --bin rajacek-api
```

Open the dashboard at <http://127.0.0.1:18080/>.

The default API bind address is `0.0.0.0:8080`; the command above intentionally uses loopback-only port `18080` so a local demo does not expose an administrator development token to the network.

### Health and contract checks

In a second terminal, run:

```bat
curl.exe --fail --silent http://127.0.0.1:18080/health/live
curl.exe --fail --silent http://127.0.0.1:18080/health/ready
curl.exe --fail --silent http://127.0.0.1:18080/openapi/openapi.yaml
```

A healthy demo returns JSON with `status: "ok"` from `/health/live` and `status: "ready"` from `/health/ready`, each reporting `provider_mode: "demo"`.

### Bank-account validation smoke test

Set the same local demo key in the terminal that runs the request, then submit a request with a stable idempotency key:

```bat
set "RAJACEK_API_KEY=rv_live_local_0123456789abcdef0123456789abcdef0123456789abcdef"
curl.exe --fail --silent --show-error ^
  -X POST http://127.0.0.1:18080/v1/validate/bank-account ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %RAJACEK_API_KEY%" ^
  -H "Idempotency-Key: local-bank-validation-001" ^
  --data "{\"bank_code\":\"BCA\",\"account_number\":\"1234567890\",\"account_holder_hint\":\"BUDI SANTOSO\"}"
```

Run the same command again without changing `Idempotency-Key`. The second response should replay the cached result rather than invoking the provider or reserving quota again. Use a new idempotency key for a genuinely new validation request.

### Development-only admin access

[`src/auth.rs`](src/auth.rs) supports `x-admin-token` only when the application is **not** in production and `DEVELOPMENT_ADMIN_TOKEN` is configured. It is useful for API/dashboard integration testing, for example:

```bat
curl.exe --fail --silent --show-error ^
  -H "x-admin-token: replace-with-a-local-only-token" ^
  http://127.0.0.1:18080/v1/admin/overview
```

Do not send that header to a deployed environment and never set `DEVELOPMENT_ADMIN_TOKEN` in production. Production dashboard authentication uses the Google OpenID Connect flow and session cookies once its required configuration is supplied.

## Full local stack with Docker Compose (not verified in this environment)

1. Copy the template and set development values:

   ```bat
   copy .env.example .env
   ```

2. Keep `APP_ENV=development` and configure a local-only `DEVELOPMENT_ADMIN_TOKEN` and `DEMO_API_KEY` in [`.env`](.env). For real upstream calls, set `PROVIDER_MODE=http`, `PROVIDER_BASE_URL`, and `PROVIDER_API_KEY` only after an approved provider contract is available.

3. Start the complete stack:

   ```bat
   docker compose up --build
   ```

[`compose.yaml`](compose.yaml) starts:

| Service | Image/role | Host port | Notes |
|---|---|---:|---|
| `mysql` | MySQL 8.4 system of record | `3306` | Persists data in the `mysql-data` volume. |
| `redis` | Redis 7.4 append-only cache/stream store | `6379` | Persists data in the `redis-data` volume. |
| `api` | `rajacek-api` HTTP service | `8080` | Waits for healthy MySQL and Redis. |
| `worker` | `rajacek-worker` background consumer | — | Uses `AUTO_MIGRATE=true` in this local Compose profile. |

Then check the stack:

```bat
curl.exe --fail --silent http://127.0.0.1:8080/health/live
docker compose ps
docker compose logs --follow api worker
```

Stop the services while retaining local data:

```bat
docker compose down
```

To remove the local MySQL and Redis volumes as well:

```bat
docker compose down --volumes
```

> The credentials in [`compose.yaml`](compose.yaml) are development-only values. Replace them with managed credentials and secret injection before any shared or production deployment.

## Configuration

Start with [`.env.example`](.env.example). Do not commit `.env`, production credentials, provider secrets, Google client secrets, or real API keys.

### Core variables

| Variable | Default / local use | Notes |
|---|---|---|
| `APP_ENV` | `development` | Accepted values: `development`, `production`, `test`. |
| `BIND_ADDRESS` | `0.0.0.0:8080` | Use `127.0.0.1:18080` for an isolated local demo. |
| `DATABASE_URL` | Optional only for development/demo fallback | Required in production and by the worker. |
| `REDIS_URL` | Optional only for development/demo fallback | Required in production and by the worker. |
| `PROVIDER_MODE` | `demo` | Use `http` to route requests through dashboard-managed third-party endpoints. |
| `PROVIDER_BASE_URL` | — | Bootstrap URL used to seed products before the first dashboard update in HTTP mode. |
| `PROVIDER_API_KEY` | — | Bootstrap bearer credential; it is never returned by admin reads. |
| `PROVIDER_CREDENTIAL_KEY` | Development fallback | Required at 32+ characters in production; encrypts provider credentials stored in MySQL. Keep stable and manage through KMS/Vault. |
| `PROVIDER_ALLOWED_HOSTS` | — | Required in production; comma-separated exact/suffix host allowlist for SSRF protection. |
| `DEMO_API_KEY` | — | Local/demo API-key override; do not reuse outside local development. |
| `DEVELOPMENT_ADMIN_TOKEN` | — | Development-only override; production startup rejects it. |
| `DASHBOARD_SESSION_SECRET` | — | Must contain at least 32 characters in production. |
| `DATA_FINGERPRINT_SECRET` | — | Must contain at least 32 characters in production. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` | — | Required with MySQL, Redis, and the dashboard session secret to enable Google OIDC. |
| `ADMIN_GOOGLE_EMAILS` | — | Comma-separated Google-account allowlist for administrators. |
| `REQUEST_TIMEOUT_SECONDS` | `8` | Must be greater than zero. |
| `DEFAULT_RATE_LIMIT_PER_MINUTE` | `60` | Must be greater than zero. |
| `IDEMPOTENCY_TTL_SECONDS` | `86400` | Retention period for replayable validation results. |
| `EVENT_STREAM_NAME` | `validation-events` | Redis stream used for durable usage/audit handoff. |

### Provider guard (semaphore + circuit breaker)

In HTTP mode every outbound provider call passes `src/provider_guard.rs`, keyed per product:

- **Semaphore:** at most `PROVIDER_MAX_CONCURRENCY_PER_PRODUCT` (default 16) calls per product are in flight at once. Extra callers wait up to `PROVIDER_QUEUE_WAIT_MS` (default 2000 ms) for a slot and are then rejected with Rajacek's own 429 — bursts are absorbed here instead of being rejected by the provider.
- **Circuit breaker:** `PROVIDER_BREAKER_FAILURE_THRESHOLD` (default 5) consecutive provider failures (transport errors, HTTP 429, HTTP 5xx, unparseable responses) open the product's circuit for `PROVIDER_BREAKER_COOLDOWN_SECONDS` (default 30). While open, calls fail fast with 503 and never reach the provider. After the cooldown a single probe call is admitted; success closes the circuit, failure re-opens it. Client/config errors (unknown bank code, HTTP 400/401, unconfigured endpoint) are neutral and never trip the breaker. Breaker state is per product and per process.

### MySQL ringan (low-memory profile)

`deploy/mysql-low-memory.cnf` tunes MySQL 8 for this workload (small dataset, append-only worker writes, indexed history lookups): Performance Schema and the X Plugin off, binary log disabled, a 128 MB InnoDB buffer pool that still holds the entire hot dataset + indexes, per-connection buffers trimmed, and `max_connections` sized for the app pools (20 per pool). Ledger durability is not traded away — `innodb_flush_log_at_trx_commit` stays 1. Expected mysqld RSS is roughly 180–250 MB instead of the 400–600 MB default footprint; verify after restart with `SELECT @@performance_schema, @@innodb_buffer_pool_size` and the process RSS. If `validation_requests` grows past a few million rows, archive old months — history reads are newest-first and stay index-served.

### Production safeguards

[`AppConfig::validate()`](src/config.rs:134) rejects production startup unless all of the following are true:

- `DATABASE_URL` and `REDIS_URL` are configured.
- `DASHBOARD_SESSION_SECRET`, `DATA_FINGERPRINT_SECRET`, and `PROVIDER_CREDENTIAL_KEY` are each at least 32 characters.
- `PROVIDER_MODE` is not `demo`.
- `DEVELOPMENT_ADMIN_TOKEN` is absent.
- `PROVIDER_ALLOWED_HOSTS` contains only approved third-party API hosts.
- When `PROVIDER_MODE=http`, `PROVIDER_BASE_URL` and `PROVIDER_API_KEY` bootstrap the first configuration; administrators can then manage a distinct endpoint per product from `/admin` without restarting the API.

Production requires more than valid environment variables: use TLS, an approved provider, managed secret storage, a configured Google consent screen and redirect URI, restricted CORS/dashboard origins, monitoring, backups, security review, retention controls, and load/failure testing before accepting live traffic.

### Akun dummy lokal

Daftar terpusat untuk seluruh kredensial, payload, endpoint provider, produk, paket, dan rate-limit dummy tersedia di [`DUMMY_DATA.md`](DUMMY_DATA.md). Ringkasan akun berikut dipertahankan untuk referensi cepat.

Saat `APP_ENV=development`, dashboard menawarkan login lokal yang menerbitkan cookie sesi HttpOnly. Akun ini hanya untuk pengujian lokal dan endpoint-nya tidak tersedia pada mode production.

| Peran | Email | Password | Hasil |
|---|---|---|---|
| Administrator | `bunny.admin@local.test` | `BunnyAdmin!2026` | Dapat mengakses dashboard dan endpoint `/v1/admin/*`. |
| Member | `dummy.member@local.test` | `DummyMember!2026` | Sesi valid, namun seluruh endpoint administrator ditolak oleh pemeriksaan peran server. |

Endpoint login: `POST /v1/auth/local/login` dengan JSON `{"email":"…","password":"…"}`. Kredensial dummy dan fallback secret sesi hanya berlaku ketika aplikasi berjalan dalam mode development; jangan gunakan, ubah, atau salin mekanisme ini ke produksi.

## Dokumentasi member & publik

- **Halaman dokumentasi:** `/docs` (`web/docs.html`) — panduan member berbahasa Indonesia: mulai cepat, autentikasi, idempotensi, rate limit & kuota, referensi ketiga endpoint validasi, status hasil, kode error, dan FAQ.
- **OpenAPI khusus member:** `openapi/openapi.json` disajikan di `/openapi.json` dan `/openapi/openapi.json` — hanya berisi endpoint member/publik (`/health/live`, `/v1/banks`, tiga endpoint validasi); **tidak ada endpoint admin** di dalamnya. Siap impor ke Postman/Insomnia/generator klien.
- `openapi/openapi.yaml` tetap menjadi spesifikasi internal lengkap (termasuk permukaan admin) untuk tim internal.

## API contract

The canonical OpenAPI 3.1 definition is [`openapi/openapi.yaml`](openapi/openapi.yaml), and a running API serves the same document at `/openapi/openapi.yaml`.

Key endpoints:

| Method | Endpoint | Authentication | Purpose |
|---|---|---|---|
| `GET` | `/health/live` | None | Process liveness. |
| `GET` | `/health/ready` | None | Service readiness. |
| `POST` | `/v1/validate/bank-account` | API key + idempotency key | Bank-account validation. |
| `POST` | `/v1/validate/ewallet` | API key + idempotency key | E-wallet validation. |
| `POST` | `/v1/validate/whatsapp` | API key + idempotency key | WhatsApp validation, pending confirmed provider semantics. |
| `GET` | `/v1/auth/session` | None | Dashboard session state. |
| `GET` | `/v1/auth/google/start` | None | Begins Google OIDC dashboard login. |
| `GET` | `/v1/admin/overview` | Admin session or development token | Dashboard overview data. |

| `GET` | `/v1/admin/provider-endpoints` | Admin session | Lists endpoint metadata; never returns credentials. |
| `PUT` | `/v1/admin/provider-endpoints/{product}` | Admin session | Creates/updates URL, timeout, active status, and optional credential rotation. |
| `POST` | `/v1/admin/provider-endpoints/{product}/test` | Admin session | Validates URL, allowlist, DNS, and network destination without sending customer data. |

Validation requests require a unique `Idempotency-Key` header and an API key with the matching scope, such as `validate:bank_account` or `validate:*`. Treat all submitted identifiers and provider responses as sensitive.

### Managing third-party endpoints

1. Run the API with `PROVIDER_MODE=http`, MySQL, and the provider security variables above.
2. Sign in to `/admin` as an administrator and open **Endpoint Provider**.
3. Configure one endpoint for each product (`bank_account`, `ewallet`, and `whatsapp`). Select **Tukangcek** to use its product-specific request body and set the credential header to `X-API-Key`. Leaving the credential field empty preserves the current secret; entering a value rotates it.
4. Use **Tes** to verify syntax, allowlist membership, DNS, and that resolved addresses are public. This safe check does not submit an account number or phone number.
5. Configure **Mapping respons JSON** using dot paths such as `data.status`, `data.account.name`, or array paths such as `data.items[0].registered`.
6. New validation requests immediately resolve the latest active configuration and mapping; no process restart is required.

Status values can be mapped into `valid`, `invalid`, `not_found`, and `pending`. Bank endpoints may expose the mapped account-holder name. WhatsApp endpoints may expose registration status plus safe provider/reference metadata. E-wallet output is intentionally restricted to registered/not-registered status: upstream account names, provider-result labels, and references are discarded even if present in the provider payload.

Production HTTP calls disable redirects, enforce a per-endpoint timeout, repeat destination verification to reduce DNS-rebinding/SSRF exposure, and decrypt credentials only inside the server process. Dashboard responses expose only `api_key_configured`; plaintext provider credentials are never returned.

### Tukangcek contract

- Bank and e-wallet use `https://tukangcek.id/api/check`; WhatsApp uses `https://tukangcek.id/api/check-wa`.
- Authentication uses the configurable `X-API-Key` header. The real key must be entered through the encrypted dashboard credential field or environment secret and must not be committed.
- Public bank requests accept a three-digit `code_bank` from `GET /v1/banks`. Provider-specific IDs remain internal.
- All 111 public three-digit bank codes in the catalog are mapped to a Tukangcek `instId` (for example BRI `002` → `BRIC1ID`, BCA `014` → `BCAC1ID`). The mapping was cross-verified on 2026-10-21 against the live `GET https://tukangcek.id/api/banks` list and the production ApiValidasi mappings; codes shared by conventional/Syariah variants resolve to the single primary instId assigned to that code. Unknown codes are rejected; Rajacek does not invent mappings. See `FIX_2026-10-21.md`.
- Bank requests send `{ "type": "bank", "target": "...", "id": "BRIC1ID" }`.
- E-wallet requests translate the public provider slug to a Tukangcek ID; for example `gopay_driver` sends `{ "type": "ewallet", "target": "...", "id": "GOPAY002" }`. Supported translations: `dana` → `DANA001`, `astrapay` → `ASTRAPAY001`, `gopay` → `GOPAY001`, `gopay_driver` → `GOPAY002`, `isaku` → `ISAKU001`, `kaspro` → `KASPRO001`, `linkaja` → `LINKAJA001`, `ovo` → `OVO001`, `shopeepay` → `SHOPEEPAY001`. Unknown slugs are rejected for Tukangcek mode.
- WhatsApp requests send `{ "target": "628..." }`.
- For Tukangcek, bank and e-wallet use the `found` boolean; WhatsApp uses `registered`. E-wallet responses expose only the normalized `registered` result, never the upstream `name`, `target`, `channel`, `balance`, or `checkedAt` fields. Tukangcek-mode normalization uses this fixed contract even if an older custom response mapping is stored; generic-mode endpoints continue to use their configured mapping.
- HTTP 400/401/429/500/503 are converted into safe Rajacek errors without returning provider response bodies or credentials.

### Admin provider tester

The `/admin` sidebar includes **Tester Layanan**. The form changes according to the selected product:

- **Bank:** select an enabled three-digit bank code and enter an account number.
- **E-wallet:** select the wallet provider (`dana`, `astrapay`, `gopay`, `gopay_driver`, `isaku`, `kaspro`, `linkaja`, `ovo`, or `shopeepay`) and enter the account number.
- **WhatsApp:** enter an Indonesian phone number.

The tester calls `POST /v1/admin/provider-tester`, requires an administrator session, and uses the currently active endpoint/mapping. It deliberately bypasses member API-key quota, billing ledger, and idempotency because it is an operational integration check—not a member transaction. Use only authorized test identifiers. Raw upstream capture is limited to this route, not member validation requests. It includes only the HTTP status and up to 64 KiB of the response body, without upstream headers; the capture is not logged or stored by Rajacek. HTTP upstream failures can return the raw response under `details.upstream_response` in the admin tester error body. Connection failures and requests rejected before an upstream response do not have a raw body.

Only fields relevant to the selected service are displayed: bank code is hidden for e-wallet/WhatsApp, and the e-wallet-provider selector is hidden for bank/WhatsApp. Tester results have keyboard-accessible **HTML**, **JSON**, and **Respons Asli** tabs. HTML presents normalized fields and provider/Rajacek/total latency. JSON shows the complete Rajacek tester response (including raw capture where available), while Respons Asli shows the captured third-party body as plain text plus HTTP status, encoding, and truncation flag. Non-UTF-8 bodies are Base64 encoded. A new test replaces all prior tab content, including on errors. Treat both JSON and raw views as sensitive: upstream responses can echo credentials or contain personal data even when Rajacek's normalized output omits them. Do not copy, log, or retain them without authorization. Do not expose this admin route to members.

Normal member validation responses expose the same timing split in `meta.provider_latency_ms`, `meta.rajacek_processing_ms`, and `meta.total_latency_ms`. Cached idempotent replays report no new provider call; their elapsed time is represented as Rajacek processing/total latency.

## Architecture and delivery status

- **Request path:** API key authorization, rate/quota reservation, provider call, normalized response, then durable event handoff.
- **System of record:** MySQL stores keys, pricing, usage ledger, audit data, and durable business state.
- **Low-latency state:** Redis provides key metadata cache, idempotency state, distributed limits/quota reservations, and Redis Streams.
- **Background processing:** [`src/bin/worker.rs`](src/bin/worker.rs) consumes usage events idempotently and writes MySQL records after the API responds.
- **Provider integration:** [`src/provider.rs`](src/provider.rs) keeps demo and dynamic approved HTTP providers behind one normalized interface; [`src/provider_config.rs`](src/provider_config.rs) performs encrypted runtime configuration and SSRF controls.
- **Admin dashboard:** [`web/index.html`](web/index.html) and [`web/app.js`](web/app.js) are a dependency-light Indonesian SPA served by the API.

The current MVP is a foundation, not a production authorization to process live personal data. Real provider contracts, payment semantics, Google OIDC registration, production observability, abuse testing, retention controls, and operational approval remain necessary before launch. The detailed architecture, constraints, and implementation plan are retained in [`task_plan.md`](task_plan.md).

## Verification status

The following checks have passed in the current Windows environment:

```bat
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
node --check web\app.js
```

A live API process was also checked in `APP_ENV=development` / `PROVIDER_MODE=demo` mode at `127.0.0.1:18080`:

- `/health/live` returned HTTP 200 with `status: "ok"`.
- `/health/ready` returned HTTP 200 with `status: "ready"`.
- Static dashboard and OpenAPI routes were previously smoke-tested successfully.
- Repeating a bank-account request with the same idempotency key returned the cached result without double-charging the demo quota.
- The development admin token successfully authorized `/v1/admin/overview`.

Not verified in the current environment:

- Docker Compose build/start behavior.
- MySQL migrations and persistence against a running MySQL instance.
- Redis Lua limiting, Redis Streams durability, worker consumer-group processing, and cross-process idempotency/cache behavior.
- Google OIDC callback flow.
- Production configuration, deployment, performance, fault tolerance, security, and provider integrations.

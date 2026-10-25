# Progress Log — High-Performance Validation API

## 2026-10-26 — Admin dashboard UX redesign started
- Began a full admin dashboard audit before editing, covering the shared navigation shell, all view sections, cards, forms, tables, dialogs, feedback states, and responsive rules.
- Design direction: restrained premium operations console; clear page titles and task-oriented descriptions; consistent spacing and surface hierarchy; accessible focus and readable contrast; concise Indonesian operational copy.
- Preserve all existing IDs, `data-*` hooks, routes, permissions, and event behavior while changing presentation.
- Current phase: source audit, followed by shared UI system implementation and copy/layout refinement.

## 2026-10-26 — Admin dashboard UX redesign completed
- Standardized headings, card surfaces, navigation, buttons, forms, tables, status chips, dynamic product/package cards, spacing, and responsive sizing across 13 admin views.
- Clarified analytics, admin access, order, and other page descriptions. Replaced the static system-health claim and inert notification/help controls with a neutral workspace label.
- Preserved all 327 HTML IDs and all 17 `data-view-target` hooks. `git diff --check` is clean; no tests were run.
- Deployed the admin UI to VPS `43.157.205.163` as a web-only update. Backed up the previous HTML/CSS at `/opt/rajacek/backups/admin-ui-20261026-005359`, verified local/staged and public CSS SHA-256 hashes, checked the new HTML at localhost and `www.rajacek.com`, and confirmed API health plus both active services with unchanged restart counts.

## 2026-10-20 — Planning Session Started

### Completed
- Loaded the persistent planning workflow for this multi-step architecture task.
- Inspected the empty project workspace.
- Attempted repository diff inspection; confirmed the workspace is not a Git repository.
- Created `task_plan.md` with a seven-phase architecture and delivery plan.
- Created `findings.md` containing requirements, technical conclusions, risks, and unresolved inputs.

### Current Phase
- Phase 1 — Requirements, Compliance, and Provider Discovery: **in progress**.

### Current Design Direction
- Rust + Tokio + Axum on stateless API nodes.
- MySQL 8 as system of record.
- Redis for cached key authorization profiles, distributed token-bucket rate limiting, idempotency state, quota reservations, and a durable stream handoff.
- A separate Rust worker consumes stream events and persists audit/usage/ledger data asynchronously to MySQL.
- Google OpenID Connect authorization-code flow with PKCE for dashboard authentication.
- Per-member API keys stored only as hashed secrets; configurable packages and versioned price-per-hit records.
- Append-only, idempotent billing ledger and reconciliation between fast Redis reservations and MySQL records.

### Blockers / Inputs Needed
- Exact third-party providers and their API documentation/terms.
- Definition of each validation product, particularly WhatsApp validation semantics.
- Traffic, latency, billing, retention, payment, and infrastructure requirements.

### Errors
- `git diff --stat` cannot run because the workspace is not a Git repository. No correction required at this planning stage.
- Rust toolchain verification failed: `cargo` and `rustc` are not available on this Windows environment. Source code can be scaffolded, but build/test verification requires installing the Rust toolchain first.

### Implementation Update — 2026-10-20
- Bootstrapped the Rust/Axum source modules for configuration, secure errors, dashboard sessions, provider adapters, API-key administration, request idempotency, rate limiting, and asynchronous usage-event handoff.
- Created an Indonesian premium responsive admin SPA in `web/`, including overview analytics, product configuration, package/pricing management, rate-limit policies, API-key issuance/revocation, activity feed, responsive navigation, and modal workflows.
- Syntax-checked `web/app.js` with the installed Node runtime after fixing one malformed HTML-escaping expression; the syntax check passed.
- Discovered that application startup (`src/main.rs`), worker entry point, migrations, deployment files, OpenAPI contract, and production documentation remain to be created.

### Infrastructure Update — 2026-10-20
- Added the Rust API and worker entry points, MySQL system-of-record repository, idempotent Redis Stream consumption, initial MySQL schema migration, Dockerfile, Compose environment, and environment template.
- The worker uses a Redis consumer group, persists each event within a MySQL transaction, relies on unique event IDs for safe redelivery, and acknowledges the stream message only after persistence succeeds.
- Confirmed Docker Desktop/CLI is not installed in the current environment, so Compose build and service smoke tests cannot be run locally yet.
- Corrected API routing syntax for Axum 0.7-style path parameters and made public validation activity logging non-blocking after the durable usage event is accepted.

### Verification Update — 2026-10-20
- Added the OpenAPI 3.1 contract at `openapi/openapi.yaml` and exposed it from the API at `GET /openapi/openapi.yaml`.
- Installed the Windows Rust toolchain through Rustup. Verified `cargo 1.99.1` and `rustc 1.99.1` are available at `C:\\Users\\ASUS\\.cargo\\bin`.
- Ran `cargo fmt -- --check`; it reported only Rust formatting differences. Ran `cargo fmt` successfully to normalize the source tree.
- Ran `cargo check`; Cargo resolved and downloaded the dependency graph and generated `Cargo.lock`, but compilation stopped before application diagnostics because the MSVC Rust target cannot find `link.exe`.
- Root cause: Visual C++ Build Tools (or an alternate configured GNU Rust target) are not installed. This is an environment prerequisite, not an application compile failure yet.
- Started the Microsoft Visual Studio 2022 Build Tools installation with the C++ build-tools workload through `winget`; the installer remains active as of the latest process check.
- A first wait attempt using `timeout /t` failed because this non-interactive terminal host does not support its console-input redirection. Replaced it with a loopback-only `ping` delay; no project files or services were affected.
- The Visual C++ Build Tools installation subsequently completed enough to provide `link.exe`.
- Re-ran `cargo check` from the Visual Studio Developer Command Prompt. It reached application compilation and found 29 source-level errors rather than a toolchain blocker.
- The diagnostics cluster around Redis 0.27 async command generic parameters/connection access, incompatible Axum response-layer defaults, and missing `Deserialize` on the cached validation response model. The next step is targeted source inspection and compatibility repairs.

### Compatibility Repair Update — 2026-10-20
- Restored the persistent plan, progress, and findings context before resuming the compiler-repair work.
- Confirmed again that the workspace is intentionally not a Git repository; `git diff --stat` exits with code 129 and is not a source-code failure.
- Updated all remaining Redis 0.27 `query_async` call sites to use the current single result-type generic form.
- Added `Deserialize` to the cached validation response and metadata models so idempotency response replay can be decoded safely.
- Reordered the Axum/Tower middleware stack so the timeout layer sees Axum's defaultable response body before tracing and compression wrap it.
- Ran `cargo fmt --all` and `cargo check --all-targets` through the installed Visual Studio developer environment. Compilation now succeeds for every target; the only remaining diagnostic is a deprecated `TimeoutLayer::new` constructor.
- Replaced the deprecated timeout constructor with `TimeoutLayer::with_status_code`, then verified `cargo fmt --all -- --check`, `cargo check --all-targets`, and `cargo test --all-targets` successfully through the Visual Studio developer environment.
- Reconfirmed that `git diff --stat` cannot provide a change summary because this workspace intentionally has no Git repository; this does not affect source compilation or test execution.

### Local Demo Smoke-Test Update — 2026-10-20
- Kept the local API process running on `127.0.0.1:18080` in development mode with the demo provider, in-memory fallbacks, the development-only administrator token, and a demo API key.
- Verified `GET /health/live`, `GET /health/ready`, `GET /openapi/openapi.yaml`, and the dashboard fallback return successful responses during the local demo run.
- Exercised `POST /v1/validate/bank-account` with a stable `Idempotency-Key`: the initial response was billable/demo-valid, while the retry returned the cached result with unchanged remaining quota, proving the demo idempotency path does not double-charge.
- Verified the development-only `x-admin-token` is accepted in development and that `GET /v1/admin/overview` returns `200 OK` with the dashboard’s real schema: metrics, traffic points, service state, masked activity, and alerts.
- The earlier overview assertion’s `findstr` filter did not match the actual field names and exited with code 1; the endpoint was healthy. The unfiltered response confirmed the expected `metrics.total_requests_today` and related data.
- Ran `node --check web\\app.js` successfully.
- Confirmed the live server serves `GET /` as `text/html` (30,361 bytes) and `GET /app.js` as `text/javascript` (33,882 bytes).

### Current Limits of Verification
- Docker Desktop/CLI is still absent, so the Compose deployment cannot be built or started locally.
- The current smoke test deliberately omits `DATABASE_URL` and `REDIS_URL`; it verifies documented in-memory/demo fallbacks, not MySQL migrations, Redis Lua limiter behavior, Redis Streams durability, worker consumer-group processing, or cross-process cache/idempotency.
- Production mode remains intentionally untested because it must use real secrets, approved provider configuration, MySQL, Redis, and a deployed Google OIDC configuration.

### Resumption Update — 2026-10-20
- Restored the active implementation plan, findings, and verification history before continuing the documentation work.
- Reconfirmed that the workspace is not a Git repository: `git diff --stat` exits with code 129. This expected limitation is logged and will not be retried as a source-code verification action.
- Confirmed that no existing top-level user-facing run guide is present. The guide must cover the verified in-memory demo launch, Rust/MSVC prerequisites, dashboard and OpenAPI smoke checks, and the separate Docker/MySQL/Redis/worker path.

### Documentation Preparation — 2026-10-20
- Inspected the full-stack service and container definitions. The full-stack route exposes MySQL on port 3306, Redis on port 6379, and the API on port 8080 after dependency health checks; the worker is a distinct process and performs development migrations in that route.
- Confirmed the production image contains both executables, static dashboard assets, and migrations, runs as a non-root user, and starts the API executable by default.

### Documentation Verification Update — 2026-10-20
- Restored the active plan, findings, and progress files, then reconfirmed the dependency and production-mode rules directly from the runtime configuration.
- Confirmed the documented dependency-free path is valid only with `APP_ENV=development` and `PROVIDER_MODE=demo`; production rejects demo mode and requires MySQL, Redis, sufficiently long dashboard/data-fingerprint secrets, and no development administrator token.
- Re-ran `git diff --stat` as part of session recovery. It again exited with code 129 because this workspace is not a Git repository; this expected state does not block source or documentation work.

### Final Dependency-Free Verification — 2026-10-20
- Re-ran `node --check web\\app.js`; it completed successfully.
- Against the already-running development/demo API on `127.0.0.1:18080`, `GET /health/live` returned HTTP 200 with `status: ok` and `GET /health/ready` returned HTTP 200 with `status: ready`; both responses reported `provider_mode: demo`.
- Confirmed that the root `README.md` now documents the verified Windows demo route, health and validation smoke checks, development-only admin access, environment safeguards, and the separately unverified Docker/MySQL/Redis/worker route.
- This verification covers the dependency-free demo mode only. Docker Compose, MySQL, Redis, Redis Streams, the worker, Google OIDC, real providers, and production deployment remain explicitly unverified in this environment.

### Local Role Sign-In Resumption — 2026-10-20
- Restored the active plan, findings, and prior verification history for Phase 8 — Development-Only Local Role Sign-In.
- Confirmed the working API process is currently bound to `127.0.0.1:18080` in development/demo mode and must not be interrupted during source inspection.
- Confirmed the implementation objective: add development-only Bunny administrator and dummy member email/password authentication while preserving signed session claims and server-side RBAC.
- Reconfirmed that source-diff inspection is unavailable because the workspace is not initialized as a Git repository; this expected constraint was already recorded in `findings.md`.
- Re-ran the required recovery check, `git diff --stat`; it again exited with code 129 because this workspace has no Git repository. This is an expected environment constraint, not an implementation failure, and source files will be inspected directly.
- Re-read the active plan, progress log, and findings before implementation. A repeated `git diff --stat` recovery check again exited with code 129 because the workspace is intentionally not a Git repository; direct source inspection remains the selected verification path.

### Local Role Sign-In Discovery — 2026-10-20
- Confirmed that the current configuration exposes only a development administrator bearer-token override; it has no local email/password credential model.
- Confirmed that the current router exposes session, Google OIDC start/callback, and logout routes, but no local sign-in route.
- Confirmed that administrative endpoints delegate authorization to the server-side `auth::require_admin` boundary, so role claims must be enforced there rather than by dashboard presentation logic.

### Recovery Verification — 2026-10-20
- Re-ran the required `git diff --stat` recovery check. It exited with code 129 because `e:/PROJEK/rajacek` is not a Git repository; this known environment constraint will not be retried during this phase.
- Re-read the active plan, progress log, and findings. The active change remains development-only local administrator/member email-password sign-in with signed role-bearing sessions and server-enforced RBAC.
- Repeated the recovery check after session compaction. It produced the same known exit code 129 because the workspace has no Git repository; direct source inspection remains the selected source-verification approach.
- Repeated the planning-skill recovery check after the latest session summary; it again exited with code 129 for the same non-repository workspace condition. No source change was inferred from this command.
- Re-read the complete session implementation. Google OIDC already creates a signed `SessionClaims` cookie, while its parser rejects all non-admin claims and requires a Google allowlisted address. Local sessions must therefore use the same signing routine but move role-specific authorization into `require_admin`.

### Session Recovery — 2026-10-21
- Reloaded the active plan, findings, and progress records before resuming Phase 8.
- The active target remains development-only local Bunny administrator and dummy member email/password sign-in, using existing signed session cookies and server-enforced roles.
- The existing API process remains active on `127.0.0.1:18080`; source inspection and later verification must avoid assuming its binary reflects new source until it is deliberately restarted.
- Reconfirmed the planned security boundary: the local route is development-gated, role claims remain server-signed, and administrator checks must remain server-side rather than relying on dashboard navigation.

### Session Recovery — 2026-10-21 (continued)
- Restored the project plan and progress ledger after the session summary and confirmed that Phase 8 remains the only active implementation phase.
- The existing local process still runs the pre-change binary on `127.0.0.1:18080`; it will need a deliberate restart before role-login verification.
- Re-read the persisted Phase 8 scope and prior authentication findings: local credentials must be development-gated, issue the existing HttpOnly signed-cookie session, and preserve server-side admin authorization.
- Next source-inspection targets are configuration, authentication claims/authorization, route contracts, and dashboard login UI. No local credential behavior has been assumed from the active process.

### Planning Recovery — 2026-10-21 (latest)
- Re-read the active plan, findings, and progress ledger before implementation work.
- Ran the planning workflow's required `git diff --stat` check; it again exited with code 129 because `e:/PROJEK/rajacek` is not a Git repository. This is the known expected workspace constraint, so direct source inspection remains the verification method.
- Phase 8 remains in progress; no source changes have been made in this recovered session.

### Next Action
- Continue Phase 1 provider/compliance discovery, then add automated behavioral coverage for local role sign-in.

### Project Audit — 2026-10-21
- Reviewed the project plan, source layout, runtime configuration, API routes, migration schema, OpenAPI artefact, Compose deployment and README. The current implementation is a functional development/demo foundation, but the project plan still records phases 1, 6 and 8 as in progress and phases 2–5 and 7 as pending.
- No Rust test modules are present under `src`; the documented `cargo test --all-targets` therefore validates compilation/test harness execution but does not evidence behavioral coverage.
- The local API at `127.0.0.1:18080` answered `GET /health/ready` with HTTP 200 in `demo` provider mode. This only confirms the already-running demo binary, not uncommitted/current source behavior.
- Docker CLI is absent, so the Compose/MySQL/Redis/worker path remains unverified locally.
- Attempted to run `cargo test --all-targets` from the current PowerShell host, but `cargo` is not on PATH. Earlier verification used a Visual Studio developer environment; reproduce tests there or restore Rust/Cargo to PATH before treating the current source as freshly verified.
- A first attempt to invoke the Visual Studio developer environment through `cmd` failed due to nested-path quoting around `Program Files`; this is an invocation issue, not a Rust project diagnostic. The next verification attempt will use `call` to load `VsDevCmd.bat` in the same `cmd` process.
- Re-ran `cargo test --all-targets` successfully via `VsDevCmd.bat` and the absolute Cargo path. Compilation passed for all targets, but all three test binaries reported `running 0 tests`; the project currently has no automated Rust behavioral tests.
- The combined OpenAPI/README documentation patch did not apply because the README heading level differed from the patch context. No file was changed by that failed patch; the next edit will use the exact heading text.
- First compile attempt after local-login implementation failed with Rust `E0308`: `google_login_callback` passes `Arc<AppConfig>` to the new cookie helper, which expects `&AppConfig`. The targeted correction is to borrow the Arc at that call site; no behavior or security boundary changes are required.
- The first local-restart command was blocked by the execution policy before it ran because it combined process termination and background startup. The old API process remains untouched; the restart will be split into separately auditable commands after the exact target was verified.
- The replacement API process became ready, but `POST /v1/auth/local/login` returned 405. Root cause: `cargo test --all-targets` compiled test executables but did not refresh the standalone `target\\debug\\rajacek-api.exe` launched for the local server. Build the `rajacek-api` binary explicitly, then restart that exact process before retrying login verification.
- The standalone API binary was then built successfully. A combined launch-and-poll command was blocked by the execution policy before it ran, so the launch and readiness poll will be issued as separate commands.
- Rebuilt the standalone API binary and launched the current source successfully at `127.0.0.1:18080` in development/demo mode.
- Verified the completed local role flow manually: the Bunny administrator login returned 200 and accessed `/v1/admin/overview` with 200; the dummy member login returned 200 but was denied from the same endpoint with 401; an incorrect password returned 401.
- `cargo fmt --all -- --check`, `cargo test --all-targets` (zero test cases), and `node --check web\\app.js` completed successfully. Phase 8 is complete; the running local API process is PID 1112.
- Could not append the final discovery to `findings.md` through the mandated patch tool because that existing file contains a non-UTF-8 byte near index 19351. Its content was not rewritten to avoid destructive encoding conversion.

### Public Landing Page — 2026-10-21
- Added a public, semantic, responsive landing page at the root route, with a separate `/admin` route retained for the existing dashboard. The page contains title/description metadata, crawler directives, canonical marker, Open Graph metadata, JSON-LD structured data, product content, FAQ, and accessible navigation.
- The first rebuild after this routing change could not replace `target\\debug\\rajacek-api.exe` because the currently running local API process owns the file. The process will be stopped only after confirming its exact executable path, then the current binary will be rebuilt and relaunched.
- Confirmed the old listener was the expected Rajacek API executable, stopped it, rebuilt the current API binary, and restarted it at `127.0.0.1:18080` (PID 27916) in development/demo mode.
- Runtime checks passed: `/` returns the public landing page with its SEO title, JSON-LD, FAQ content and responsive stylesheet; `/admin` returns the preserved dashboard; `landing.css` is served as `text/css`.
- `cargo build --bin rajacek-api`, `cargo test --all-targets` (zero test cases), and `node --check web\\app.js` completed successfully.

### Admin-Managed Provider Endpoint Analysis — 2026-10-21
- Restored the persistent plan, findings, and progress files and ran the required recovery diff check. The workspace remains outside a Git repository, so direct source inspection is used.
- Confirmed the current HTTP provider is immutable after startup: one `PROVIDER_BASE_URL` and `PROVIDER_API_KEY` are read from environment variables, captured by `HttpProvider`, and used for every product.
- Confirmed the existing `provider_configs` MySQL table is not connected to the API runtime or dashboard. The active `AdminStore` is an in-memory administration implementation, while MySQL is currently used by the worker for usage persistence.
- Confirmed product `provider_route` is currently presentation/configuration metadata only; validation calls do not resolve it.
- Phase 9 will introduce a shared runtime provider-config registry with masked admin reads, write-only secret rotation, product-specific route selection, strict URL/timeout validation, and production SSRF safeguards. The existing environment HTTP configuration will seed the registry for backward compatibility.

### Admin-Managed Provider Endpoint Completion — 2026-10-21
- Added a product-specific runtime provider configuration registry, MySQL migration, AES-256-GCM credential encryption, masked administrator reads, write-only credential rotation, and immediate request routing through the latest active configuration.
- Added production safeguards: HTTPS-only endpoints, explicit host allowlisting, redirect refusal, URL/userinfo validation, DNS resolution checks on outbound use, public-address enforcement, and bounded per-endpoint timeouts.
- Added authenticated list/update/test admin APIs and a new **Endpoint Provider** dashboard view with configuration and safe destination-test workflows. The test endpoint verifies URL/host/DNS/network policy without sending customer identifiers.
- Updated OpenAPI, `.env.example`, README operations guidance, and the persistent project plan.
- Verification passed: `cargo fmt --all`, `cargo test --all-targets` (one SSRF unit test passed), `cargo build --bin rajacek-api`, `node --check web\\app.js`, and Python/PyYAML parsing of the OpenAPI document.
- Runtime HTTP-mode smoke verification passed on `127.0.0.1:18080`: local administrator authentication succeeded; endpoint update returned the new name and `api_key_configured=true` without leaking an `api_key`; safe destination verification returned reachable; and `/admin` served the new Endpoint Provider UI. The current API process is PID 27964.
- MySQL-backed persistence/migration execution remains unverified locally because Docker/MySQL are unavailable; the runtime smoke check used the intentional in-memory development fallback.

### Dummy Data Documentation — 2026-10-21
- Added `DUMMY_DATA.md` as the central reference for development-only dashboard accounts, passwords, administrator token, member API key, bank/e-wallet/WhatsApp request payloads, provider endpoint placeholders, product prices, packages, and rate-limit seeds.
- Added prominent links from `README.md` and its local-account section so dummy values can be found without searching source files.
- The document explicitly marks every value as development-only and preserves the existing production safeguards.

### Product-Aware JSON Mapping and Sidebar Repair — 2026-10-21
- Added administrator-configurable dot/array JSON paths and status-value lists to every third-party endpoint. Mapping is validated server-side, returned in masked endpoint metadata, persisted through migration `0003_provider_response_mapping.sql`, and resolved without restarting the API.
- Replaced the fixed upstream response schema with a generic JSON normalizer. Bank mapping supports account name/provider/reference; WhatsApp supports registration plus safe optional metadata; e-wallet enforces a privacy boundary that returns only `registered` and discards account name, provider-result label, and reference.
- Added tests for nested bank extraction and e-wallet name suppression. `cargo test --all-targets` passed with 3 tests, including the existing SSRF test.
- Added a product-aware dashboard mapping editor with default reset, clear path/value guidance, conditional fields, and explicit e-wallet privacy messaging.
- Repaired the fixed sidebar by making the navigation region independently scrollable, keeping the footer in a non-overlapping flex region, reducing spacing on short desktop viewports, and retaining mobile stacking behavior. The Settings button remains in the scrollable navigation and is no longer covered by the footer.
- Updated OpenAPI, README, and `DUMMY_DATA.md` with mapping contracts and bank/e-wallet examples. Node syntax and OpenAPI YAML parsing passed.
- Runtime smoke verification passed in HTTP mode: an administrator saved the e-wallet mapping, the API returned `registered_path=payload.is_registered` with `account_name_path=null`, `/admin` contained the mapping editor, and the served stylesheet contained the scrollable sidebar rule. The current API process is PID 3520.
- MySQL migration execution remains unverified locally because no MySQL/Docker service is available.

### Tukangcek Contract and Bank-Code Translation — 2026-10-21
- Imported `C:\Users\ASUS\Downloads\BANK_CODE.json`, normalized 110 distinct code/name rows into `data/bank_codes.json`, corrected the source key typo (`code_ bank` → `code_bank`), and added `GET /v1/banks`.
- Rajacek bank validation now accepts exactly three-digit public `code_bank` values. The confirmed BRI mapping is `002` → Tukangcek `BRIC1ID`; all unconfirmed provider IDs remain null and fail safely rather than being guessed.
- Added selectable `generic`/`tukangcek` outbound request modes and a validated credential-header name. Tukangcek uses `X-API-Key`, bank/e-wallet `/api/check` bodies, and WhatsApp `/api/check-wa` bodies. The user-supplied real credential was deliberately not written to any project file.
- Added safe normalization for Tukangcek `found` and `registered` booleans. E-wallet remains registration-only; `balance`, `checkedAt`, upstream target, and raw payload fields are not exposed.
- Mapped documented upstream HTTP 400/401/429/500/503 states into safe Rajacek errors without leaking upstream response bodies.
- Added migration `0004_provider_request_contract.sql`, dashboard controls for request mode/auth header, Tukangcek presets, OpenAPI bank catalog/request-mode contracts, and operational documentation.
- Verification passed: formatting, JavaScript syntax, OpenAPI parsing, secret scan (supplied API key absent), binary build, and 7 Rust tests. Tests cover catalog mapping, refusal to invent unknown mappings, BRI request translation, Tukangcek e-wallet/WhatsApp normalization, generic mapping, e-wallet privacy, and SSRF controls.
- Runtime smoke verification passed: `/v1/banks` returned 110 rows and BRI `BRIC1ID`; admin saved a Tukangcek endpoint with `X-API-Key`; the API returned mode/header metadata without leaking the credential. The current development API process is PID 22948.
- MySQL migrations 0002–0004 remain unverified locally because MySQL/Docker is unavailable.

### Tester Conditional Fields and Latency Telemetry — 2026-10-21
- Root cause of irrelevant tester controls remaining visible: `.form-grid label { display: grid; }` overrode the browser's default `[hidden]` styling. Added a global `[hidden] { display: none !important; }` rule, so bank shows only bank selection, e-wallet shows only wallet-provider selection, and WhatsApp shows neither.
- Added `provider_latency_ms`, `rajacek_processing_ms`, and `total_latency_ms` to normal validation response metadata and the admin tester response.
- Added a responsive three-card timing panel to Tester Layanan showing provider, Rajacek processing, and total milliseconds.
- Updated OpenAPI and README timing semantics, including cached idempotency replay behavior.
- Formatting, 7 Rust tests, Node syntax, OpenAPI parsing, and binary build passed. Runtime demo verification returned tester timing `87/0/87 ms` and member WhatsApp timing `45/380/425 ms` (provider/Rajacek/total), confirming all fields serialize and total timing includes the platform path.

### Visible Tukangcek State and Live Tester Enforcement — 2026-10-21
- Diagnosed two separate issues: Tukangcek was configured only inside the endpoint edit modal/card subtitle, and the service was deliberately running in `PROVIDER_MODE=demo`, so tester results came from `demo-provider`.
- Endpoint Provider now has a prominent page-level contract summary, Tukangcek/Generic badges on every card, explicit request-contract/header rows, and cache-busted CSS/JavaScript URLs.
- HTTP bootstrap now recognizes a `tukangcek.id` URL and initializes bank/e-wallet to `/api/check`, WhatsApp to `/api/check-wa`, all in Tukangcek mode with `X-API-Key` and product-specific response mappings.
- Admin tester now rejects `PROVIDER_MODE=demo`; it can no longer return simulated data while presented as a provider integration test.
- Rebuilt and restarted in HTTP/Tukangcek mode with the supplied credential held only in process environment (not written to project files). Runtime endpoint metadata confirmed all three routes are Tukangcek. A live WhatsApp call returned HTTP 200, `registered=false`, normalized `not_found`, and `526 ms` total. E-wallet returned Tukangcek's documented HTTP 503 offline state, proving the path is live rather than demo.
- Formatting, 7 tests, JavaScript syntax, binary build, and served cache-busted UI verification passed. Current API PID: 22048.

### Admin Service Tester and Tukangcek UI Verification — 2026-10-21
- Verified the served `/admin` HTML and `/app.js` already contained the Tukangcek controls; they are located inside Endpoint Provider → **Kelola**, not directly on the provider card. Added the request mode to each provider-card summary so the active `Tukangcek`/`Generic` mode is immediately visible.
- Added a dedicated **Tester Layanan** sidebar page with product-aware fields: selectable mapped bank code plus account number, e-wallet provider plus account number, or WhatsApp phone number.
- Added authenticated `POST /v1/admin/provider-tester`. It calls the active provider adapter and returns normalized safe fields without consuming member quota, writing a billing/usage event, or using member idempotency.
- Bank choices are loaded from `/v1/banks`; rows without a confirmed Tukangcek code are disabled. E-wallet result rendering remains registration-only.
- Updated responsive tester styles, OpenAPI, and README.
- Formatting, 7 Rust tests, Node syntax, OpenAPI parsing, and binary build passed. After restart, runtime checks confirmed the Tukangcek control, Tester menu/form/JavaScript, and authenticated tester route. The test route returned expected HTTP 503 because the local placeholder upstream on port 19090 is intentionally not running; route/auth/request validation succeeded. Current API PID: 26124.

### Live Provider Re-verification — 2026-10-21
- Reopened verification at user request. Recovery `git diff --stat` again showed this workspace is not a Git repository; use runtime and direct source checks instead.
- Local listener `127.0.0.1:18080` is process 22048. Fresh `/health/ready` returned HTTP 200 and `provider_mode: http`, so the service is not running its demo adapter.
- Dashboard source contains the active-contract summary, request-mode control, tester form, and cache-busted assets; served contents and authenticated settings still require confirmation.
- Fresh local administrator login succeeded. Authenticated endpoint listing returned three active configurations, each with `request_mode=tukangcek`, `auth_header=X-API-Key`, `api_key_configured=true`, timeout 8000 ms: bank and e-wallet use `https://tukangcek.id/api/check`, WhatsApp uses `https://tukangcek.id/api/check-wa`. Status mapping paths are `found` (bank/e-wallet) and `registered` (WhatsApp). No credential value was fetched or logged.
- Served `/admin` HTML and `/app.js` both returned HTTP 200; HTML contains provider contract summary, request-mode selector, and tester form; served JS contains the active Tukangcek badge and admin tester route.
- Three separate authenticated tester calls using documented development-only sample identifiers returned bank HTTP 200 / normalized `not_found` / provider `HTTP Validasi rekening` (provider 211 ms, total 257 ms), e-wallet HTTP 503, and WhatsApp HTTP 200 / normalized `not_found` / provider `HTTP Validasi WhatsApp` (provider 312 ms, total 313 ms). No real user data or upstream raw response was recorded. The e-wallet upstream remains unavailable for this sample; do not label it successful or demo data.
- Each provider endpoint's `/test` check returned HTTP 200 and `reachable=true`, but this check verifies destination policy/DNS, not business API availability; its success does not contradict the e-wallet business request's HTTP 503. Follow-up error-body reading did not produce a parsed message; status 503 is confirmed, upstream detail is not.

### Tester HTML/JSON Response Audit — 2026-10-21
- Audited admin tester route: it returns a normalized `AdminProviderTesterResponse` from the active HTTP adapter, not a raw third-party response. API errors use the Rajacek error envelope.
- Added HTML/JSON result tabs with keyboard navigation and accessible tab semantics. JSON is formatted from the actual admin tester response; HTML displays the safe normalized fields, status, and latency. On failures both tabs show the current safe API error instead of stale success data; network failures show a local error envelope.
- UI warns that raw upstream payloads and credentials are not shown. Normalized names/references are still sensitive and remain admin-only. Cache-busted dashboard assets. Node syntax and markup/content checks passed; browser automation was unavailable because Playwright is not installed. No new live provider calls were made for this UI-only change.

### Admin Tester Raw Upstream Response — 2026-10-21
- Added a dedicated HTTP provider admin capture path: the existing member validation method remains body-free; admin tester receives upstream status and original response bytes capped at 64 KiB, rendered as UTF-8 verbatim or Base64 for binary/non-UTF-8 bodies. Non-2xx responses and invalid JSON/mapping errors include the captured upstream body in the admin-only error envelope. Upstream headers are never returned; no raw body is persisted or intentionally logged.
- Added a third keyboard-accessible Respons Asli tab, plain-text rendering, cleared loading/error state, and prominent sensitive-data warnings. JSON tab now reflects the complete tester response. Updated README and OpenAPI descriptions and cache-busted static assets.
- Verified `cargo fmt --all -- --check`, `cargo test --all-targets` (9 passed), `cargo check --all-targets`, `node --check web/app.js`, OpenAPI YAML parsing, and UI markup/render-path assertions. No new live provider calls were made; controlled end-to-end behavior remains unverified without a running controlled provider.

### Tukangcek E-wallet IDs and `found` Contract — 2026-10-21
- Rechecked public e-wallet slugs, the outbound Tukangcek request builder, and fixed response normalization. All nine public slugs now translate to their supplied provider IDs; unknown slugs are rejected without forwarding to Tukangcek. Generic-mode requests retain their existing contract.
- Tukangcek bank/e-wallet responses normalize `found` to `valid`/`not_found`, while WhatsApp still uses `registered`. E-wallet result data continues to expose registration only; upstream identity/account metadata remains private in member responses. The admin-only raw-response diagnostic remains intentionally separate and sensitive.
- Updated README and dummy-data contract examples and added tests covering all nine translations, unknown IDs, outbound e-wallet IDs, and `found` true/false and WhatsApp `registered` behavior.
- Verification: `cargo fmt --all -- --check`, `cargo test --all-targets` (12 tests passed), `cargo check --all-targets`, `node --check web/app.js`, and OpenAPI 3.1 YAML parsing (24 paths) passed. No live provider request, database migration run, or browser smoke test was performed in this verification pass.

### aaPanel Deployment Guide — 2026-10-21
- Also removed the stale `Cargo.lock` ignore rule from `.gitignore` so the locked dependency graph can be committed for reproducible server and container builds, matching the Dockerfile's `COPY Cargo.toml Cargo.lock* ./`.
- Removed `--default-authentication-plugin=caching_sha2_password` from the MySQL service command in `compose.yaml`: the flag was removed in MySQL 8.4, so the container would refuse to start against the pinned `mysql:8.4` image.
- Guide review pass corrected four operational traps before delivery: `.env` ownership/permissions for the `www` service user, systemd `EnvironmentFile=` overriding `Environment=`, MySQL/Redis unit names that vary on aaPanel, and Compose `$` interpolation inside database passwords.
- Added accuracy notes grounded in source: `ProviderConfigStore::build()` opens MySQL at API startup, provider endpoints persist in `third_party_endpoints` while `AdminStore` remains in memory, and both rate limiting and event handoff fail closed with `503` when Redis is unavailable.
- Reviewed `src/config.rs`, `src/main.rs`, `src/api.rs`, `src/bin/worker.rs`, `src/database.rs`, `src/store.rs`, `Dockerfile`, `compose.yaml`, `.env.example`, `README.md`, and the migrations before writing deployment instructions.
- Found and fixed two container build blockers: three assets are embedded with `include_str!` (`web/landing.html` and `openapi/openapi.yaml` in `src/api.rs`, `data/bank_codes.json` in `src/bank_codes.rs`), but the Dockerfile builder stage copied only `Cargo.toml`, `src`, and `migrations`. Added `COPY web ./web`, `COPY openapi ./openapi`, and `COPY data ./data` before `cargo build --release --bins`.
- Created `DEPLOY_AAPANEL.md` in Indonesian: aaPanel installation and panel hardening, App Store prerequisites (Nginx, MySQL 8.0, Redis, Docker), project upload, MySQL/Redis preparation, production `.env` with the enforced validation rules, a production Docker Compose profile with loopback-only API binding and no exposed database ports, a native systemd profile for API and worker, Nginx reverse proxy plus Let's Encrypt/Force HTTPS, Google OAuth redirect alignment, post-deploy verification checklist, update and rollback procedures, backup/monitoring guidance, a troubleshooting matrix, and a pre-launch limitation list.
- Documented the in-memory `AdminStore` limitation as the primary production blocker, alongside the HTTPS requirement for `Secure` session cookies and the worker-only migration execution path.
- Verification performed: Markdown fence balance (`68` fences, balanced) and YAML parsing of both `compose.yaml` and the guide's `compose.production.yaml` snippet. The production snippet parses with services `mysql`, `redis`, `api`, `worker`, API bound to `127.0.0.1:8080`, and **no** host port mappings for MySQL or Redis.
- Docker CLI is still unavailable in this environment (`docker compose version` is not recognized), so no image build or `docker compose config` interpolation check could run. No Rust compilation, container build, or server deployment was executed; the Compose and systemd paths remain configuration-checked only.

### Fix Session — 2026-10-21 (bank mapping + hot-path/flow/overview)
- Completed the Tukangcek bank mapping: catalog now covers 111 unique public 3-digit codes (120 rows incl. conventional/Syariah name variants) with exactly one verified-live instId per code; 10 missing banks added (036, 037, 067, 087, 145, 212, 490, 546, 562, 949). Sources cross-verified: live `GET tukangcek.id/api/banks` + production ApiValidasi `mappings.json`. New catalog tests assert full coverage and reject unknown codes.
- Validation flow: idempotency resolved before rate limiting (replays no longer consume admission; no fabricated rate-limit headers on replay); rate-limiter failures abandon the in-flight idempotency entry; an idempotency-complete failure after the usage event is queued no longer fails an already-ledgered request.
- API-key verification moved from per-request Argon2 to salted SHA-256 with constant-time compare (server-generated high-entropy secrets); `argon2` dependency removed.
- Removed `Mutex<ConnectionManager>` serialization from the Redis rate limiter, idempotency coordinator, and event sink (clone-per-operation multiplexing).
- Dashboard overview no longer fabricates metrics: totals/success/latency are computed from validations actually handled since process start; unmeasured values are 0/None/`unknown`; seeded sample activities removed. Details and verification (14 tests passed, demo smoke test) in `FIX_2026-10-21.md`.

### Provider Guard — 2026-10-21 (lanjutan)
- Added `src/provider_guard.rs`: per-product semaphore (default 16 concurrent calls, 2s bounded queue wait, then Rajacek 429) and per-product circuit breaker (5 consecutive provider failures -> 30s open, fail-fast 503, single half-open probe; transport/429/5xx/unparseable count as failures, client/config errors neutral). Wired into `HttpProvider` only; configurable via four validated env vars.
- Verification: 20 unit tests pass (6 new guard tests). Runtime smoke against a local fake upstream (1s delay): 10 parallel bank validations finished in ~1.1s with exactly 10 upstream calls; forced-503 mode opened the bank circuit after 3 failures (threshold set to 3) and the 4th request failed fast without an upstream call, while e-wallet remained unaffected.

### Admin-Managed Provider Guard Settings — 2026-10-21 (lanjutan)
- Provider guard settings moved to the admin panel (Settings view): dynamic-capacity semaphore + RwLock config make all four numbers (max concurrency per product, queue wait, breaker threshold, breaker cooldown) changeable live without restart via GET/PUT `/v1/admin/provider-guard` with range validation and admin-activity logging.
- Persistence via migration `0005_runtime_settings.sql` (`runtime_settings` table): panel values are saved to MySQL when attached and override env seeds at startup; without a database the PUT response honestly reports `persisted: false`.
- Panel also shows per-product circuit state, in-flight count, and consecutive failures. Verified: 23 unit tests pass; live smoke changed concurrency 16->8 and threshold 5->2 without restart, invalid values returned 400, and the lowered threshold opened the bank circuit after exactly 2 upstream 503s with the third request failing fast and panel status reading `open`.

### Member Validation History for Admin — 2026-10-21 (lanjutan)
- New admin history view ("Riwayat Cek") + `GET /v1/admin/validation-history` with product/outcome/api-key-prefix filters and limit/offset paging. Primary source is the durable MySQL `validation_requests` table (worker-written, masked targets only); without a database it falls back to a 500-entry in-memory ring mirroring exactly the validations whose usage events were queued, and the response/panel label the source honestly.
- Verified in demo mode: two real validations appear newest-first with member prefix, masked target, provider reference and latency; product filter narrows correctly; unauthenticated access returns 401. The MySQL query path is compiled against the worker's table schema but was not exercised against a live MySQL in this session.

### Low-Memory MySQL Profile — 2026-10-21 (lanjutan)
- Added `deploy/mysql-low-memory.cnf`: Performance Schema/X Plugin/binlog off, 128 MB InnoDB buffer pool sized to hold the whole hot dataset, trimmed per-connection buffers, `max_connections` 75 matched to the sqlx pools, durability kept (`flush_log_at_trx_commit=1`, O_DIRECT). Estimated mysqld RSS ~180–250 MB vs 400–600 MB default; verification queries are in the file header. Not measured against a live mysqld in this environment (none available locally).

### Member/Public Documentation + OpenAPI JSON — 2026-10-21 (lanjutan)
- Added a public member documentation page at `/docs` (Indonesian: quickstart, auth, idempotency, rate limits/quota, endpoint references, result statuses, error codes, FAQ) and a member/public-only OpenAPI 3.1 JSON spec at `/openapi.json` (also `/openapi/openapi.json`) containing only `/health/live`, `/v1/banks`, and the three validation endpoints — no admin surface. Landing's documentation button now points to `/docs`; the stale `bank_code: BCA` example in the internal YAML was corrected to the 3-digit `'014'`. Verified live locally: /docs 200, spec JSON parses with exactly the 5 public paths and zero admin paths.

### Admin-Adjustable Default Rate Limit — 2026-10-21 (lanjutan)
- The env-locked default rate limit (60/min) is now admin-adjustable live: AtomicU32 in both rate limiters and the AdminStore, GET/PUT `/v1/admin/rate-limit-default` (range 1–100000) with admin-activity logging, persisted via `runtime_settings` (`rate_limit.default_per_minute`) and loaded at startup over the env seed. A settings card on the Rate Limit page shows the effective default plus derived IP (x3) and global (x100, min 1000) buckets. Existing keys keep their own per-key limit (already admin-settable per key/package); the default drives new-key fallback, IP, and global buckets.
- Verified: 24 unit tests pass including a live-bucket test (default=1 makes the 4th same-IP request fail across different keys). Live smoke: key A issued at 60, PUT default to 7, key B issued at 7 without restart; PUT 0 returns 400.

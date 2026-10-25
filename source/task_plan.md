# Project Plan — High-Performance Validation API

## Goal
Design and later implement a production-grade Rust REST API for validating Indonesian bank accounts, e-wallet accounts, and WhatsApp numbers through approved third-party providers. The platform must support Google-based member authentication, member API keys, configurable commercial packages and per-hit pricing, strong rate limiting, auditability, and very low response latency without synchronously blocking API responses on non-critical MySQL writes.

## Scope Boundaries
- **In scope:** architecture, data model, REST contracts, async request path, provider integration abstraction, authorization, rate limiting, billing/usage, observability, security, deployment, and test strategy.
- **Not yet confirmed:** exact third-party provider contracts, business verification/consent requirements, payment gateway, API domain, expected traffic, retention rules, and whether WhatsApp validation is ownership verification or merely number reachability.
- **Important compliance constraint:** validation must only use authorized provider APIs and users must have a lawful basis/consent for any personal data processed.

## Recommended Architecture Decisions
| Area | Decision | Reason |
|---|---|---|
| Runtime | Rust + Tokio | Efficient async I/O and predictable resource use under concurrent API traffic. |
| HTTP framework | Axum + Tower middleware | Type-safe routing/extractors with mature middleware for auth, tracing, timeouts, and rate limits. |
| Database | MySQL 8 + SQLx | MySQL compatibility, compile-time checked queries where enabled, async pooling, and migrations. |
| Cache / limiter / queue | Redis | Atomic distributed rate limiting, API-key metadata cache, idempotency state, short-lived responses, and durable stream/queue handoff. |
| Background processing | Separate Rust worker consuming Redis Streams | Keeps audit, usage aggregation, billing events, webhook retries, and non-critical writes off the member-facing latency path. |
| Provider integration | Provider adapter trait + normalized internal request/response model | Allows bank, e-wallet, and WhatsApp providers to change independently and supports failover later. |
| Authentication | Google OpenID Connect authorization-code flow with PKCE, server-side session or short-lived JWT access token + rotated refresh token | Avoids trusting client-supplied Google identity data and supports secure member/admin login. |
| API authorization | Opaque, prefix-identifiable, hashed API keys with scopes | API key secrets are never stored plaintext; scopes enable product-level permissions. |
| Commercial model | Immutable package-price snapshots and append-only usage ledger | Price changes never alter historical billing calculations. |
| Deployment | Stateless API replicas behind TLS load balancer; separate worker replicas; managed MySQL and Redis | Horizontal scaling and fault isolation. |

## Non-Negotiable Request-Path Principle
The member-facing validation response must depend only on work essential to correctness:
1. Authenticate and authorize the API key.
2. Enforce atomic quota/rate-limit reservation.
3. Call the required third-party provider through a strict timeout/circuit-breaker policy.
4. Normalize and return the JSON result.

Everything non-critical—full audit logs, analytics, invoice aggregation, notification/webhook dispatch, and long retention writes—must be appended to a durable Redis Stream/outbox before responding and processed by workers. A small, bounded synchronous database transaction remains allowed only for correctness-critical state such as a hard monthly quota if Redis cannot be the source of truth. The final design must explicitly define failure behavior so a successful validation cannot be billed twice or silently lost.

## Phases

### Phase 1 — Requirements, Compliance, and Provider Discovery
**Status:** in_progress

- Define supported validation types and exact normalized outcomes: `valid`, `invalid`, `not_found`, `pending`, `provider_error`, `rate_limited`, and `quota_exhausted`.
- Obtain each provider's endpoint, credentials model, contractual rate limits, webhook behavior, retries, SLA, error codes, regional constraints, permitted use, and cost per request.
- Clarify whether WhatsApp validation means format check, provider reachability/registration lookup, or OTP ownership verification. OTP verification requires consent, anti-abuse controls, and a separate flow.
- Define customer roles: `member`, `admin`, and optionally `support`/`finance`, along with least-privilege permissions.
- Define data-retention periods, data-minimization policy, support-access policy, and deletion/export process.
- Establish traffic targets: peak requests per second, p95/p99 latency target excluding provider time, acceptable provider timeout, expected tenant count, and budget limits.

**Deliverable:** approved functional and non-functional requirements document with provider capability matrix.

### Phase 2 — Domain Model and Data Ownership
**Status:** pending

Model the following core entities:

| Entity | Core fields / purpose |
|---|---|
| `users` | Google subject ID, email, display data, account status, timestamps. Do not use email as Google identity primary key. |
| `roles` / `user_roles` | Admin/member/support roles and explicit authorization assignment. |
| `organizations` | Optional tenant/business boundary, plan ownership, billing profile, and member grouping. Start with one organization per member if teams are needed later. |
| `api_keys` | Public prefix, secret hash, scopes, key status, organization/user owner, expiry, last-used timestamp, revocation metadata. |
| `products` | `bank_account_validation`, `ewallet_validation`, `whatsapp_validation`; active state and provider routing policy. |
| `packages` | Admin-defined purchasable bundles, validity rules, and enabled products. |
| `package_prices` | Versioned price-per-hit / bundle pricing effective at a time range; never overwrite prior price rows. |
| `subscriptions` / `balances` | Active package or prepaid quota state per organization. |
| `usage_reservations` | Idempotent quota reservation keyed by request ID/idempotency key. |
| `usage_ledger` | Append-only charge/refund/adjustment record with price snapshot, product, outcome, provider reference, and correlation ID. |
| `validation_requests` | Minimal canonical audit record, PII-safe request fingerprint, outcome, timings, and provider response reference. |
| `provider_configs` | Encrypted provider credentials/revision and route configuration; never expose via normal admin reads. |
| `rate_limit_policies` | Global, per-plan, per-key, per-IP, and endpoint limits plus burst/window parameters. |
| `webhook_endpoints` / `webhook_deliveries` | Optional asynchronous result delivery, signing secret hash, retry status, and delivery audit. |
| `admin_audit_logs` | Immutable log for sensitive admin changes: pricing, keys, roles, providers, limits, manual credits. |

Data design rules:
- Use binary/UUIDv7 or sortable IDs for externally exposed resources; never expose sequential internal IDs as the only identifier.
- Store minimal personal data; hash/redact account numbers, phone numbers, and provider payloads in ordinary logs.
- Encrypt sensitive provider credentials using a KMS/Vault-backed envelope-encryption design. If unavailable initially, use application-managed encryption only as a transitional, documented risk.
- Partition/archive high-volume ledger and request-audit records by time before scale makes migration risky.
- Create explicit indexes for API-key lookup, active quota lookup, ledger/accounting queries, request correlation, and retention jobs.

**Deliverable:** ERD, migration sequence, index review, and data classification table.

### Phase 3 — API Contract and Authentication Design
**Status:** pending

Define versioned endpoints under `/v1`:

| Area | Example endpoints | Notes |
|---|---|---|
| Authentication | `GET /v1/auth/google/start`, `GET /v1/auth/google/callback`, `POST /v1/auth/refresh`, `POST /v1/auth/logout` | Google OIDC authorization-code + PKCE; state/nonce verification; secure cookie for dashboard flow or JWT pair for an SPA. |
| Member profile | `GET /v1/me` | Returns identity, roles, organization, package, quota summary. |
| API keys | `POST /v1/api-keys`, `GET /v1/api-keys`, `PATCH /v1/api-keys/{id}`, `DELETE /v1/api-keys/{id}` | Reveal plaintext API secret only once at creation. Require re-authentication for sensitive key actions. |
| Validation | `POST /v1/validate/bank-account`, `POST /v1/validate/ewallet`, `POST /v1/validate/whatsapp` | API-key auth, idempotency key support, normalized result schema, no provider-specific data leakage. |
| Usage | `GET /v1/usage`, `GET /v1/usage/ledger` | Paginated, filterable, masked data only. |
| Admin products/pricing | CRUD `/v1/admin/products`, `/v1/admin/packages`, `/v1/admin/package-prices` | Versioned, approval/audit protected; price changes create future effective records. |
| Admin limits | CRUD `/v1/admin/rate-limit-policies` | Validate that policies cannot accidentally disable global safety caps. |
| Admin operations | `/v1/admin/users`, `/v1/admin/api-keys`, `/v1/admin/credits`, `/v1/admin/provider-routes` | Strict RBAC, audit log, and two-person review recommended for credential/routing changes. |
| System | `GET /health/live`, `GET /health/ready`, `GET /metrics` | Metrics endpoint restricted to internal observability network. |

Contract rules:
- Use a stable JSON error envelope: `code`, `message`, `request_id`, optional safe `details`.
- Return a generated `request_id` / correlation ID on every response.
- Use `Idempotency-Key` for paid validation requests; retain result/reservation state long enough for client retry windows.
- Version additive changes safely; introduce `/v2` only for breaking behavior.
- Publish OpenAPI 3.1, generated SDK examples, request/response samples, and documented error/retry semantics.

**Deliverable:** OpenAPI 3.1 contract approved before endpoint implementation.

### Phase 4 — Low-Latency Validation and Billing Flow
**Status:** pending

Recommended successful request flow:
1. Edge proxy terminates TLS, applies request-size limits and coarse DDoS/IP protection.
2. Axum handler creates a correlation ID and structured tracing span.
3. Validate API-key format; retrieve its compact authorization/quota profile from Redis. On cache miss, read MySQL and repopulate cache.
4. Verify secret with an Argon2id hash (or keyed HMAC lookup plus constant-time secret verification), verify key state/scopes/expiry.
5. Evaluate Redis Lua script atomically for per-key, per-organization, per-IP, and global token buckets plus package quota reservation. The script returns remaining capacity and reset timing.
6. Validate request schema, normalize identifiers, and calculate a privacy-safe fingerprint for idempotency. Do not log raw sensitive identifiers by default.
7. Look up idempotency result/reservation in Redis. If duplicate, return the prior deterministic response without a second provider call or second charge.
8. Select provider route using product configuration, health state, tenant entitlement, and circuit-breaker state.
9. Make a pooled async HTTPS provider call with a short connect timeout, bounded overall deadline, no unbounded retries, and retry only when the provider contract makes repetition safe.
10. Normalize the provider response into the public schema. Map upstream errors to safe API errors without exposing credentials or provider internals.
11. Save the response/idempotency state to Redis and append a compact, durable event to Redis Streams using `XADD` before returning. The event contains the immutable usage reservation ID, request ID, charge outcome, and masked metadata.
12. Return JSON immediately. A background worker consumes the stream and writes append-only ledger/audit records to MySQL in batch transactions.
13. For an event write failure, follow a deliberately selected policy: either fail closed before external provider invocation, or use a transactional outbox/secondary durable queue. Do not report a billable success that has no durable recovery path.

Important balance-consistency design:
- Prefer a Redis atomic reservation as the fast-path gate, backed by MySQL reconciliation.
- Make the worker idempotent with unique event/reservation IDs and `INSERT ... ON DUPLICATE KEY`/upsert semantics.
- Reconcile Redis reservation state against MySQL ledger periodically; alert on discrepancy and pause affected keys only when necessary.
- Define clear refund policy for provider errors/timeouts and make it automatic/idempotent.

**Deliverable:** sequence diagram, failure matrix, idempotency model, and benchmarked proof of the selected queue durability behavior.

### Phase 5 — Security, Abuse Prevention, and Operational Controls
**Status:** pending

- Enforce TLS everywhere, HSTS, secure headers, strict CORS for dashboard origins, body-size limits, request deadlines, and connection limits.
- Store API keys only as salted hashes; prefix keys for operational identification, for example `rv_live_<prefix>_<secret>`.
- Authenticate dashboard/admin users through Google OIDC with domain/allowlist controls if required; rotate refresh tokens; protect state/nonce/PKCE; use CSRF defenses for cookie-based sessions.
- Apply RBAC and action-level authorization; never rely solely on a frontend admin route.
- Use distinct global/per-IP/per-API-key/per-organization endpoint token buckets. Include concurrency limits to prevent an individual key from consuming all provider connections.
- Use exponential backoff and a circuit breaker per provider route. Open circuits fail fast with a documented retry-after response rather than allowing cascading latency.
- Separate secrets by environment, rotate them, and restrict database/Redis permissions by role.
- Log security-relevant events: failed authentication, key creation/revocation, pricing changes, rate-limit changes, privilege changes, credits/refunds, provider configuration changes.
- Apply PII masking/redaction in application logs, traces, worker events, support views, and database exports.
- Add threat modeling for stolen API keys, replay attacks, mass enumeration, provider abuse, quota race conditions, admin takeover, SSRF through provider configuration, queue poisoning, and MySQL/Redis outages.

**Deliverable:** threat model, security test cases, secret-handling runbook, and reviewed retention policy.

### Phase 6 — Implementation Structure and Delivery Milestones
**Status:** in_progress

Recommended Rust workspace layout:

```text
rajacek/
|-- crates/
|   |-- api/                 # Axum HTTP server, routes, extractors, middleware
|   |-- application/         # Use cases, authorization, validation orchestration
|   |-- domain/              # Entities, value objects, interfaces, error model
|   |-- infrastructure/      # MySQL, Redis, providers, crypto, OpenTelemetry
|   `-- worker/              # Redis Stream consumers and scheduled reconciliation
|-- migrations/              # SQLx MySQL migrations
|-- openapi/                 # Contract source and generated artifacts
|-- deploy/                  # Docker, environment templates, monitoring configuration
|-- docs/                    # ADRs, ERD, threat model, operational runbooks
`-- tests/                   # Contract, integration, load, and chaos tests
```

Implementation order:
1. Bootstrap workspace, configuration validation, health checks, tracing, error envelope, and CI quality gates.
2. Build MySQL migrations and repositories for users, API keys, products/packages/prices, and append-only ledger.
3. Implement Google OIDC, session/JWT lifecycle, RBAC, and API key issuance/revocation.
4. Implement Redis token buckets, quota reservation, idempotency, and cache invalidation.
5. Implement one provider adapter end-to-end plus mock adapter and normalized validation endpoint.
6. Implement durable stream event production, worker consumer, retry/dead-letter workflow, and reconciliation job.
7. Implement remaining product adapters and admin management APIs with audit logging.
8. Generate OpenAPI documentation and SDK examples; add dashboard separately if desired.
9. Run load, fault-injection, security, and acceptance tests before production rollout.

**Deliverable:** incrementally deployable MVP, followed by controlled production rollout.

### Phase 7 — Testing, Performance, and Production Readiness
**Status:** pending

- Unit tests: domain rules, price selection, quota calculation, API-key validation, PII masking, provider response normalization.
- Integration tests: MySQL migrations, Redis Lua scripts, Google OIDC mock, provider mock, idempotency, worker deduplication, and reconciliation.
- Contract tests: OpenAPI request/response/error compatibility and provider adapter expectations.
- Load tests: establish baseline at target peak RPS using realistic provider latency distributions; report API-side p50/p95/p99 separately from provider latency.
- Failure tests: MySQL slow/down, Redis failover, provider timeout/429/5xx/malformed payload, duplicate stream delivery, worker restart, cache invalidation, depleted quota, clock drift.
- Security tests: SAST, dependency audit, secrets scan, OWASP API checks, fuzzing key/request parsers, authorization regression suite, and manual pen test before launch.
- Observability: OpenTelemetry traces; Prometheus metrics for API latency, provider latency/error rate, limiter rejections, quota use, worker lag, stream pending count, ledger reconciliation differences, MySQL pool utilization, Redis errors, and circuit state.
- SLO proposal: API overhead p95 under 20 ms when cache/Redis are healthy (excluding provider latency); define end-to-end targets separately per provider. Alert on p95/p99 regression, provider degradation, queue lag, reconciliation mismatch, and error budgets.

**Deliverable:** production-readiness checklist, capacity plan, dashboards, alerts, rollback plan, and incident runbooks.

### Phase 8 — Development-Only Local Role Sign-In
**Status:** complete

- Inspect the current Google OIDC, session, development-token, API authorization, and dashboard authentication paths.
- Add a development-only email/password sign-in path for a Bunny administrator and temporary dummy member. The path must be unavailable outside the development environment.
- Issue normal signed sessions with explicit roles and enforce authorization on the server; a member session must never gain administrative access through client-side dashboard behavior.
- Adapt the static dashboard's unauthenticated UX to offer the local credentials only when the API explicitly advertises local development access.
- Verify administrator and member behavior against the local API, then document credentials and production safeguards.

**Deliverable:** safely isolated development credentials, role-aware local authentication behavior, and verified documentation.

### Phase 9 — Admin-Managed Third-Party Endpoints
**Status:** complete

- Re-analyze the current environment-only HTTP provider, administration store, routes, and dashboard controls.
- Add a runtime provider configuration abstraction that supports safe masked reads and audited administrator updates without exposing stored credentials.
- Persist provider routes in MySQL where available and provide a development-only in-memory fallback consistent with the existing demo architecture.
- Validate outbound endpoint URLs against SSRF risks, enforce bounded timeouts, and reject unsafe production destinations.
- Route validation requests through the active product-specific provider configuration without restarting the API.
- Add dashboard controls, API documentation, tests, and end-to-end verification.

**Deliverable:** authenticated administrator management of third-party endpoints, safe secret rotation, dynamic validation routing, and verified documentation.

### Phase 10 — Product-Aware Provider JSON Mapping and Sidebar Repair
**Status:** complete

- Add administrator-configurable JSON response paths and status-value mappings per third-party endpoint.
- Normalize bank responses into status, account name, provider, reference, and message fields.
- Normalize e-wallet responses as registration status only, intentionally suppressing account-holder names even if an upstream payload contains them.
- Normalize WhatsApp responses into registration/reachability status with optional provider/reference metadata.
- Validate mappings server-side, persist them with endpoint configuration, and preserve compatibility with the normalized default provider contract.
- Build a product-aware dashboard mapping editor with clear examples and fix sidebar scrolling/stacking so Settings remains clickable at short viewport heights.
- Update contracts/documentation and add behavioral tests for JSON-path extraction and product-specific privacy behavior.

**Deliverable:** safe configurable upstream JSON normalization and a reliable responsive administration navigation layout.

### Phase 11 — Tukangcek Provider Contract and Bank-Code Translation
**Status:** complete

- Import and normalize the supplied bank catalog so Rajacek accepts public three-digit bank codes.
- Keep Rajacek bank codes separate from Tukangcek IDs; initially record only explicitly confirmed mappings such as BRI `002` → `BRIC1ID` rather than inventing unknown provider codes.
- Add endpoint-selectable request contracts and credential-header names so Tukangcek receives `X-API-Key` and its product-specific JSON bodies.
- Normalize Tukangcek `found`/`registered` booleans and documented HTTP errors without leaking upstream balance or internal data.
- Keep the supplied credential out of source, documentation, logs, and versioned configuration; it must be entered through the encrypted admin credential field or environment bootstrap.
- Update dashboard controls, OpenAPI, documentation, tests, and runtime verification.

**Deliverable:** verified Tukangcek bank/e-wallet/WhatsApp adapter behavior with safe secret handling and explicit bank-code translation.

### Phase 12 — Admin Service Tester and Tukangcek UI Visibility
**Status:** complete

- Verify the served dashboard bundle contains Tukangcek request-mode controls and clarify that they appear inside each endpoint's **Kelola** modal.
- Add a dedicated, protected administration tester for bank, e-wallet, and WhatsApp with service-specific fields.
- Use active provider configuration and normalized output while deliberately bypassing member quota, billing, and idempotency.
- Populate bank selection from the normalized catalog and disable entries whose Tukangcek mapping is not yet available.
- Present only safe normalized result fields and preserve e-wallet privacy restrictions.
- Update OpenAPI/documentation and perform rebuild/runtime verification.

**Deliverable:** clearly visible Tukangcek endpoint configuration and an admin-only product-aware provider tester.

### Phase 13 — Tester Field Visibility and Latency Telemetry
**Status:** complete

- Enforce the HTML `hidden` attribute globally so bank and e-wallet controls cannot be made visible by form-grid display rules.
- Show only bank code for bank, only wallet provider for e-wallet, and neither selector for WhatsApp.
- Add provider latency, Rajacek processing latency, and total latency in milliseconds to normal validation metadata.
- Add the same timing split to the administrator tester API and result UX.
- Document timing semantics and verify runtime output for tester and member validation paths.

**Deliverable:** context-correct tester controls and explicit end-to-end latency telemetry.

### Phase 14 — Visible Tukangcek State and Live Tester Enforcement
**Status:** complete

- Show Tukangcek/Generic mode directly on each Endpoint Provider card and add a page-level active-contract summary.
- Cache-bust dashboard CSS/JavaScript assets so clients cannot remain on the previous UI after deployment.
- Bootstrap all three product endpoints as Tukangcek when the HTTP bootstrap URL belongs to `tukangcek.id`.
- Reject admin tester execution in demo mode so tester results can never be mistaken for live Tukangcek responses.
- Restart the local service in HTTP mode with the supplied credential held only in process environment and verify a real WhatsApp response.

**Deliverable:** unmistakable live Tukangcek configuration in admin UI and tester output that cannot originate from the demo adapter.

### Phase 15 — Re-verify Live Provider Tester and Endpoint Settings
**Status:** complete

- Check the running local API's actual provider mode and the served admin dashboard contract controls.
- Authenticate as a development administrator and inspect masked endpoint configuration for every product.
- Execute safe per-product tester requests through the admin route; distinguish genuine upstream errors from demo responses and never disclose secrets or customer data.
- Record current operational results and any unavailable dependencies without claiming unverified services work.

**Deliverable:** current, credential-safe verification of live Tukangcek routing and administrator endpoint visibility. Completed: HTTP-mode listener and served dashboard verified; three active masked Tukangcek settings confirmed; bank/WhatsApp returned normalized `not_found`; e-wallet returned HTTP 503, while DNS/destination checks succeeded. Detailed results are in `progress.md`.

### Phase 16 — Admin Tester HTML / JSON Audit Views
**Status:** complete

- Inspect the admin tester response contract and current rendering, including failed-request behavior.
- Provide accessible HTML and JSON tabs showing the same safe normalized tester response, with clear error feedback and no upstream raw payload or credentials.
- Verify UI behavior, syntax, and relevant server checks; update documentation and progress.

**Deliverable:** administrator tester response with readable HTML and inspectable JSON views, both safe for auditing.

### Phase 17 — Admin Tester Raw Upstream Response Tab
**Status:** complete

- Trace provider HTTP read, normalization, tester success/error paths, and admin authorization.
- Expose bounded raw upstream response only on the admin tester path, including non-2xx upstream responses where available; prevent secrets in upstream headers and avoid logging or persistence.
- Add a third accessible tester tab showing the exact captured response body and status without HTML interpretation; document privacy/security limitations.
- Add targeted tests and run available Rust and UI checks.

**Deliverable:** admin-only third tab showing the real third-party response body from the same tester request, with bounded capture and documented sensitive-data behavior.

### Phase 18 — Tukangcek E-wallet Codes and Found Response
**Status:** completed

- Trace public e-wallet slugs, admin tester input, Tukangcek request mapping, and persisted/default response mapping.
- Translate the nine supported public e-wallet slugs into the provider's supplied IDs while keeping public API codes stable; normalize provider `found`, `name`, `target`, and `channel` without exposing balance/account fields.
- Add focused mapping and response tests, update documentation and configuration defaults, and run available checks.

**Deliverable:** correct Tukangcek e-wallet outbound IDs and success/not-found normalization for member and admin tester requests.

### Phase 19 — aaPanel Deployment Guide
**Status:** complete

- Inspect the runtime configuration, production validation rules, Dockerfile, Compose profile, migrations, and static asset embedding before documenting a deployment path.
- Fix the container build so the builder stage contains the compile-time embedded `web/` and `openapi/` directories.
- Write an Indonesian installation and deployment guide covering aaPanel hardening, MySQL/Redis, production `.env` requirements, a Docker Compose production profile, a native systemd profile, Nginx reverse proxy with SSL, Google OAuth, verification, updates, backup, and troubleshooting.
- Document current implementation limits that affect a real production rollout, especially the in-memory administration store.

**Deliverable:** `DEPLOY_AAPANEL.md` plus a buildable production container context.

## MVP Implementation Assumptions
- Build a working, Indonesian-language administrative web dashboard together with a Rust/Axum API foundation now.
- Use local/demo provider adapters until the user supplies approved third-party provider specifications and credentials.
- Make Google OIDC configuration-ready; actual sign-in cannot be activated without the Google client ID, secret, callback URL, and consent-screen setup.
- Provide MySQL/Redis schema, configuration, and Docker development environment; no production secret or provider credential will be hard-coded.
- Implement the commercial/rate-limit controls as an administrator-facing foundation. Final charging semantics and real payment integration remain pending business confirmation.

## Immediate Next Step
Phase 19 documentation is complete. Any future live Tukangcek test should use approved credentials and an available upstream; database migration execution remains dependent on a running MySQL environment, and the aaPanel guide's Compose/systemd paths remain unexecuted until a server is available.

## Decisions Made
| Decision | Rationale | Status |
|---|---|---|
| Use Rust/Axum/Tokio for API runtime | High-concurrency async HTTP with strong type safety | Confirmed for MVP |
| Build the first admin dashboard as a dependency-light static SPA served by Axum | Enables a polished responsive UI without a separate Node build pipeline; API remains independently consumable | Confirmed for MVP |
| Use explicit demo/provider-mock mode until real approved provider contracts are supplied | Prevents unsafe fabricated upstream integrations while making the product demonstrable | Confirmed for MVP |
| Use MySQL for system-of-record data | User requirement and operational compatibility | Confirmed |
| Use Redis Streams plus a separate worker for non-critical writes | Keeps response latency independent from audit/analytics write latency | Proposed |
| Use Redis atomic scripts for rate limits and fast quota reservation | Avoids MySQL contention on every validation hit | Proposed |
| Use Google OIDC authorization-code flow with PKCE | Secure server-side identity verification | Proposed |
| Use append-only, idempotent ledger with price snapshots | Correct billing despite retries and future price changes | Proposed |
| Gate temporary local email/password sign-in to development mode only | Supports local role demonstrations without creating a production password-authentication surface | Confirmed for local demo |
| Manage third-party endpoints through an authenticated admin API with masked credentials and server-side URL validation | Enables runtime operations without exposing secrets or trusting dashboard-only controls | Confirmed for Phase 9 |

## Errors Encountered
| Error | Attempt | Resolution |
|---|---:|---|
| `git diff --stat` returned exit code 129 because the empty workspace is not a Git repository. | 1 | Recorded workspace state; no retry needed. Initialize Git later if version control is desired. |
| Initial `cargo check` could not find MSVC `link.exe`. | 1 | Installed Visual C++ Build Tools; the toolchain now reaches application compilation from a Visual Studio developer environment. |
| Application compilation reported Redis async generic/connection errors, Axum response-layer type incompatibilities, and cached response deserialization errors. | 1 | Updated Redis 0.27 command signatures, cached-response deserialization, and middleware ordering. `cargo fmt --all -- --check`, `cargo check --all-targets`, and `cargo test --all-targets` now pass. |
| Developer-command prompt path assumed in an automated check was not found. | 1 | Discover the installed Visual Studio location with `vswhere` or locate `link.exe`, then use the discovered environment setup path instead of retrying the hard-coded command. |
| Authenticated overview smoke assertion piped through `findstr` exited with code 1. | 1 | The endpoint itself returned `200 OK`; the filter used nonexistent field names. Retrieved the unfiltered response and verified the actual dashboard schema (`metrics.total_requests_today`, traffic, service health, masked activity, and alerts). |
| Recovery `git diff --stat` returned exit code 129 because the project remains outside a Git repository. | 1 | Expected environmental limitation. Do not retry it for source verification; inspect tracked files directly instead. |
| Local role-sign-in resumption `git diff --stat` returned exit code 129 because the workspace remains outside a Git repository. | 1 | Expected environmental limitation reconfirmed during plan recovery; inspect source files directly rather than retrying source-diff verification. |
| Phase 9 recovery `git diff --stat` returned exit code 129 because the workspace remains outside a Git repository. | 1 | Logged the known limitation and continued with direct source inspection. |
| Phase 9 combined format/test command stopped because `cargo fmt --check` found formatting differences. | 1 | Run `cargo fmt --all` first, then execute the checks/tests as separate verification. |
| PowerShell `ConvertFrom-Yaml` was unavailable while validating OpenAPI. | 1 | Used Python/PyYAML successfully instead of repeating the unavailable cmdlet. |
| `cargo build --bin rajacek-api` could not replace the executable because the currently running API process holds it open. | 1 | Verified/stopped the exact Rajacek process, rebuilt successfully, and relaunched the current binary. |
| First PowerShell runtime update smoke test returned HTTP 405 for `PUT /v1/admin/provider-endpoints/bank_account`. | 1 | Corrected Axum path syntax, rebuilt, and verified update/test routes successfully. |
| Initial Phase 10 provider-adapter patch was rejected because one search/replace block omitted the required separator. | 1 | No source was changed; split the provider edit into smaller valid patches instead of repeating the malformed block. |
| Phase 10 compile check found `serde_json::Value` lacks MySQL SQLx encode/decode support under the current feature set. | 1 | Store/load the JSON mapping as a serialized `String`; MySQL validates/casts it into the JSON column without adding broader SQLx features. |
| First BANK_CODE normalization command could not write `data/bank_codes.json` because the `data` directory did not exist. | 1 | Created the project data directory, then normalized 110 distinct code/name entries. |
| Rust tests could not parse embedded `data/bank_codes.json` because PowerShell wrote a UTF-8 BOM. | 1 | Rewrote the normalized catalog as UTF-8 without BOM; all tests passed. |
| Combined live Tukangcek smoke command stopped when the e-wallet upstream returned documented HTTP 503. | 1 | Query each service independently and record status/body; do not treat a real upstream offline response as evidence that the tester used demo data. |
| Phase 15 recovery `git diff --stat` returned exit code 129 because this workspace is not a Git repository. | 1 | Inspect the actual running service and source directly instead. |
| A progress-log patch failed because a whitespace-only search block was treated as empty. | 1 | Anchor the insertion on the final substantive progress-log sentence. |
| Phase 17 recovery `git diff --stat` returned exit code 129: workspace remains outside Git. | 1 | Inspect files directly; no retry. |
| Phase 18 recovery `git diff --stat` returned exit code 129: workspace remains outside Git. | 1 | Inspect files directly; no retry. |
| Phase 18 `cargo fmt --all -- --check` found formatting differences in new tests, so chained tests did not run. | 1 | Run `cargo fmt --all`, then rerun format and tests. |
| Phase 19 Dockerfile builder stage omitted `web/` and `openapi/` while `src/api.rs` embeds both with `include_str!`, which would fail the container build. | 1 | Added `COPY web ./web` and `COPY openapi ./openapi` to the builder stage before `cargo build`. |

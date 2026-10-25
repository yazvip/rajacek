# Rajacek Dummy Development Data

This file centralizes the dummy values currently used for local development and smoke testing. None of these values are approved for production use.

## Safety Rules

- Use these values only with `APP_ENV=development`.
- Never use real account numbers, phone numbers, credentials, or customer data in demo tests.
- Do not reuse these passwords, tokens, or API keys in another environment.
- Production must use Google OIDC, generated member API keys, approved provider credentials, MySQL, Redis, and managed secrets.

## Local Dashboard Accounts

| Role | Email | Password | Expected access |
|---|---|---|---|
| Administrator | `bunny.admin@local.test` | `BunnyAdmin!2026` | Can access `/admin` and `/v1/admin/*`. |
| Member | `dummy.member@local.test` | `DummyMember!2026` | Can create a valid local session but must be denied access to `/v1/admin/*`. |

These accounts are available only in development mode. Their current implementation is defined in `src/auth.rs`.

## Development Administrator Token

Example value:

```text
replace-with-a-local-only-token
```

Environment variable:

```dotenv
DEVELOPMENT_ADMIN_TOKEN=replace-with-a-local-only-token
```

This token is an optional development-only fallback. Production startup rejects it.

## Demo Member API Key

Example value:

```text
rv_live_local_0123456789abcdef0123456789abcdef0123456789abcdef
```

Environment variable:

```dotenv
DEMO_API_KEY=rv_live_local_0123456789abcdef0123456789abcdef0123456789abcdef
```

The demo key has the `validate:*` scope in the in-memory development store.

## Dummy Bank Account Validation

Endpoint:

```text
POST /v1/validate/bank-account
```

Headers:

```text
X-API-Key: rv_live_local_0123456789abcdef0123456789abcdef0123456789abcdef
Idempotency-Key: dummy-bank-validation-001
Content-Type: application/json
```

Body:

```json
{
  "bank_code": "BCA",
  "account_number": "1234567890",
  "account_holder_hint": "BUDI SANTOSO"
}
```

Use a new `Idempotency-Key` for a new operation. Reusing the same key and payload tests idempotent replay.

## Dummy E-Wallet Validation

Endpoint:

```text
POST /v1/validate/ewallet
```

Headers:

```text
X-API-Key: rv_live_local_0123456789abcdef0123456789abcdef0123456789abcdef
Idempotency-Key: dummy-ewallet-validation-001
Content-Type: application/json
```

Body:

```json
{
  "provider": "gopay",
  "account_number": "081234567890"
}
```

## Dummy WhatsApp Validation

Endpoint:

```text
POST /v1/validate/whatsapp
```

Headers:

```text
X-API-Key: rv_live_local_0123456789abcdef0123456789abcdef0123456789abcdef
Idempotency-Key: dummy-whatsapp-validation-001
Content-Type: application/json
```

Body:

```json
{
  "phone_number": "+6281234567890"
}
```

This is test data only and does not assert ownership of a real WhatsApp number.

## Dummy Third-Party Provider Endpoints

Use these only to exercise dashboard configuration. They are placeholders and do not represent approved or operational providers.

| Product | Provider name | Endpoint URL | Timeout | Active |
|---|---|---|---:|---|
| `bank_account` | Bank Sandbox | `http://127.0.0.1:19090/validate/bank-account` | `2500` ms | Yes |
| `ewallet` | E-Wallet Sandbox | `http://127.0.0.1:19090/validate/ewallet` | `2500` ms | Yes |
| `whatsapp` | WhatsApp Sandbox | `http://127.0.0.1:19090/validate/whatsapp` | `2500` ms | Yes |

Example dummy bearer credential:

```text
sandbox-provider-secret
```

Local loopback URLs are accepted only in non-production environments. Production requires HTTPS, an explicit `PROVIDER_ALLOWED_HOSTS` entry, and a public network destination.

For Tukangcek configuration, select request mode `tukangcek`, use auth header `X-API-Key`, and enter the real credential only in the encrypted dashboard field. The credential supplied during integration discovery is intentionally not copied into this file or source code.

Confirmed bank-code translation:

| Public `code_bank` | Bank | Tukangcek request `id` |
|---|---|---|
| `002` | BRI | `BRIC1ID` |

The complete public catalog is stored in `data/bank_codes.json`. Rows with `tukangcek_code: null` cannot be sent through Tukangcek until their exact provider IDs are supplied and reviewed.

Tukangcek e-wallet IDs are internal and differ from the public request slugs:

| Public `provider` | Tukangcek request `id` |
|---|---|
| `dana` | `DANA001` |
| `astrapay` | `ASTRAPAY001` |
| `gopay` | `GOPAY001` |
| `gopay_driver` | `GOPAY002` |
| `isaku` | `ISAKU001` |
| `kaspro` | `KASPRO001` |
| `linkaja` | `LINKAJA001` |
| `ovo` | `OVO001` |
| `shopeepay` | `SHOPEEPAY001` |

For example, the public dummy request using `gopay` sends `{ "type": "ewallet", "target": "081234567890", "id": "GOPAY001" }` in Tukangcek mode. Its e-wallet response `found: true` / `found: false` becomes `registered: true` / `registered: false` and `valid` / `not_found`, respectively. If `found` is missing or invalid the response is rejected. The normal member response never exposes upstream `name`, `target`, `channel`, `balance`, or `checkedAt`.

### Dummy JSON Mapping Examples

Bank response:

```json
{
  "data": {
    "status": "OK",
    "message": "Account matched",
    "bank": { "code": "BCA" },
    "account": { "name": "BUDI SANTOSO" }
  },
  "meta": { "reference": "bank-ref-001" }
}
```

Suggested bank mapping:

```json
{
  "status_path": "data.status",
  "valid_values": ["OK"],
  "invalid_values": ["INVALID"],
  "not_found_values": ["MISSING"],
  "pending_values": ["PENDING"],
  "message_path": "data.message",
  "account_name_path": "data.account.name",
  "provider_path": "data.bank.code",
  "registered_path": null,
  "reference_path": "meta.reference"
}
```

E-wallet response:

```json
{
  "payload": {
    "state": "ACTIVE",
    "is_registered": true,
    "account_name": "MUST NOT BE EXPOSED"
  }
}
```

Suggested e-wallet mapping:

```json
{
  "status_path": "payload.state",
  "valid_values": ["ACTIVE"],
  "invalid_values": ["INACTIVE"],
  "not_found_values": ["NOT_REGISTERED"],
  "pending_values": ["PENDING"],
  "message_path": null,
  "account_name_path": null,
  "provider_path": null,
  "registered_path": "payload.is_registered",
  "reference_path": null
}
```

For custom generic-mode endpoints, Rajacek intentionally emits only `registered` for e-wallet result data. The upstream `account_name`, provider-result label, and reference are ignored. Tukangcek-mode endpoints instead use the fixed `found` contract above, even if an older generic mapping is stored.

## Seeded Dashboard Catalog

### Products

| Code | Name | Provider route | Base price |
|---|---|---|---:|
| `bank_account_validation` | Validasi Rekening | `primary-bank-id` | Rp250/hit |
| `ewallet_validation` | Validasi E-Wallet | `primary-ewallet-id` | Rp200/hit |
| `whatsapp_validation` | Validasi WhatsApp | `primary-whatsapp-id` | Rp150/hit |

### Packages

| Package | Price | Included hits | Rate limit | Products |
|---|---:|---:|---:|---|
| Starter | Rp99,000 | 500 | 30 RPM | Bank account, e-wallet |
| Growth | Rp399,000 | 3,000 | 120 RPM | All products |
| Scale | Rp1,499,000 | 15,000 | 600 RPM | All products |

### Rate-Limit Policies

| Policy | Scope | Requests/minute | Burst | Concurrency |
|---|---|---:|---:|---:|
| Pengaman global | `global` | 8,000 | 400 | 800 |
| Kunci API standar | `api_key` | 120 | 30 | 12 |
| Proteksi IP publik | `ip` | 180 | 45 | 24 |

The seeded dashboard catalog is generated by the in-memory development store in `src/store.rs`. It is illustrative and does not replace production database configuration.

# CLAUDE.md — HA Easy Control

Home Assistant HACS integration providing scoped guest access to door locks and garage covers via an iOS companion app.

- **Domain:** `easy_control` | **Version:** 0.4.0 | **Python:** 3.12
- **Runtime dep:** `segno==1.6.6` (QR generation, lazy-imported in `api.py`)
- **iOS companion app repo:** `../ha-easy-control` (Swift/SwiftUI, iOS 16+, MVVM)
- **Deep link scheme:** `easy-control://pair`

## How It Works

This is a **HACS custom component** that pairs with an iOS app to give guests scoped, time-limited access to specific Home Assistant entities (door locks, garage covers) without giving them a full HA account.

### End-to-End Flow
1. **Admin** calls `create_guest_pass` service → creates `PairingRecord` (in-memory, 5-min TTL) + QR deep link
2. **QR code** is shown via persistent notification or `/api/easy_control/qr` endpoint (non-consuming, repeatable until scan)
3. **iOS app** scans QR → calls `POST /pair/scanned` to acknowledge scan (one-time, disables QR display)
4. **iOS app** calls `POST /pair` with `pairing_code`, `device_id`, `device_public_key` → receives scoped JWT
5. **iOS app** requests nonce (`GET /action/nonce`) then executes action (`POST /action`) with optional Ed25519 proof
6. **Action mapping:** `door.open` → `lock.unlock`, `garage.open` → `cover.open_cover`

### QR Payload
Actions and configuration are transmitted to the iOS app via QR code containing a deep link:
```
easy-control://pair?pairing_code=...&base_url=...&entity_id=...&allowed_action=...&scan_ack_token=...
```

## Module Map

```
custom_components/easy_control/
  __init__.py          Setup: registers API views + services, reads config entry options
  api.py               6 HTTP views (all HomeAssistantView, requires_auth=False for public endpoints)
  config_flow.py       Single-instance config flow + options flow
  const.py             All CONF_*, DATA_*, DEFAULT_*, EVENT_* constants
  network.py           RFC1918 CIDR validation (is_remote_allowed, normalize_allowed_cidrs)
  pairing.py           PairingRecord dataclass + PairingStore (in-memory dict, auto-purge)
  proof.py             Ed25519 action proof: parse, verify, canonical signing input
  runtime_security.py  ActionNonceStore (single-use nonces) + FixedWindowRateLimiter
  services.py          5 HA service handlers (create/revoke/approve/reject)
  storage.py           HA Store persistence: signing keyring, token metadata, revocations
  token.py             GuestTokenManager: create/verify JWT-like tokens, GuestTokenPayload
  services.yaml        Service field definitions for HA UI
  strings.json         UI localization keys
```

## Security Model

- **JWT-like tokens** (HS256) with rotating signing keyring (`storage.py`)
- **Token claims:** `iss`, `aud` (localkey_ios), `jti`, `guest_id`, `entity_id`, `allowed_action`, `iat`, `nbf`, `exp`, `max_uses`, `token_version`, `device_id`, `cnf.jkt`
- **Multi-use tokens:** `max_uses=0` means unlimited until expiry/revocation; finite values enforce use count
- **Optional Ed25519 device binding** + proof of possession (nonce + signed action proof)
- **Revocation:** per-token JTI, per-guest_id, or global `token_version` increment
- **Rate limiting:** fixed-window per endpoint bucket (pair/action/qr/nonce)
- **Network policy:** optional RFC1918 local-only restriction
- **Constant-time comparison:** `hmac.compare_digest` for all token/code checks
- **Thread safety:** `asyncio.Lock` via `_get_storage_lock()` for storage mutations

## Allowed Entities & Actions

- `lock.*` entities → `door.open` action → `lock.unlock` service
- `cover.*` entities → `garage.open` action → `cover.open_cover` service

## Key Data Flow

- `hass.data[DOMAIN]` holds: `PairingStore`, `ActionNonceStore`, `FixedWindowRateLimiter`, per-entry config
- Persistent state via HA Store (key `easy_control.keys`): signing keyring, active_kid, token_version, use counts, revoked JTIs, issued token metadata
- Pairing store is **in-memory only** (not persisted); records auto-purge on 5-min expiry

## Action Proof Canonical Format

The Ed25519 proof uses a **newline-delimited** canonical signing input (NOT JSON-signed):
```
METHOD\npath\nts\nnonce\njti\ndevice_id\nbody_sha256
```
- Source of truth: `proof.py:build_proof_signing_input()`
- `body_sha256` is **hex-encoded** (not base64url)
- Headers: `X-Easy-Control-Proof` (base64url JSON), `X-Easy-Control-Proof-Signature` (base64url Ed25519 sig)

## API Response Contracts

**`POST /pair`** (pairing exchange):
```json
{"guest_token", "allowed_actions", "expires_at", "guest_id", "max_uses",
 "proof_required", "device_binding_required", "nonce_endpoint", "scan_ack_supported"}
```

**`POST /pair/scanned`** (scan acknowledge):
```json
{"success": true, "status": "acknowledged"|"already_acknowledged",
 "pairing_code", "qr_scanned_at"}
```

**`POST /action`** (action execution):
```json
{"success": true, "action", "entity_id", "remaining_uses", "used_count"}
```
`remaining_uses=-1` signals unlimited (`max_uses=0`)

**`POST /token/validate`** (token validation):
```json
{"guest_id", "allowed_actions", "entity_id", "expires_at", "remaining_uses"}
```

## iOS Companion App

- **Repo:** `../ha-easy-control`
- **Bundle ID:** `de.vselas.HAEasyControl`
- **Stack:** Swift/SwiftUI, iOS 16+, MVVM, async/await
- **QR scanning:** `AVCaptureSession` + `AVCaptureMetadataOutput`
- **Crypto:** Ed25519 via CryptoKit `Curve25519.Signing`, SHA-256 for body hashes
- **Token storage:** iOS Keychain (`de.vselas.HAEasyControl` service), structured JSON with metadata
- **Auth:** Biometric (Face ID) + passcode via `LocalAuthentication`
- **TLS pinning:** Custom `URLSessionDelegate` with per-host SHA-256 pinning
- **Logging:** `os.Logger` with 8 structured categories, privacy-aware redaction

## Development Commands

```bash
source .venv/bin/activate

# Lint
ruff check .

# Type check
mypy

# Tests
pytest --maxfail=1 --disable-warnings

# Tests with coverage (matches CI)
pytest --cov=custom_components/easy_control --cov-report=term-missing --cov-fail-under=60

# Security module coverage gate (CI enforced at 85%)
# Modules: network.py, pairing.py, proof.py, runtime_security.py, token.py
```

## Testing Patterns

- **Async:** `asyncio_mode = auto` in `pytest.ini`; all HA-dependent tests are async
- **Deterministic time:** `now_ts` fixture in `conftest.py`; pass `now_timestamp=` to token/limiter methods
- **Token helpers:** `GuestTokenManager("test-signing-key")` + `create_guest_token(...)`
- **Markers:** `@pytest.mark.integration`, `@pytest.mark.security`
- **Fuzz:** `hypothesis` for malformed input tests (`test_fuzz_security.py`)
- **Coverage gates:** overall 60%, security modules 85%

## CI Pipeline (GitHub Actions)

1. ruff lint → 2. mypy → 3. pytest + coverage (60%) → 4. security module coverage (85%) → 5. pip-audit on manifest deps → 6. gitleaks secret scan

## Conventions & Gotchas

- **Single instance:** `async_set_unique_id(DOMAIN)` + `_abort_if_unique_id_configured()`
- **API registration:** guarded by `DATA_API_REGISTERED` flag (once per HA restart)
- **Service registration:** guarded by `has_service()` checks; unregistered on last entry unload
- **Config reads:** options override data via `_get_entry_value(entry, key, default)` in `__init__.py`
- **QR access tokens:** `secrets.token_urlsafe(32)`, separate from guest JWT tokens
- **`segno` import:** lazy (inside QR view handler) so tests don't require it installed
- **`max_uses=0`:** sentinel for unlimited uses; `remaining_uses=-1` in action responses signals unlimited
- **Error responses:** consistent `{"error": "code", "message": "detail"}` JSON structure
- **Events:** prefixed `easy_control.` (services) or literal `easy_control_used` (action audit)
- **Frozen dataclasses:** `PairingRecord`, `GuestTokenPayload`, `ActionProof`, `ActionNonceRecord`
- **`scan_ack_supported: true`:** always included in pairing response for backward compat signaling
- **Proof canonical format:** newline-delimited, NOT JSON-signed (see `proof.py`)
- **Ruff config:** line-length 100, target py312, rules E/F/I/B/UP/SIM

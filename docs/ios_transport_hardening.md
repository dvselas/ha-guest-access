# iOS Transport & Trust Hardening (Companion App)

This backend repo cannot implement iOS runtime security directly, but this document defines the expected app behavior to match the `easy_control` API.

## 1. `base_url` Trust Policy
- Parse `base_url` from scanned QR deep link.
- Show host to the user before pairing.
- Require explicit confirmation for unknown hosts.
- Persist trusted hosts in Keychain-backed settings (not `UserDefaults` if it stores secrets/tokens).
- Re-confirm if a later QR uses a different host.

## 2. HTTPS Enforcement
- Reject `http://` for non-local hosts by default.
- Allow HTTP only in explicit local dev mode.
- Consider RFC1918 + `.local` hosts "local" for dev-mode exception logic.

## 3. TLS Pinning
- Support certificate or public-key pinning for proxy host (Pangolin / reverse proxy).
- Allow at least two pins for rotation.
- Pinning failures must surface a user-visible error state and block pairing/action calls.

## 4. Sensitive Logging
- Never log:
  - `guest_token`
  - `Authorization` header
  - raw QR payload
  - pairing code
- Redact these in network debug logs and crash reports.

## 5. PoP Action Flow (Required when `proof_required=true`)
1. `GET /api/easy_control/action/nonce` with bearer token
2. Build proof payload:
   - `nonce`
   - `ts`
   - `method`
   - `path`
   - `body_sha256`
   - `jti`
   - `device_id`
3. Sign canonical payload with Ed25519 private key
4. Send proof headers with `POST /api/easy_control/action`

## 6. Error Handling Contract
- `pending_approval` (202): show waiting UI and poll/retry pairing
- `token_expired`, `token_revoked`, `token_max_uses_exceeded` (401): delete token and move to expired state
- `action_proof_replay`, `action_nonce_expired`, `action_proof_clock_skew`, `action_proof_invalid` (401): refresh nonce and retry once, then fail closed
- `rate_limited` (429): respect `Retry-After`

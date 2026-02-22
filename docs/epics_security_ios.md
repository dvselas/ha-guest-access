# Backlog Proposal: Security + iOS Compatibility

## EPIC A: JWT Security Hardening

### Feature A.1: Hardened Token Claims
- [x] Add claims: `iss`, `aud`, `jti`, `iat`, `nbf`, `exp`, `max_uses`, `token_version`
- [x] Add `kid` in token header
- [x] Enforce issuer/audience checks

### Feature A.2: Revocation and Replay Protection
- [x] Persist global `token_version` in `.storage`
- [x] Increment `token_version` on `easy_control.revoke_all_guest_pass`
- [x] Persist per-`jti` usage counter and enforce `max_uses`

### Feature A.3: Action Validation Sequence
- [x] Require bearer token
- [x] Validate signature + temporal claims + audience + issuer + token_version + max_uses
- [x] Validate requested action and entity scope before HA service call

## EPIC B: Test Readiness

### Feature B.1: Unit test baseline
- [x] Token tests (`tests/test_token.py`)
- [x] Pairing tests (`tests/test_pairing.py`)
- [x] Network policy tests (`tests/test_security.py`)

### Feature B.2: Integration blueprint
- [x] Action endpoint test blueprint (`tests/test_action_endpoint.py`)
- [x] Revocation test blueprint (`tests/test_revocation.py`)
- [x] Test plan doc (`tests/README.md`)

## EPIC C: iOS Client Compatibility

### Feature C.1: Stable API contract
- [x] Pair endpoint returns `guest_token`, `allowed_actions`, `expires_at`, `guest_id`, `max_uses`
- [x] Action endpoint returns explicit 401 error codes (`token_expired`, `token_revoked`, etc.)

### Feature C.2: SwiftUI integration guidance
- [x] Add iOS networking/security blueprint (`docs/ios_swiftui_blueprint.md`)

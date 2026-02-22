# HA Easy Control Test Blueprint

## Goals
- Verify hardened JWT validation end-to-end.
- Verify pairing one-time behavior, admin approval, and expiration.
- Verify action proof (nonce/signature) parsing and validation helpers.
- Verify revocation state normalization and per-pass revoke building blocks.
- Verify action scoping and local-network policy enforcement.
- Verify parser robustness against malformed token/proof inputs.

## Suggested stack
- `pytest`
- Home Assistant test harness (`pytest-homeassistant-custom-component`)
- async fixtures (`hass`, `hass_client`)

## Structure
- `conftest.py`: shared fixtures
- `test_token.py`: JWT/security claim unit tests
- `test_pairing.py`: pairing lifecycle tests
- `test_proof.py`: proof envelope, thumbprint, signature tests
- `test_runtime_security.py`: nonce + rate limit tests
- `test_security.py`: RFC1918 policy tests
- `test_action_endpoint.py`: action endpoint helper/security response tests
- `test_revocation.py`: revocation storage normalization tests
- `test_fuzz_security.py`: hypothesis-based malformed input robustness tests

## Security Definition of Done
- Token validation paths covered (signature, `iss`, `aud`, `nbf`, `exp`, `token_version`, `max_uses`)
- Device-binding + proof helper validation covered
- Rate limit and nonce replay primitives covered
- No action execution when validation fails
- Malformed JSON and invalid payload paths covered

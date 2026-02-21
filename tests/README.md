# Guest Access Test Blueprint

## Goals
- Verify hardened JWT validation end-to-end.
- Verify pairing one-time behavior and expiration.
- Verify `revoke_all` invalidates existing tokens.
- Verify action scoping and local-network policy enforcement.

## Suggested stack
- `pytest`
- Home Assistant test harness (`pytest-homeassistant-custom-component`)
- async fixtures (`hass`, `hass_client`)

## Structure
- `conftest.py`: shared fixtures
- `test_token.py`: JWT/security claim unit tests
- `test_pairing.py`: pairing lifecycle tests
- `test_security.py`: RFC1918 policy tests
- `test_action_endpoint.py`: integration blueprint
- `test_revocation.py`: integration blueprint

## Security Definition of Done
- Token validation paths covered (signature, `iss`, `aud`, `nbf`, `exp`, `token_version`, `max_uses`)
- `revoke_all` covered with existing token rejection
- No action execution when validation fails
- Malformed JSON and invalid payload paths covered

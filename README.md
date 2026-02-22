# HA Easy Control

Home Assistant custom integration for secure, scoped guest access (door/garage).

## Security model (MVP+)
- Signed JWT-like token (`HS256`)
- Claims: `iss`, `aud`, `jti`, `guest_id`, `entity_id`, `allowed_action`, `iat`, `nbf`, `exp`, `max_uses`, `token_version`
- Optional device binding claims: `device_id`, `cnf.jkt`
- Audience lock: `aud=localkey_ios`
- Replay mitigation: `max_uses` with server-side use counter
- Optional PoP flow: nonce + Ed25519 signed action proof
- Per-pass revocation by `jti` / `guest_id` plus global `token_version` revoke
- Revocation: global `token_version` increment on `easy_control.revoke_all_guest_pass`
- Optional local-network restriction by RFC1918 CIDRs

## API endpoints
- `POST /api/easy_control/pair`
- `GET /api/easy_control/action/nonce`
- `POST /api/easy_control/action`
- `POST /api/easy_control/token/validate`

### Pairing exchange
`POST /api/easy_control/pair`

Body:
```json
{
  "pairing_code": "ABC123XYZ0",
  "device_id": "iphone-guest-01",
  "device_public_key": "<base64url raw ed25519 pubkey>"
}
```

Response:
```json
{
  "guest_token": "<token>",
  "allowed_actions": ["garage.open"],
  "expires_at": 1700003600,
  "guest_id": "guest_xxx",
  "max_uses": 10,
  "proof_required": true,
  "device_binding_required": true,
  "nonce_endpoint": "/api/easy_control/action/nonce"
}
```

Pending approval response (`202`):
```json
{
  "error": "pending_approval",
  "message": "Pairing request is awaiting admin approval"
}
```

### Action nonce
`GET /api/easy_control/action/nonce`

Headers:
```http
Authorization: Bearer <guest_token>
```

Response:
```json
{
  "nonce": "<one-time nonce>",
  "expires_at": 1700000045,
  "jti": "..."
}
```

### Action execution
`POST /api/easy_control/action`

Headers:
```http
Authorization: Bearer <guest_token>
X-Easy-Control-Proof: <base64url(json-proof)>
X-Easy-Control-Proof-Signature: <base64url(ed25519-signature)>
```

Body:
```json
{
  "action": "garage.open"
}
```

Service mapping:
- `door.open` -> `lock.unlock`
- `garage.open` -> `cover.open_cover`

Proof payload JSON (before base64url encoding):
```json
{
  "nonce": "<nonce from /action/nonce>",
  "ts": 1700000000,
  "method": "POST",
  "path": "/api/easy_control/action",
  "body_sha256": "<sha256 hex of request body bytes>",
  "jti": "<token jti>",
  "device_id": "iphone-guest-01"
}
```

### Token validation
`POST /api/easy_control/token/validate`

Body:
```json
{
  "guest_token": "<guest_token>"
}
```

On expiry:
```json
{
  "error": "token_expired",
  "message": "Token has expired"
}
```

## Home Assistant services
- `easy_control.create_guest_pass`
- `easy_control.revoke_all_guest_pass`
- `easy_control.revoke_guest_pass`
- `easy_control.approve_pairing_request`
- `easy_control.reject_pairing_request`

### QR-Code direkt in Home Assistant anzeigen
`easy_control.create_guest_pass` liefert jetzt zusätzlich:
- `qr_image_url` (relativer Pfad innerhalb deiner HA-Instanz)
- `qr_image_path` (immer relativ, z. B. `/api/easy_control/qr?code=H5V24N9PZQ&qr_token=...`)
- `qr_string` (deep link für die App mit `pairing_code`)
- QR deep link scheme: `easy-control://pair`
- `base_url` (Basis-URL für die App)
- QR payload enthält zusätzlich: `entity_id`, `allowed_action`

Wenn `show_qr_notification: true` (Default), erstellt die Integration automatisch eine
`persistent_notification` mit QR-Link und Fallback-Code.

Sicherheitsmodell für den QR-Endpoint:
- `/api/easy_control/qr` ist absichtlich ohne Login erreichbar (Proxy/Internet-kompatibel)
- Zugriff nur mit `code + qr_token` möglich
- `qr_token` ist high-entropy, kurzlebig (max. Pairing TTL) und serverseitig validiert
- `qr_token` ist One-Time-Use: der QR-Bild-Endpoint kann pro Code nur einmal erfolgreich aufgerufen werden
- Antwort ist `Cache-Control: no-store` (Proxy/Browser-Caching minimiert)
- Nach Pairing-Verbrauch oder Ablauf liefert der Endpoint keinen QR mehr

Manuelle Anzeige:
1. Service `easy_control.create_guest_pass` in Developer Tools ausführen.
2. `qr_image_url` aus der Antwort kopieren.
3. URL im eingeloggten Browser öffnen oder in einem Lovelace `picture`/`markdown` Card nutzen.

## Audit
- Event: `easy_control_used`
- Fields: `guest_id`, `entity`, `timestamp`
- Logbook entry written locally in HA

## iOS compatibility notes
- Designed for local iOS client audience: `localkey_ios`
- Bearer-token flow compatible with Swift `URLSession`
- See `/docs/ios_swiftui_blueprint.md`
- See `/docs/ios_transport_hardening.md`

## Tests
See `/tests/README.md` for the security/integration test blueprint.

# HA Easy Control

Home Assistant custom integration for secure, scoped guest access (door/garage).

## Security model (MVP+)
- Signed JWT-like token (`HS256`)
- Claims: `iss`, `aud`, `jti`, `guest_id`, `entity_id`, `allowed_action`, `iat`, `nbf`, `exp`, `max_uses`, `token_version`
- Audience lock: `aud=localkey_ios`
- Replay mitigation: `max_uses` with server-side use counter
- Revocation: global `token_version` increment on `easy_control.revoke_all_guest_pass`
- Optional local-network restriction by RFC1918 CIDRs

## API endpoints
- `POST /api/easy_control/pair`
- `POST /api/easy_control/action`
- `POST /api/easy_control/token/validate`

### Pairing exchange
`POST /api/easy_control/pair`

Body:
```json
{
  "pairing_code": "ABC123XYZ0"
}
```

Response:
```json
{
  "guest_token": "<token>",
  "allowed_actions": ["garage.open"],
  "expires_at": 1700003600,
  "guest_id": "guest_xxx",
  "max_uses": 10
}
```

### Action execution
`POST /api/easy_control/action`

Headers:
```http
Authorization: Bearer <guest_token>
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

### QR-Code direkt in Home Assistant anzeigen
`easy_control.create_guest_pass` liefert jetzt zusätzlich:
- `qr_image_url` (relativer Pfad innerhalb deiner HA-Instanz)
- `qr_image_path` (immer relativ, z. B. `/api/easy_control/qr?code=H5V24N9PZQ&qr_token=...`)
- `qr_string` (deep link für die App mit `pairing_code`)
- `base_url` (Basis-URL für die App)

Wenn `show_qr_notification: true` (Default), erstellt die Integration automatisch eine
`persistent_notification` mit QR-Link und Fallback-Code.

Sicherheitsmodell für den QR-Endpoint:
- `/api/easy_control/qr` ist absichtlich ohne Login erreichbar (Proxy/Internet-kompatibel)
- Zugriff nur mit `code + qr_token` möglich
- `qr_token` ist high-entropy, kurzlebig (max. Pairing TTL) und serverseitig validiert
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

## Tests
See `/tests/README.md` for the security/integration test blueprint.

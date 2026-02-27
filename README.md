# HA Easy Control

Give guests, family and friends scoped, time-limited access to your smart home — no Home Assistant account needed.

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz)
[![HA Version](https://img.shields.io/badge/Home%20Assistant-2024.1%2B-blue.svg)](https://www.home-assistant.io)

## Overview

HA Easy Control is a Home Assistant custom integration that lets you create temporary guest passes for specific devices. Guests scan a QR code (or tap a link in an email) with the iOS companion app and get instant access — scoped to exactly the entities and actions you allow.

No passwords, no shared accounts, no full dashboard access. When the pass expires or you revoke it, access is gone.

## Features

- **Locks, garages, switches, lights, sensors & climate** — grant access to exactly what you choose
- **Time-limited & use-limited** — passes expire automatically; optionally limit the number of uses
- **QR code delivery** — shown as a persistent notification in HA, or served via a direct URL
- **Email delivery** — send the QR code and a clickable deep link directly to the guest's inbox
- **Admin approval workflow** — optionally require manual approval before a pass becomes active
- **Revocation** — revoke a single token, all tokens for a guest, or all tokens globally
- **Rate limiting** — per-endpoint rate limits to prevent abuse
- **Local-only mode** — optionally restrict access to your local network
- **Device binding** — optional Ed25519 cryptographic proof-of-possession
- **Audit events** — every guest action fires an event you can use in automations

## Requirements

| Requirement | Version |
|---|---|
| Home Assistant | 2024.1 or later |
| HACS | Latest |
| HA Easy Control iOS app | iOS 16+ |

## Installation

### Via HACS (recommended)

1. Open HACS in your Home Assistant instance
2. Click the three-dot menu (top right) → **Custom repositories**
3. Add the repository URL and select category **Integration**
4. Search for "HA Easy Control" and click **Install**
5. Restart Home Assistant

### Manual

1. Copy the `custom_components/easy_control` folder into your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant

## Setup

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **HA Easy Control**
3. Follow the config flow — no additional parameters are needed for initial setup
4. The integration is single-instance (one config entry per HA installation)

To change settings later: **Settings → Devices & Services → HA Easy Control → Configure**.

## Configuration Options

All options are configured through the integration's options flow in the UI.

### Security

| Option | Default | Description |
|---|---|---|
| Local only | `false` | Restrict all API endpoints to local network (RFC 1918) |
| Allowed CIDRs | `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16` | Comma-separated CIDRs allowed when local-only is enabled |
| Require device binding | `false` | Enforce Ed25519 device key binding on pairing |
| Require action proof | `false` | Require signed proof-of-possession for every action |
| Default require admin approval | `false` | New passes require admin approval before activation |

### Rate Limits

| Option | Default |
|---|---|
| Pairing rate limit | 10/min |
| Action rate limit | 30/min |
| QR rate limit | 20/min |
| Entity states rate limit | 30/min |

### Proof-of-Possession

| Option | Default | Description |
|---|---|---|
| Nonce TTL | 45 seconds | How long a single-use nonce remains valid |
| Clock skew tolerance | 30 seconds | Allowed time drift for action proofs |

## Usage

### Creating a Guest Pass

Open **Developer Tools → Services** and call `easy_control.create_guest_pass`:

```yaml
service: easy_control.create_guest_pass
data:
  entities:
    - lock.front_door
  expiration_time: 3600
```

This creates a pairing code valid for 5 minutes. The guest has that window to scan the QR code with the iOS app. Once paired, their token is valid for the duration you specified (3600 seconds = 1 hour).

#### Multiple entities

```yaml
service: easy_control.create_guest_pass
data:
  entities:
    - lock.front_door
    - cover.garage_door
    - light.porch
  expiration_time: 7200
```

Actions are auto-inferred from the entity domain — locks get lock/unlock, covers get open/close, lights get on/off, sensors get read-only access.

#### Limited uses

By default, passes allow unlimited uses until expiry. To limit uses, the token's `max_uses` is set during pairing. A value of `0` means unlimited.

#### With admin approval

```yaml
service: easy_control.create_guest_pass
data:
  entities:
    - lock.front_door
  expiration_time: 3600
  require_admin_approval: true
```

The guest's pairing attempt will be held pending until you approve it (see [Admin Approval Workflow](#admin-approval-workflow)).

### Email Delivery

Send the guest pass directly to someone's email — they receive an HTML email with an inline QR code and a clickable link that opens the iOS app.

#### Prerequisites

Set up an email notify service in your `configuration.yaml`:

```yaml
notify:
  - name: email
    platform: smtp
    server: smtp.gmail.com
    port: 587
    timeout: 15
    sender: your-email@gmail.com
    recipient: your-email@gmail.com
    encryption: starttls
    username: your-email@gmail.com
    password: !secret smtp_password
    sender_name: "Home Assistant"
```

> **Note:** `recipient` is required by the SMTP platform. Set it to your own email as a default — the integration overrides it with the guest's address at send time via the `email_recipient` parameter.

Restart Home Assistant after adding the configuration.

#### Sending a pass by email

```yaml
service: easy_control.create_guest_pass
data:
  entities:
    - lock.front_door
  expiration_time: 3600
  email_recipient: "guest@example.com"
  email_notify_service: "email"
  email_guest_name: "Alice"
```

| Parameter | Required | Description |
|---|---|---|
| `email_recipient` | Yes (with email) | The guest's email address |
| `email_notify_service` | Yes (with email) | Name of your HA notify service (e.g. `email` for `notify.email`) |
| `email_guest_name` | No | Personalizes the email greeting |

The email includes:
- An inline QR code image
- A deep link button that opens the iOS app directly
- The entity names being granted
- The expiration time
- A fallback pairing code for manual entry

Email delivery is fire-and-forget — if sending fails, the pass is still created and the QR notification still appears.

### Revoking Access

#### Revoke a specific token

```yaml
service: easy_control.revoke_guest_pass
data:
  jti: "token-id-here"
```

#### Revoke all tokens for a guest

```yaml
service: easy_control.revoke_guest_pass
data:
  guest_id: "guest_abc123"
```

#### Emergency: revoke all tokens globally

```yaml
service: easy_control.revoke_all_guest_pass
```

This rotates the signing key — all previously issued tokens become invalid immediately.

### Admin Approval Workflow

When `require_admin_approval` is set (either per-pass or as the default in options), the pairing flow changes:

1. Guest scans QR and attempts to pair → receives a "pending approval" response
2. You receive a notification with the pairing code
3. Approve or reject:

```yaml
# Approve
service: easy_control.approve_pairing_request
data:
  pairing_code: "ABC123XYZ0"

# Reject
service: easy_control.reject_pairing_request
data:
  pairing_code: "ABC123XYZ0"
```

## iOS Companion App

The [HA Easy Control iOS app](https://github.com/dvselas/ha-easy-control-companion) is the guest-facing client.

### How guests use it

1. **From QR code**: Open the app → scan the QR code shown in Home Assistant
2. **From email**: Tap the deep link in the email → the app opens and pairs automatically
3. **Use access**: Tap the action tile (e.g. "Unlock Door") — protected by Face ID / passcode

### App features

- QR code scanner with camera permissions
- Biometric authentication (Face ID) and passcode fallback
- Secure token storage in iOS Keychain
- TLS certificate pinning
- Ed25519 device key generation for proof-of-possession

## Supported Entities & Actions

| Entity Domain | Actions | HA Service Called |
|---|---|---|
| `lock.*` | `door.lock`, `door.unlock` | `lock.lock`, `lock.unlock` |
| `cover.*` | `garage.open`, `garage.close` | `cover.open_cover`, `cover.close_cover` |
| `switch.*` | `switch.on`, `switch.off` | `switch.turn_on`, `switch.turn_off` |
| `light.*` | `light.on`, `light.off` | `light.turn_on`, `light.turn_off` |
| `sensor.*` | `sensor.read` | Read-only (state retrieval) |
| `binary_sensor.*` | `binary_sensor.read` | Read-only (state retrieval) |
| `climate.*` | `climate.read` | Read-only (state retrieval) |

Actions are auto-inferred from the entity domain — you don't need to specify them manually.

## Audit & Automations

Every guest action fires an `easy_control_used` event with:
- `guest_id` — identifies the guest
- `entity` — the entity that was acted on
- `timestamp` — when the action occurred

### Example: notify when a guest unlocks the door

```yaml
automation:
  - alias: "Notify on guest access"
    trigger:
      - platform: event
        event_type: easy_control_used
    action:
      - service: notify.mobile_app
        data:
          title: "Guest Access"
          message: >
            Guest {{ trigger.event.data.guest_id }}
            used {{ trigger.event.data.entity }}
```

## Security Overview

- **Signed tokens** (HS256) with rotating signing keyring — tokens can't be forged
- **Scoped access** — each token is bound to specific entities and actions
- **Time & use limits** — tokens expire automatically and can be use-limited
- **Revocation** — per-token, per-guest, or global emergency revocation
- **Rate limiting** — fixed-window rate limits per API endpoint
- **Network restrictions** — optional local-only mode with CIDR allowlists
- **Device binding** — optional Ed25519 key binding with proof-of-possession
- **Constant-time comparison** — all secret comparisons use `hmac.compare_digest`

## Troubleshooting

| Issue | Solution |
|---|---|
| "Rate limited" error | Increase rate limits in the integration options, or wait for the window to reset |
| QR code / pairing code expired | Pairing codes have a 5-minute TTL — create a new pass |
| Email not sent | Check that the notify service name matches (e.g. `email` not `notify.email`). Check HA logs for errors. |
| Notify service not found | Verify the service exists: **Developer Tools → Services** → search for `notify.your_service` |
| Guest can't reach the server | If `local_only` is enabled, the guest must be on your local network. Check `allowed_cidrs`. |
| QR notification not showing | Ensure `show_qr_notification` is not set to `false` |
| "Pending approval" on guest's phone | You need to call `approve_pairing_request` with the pairing code |

## License

See [LICENSE](LICENSE) for details.

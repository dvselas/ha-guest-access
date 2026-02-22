# iOS SwiftUI Networking + Security Blueprint

## Architecture
```text
AccessManager
  -> SecureTokenStore (Keychain)
  -> GuestAccessAPI
  -> Home Assistant local network endpoint
```

## Token storage
Store guest token and device signing key in Keychain / Secure Enclave only.

```swift
final class SecureTokenStore {
    func save(token: String) throws { /* Keychain write */ }
    func load() -> String? { /* Keychain read */ }
    func delete() throws { /* Keychain delete */ }
}
```

Never store access tokens in:
- `UserDefaults`
- plain files

## Device binding (PoP)
- Generate Ed25519 device key pair on first run (private key in Secure Enclave/Keychain)
- Send `device_id` + `device_public_key` during pairing
- Keep `device_id` stable per install (UUID in Keychain)

## API contract
### Pair
`POST /api/easy_control/pair`

Request:
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
  "guest_token": "...",
  "allowed_actions": ["door.open"],
  "expires_at": 1700003600,
  "guest_id": "guest_xxx",
  "max_uses": 10,
  "proof_required": true,
  "device_binding_required": true,
  "nonce_endpoint": "/api/easy_control/action/nonce"
}
```

Pending approval (`202`):
```json
{
  "error": "pending_approval",
  "message": "Pairing request is awaiting admin approval"
}
```

### Action nonce
`GET /api/easy_control/action/nonce`

Headers:
`Authorization: Bearer <guest_token>`

Response:
```json
{
  "nonce": "....",
  "expires_at": 1700000045,
  "jti": "..."
}
```

### Execute action
`POST /api/easy_control/action`

Headers:
`Authorization: Bearer <guest_token>`
`X-Easy-Control-Proof: <base64url(json)>`
`X-Easy-Control-Proof-Signature: <base64url(ed25519-signature)>`

Request:
```json
{ "action": "door.open" }
```

Success:
```json
{
  "success": true,
  "action": "door.open",
  "entity_id": "lock.front_door",
  "remaining_uses": 9,
  "used_count": 1
}
```

Token-expired failure:
```json
{
  "error": "token_expired",
  "message": "Token has expired",
  "success": false
}
```

## Suggested Swift client
```swift
struct GuestTokenResponse: Decodable {
    let guestToken: String
    let allowedActions: [String]
    let expiresAt: Int
    let guestId: String
    let maxUses: Int
    let proofRequired: Bool?
    let deviceBindingRequired: Bool?
    let nonceEndpoint: String?
}

struct ActionResponse: Decodable {
    let success: Bool
    let action: String?
    let entityId: String?
    let remainingUses: Int?
    let usedCount: Int?
    let error: String?
    let message: String?
}

final class GuestAccessAPI {
    let baseURL: URL

    init(baseURL: URL) { self.baseURL = baseURL }

    func pair(pairingCode: String) async throws -> GuestTokenResponse {
        // POST /api/easy_control/pair with device_id + device_public_key
        fatalError("Implement URLSession request")
    }

    func execute(action: String, token: String) async throws -> ActionResponse {
        // 1) GET /api/easy_control/action/nonce
        // 2) Build proof payload + sign with Ed25519 private key
        // 3) POST /api/easy_control/action with Bearer token + proof headers
        fatalError("Implement URLSession request")
    }
}
```

## Biometric gate before execute
```swift
import LocalAuthentication

func authorizeForAction() async throws {
    let context = LAContext()
    try await context.evaluatePolicy(
        .deviceOwnerAuthentication,
        localizedReason: "Confirm guest access action"
    )
}
```

## UI state machine
```swift
enum AccessState {
    case loading
    case ready
    case executing
    case success
    case error(String)
    case expired
}
```

## Expiration / revoke handling
- On `401` with `token_expired`, `token_revoked`, or `token_max_uses_exceeded`:
- On `401` with `action_proof_replay`, `action_nonce_expired`, `action_proof_clock_skew`, or `action_proof_invalid`:
  1. Refresh nonce / retry once (except replay)
  2. If repeated, move UI to error state
- On `202` with `pending_approval`:
  1. Poll pair endpoint with backoff until approved/expired
  2. Show "Waiting for host approval" UI
- On `401` with `token_expired`, `token_revoked`, or `token_max_uses_exceeded`:
  1. Delete token from Keychain
  2. Transition UI to `.expired`
  3. Prompt user to re-pair

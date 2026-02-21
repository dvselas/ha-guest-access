# iOS SwiftUI Networking + Security Blueprint

## Architecture
```text
AccessManager
  -> SecureTokenStore (Keychain)
  -> GuestAccessAPI
  -> Home Assistant local network endpoint
```

## Token storage
Store guest token in Keychain only.

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

## API contract
### Pair
`POST /api/guest_access/pair`

Request:
```json
{ "pairing_code": "ABC123XYZ0" }
```

Response:
```json
{
  "guest_token": "...",
  "allowed_actions": ["door.open"],
  "expires_at": 1700003600,
  "guest_id": "guest_xxx",
  "max_uses": 10
}
```

### Execute action
`POST /api/guest_access/action`

Headers:
`Authorization: Bearer <guest_token>`

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
        // POST /api/guest_access/pair
        fatalError("Implement URLSession request")
    }

    func execute(action: String, token: String) async throws -> ActionResponse {
        // POST /api/guest_access/action with Bearer token
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
  1. Delete token from Keychain
  2. Transition UI to `.expired`
  3. Prompt user to re-pair

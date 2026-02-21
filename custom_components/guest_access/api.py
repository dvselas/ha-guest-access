"""HTTP API endpoints for Guest Access."""

from __future__ import annotations

import time
import uuid
from typing import Any

from aiohttp import web

from homeassistant.components.http import KEY_HASS, HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util

from .const import (
    ALLOWED_ACTIONS,
    CONF_ALLOWED_CIDRS,
    CONF_LOCAL_ONLY,
    DEFAULT_ALLOWED_CIDRS,
    DEFAULT_LOCAL_ONLY,
    DATA_API_REGISTERED,
    DATA_CONFIG_ENTRIES,
    DATA_PAIRING_STORE,
    DATA_TOKEN_MANAGER,
    DOMAIN,
    EVENT_GUEST_ACCESS_USED,
)
from .network import is_remote_allowed
from .pairing import PairingStore
from .token import (
    GuestTokenManager,
    GuestTokenPayload,
    InvalidTokenError,
    TokenExpiredError,
)


class GuestAccessPairView(HomeAssistantView):
    """Exchange pairing code for a signed guest token."""

    url = "/api/guest_access/pair"
    name = "api:guest_access:pair"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Handle pairing-code exchange for guest app onboarding."""
        hass: HomeAssistant = request.app[KEY_HASS]
        policy_error = _reject_remote_if_disallowed(request, hass.data.get(DOMAIN, {}))
        if policy_error is not None:
            return policy_error

        try:
            payload = await request.json()
        except ValueError:
            return self.json(
                {
                    "error": "invalid_json",
                    "message": "Request body must be valid JSON",
                },
                status_code=400,
            )

        if not isinstance(payload, dict):
            return self.json(
                {
                    "error": "invalid_payload",
                    "message": "Request body must be a JSON object",
                },
                status_code=400,
            )

        pairing_code = payload.get("pairing_code")
        if not isinstance(pairing_code, str) or not pairing_code:
            return self.json(
                {
                    "error": "invalid_pairing_code",
                    "message": "pairing_code must be a non-empty string",
                },
                status_code=400,
            )

        domain_data: dict[str, Any] = hass.data.get(DOMAIN, {})
        pairing_store = domain_data.get(DATA_PAIRING_STORE)
        if not isinstance(pairing_store, PairingStore):
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "Guest Access pairing is not initialized",
                },
                status_code=503,
            )

        token_manager = _get_token_manager(domain_data)
        if token_manager is None:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "Guest Access token manager is not initialized",
                },
                status_code=503,
            )

        pairing, failure_reason = pairing_store.consume_pairing(pairing_code)
        if pairing is None:
            if failure_reason == "expired":
                return self.json(
                    {
                        "error": "pairing_code_expired",
                        "message": "Pairing code has expired",
                    },
                    status_code=410,
                )

            return self.json(
                {
                    "error": "pairing_code_invalid",
                    "message": "Pairing code is invalid or already used",
                },
                status_code=400,
            )

        now_timestamp = int(time.time())
        if pairing.pass_expires_at <= now_timestamp:
            return self.json(
                {
                    "error": "pass_expired",
                    "message": "Pairing was valid but pass expiration has already elapsed",
                },
                status_code=410,
            )

        payload_model = GuestTokenPayload(
            guest_id=f"guest_{uuid.uuid4().hex}",
            allowed_actions=[pairing.allowed_action],
            entity_id=pairing.entity_id,
            exp=pairing.pass_expires_at,
        )
        guest_token = token_manager.create_token(payload_model)

        return self.json(
            {
                "guest_token": guest_token,
                "allowed_actions": [pairing.allowed_action],
                "expires_at": pairing.pass_expires_at,
            }
        )


class GuestAccessTokenValidateView(HomeAssistantView):
    """Validate an already issued guest token."""

    url = "/api/guest_access/token/validate"
    name = "api:guest_access:token_validate"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Validate guest token and map invalid/expired tokens to HTTP 401."""
        hass: HomeAssistant = request.app[KEY_HASS]
        policy_error = _reject_remote_if_disallowed(request, hass.data.get(DOMAIN, {}))
        if policy_error is not None:
            return policy_error

        try:
            payload = await request.json()
        except ValueError:
            return self.json(
                {
                    "error": "invalid_json",
                    "message": "Request body must be valid JSON",
                },
                status_code=400,
            )

        if not isinstance(payload, dict):
            return self.json(
                {
                    "error": "invalid_payload",
                    "message": "Request body must be a JSON object",
                },
                status_code=400,
            )

        guest_token = payload.get("guest_token")
        if not isinstance(guest_token, str) or not guest_token:
            return self.json(
                {
                    "error": "invalid_guest_token",
                    "message": "guest_token must be a non-empty string",
                },
                status_code=400,
            )

        token_manager = _get_token_manager(hass.data.get(DOMAIN, {}))
        if token_manager is None:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "Guest Access token manager is not initialized",
                },
                status_code=503,
            )

        try:
            token_payload = token_manager.verify_token(guest_token)
        except (InvalidTokenError, TokenExpiredError):
            return self.json(
                {
                    "error": "unauthorized",
                    "message": "Token is invalid, revoked, or expired",
                },
                status_code=401,
            )

        return self.json(
            {
                "guest_id": token_payload.guest_id,
                "allowed_actions": token_payload.allowed_actions,
                "entity_id": token_payload.entity_id,
                "expires_at": token_payload.exp,
            }
        )


class GuestAccessActionView(HomeAssistantView):
    """Execute a token-scoped door or garage action."""

    url = "/api/guest_access/action"
    name = "api:guest_access:action"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Validate bearer token and execute allowed action."""
        hass: HomeAssistant = request.app[KEY_HASS]
        policy_error = _reject_remote_if_disallowed(request, hass.data.get(DOMAIN, {}))
        if policy_error is not None:
            return policy_error

        bearer_token = _extract_bearer_token(request)
        if bearer_token is None:
            return self.json(
                {
                    "success": False,
                    "error": "missing_bearer_token",
                    "message": "Authorization header with Bearer token is required",
                },
                status_code=401,
            )

        try:
            payload = await request.json()
        except ValueError:
            return self.json(
                {
                    "success": False,
                    "error": "invalid_json",
                    "message": "Request body must be valid JSON",
                },
                status_code=400,
            )

        if not isinstance(payload, dict):
            return self.json(
                {
                    "success": False,
                    "error": "invalid_payload",
                    "message": "Request body must be a JSON object",
                },
                status_code=400,
            )

        action = payload.get("action")
        if not isinstance(action, str) or not action:
            return self.json(
                {
                    "success": False,
                    "error": "invalid_action",
                    "message": "action must be a non-empty string",
                },
                status_code=400,
            )

        if action not in ALLOWED_ACTIONS:
            return self.json(
                {
                    "success": False,
                    "error": "unsupported_action",
                    "message": f"Unsupported action '{action}'",
                },
                status_code=400,
            )

        token_manager = _get_token_manager(hass.data.get(DOMAIN, {}))
        if token_manager is None:
            return self.json(
                {
                    "success": False,
                    "error": "integration_not_ready",
                    "message": "Guest Access token manager is not initialized",
                },
                status_code=503,
            )

        try:
            token_payload = token_manager.verify_token(bearer_token)
        except (InvalidTokenError, TokenExpiredError):
            return self.json(
                {
                    "success": False,
                    "error": "unauthorized",
                    "message": "Token is invalid, revoked, or expired",
                },
                status_code=401,
            )

        if action not in token_payload.allowed_actions:
            return self.json(
                {
                    "success": False,
                    "error": "action_not_allowed",
                    "message": "Requested action is not allowed by token scope",
                },
                status_code=403,
            )

        entity_id = token_payload.entity_id
        service_target = _resolve_service_target(action, entity_id)
        if service_target is None:
            return self.json(
                {
                    "success": False,
                    "error": "scope_mismatch",
                    "message": "Token scope does not match requested action/entity",
                },
                status_code=403,
            )

        service_domain, service_name = service_target
        try:
            await hass.services.async_call(
                service_domain,
                service_name,
                {"entity_id": entity_id},
                blocking=True,
            )
        except HomeAssistantError as err:
            return self.json(
                {
                    "success": False,
                    "error": "action_execution_failed",
                    "message": str(err),
                },
                status_code=500,
            )

        timestamp = dt_util.utcnow().isoformat()
        await _emit_guest_access_usage_log(
            hass,
            guest_id=token_payload.guest_id,
            entity_id=entity_id,
            timestamp=timestamp,
        )

        return self.json(
            {
                "success": True,
                "action": action,
                "entity_id": entity_id,
            }
        )


def async_register_api(hass: HomeAssistant) -> None:
    """Register Guest Access HTTP API views exactly once."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(DATA_API_REGISTERED):
        return

    hass.http.register_view(GuestAccessPairView)
    hass.http.register_view(GuestAccessTokenValidateView)
    hass.http.register_view(GuestAccessActionView)
    domain_data[DATA_API_REGISTERED] = True


def _get_token_manager(domain_data: dict[str, Any]) -> GuestTokenManager | None:
    """Return any active token manager for the current integration instance."""
    entry_ids: set[str] = domain_data.get(DATA_CONFIG_ENTRIES, set())
    for entry_id in entry_ids:
        entry_data = domain_data.get(entry_id)
        if not isinstance(entry_data, dict):
            continue
        token_manager = entry_data.get(DATA_TOKEN_MANAGER)
        if isinstance(token_manager, GuestTokenManager):
            return token_manager
    return None


def _extract_bearer_token(request: web.Request) -> str | None:
    """Extract bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None

    return token.strip() or None


def _resolve_service_target(action: str, entity_id: str) -> tuple[str, str] | None:
    """Map allowed action to HA service and verify entity domain."""
    entity_domain = entity_id.split(".", maxsplit=1)[0]
    if action == "door.open" and entity_domain == "lock":
        return "lock", "unlock"
    if action == "garage.open" and entity_domain == "cover":
        return "cover", "open_cover"
    return None


def _reject_remote_if_disallowed(
    request: web.Request, domain_data: dict[str, Any]
) -> web.Response | None:
    """Reject requests from outside configured local CIDR ranges."""
    local_only, allowed_cidrs = _get_network_policy(domain_data)
    if not local_only:
        return None

    if is_remote_allowed(request.remote, allowed_cidrs):
        return None

    return web.json_response(
        {
            "error": "forbidden_remote",
            "message": "Guest access is restricted to configured local networks",
        },
        status=403,
    )


def _get_network_policy(domain_data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Get effective local-only policy from active config entry data."""
    entry_ids: set[str] = domain_data.get(DATA_CONFIG_ENTRIES, set())
    for entry_id in entry_ids:
        entry_data = domain_data.get(entry_id)
        if not isinstance(entry_data, dict):
            continue
        local_only = bool(entry_data.get(CONF_LOCAL_ONLY, DEFAULT_LOCAL_ONLY))
        allowed_cidrs = entry_data.get(CONF_ALLOWED_CIDRS, list(DEFAULT_ALLOWED_CIDRS))
        if isinstance(allowed_cidrs, list):
            return local_only, allowed_cidrs
        return local_only, list(DEFAULT_ALLOWED_CIDRS)

    return DEFAULT_LOCAL_ONLY, list(DEFAULT_ALLOWED_CIDRS)


async def _emit_guest_access_usage_log(
    hass: HomeAssistant, guest_id: str, entity_id: str, timestamp: str
) -> None:
    """Write local audit trail for successful guest access usage."""
    event_data = {
        "guest_id": guest_id,
        "entity": entity_id,
        "timestamp": timestamp,
    }
    hass.bus.async_fire(EVENT_GUEST_ACCESS_USED, event_data)

    if hass.services.has_service("logbook", "log"):
        await hass.services.async_call(
            "logbook",
            "log",
            {
                "name": "Guest Access",
                "message": f"Guest {guest_id} used access on {entity_id} at {timestamp}",
                "domain": DOMAIN,
                "entity_id": entity_id,
            },
            blocking=False,
        )

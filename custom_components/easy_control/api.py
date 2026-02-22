"""HTTP API endpoints for HA Easy Control."""

from __future__ import annotations

import io
import logging
import time
import uuid
from hmac import compare_digest
from typing import Any
from urllib.parse import urlencode

from aiohttp import web

from homeassistant.components.http import KEY_HASS, HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.util import dt as dt_util

from .const import (
    ALLOWED_ACTIONS,
    CONF_ALLOWED_CIDRS,
    CONF_LOCAL_ONLY,
    CONF_TOKEN_VERSION,
    DEFAULT_ALLOWED_CIDRS,
    DEFAULT_LOCAL_ONLY,
    DEFAULT_TOKEN_MAX_USES,
    DATA_API_REGISTERED,
    DATA_CONFIG_ENTRIES,
    DATA_PAIRING_STORE,
    DATA_TOKEN_MANAGER,
    DOMAIN,
    EVENT_GUEST_ACCESS_USED,
)
from .network import is_remote_allowed
from .pairing import PairingStore
from .storage import async_get_token_use_count, async_record_token_use
from .token import (
    GuestTokenManager,
    GuestTokenPayload,
    InvalidTokenError,
    TokenAudienceMismatchError,
    TokenExpiredError,
    TokenIssuerMismatchError,
    TokenMaxUsesExceededError,
    TokenNotYetValidError,
    TokenVersionMismatchError,
)

_LOGGER = logging.getLogger(__name__)

NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
}


class GuestAccessPairView(HomeAssistantView):
    """Exchange pairing code for a signed guest token."""

    url = "/api/easy_control/pair"
    name = "api:easy_control:pair"
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
                {"error": "invalid_json", "message": "Request body must be valid JSON"},
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
                    "message": "HA Easy Control pairing is not initialized",
                },
                status_code=503,
            )

        entry_data = _get_active_entry_data(domain_data)
        if entry_data is None:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "HA Easy Control entry data is not initialized",
                },
                status_code=503,
            )

        token_manager = entry_data.get(DATA_TOKEN_MANAGER)
        if not isinstance(token_manager, GuestTokenManager):
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "HA Easy Control token manager is not initialized",
                },
                status_code=503,
            )

        token_version = entry_data.get(CONF_TOKEN_VERSION)
        if not isinstance(token_version, int) or token_version < 1:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "HA Easy Control token version is not initialized",
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

        guest_token, token_payload = token_manager.create_guest_token(
            guest_id=f"guest_{uuid.uuid4().hex}",
            entity_id=pairing.entity_id,
            allowed_action=pairing.allowed_action,
            expires_at=pairing.pass_expires_at,
            token_version=token_version,
            max_uses=DEFAULT_TOKEN_MAX_USES,
        )

        return self.json(
            {
                "guest_token": guest_token,
                "allowed_actions": [token_payload.allowed_action],
                "expires_at": token_payload.exp,
                "guest_id": token_payload.guest_id,
                "max_uses": token_payload.max_uses,
            }
        )


class GuestAccessTokenValidateView(HomeAssistantView):
    """Validate an already issued guest token."""

    url = "/api/easy_control/token/validate"
    name = "api:easy_control:token_validate"
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
                {"error": "invalid_json", "message": "Request body must be valid JSON"},
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

        token_manager, token_version = _resolve_token_context(hass.data.get(DOMAIN, {}))
        if token_manager is None or token_version is None:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "HA Easy Control token context is not initialized",
                },
                status_code=503,
            )

        try:
            token_payload, use_count = await _verify_guest_token_for_action(
                hass=hass,
                token_manager=token_manager,
                token=guest_token,
                token_version=token_version,
            )
        except (
            InvalidTokenError,
            TokenExpiredError,
            TokenNotYetValidError,
            TokenVersionMismatchError,
            TokenAudienceMismatchError,
            TokenIssuerMismatchError,
            TokenMaxUsesExceededError,
        ) as err:
            return _unauthorized_token_response(self, err)

        return self.json(
            {
                "guest_id": token_payload.guest_id,
                "allowed_actions": [token_payload.allowed_action],
                "entity_id": token_payload.entity_id,
                "expires_at": token_payload.exp,
                "remaining_uses": max(token_payload.max_uses - use_count, 0),
            }
        )


class GuestAccessActionView(HomeAssistantView):
    """Execute a token-scoped door or garage action."""

    url = "/api/easy_control/action"
    name = "api:easy_control:action"
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

        token_manager, token_version = _resolve_token_context(hass.data.get(DOMAIN, {}))
        if token_manager is None or token_version is None:
            return self.json(
                {
                    "success": False,
                    "error": "integration_not_ready",
                    "message": "HA Easy Control token context is not initialized",
                },
                status_code=503,
            )

        try:
            token_payload, use_count = await _verify_guest_token_for_action(
                hass=hass,
                token_manager=token_manager,
                token=bearer_token,
                token_version=token_version,
            )
        except (
            InvalidTokenError,
            TokenExpiredError,
            TokenNotYetValidError,
            TokenVersionMismatchError,
            TokenAudienceMismatchError,
            TokenIssuerMismatchError,
            TokenMaxUsesExceededError,
        ) as err:
            return _unauthorized_token_response(self, err, include_success=True)

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

        if action != token_payload.allowed_action:
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

        new_use_count = await async_record_token_use(hass, token_payload.jti)
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
                "remaining_uses": max(token_payload.max_uses - new_use_count, 0),
                "used_count": new_use_count,
            }
        )


class GuestAccessQrView(HomeAssistantView):
    """Render pairing QR code as SVG image for Home Assistant UI."""

    url = "/api/easy_control/qr"
    name = "api:easy_control:qr"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Return QR image for an active pairing code."""
        hass: HomeAssistant = request.app[KEY_HASS]
        domain_data: dict[str, Any] = hass.data.get(DOMAIN, {})

        pairing_code = request.query.get("code", "")
        qr_access_token = request.query.get("qr_token", "")
        if not pairing_code:
            return web.Response(
                text="Missing required query parameter: code",
                status=400,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )
        if not qr_access_token:
            return web.Response(
                text="Missing required query parameter: qr_token",
                status=400,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )

        pairing_store = domain_data.get(DATA_PAIRING_STORE)
        if not isinstance(pairing_store, PairingStore):
            return web.Response(
                text="HA Easy Control pairing store is not initialized",
                status=503,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )

        pairing_record = _resolve_pairing_for_qr(
            pairing_store, pairing_code, qr_access_token
        )
        if pairing_record is None:
            return web.Response(
                text="Invalid or expired qr access token",
                status=401,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )

        base_url = _resolve_home_assistant_url_from_request(request, hass)
        qr_payload = (
            "guest-access://pair?"
            + urlencode(
                {
                    "pairing_code": pairing_record.pairing_code,
                    "code": pairing_record.pairing_code,
                    "base_url": base_url,
                }
            )
        )
        try:
            import segno  # Local import keeps tests independent of optional QR dependency.
        except ModuleNotFoundError:
            return web.Response(
                text="QR rendering dependency is missing",
                status=503,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )

        try:
            qr = segno.make(qr_payload, error="m")
            svg_output = io.BytesIO()
            qr.save(
                svg_output,
                kind="svg",
                scale=8,
                border=2,
                xmldecl=False,
                dark="#000000",
                light="#ffffff",
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Failed to render guest access QR code")
            return web.Response(
                text="Failed to render QR code",
                status=500,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )
        return web.Response(
            body=svg_output.getvalue(),
            content_type="image/svg+xml",
            headers=NO_STORE_HEADERS,
        )


def async_register_api(hass: HomeAssistant) -> None:
    """Register HA Easy Control HTTP API views exactly once."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(DATA_API_REGISTERED):
        return

    hass.http.register_view(GuestAccessPairView)
    hass.http.register_view(GuestAccessTokenValidateView)
    hass.http.register_view(GuestAccessActionView)
    hass.http.register_view(GuestAccessQrView)
    domain_data[DATA_API_REGISTERED] = True


async def _verify_guest_token_for_action(
    *,
    hass: HomeAssistant,
    token_manager: GuestTokenManager,
    token: str,
    token_version: int,
) -> tuple[GuestTokenPayload, int]:
    """Verify token claims and replay limits for action-like requests."""
    token_payload = token_manager.verify_token(
        token,
        expected_token_version=token_version,
    )
    use_count = await async_get_token_use_count(hass, token_payload.jti)
    if use_count >= token_payload.max_uses:
        raise TokenMaxUsesExceededError("Token max_uses has been reached")
    return token_payload, use_count


def _resolve_token_context(
    domain_data: dict[str, Any],
) -> tuple[GuestTokenManager | None, int | None]:
    """Get token manager and token version from active integration entry."""
    entry_data = _get_active_entry_data(domain_data)
    if entry_data is None:
        return None, None

    token_manager = entry_data.get(DATA_TOKEN_MANAGER)
    token_version = entry_data.get(CONF_TOKEN_VERSION)
    if not isinstance(token_manager, GuestTokenManager):
        return None, None
    if not isinstance(token_version, int) or token_version < 1:
        return None, None
    return token_manager, token_version


def _get_active_entry_data(domain_data: dict[str, Any]) -> dict[str, Any] | None:
    """Return first active config-entry data block."""
    entry_ids: set[str] = domain_data.get(DATA_CONFIG_ENTRIES, set())
    for entry_id in entry_ids:
        entry_data = domain_data.get(entry_id)
        if isinstance(entry_data, dict):
            return entry_data
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
    """Get effective local-only policy from active config-entry data."""
    entry_data = _get_active_entry_data(domain_data)
    if entry_data is None:
        return DEFAULT_LOCAL_ONLY, list(DEFAULT_ALLOWED_CIDRS)

    local_only = bool(entry_data.get(CONF_LOCAL_ONLY, DEFAULT_LOCAL_ONLY))
    allowed_cidrs = entry_data.get(CONF_ALLOWED_CIDRS, list(DEFAULT_ALLOWED_CIDRS))
    if isinstance(allowed_cidrs, list):
        return local_only, allowed_cidrs
    return local_only, list(DEFAULT_ALLOWED_CIDRS)


def _unauthorized_token_response(
    view: HomeAssistantView, err: Exception, include_success: bool = False
) -> web.Response:
    """Map token failures to explicit 401 error codes for iOS state handling."""
    error = "unauthorized"
    message = "Token is invalid, revoked, or expired"

    if isinstance(err, TokenExpiredError):
        error = "token_expired"
        message = "Token has expired"
    elif isinstance(err, TokenNotYetValidError):
        error = "token_not_yet_valid"
        message = "Token is not valid yet"
    elif isinstance(err, TokenVersionMismatchError):
        error = "token_revoked"
        message = "Token has been revoked"
    elif isinstance(err, TokenAudienceMismatchError):
        error = "token_audience_invalid"
        message = "Token audience is invalid"
    elif isinstance(err, TokenIssuerMismatchError):
        error = "token_issuer_invalid"
        message = "Token issuer is invalid"
    elif isinstance(err, TokenMaxUsesExceededError):
        error = "token_max_uses_exceeded"
        message = "Token usage limit exceeded"

    payload: dict[str, Any] = {"error": error, "message": message}
    if include_success:
        payload["success"] = False
    return view.json(payload, status_code=401)


def _resolve_pairing_for_qr(
    pairing_store: PairingStore, pairing_code: str, qr_access_token: str
) -> Any | None:
    """Validate QR access against current store, with backward compatibility."""
    validate_qr_access = getattr(pairing_store, "validate_qr_access", None)
    if callable(validate_qr_access):
        try:
            return validate_qr_access(pairing_code, qr_access_token)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Failed to validate qr access token")
            return None

    # Backward compatibility path for older PairingStore objects.
    get_pairing = getattr(pairing_store, "get_pairing", None)
    if not callable(get_pairing):
        return None

    try:
        pairing_record = get_pairing(pairing_code)
    except Exception:  # noqa: BLE001
        _LOGGER.exception("Failed to load pairing record for qr endpoint")
        return None

    if pairing_record is None:
        return None

    record_qr_access_token = getattr(pairing_record, "qr_access_token", None)
    if not isinstance(record_qr_access_token, str) or not record_qr_access_token:
        return None
    if not compare_digest(record_qr_access_token, qr_access_token):
        return None
    return pairing_record


def _resolve_home_assistant_url_from_request(
    request: web.Request, hass: HomeAssistant
) -> str:
    """Resolve base URL for QR deep links (external URL preferred)."""
    external_url = getattr(hass.config, "external_url", None)
    if isinstance(external_url, str) and external_url:
        return external_url.rstrip("/")

    internal_url = getattr(hass.config, "internal_url", None)
    if isinstance(internal_url, str) and internal_url:
        return internal_url.rstrip("/")

    for prefer_external in (True, False):
        try:
            return str(get_url(hass, prefer_external=prefer_external)).rstrip("/")
        except (NoURLAvailableError, TypeError):
            continue

    return f"{request.scheme}://{request.host}".rstrip("/")


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
                "name": "HA Easy Control",
                "message": f"Guest {guest_id} used access on {entity_id} at {timestamp}",
                "domain": DOMAIN,
                "entity_id": entity_id,
            },
            blocking=False,
        )

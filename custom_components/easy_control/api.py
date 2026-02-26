"""HTTP API endpoints for HA Easy Control."""

from __future__ import annotations

import io
import json
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
    ACTION_SERVICE_MAP,
    ALLOWED_ACTIONS,
    CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
    CONF_ACTION_RATE_LIMIT_PER_MIN,
    CONF_ALLOWED_CIDRS,
    CONF_LOCAL_ONLY,
    CONF_NONCE_TTL_SECONDS,
    CONF_PAIR_RATE_LIMIT_PER_MIN,
    CONF_QR_RATE_LIMIT_PER_MIN,
    CONF_REQUIRE_ACTION_PROOF,
    CONF_REQUIRE_DEVICE_BINDING,
    CONF_STATES_RATE_LIMIT_PER_MIN,
    CONF_TOKEN_VERSION,
    DATA_API_REGISTERED,
    DATA_CONFIG_ENTRIES,
    DATA_NONCE_STORE,
    DATA_PAIRING_STORE,
    DATA_RATE_LIMITER,
    DATA_TOKEN_MANAGER,
    DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS,
    DEFAULT_ACTION_RATE_LIMIT_PER_MIN,
    DEFAULT_ALLOWED_CIDRS,
    DEFAULT_LOCAL_ONLY,
    DEFAULT_NONCE_TTL_SECONDS,
    DEFAULT_PAIR_RATE_LIMIT_PER_MIN,
    DEFAULT_QR_RATE_LIMIT_PER_MIN,
    DEFAULT_REQUIRE_ACTION_PROOF,
    DEFAULT_STATES_RATE_LIMIT_PER_MIN,
    DEFAULT_TOKEN_MAX_USES,
    DOMAIN,
    EVENT_GUEST_ACCESS_USED,
    EVENT_RATE_LIMITED,
    READ_ONLY_DOMAINS,
)
from .network import is_remote_allowed
from .pairing import PairingStore
from .proof import (
    ActionProofClockSkewError,
    ActionProofInvalidError,
    ActionProofMissingError,
    ActionProofNonceExpiredError,
    ActionProofReplayError,
    build_proof_signing_input,
    canonicalize_public_key,
    decode_action_proof_headers,
    hash_request_body,
    validate_proof_clock,
    verify_ed25519_signature,
)
from .runtime_security import ActionNonceStore, FixedWindowRateLimiter
from .storage import (
    async_get_issued_token_metadata,
    async_get_token_use_count,
    async_is_token_revoked,
    async_record_token_use,
    async_register_issued_token,
)
from .token import (
    GuestTokenManager,
    GuestTokenPayload,
    InvalidTokenError,
    TokenAudienceMismatchError,
    TokenExpiredError,
    TokenIssuerMismatchError,
    TokenMaxUsesExceededError,
    TokenNotYetValidError,
    TokenRevokedError,
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
        domain_data: dict[str, Any] = hass.data.get(DOMAIN, {})
        policy_error = _reject_remote_if_disallowed(request, domain_data)
        if policy_error is not None:
            return policy_error
        rate_limit_error = _rate_limit_request(
            hass,
            domain_data,
            request=request,
            bucket="pair",
        )
        if rate_limit_error is not None:
            return rate_limit_error

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
        rate_limit_error = _rate_limit_request(
            hass,
            domain_data,
            request=request,
            bucket="pair",
            extra_keys=[pairing_code],
            include_ip=False,
        )
        if rate_limit_error is not None:
            return rate_limit_error

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

        require_device_binding = bool(
            entry_data.get(CONF_REQUIRE_DEVICE_BINDING, False)
        )
        require_action_proof = bool(entry_data.get(CONF_REQUIRE_ACTION_PROOF, False))

        device_id = payload.get("device_id")
        device_public_key = payload.get("device_public_key")
        cnf_jkt: str | None = None
        if (require_device_binding or require_action_proof) and (
            not isinstance(device_id, str)
            or not device_id
            or not isinstance(device_public_key, str)
            or not device_public_key
        ):
            return self.json(
                {
                    "error": "device_binding_required",
                    "message": "device_id and device_public_key are required for pairing",
                },
                status_code=400,
            )

        if device_public_key is not None:
            if not isinstance(device_public_key, str) or not device_public_key:
                return self.json(
                    {
                        "error": "invalid_device_public_key",
                        "message": "device_public_key must be a non-empty base64url string",
                    },
                    status_code=400,
                )
            try:
                _raw_key, cnf_jkt = canonicalize_public_key(device_public_key)
            except ActionProofInvalidError as err:
                return self.json(
                    {
                        "error": "invalid_device_public_key",
                        "message": str(err),
                    },
                    status_code=400,
                )
        if device_id is not None and (not isinstance(device_id, str) or not device_id):
            return self.json(
                {
                    "error": "invalid_device_id",
                    "message": "device_id must be a non-empty string",
                },
                status_code=400,
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

            if failure_reason == "pending_approval":
                return self.json(
                    {
                        "error": "pending_approval",
                        "message": "Pairing request is awaiting admin approval",
                    },
                    status_code=202,
                )
            if failure_reason == "rejected":
                return self.json(
                    {
                        "error": "pairing_rejected",
                        "message": "Pairing request was rejected by an administrator",
                    },
                    status_code=403,
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
            entities=list(pairing.entities),
            expires_at=pairing.pass_expires_at,
            token_version=token_version,
            max_uses=DEFAULT_TOKEN_MAX_USES,
            device_id=device_id if isinstance(device_id, str) else None,
            cnf_jkt=cnf_jkt,
        )
        await async_register_issued_token(
            hass,
            jti=token_payload.jti,
            guest_id=token_payload.guest_id,
            exp=token_payload.exp,
            device_id=token_payload.device_id,
            cnf_jkt=token_payload.cnf_jkt,
            device_public_key=device_public_key if isinstance(device_public_key, str) else None,
        )

        return self.json(
            {
                "guest_token": guest_token,
                "entities": token_payload.to_dict()["entities"],
                "allowed_actions": [
                    a
                    for e in token_payload.entities
                    for a in e.get("allowed_actions", [])
                ],
                "entity_id": token_payload.entity_id,
                "expires_at": token_payload.exp,
                "guest_id": token_payload.guest_id,
                "max_uses": token_payload.max_uses,
                "proof_required": require_action_proof,
                "device_binding_required": require_device_binding,
                "nonce_endpoint": "/api/easy_control/action/nonce",
                "states_endpoint": "/api/easy_control/states",
                "scan_ack_supported": True,
            }
        )


class GuestAccessPairScannedView(HomeAssistantView):
    """Acknowledge that the app has scanned a pairing QR code."""

    url = "/api/easy_control/pair/scanned"
    name = "api:easy_control:pair_scanned"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Mark QR as scanned without consuming the pairing code."""
        hass: HomeAssistant = request.app[KEY_HASS]
        domain_data: dict[str, Any] = hass.data.get(DOMAIN, {})
        policy_error = _reject_remote_if_disallowed(request, domain_data)
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
        scan_ack_token = payload.get("scan_ack_token")
        if not isinstance(pairing_code, str) or not pairing_code:
            return self.json(
                {
                    "error": "invalid_pairing_code",
                    "message": "pairing_code must be a non-empty string",
                },
                status_code=400,
            )
        if not isinstance(scan_ack_token, str) or not scan_ack_token:
            return self.json(
                {
                    "error": "invalid_scan_ack_token",
                    "message": "scan_ack_token must be a non-empty string",
                },
                status_code=400,
            )

        rate_limit_error = _rate_limit_request(
            hass,
            domain_data,
            request=request,
            bucket="pair",
            extra_keys=[pairing_code],
        )
        if rate_limit_error is not None:
            return rate_limit_error

        pairing_store = domain_data.get(DATA_PAIRING_STORE)
        if not isinstance(pairing_store, PairingStore):
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "HA Easy Control pairing is not initialized",
                },
                status_code=503,
            )

        pairing_record, failure_reason = _acknowledge_pairing_qr_scan(
            pairing_store,
            pairing_code,
            scan_ack_token,
        )
        if pairing_record is None:
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
                    "error": "invalid_scan_ack_token",
                    "message": "Pairing code or scan acknowledgement token is invalid",
                },
                status_code=401,
            )

        status = "already_acknowledged" if failure_reason == "already_scanned" else "acknowledged"
        if hass.services.has_service("persistent_notification", "dismiss"):
            await hass.services.async_call(
                "persistent_notification",
                "dismiss",
                {
                    "notification_id": (
                        f"easy_control_pairing_{pairing_record.pairing_code.lower()}"
                    )
                },
                blocking=False,
            )
        return self.json(
            {
                "success": True,
                "status": status,
                "pairing_code": pairing_record.pairing_code,
                "qr_scanned_at": pairing_record.qr_scanned_at,
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
            TokenRevokedError,
        ) as err:
            return _unauthorized_token_response(self, err)

        return self.json(
            {
                "guest_id": token_payload.guest_id,
                "entities": token_payload.to_dict()["entities"],
                "allowed_actions": [
                    a
                    for e in token_payload.entities
                    for a in e.get("allowed_actions", [])
                ],
                "entity_id": token_payload.entity_id,
                "expires_at": token_payload.exp,
                "remaining_uses": (
                    -1 if token_payload.max_uses == 0
                    else max(token_payload.max_uses - use_count, 0)
                ),
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
        domain_data: dict[str, Any] = hass.data.get(DOMAIN, {})
        policy_error = _reject_remote_if_disallowed(request, domain_data)
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

        token_manager, token_version = _resolve_token_context(domain_data)
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
            TokenRevokedError,
        ) as err:
            return _unauthorized_token_response(self, err, include_success=True)

        try:
            raw_body = await request.read()
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
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

        rate_limit_error = _rate_limit_request(
            hass,
            domain_data,
            request=request,
            bucket="action",
            extra_keys=[token_payload.jti],
        )
        if rate_limit_error is not None:
            return rate_limit_error

        require_action_proof, proof_clock_skew = _get_proof_policy(domain_data)
        if require_action_proof or token_payload.cnf_jkt:
            try:
                await _verify_action_proof_request(
                    hass=hass,
                    domain_data=domain_data,
                    request=request,
                    token_payload=token_payload,
                    raw_body=raw_body,
                    max_clock_skew_seconds=proof_clock_skew,
                )
            except (
                ActionProofMissingError,
                ActionProofInvalidError,
                ActionProofReplayError,
                ActionProofNonceExpiredError,
                ActionProofClockSkewError,
                TokenRevokedError,
            ) as err:
                return _proof_failure_response(self, err)

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

        # Resolve entity_id: from request body (multi-entity) or token (legacy)
        request_entity_id = payload.get("entity_id")
        if isinstance(request_entity_id, str) and request_entity_id:
            entity_id = request_entity_id
        else:
            # Backward compat: single-entity token, use first entity
            entity_id = token_payload.entity_id

        # Validate entity_id is in token scope and action matches
        granted_actions = token_payload.allowed_actions_for(entity_id)
        if not granted_actions:
            return self.json(
                {
                    "success": False,
                    "error": "entity_not_in_scope",
                    "message": "Entity is not in token scope",
                },
                status_code=403,
            )
        if action not in granted_actions:
            return self.json(
                {
                    "success": False,
                    "error": "action_not_allowed",
                    "message": "Requested action is not allowed for this entity",
                },
                status_code=403,
            )

        # Read-only domains cannot execute actions
        entity_domain = entity_id.split(".", maxsplit=1)[0]
        if entity_domain in READ_ONLY_DOMAINS:
            return self.json(
                {
                    "success": False,
                    "error": "read_only_entity",
                    "message": f"Entity domain '{entity_domain}' is read-only",
                },
                status_code=400,
            )

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
            jti=token_payload.jti,
            remote=request.remote,
            result="success",
        )

        return self.json(
            {
                "success": True,
                "action": action,
                "entity_id": entity_id,
                "remaining_uses": (
                    -1 if token_payload.max_uses == 0
                    else max(token_payload.max_uses - new_use_count, 0)
                ),
                "used_count": new_use_count,
            }
        )


class GuestAccessActionNonceView(HomeAssistantView):
    """Issue a short-lived nonce for a signed action proof."""

    url = "/api/easy_control/action/nonce"
    name = "api:easy_control:action_nonce"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Return a single-use nonce bound to the bearer token jti."""
        hass: HomeAssistant = request.app[KEY_HASS]
        domain_data: dict[str, Any] = hass.data.get(DOMAIN, {})
        policy_error = _reject_remote_if_disallowed(request, domain_data)
        if policy_error is not None:
            return policy_error

        rate_limit_error = _rate_limit_request(
            hass,
            domain_data,
            request=request,
            bucket="nonce",
        )
        if rate_limit_error is not None:
            return rate_limit_error

        bearer_token = _extract_bearer_token(request)
        if bearer_token is None:
            return self.json(
                {
                    "error": "missing_bearer_token",
                    "message": "Authorization header with Bearer token is required",
                },
                status_code=401,
            )

        token_manager, token_version = _resolve_token_context(domain_data)
        if token_manager is None or token_version is None:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "HA Easy Control token context is not initialized",
                },
                status_code=503,
            )

        try:
            token_payload, _ = await _verify_guest_token_for_action(
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
            TokenRevokedError,
        ) as err:
            return _unauthorized_token_response(self, err)

        nonce_store = _get_nonce_store(domain_data)
        if nonce_store is None:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "Action nonce store is not initialized",
                },
                status_code=503,
            )

        nonce_ttl_seconds = _get_nonce_ttl(domain_data)
        nonce = nonce_store.issue(jti=token_payload.jti, ttl_seconds=nonce_ttl_seconds)
        return self.json(
            {
                "nonce": nonce.nonce,
                "expires_at": nonce.expires_at,
                "jti": token_payload.jti,
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

        rate_limit_error = _rate_limit_request(
            hass,
            domain_data,
            request=request,
            bucket="qr",
            extra_keys=[pairing_code],
        )
        if rate_limit_error is not None:
            return rate_limit_error

        pairing_store = domain_data.get(DATA_PAIRING_STORE)
        if not isinstance(pairing_store, PairingStore):
            return web.Response(
                text="HA Easy Control pairing store is not initialized",
                status=503,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )

        pairing_record, qr_failure_reason = _validate_pairing_for_qr(
            pairing_store, pairing_code, qr_access_token
        )
        if pairing_record is None:
            if qr_failure_reason in {"used", "scanned"}:
                return web.Response(
                    text="QR code has already been scanned",
                    status=410,
                    content_type="text/plain",
                    headers=NO_STORE_HEADERS,
                )
            if qr_failure_reason == "expired":
                return web.Response(
                    text="QR code has expired",
                    status=410,
                    content_type="text/plain",
                    headers=NO_STORE_HEADERS,
                )
            return web.Response(
                text="Invalid or expired qr access token",
                status=401,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )

        base_url = _resolve_home_assistant_url_from_request(request, hass)
        entity_ids_csv = ",".join(
            e["entity_id"] for e in pairing_record.entities
        )
        qr_payload = (
            "easy-control://pair?"
            + urlencode(
                    {
                        "pairing_code": pairing_record.pairing_code,
                        "code": pairing_record.pairing_code,
                        "base_url": base_url,
                        "entity_ids": entity_ids_csv,
                        # Backward-compat singular fields:
                        "entity_id": pairing_record.entity_id,
                        "allowed_action": pairing_record.allowed_action,
                        "scan_ack_token": pairing_record.scan_ack_token,
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


class GuestAccessEntityStatesView(HomeAssistantView):
    """Return live HA entity states for all token-scoped entities."""

    url = "/api/easy_control/states"
    name = "api:easy_control:states"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Return current state for each entity in the guest token scope."""
        hass: HomeAssistant = request.app[KEY_HASS]
        domain_data = hass.data.get(DOMAIN, {})
        policy_error = _reject_remote_if_disallowed(request, domain_data)
        if policy_error is not None:
            return policy_error

        rate_limit_error = _rate_limit_request(
            hass, domain_data, request=request, bucket="states"
        )
        if rate_limit_error is not None:
            return rate_limit_error

        bearer = _extract_bearer_token(request)
        if not bearer:
            return self.json(
                {"error": "missing_token", "message": "Bearer token is required"},
                status_code=401,
            )

        token_manager, token_version = _resolve_token_context(domain_data)
        if token_manager is None or token_version is None:
            return self.json(
                {
                    "error": "integration_not_ready",
                    "message": "HA Easy Control token context is not initialized",
                },
                status_code=503,
            )

        try:
            token_payload, _use_count = await _verify_guest_token_for_action(
                hass=hass,
                token_manager=token_manager,
                token=bearer,
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
            TokenRevokedError,
        ) as err:
            return _unauthorized_token_response(self, err)

        entity_states: list[dict[str, Any]] = []
        for grant in token_payload.entities:
            eid = grant["entity_id"]
            state_obj = hass.states.get(eid)
            domain = eid.split(".", maxsplit=1)[0]
            entry: dict[str, Any] = {
                "entity_id": eid,
                "domain": domain,
                "state": state_obj.state if state_obj else "unavailable",
                "friendly_name": (
                    state_obj.attributes.get("friendly_name", eid)
                    if state_obj
                    else eid
                ),
            }
            if state_obj:
                unit = state_obj.attributes.get("unit_of_measurement")
                if unit:
                    entry["unit"] = unit
                device_class = state_obj.attributes.get("device_class")
                if device_class:
                    entry["device_class"] = device_class
            entity_states.append(entry)

        return self.json({"entities": entity_states})


class GuestAccessDeepLinkRedirectView(HomeAssistantView):
    """HTTPS redirect page that bounces to the easy-control:// deep link.

    Email clients strip custom URL schemes for security, so emails link here
    instead. This page immediately redirects to the native app via JavaScript
    and provides a manual fallback link + pairing code.
    """

    url = "/api/easy_control/link"
    name = "api:easy_control:link"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Render an HTML page that redirects to the deep link."""
        hass: HomeAssistant = request.app[KEY_HASS]
        domain_data: dict[str, Any] = hass.data.get(DOMAIN, {})

        pairing_code = request.query.get("code", "")
        if not pairing_code:
            return web.Response(
                text="Missing required query parameter: code",
                status=400,
                content_type="text/plain",
                headers=NO_STORE_HEADERS,
            )

        rate_limit_error = _rate_limit_request(
            hass,
            domain_data,
            request=request,
            bucket="qr",
            extra_keys=[pairing_code],
        )
        if rate_limit_error is not None:
            return rate_limit_error

        base_url = request.query.get("base_url", "")
        scan_ack_token = request.query.get("scan_ack_token", "")
        entity_ids = request.query.get("entity_ids", "")
        allowed_action = request.query.get("allowed_action", "")

        deep_link_params: dict[str, str] = {
            "pairing_code": pairing_code,
            "code": pairing_code,
        }
        if base_url:
            deep_link_params["base_url"] = base_url
        if scan_ack_token:
            deep_link_params["scan_ack_token"] = scan_ack_token
        if entity_ids:
            deep_link_params["entity_ids"] = entity_ids
        if allowed_action:
            deep_link_params["allowed_action"] = allowed_action

        deep_link = "easy-control://pair?" + urlencode(deep_link_params)

        import html as html_mod

        safe_code = html_mod.escape(pairing_code)
        safe_deep_link = html_mod.escape(deep_link)

        redirect_html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Open in Easy Control</title>
<script>window.location.href={json.dumps(deep_link)};</script>
</head>
<body style="font-family:-apple-system,system-ui,sans-serif;text-align:center;\
padding:60px 20px;background:#f5f5f7;color:#1d1d1f;">
<h1 style="font-size:24px;font-weight:600;">Opening Easy Control&hellip;</h1>
<p style="color:#86868b;">If the app does not open automatically:</p>
<p style="margin:24px 0;">
<a href="{safe_deep_link}" style="display:inline-block;padding:14px 28px;\
background-color:#007AFF;color:#fff;text-decoration:none;border-radius:12px;\
font-weight:600;">Open in Easy Control</a>
</p>
<p style="color:#86868b;font-size:14px;">
Or enter this code manually in the app:<br>
<strong style="font-size:20px;letter-spacing:2px;color:#1d1d1f;">\
{safe_code}</strong>
</p>
</body>
</html>"""
        return web.Response(
            text=redirect_html,
            content_type="text/html",
            headers=NO_STORE_HEADERS,
        )


def async_register_api(hass: HomeAssistant) -> None:
    """Register HA Easy Control HTTP API views exactly once."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(DATA_API_REGISTERED):
        return

    hass.http.register_view(GuestAccessPairView)
    hass.http.register_view(GuestAccessPairScannedView)
    hass.http.register_view(GuestAccessTokenValidateView)
    hass.http.register_view(GuestAccessActionNonceView)
    hass.http.register_view(GuestAccessActionView)
    hass.http.register_view(GuestAccessQrView)
    hass.http.register_view(GuestAccessEntityStatesView)
    hass.http.register_view(GuestAccessDeepLinkRedirectView)
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
    if await async_is_token_revoked(hass, token_payload.jti):
        raise TokenRevokedError("Token jti has been revoked")
    use_count = await async_get_token_use_count(hass, token_payload.jti)
    # max_uses=0 means unlimited until expiry/revocation.
    if token_payload.max_uses > 0 and use_count >= token_payload.max_uses:
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
    mapping = ACTION_SERVICE_MAP.get(action)
    if mapping is None:
        return None
    expected_domain, service_name = mapping
    if entity_domain != expected_domain:
        return None
    return expected_domain, service_name


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


def _get_rate_limit_config(domain_data: dict[str, Any], bucket: str) -> tuple[int, int]:
    """Return per-minute rate limit config for a bucket."""
    entry_data = _get_active_entry_data(domain_data)
    if not isinstance(entry_data, dict):
        defaults = {
            "pair": DEFAULT_PAIR_RATE_LIMIT_PER_MIN,
            "action": DEFAULT_ACTION_RATE_LIMIT_PER_MIN,
            "nonce": DEFAULT_ACTION_RATE_LIMIT_PER_MIN,
            "qr": DEFAULT_QR_RATE_LIMIT_PER_MIN,
            "states": DEFAULT_STATES_RATE_LIMIT_PER_MIN,
        }
        return defaults.get(bucket, DEFAULT_ACTION_RATE_LIMIT_PER_MIN), 60

    if bucket == "pair":
        limit = int(entry_data.get(CONF_PAIR_RATE_LIMIT_PER_MIN, DEFAULT_PAIR_RATE_LIMIT_PER_MIN))
    elif bucket in {"action", "nonce"}:
        limit = int(
            entry_data.get(CONF_ACTION_RATE_LIMIT_PER_MIN, DEFAULT_ACTION_RATE_LIMIT_PER_MIN)
        )
    elif bucket == "qr":
        limit = int(entry_data.get(CONF_QR_RATE_LIMIT_PER_MIN, DEFAULT_QR_RATE_LIMIT_PER_MIN))
    elif bucket == "states":
        limit = int(
            entry_data.get(CONF_STATES_RATE_LIMIT_PER_MIN, DEFAULT_STATES_RATE_LIMIT_PER_MIN)
        )
    else:
        limit = DEFAULT_ACTION_RATE_LIMIT_PER_MIN
    return max(limit, 1), 60


def _get_nonce_store(domain_data: dict[str, Any]) -> ActionNonceStore | None:
    """Return initialized nonce store."""
    store = domain_data.get(DATA_NONCE_STORE)
    return store if isinstance(store, ActionNonceStore) else None


def _get_rate_limiter(domain_data: dict[str, Any]) -> FixedWindowRateLimiter | None:
    """Return initialized rate limiter."""
    limiter = domain_data.get(DATA_RATE_LIMITER)
    return limiter if isinstance(limiter, FixedWindowRateLimiter) else None


def _get_proof_policy(domain_data: dict[str, Any]) -> tuple[bool, int]:
    """Return action-proof required flag and max clock skew."""
    entry_data = _get_active_entry_data(domain_data)
    if not isinstance(entry_data, dict):
        return DEFAULT_REQUIRE_ACTION_PROOF, DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS
    return (
        bool(entry_data.get(CONF_REQUIRE_ACTION_PROOF, DEFAULT_REQUIRE_ACTION_PROOF)),
        int(
            entry_data.get(
                CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
                DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS,
            )
        ),
    )


def _get_nonce_ttl(domain_data: dict[str, Any]) -> int:
    """Return configured action nonce TTL."""
    entry_data = _get_active_entry_data(domain_data)
    if not isinstance(entry_data, dict):
        return DEFAULT_NONCE_TTL_SECONDS
    return max(
        int(entry_data.get(CONF_NONCE_TTL_SECONDS, DEFAULT_NONCE_TTL_SECONDS)),
        1,
    )


def _rate_limit_request(
    hass: HomeAssistant,
    domain_data: dict[str, Any],
    *,
    request: web.Request,
    bucket: str,
    extra_keys: list[str] | None = None,
    include_ip: bool = True,
) -> web.Response | None:
    """Apply fixed-window rate limiting to the request."""
    limiter = _get_rate_limiter(domain_data)
    if limiter is None:
        return None

    limit, window_seconds = _get_rate_limit_config(domain_data, bucket)
    keys: list[str] = []
    if include_ip:
        keys.append(f"ip:{request.remote or 'unknown'}")
    for value in extra_keys or []:
        if isinstance(value, str) and value:
            keys.append(f"key:{value}")

    for key in keys:
        decision = limiter.check(
            bucket=bucket,
            key=key,
            limit=limit,
            window_seconds=window_seconds,
        )
        if decision.allowed:
            continue
        hass.bus.async_fire(
            EVENT_RATE_LIMITED,
            {
                "bucket": bucket,
                "key": key,
                "remote": request.remote,
                "retry_after": decision.retry_after,
                "timestamp": dt_util.utcnow().isoformat(),
            },
        )
        response = web.json_response(
            {
                "error": "rate_limited",
                "message": "Request rate limit exceeded",
                "retry_after": decision.retry_after,
            },
            status=429,
        )
        response.headers["Retry-After"] = str(decision.retry_after)
        return response
    return None


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
    elif isinstance(err, (TokenVersionMismatchError, TokenRevokedError)):
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


def _proof_failure_response(view: HomeAssistantView, err: Exception) -> web.Response:
    """Map proof/nonce failures to explicit auth errors for client handling."""
    if isinstance(err, ActionProofMissingError):
        return view.json(
            {
                "success": False,
                "error": "action_proof_required",
                "message": str(err),
            },
            status_code=401,
        )
    if isinstance(err, ActionProofReplayError):
        return view.json(
            {
                "success": False,
                "error": "action_proof_replay",
                "message": str(err),
            },
            status_code=401,
        )
    if isinstance(err, ActionProofNonceExpiredError):
        return view.json(
            {
                "success": False,
                "error": "action_nonce_expired",
                "message": str(err),
            },
            status_code=401,
        )
    if isinstance(err, ActionProofClockSkewError):
        return view.json(
            {
                "success": False,
                "error": "action_proof_clock_skew",
                "message": str(err),
            },
            status_code=401,
        )
    if isinstance(err, TokenRevokedError):
        return view.json(
            {
                "success": False,
                "error": "token_revoked",
                "message": str(err),
            },
            status_code=401,
        )
    return view.json(
        {
            "success": False,
            "error": "action_proof_invalid",
            "message": str(err),
        },
        status_code=401,
    )


def _validate_pairing_for_qr(
    pairing_store: PairingStore, pairing_code: str, qr_access_token: str
) -> tuple[Any | None, str | None]:
    """Validate QR image access without consuming pairing state."""
    get_pairing = getattr(pairing_store, "get_pairing", None)
    if callable(get_pairing):
        try:
            pairing_record = get_pairing(pairing_code)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Failed to load pairing record for qr endpoint")
            return None, "invalid"
        if pairing_record is None:
            return None, None

        record_qr_access_token = getattr(pairing_record, "qr_access_token", None)
        if not isinstance(record_qr_access_token, str) or not record_qr_access_token:
            return None, "invalid"
        if not compare_digest(record_qr_access_token, qr_access_token):
            return None, "invalid"

        if getattr(pairing_record, "qr_scanned_at", None) is not None:
            return None, "scanned"
        if getattr(pairing_record, "qr_access_used_at", None) is not None:
            return None, "used"

        return pairing_record, None

    validate_qr_access = getattr(pairing_store, "validate_qr_access", None)
    if callable(validate_qr_access):
        try:
            pairing_record = validate_qr_access(pairing_code, qr_access_token)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Failed to validate qr access token")
            return None, "invalid"
        return pairing_record, None

    return None, "invalid"


def _acknowledge_pairing_qr_scan(
    pairing_store: PairingStore, pairing_code: str, scan_ack_token: str
) -> tuple[Any | None, str | None]:
    """Acknowledge QR scan with backward-compatible fallbacks."""
    acknowledge_qr_scan = getattr(pairing_store, "acknowledge_qr_scan", None)
    if callable(acknowledge_qr_scan):
        try:
            result = acknowledge_qr_scan(pairing_code, scan_ack_token)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Failed to acknowledge qr scan")
            return None, "invalid"
        if isinstance(result, tuple) and len(result) == 2:
            return result
        return result, None

    # Older stores do not support explicit scan-ack; fail closed.
    return None, "invalid"


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
    hass: HomeAssistant,
    guest_id: str,
    entity_id: str,
    timestamp: str,
    *,
    jti: str | None = None,
    remote: str | None = None,
    result: str = "success",
) -> None:
    """Write local audit trail for successful guest access usage."""
    event_data = {
        "guest_id": guest_id,
        "entity": entity_id,
        "timestamp": timestamp,
        "jti": jti,
        "remote": remote,
        "result": result,
    }
    hass.bus.async_fire(EVENT_GUEST_ACCESS_USED, event_data)

    if hass.services.has_service("logbook", "log"):
        await hass.services.async_call(
            "logbook",
            "log",
            {
                "name": "HA Easy Control",
                "message": (
                    f"Guest {guest_id} {result} on {entity_id} at {timestamp}"
                    + (f" (remote={remote})" if remote else "")
                ),
                "domain": DOMAIN,
                "entity_id": entity_id,
            },
            blocking=False,
        )


async def _verify_action_proof_request(
    *,
    hass: HomeAssistant,
    domain_data: dict[str, Any],
    request: web.Request,
    token_payload: GuestTokenPayload,
    raw_body: bytes,
    max_clock_skew_seconds: int,
) -> None:
    """Validate nonce + signed action proof for a device-bound request."""
    proof, signature = decode_action_proof_headers(
        request.headers.get("X-Easy-Control-Proof"),
        request.headers.get("X-Easy-Control-Proof-Signature"),
    )
    validate_proof_clock(
        proof,
        max_skew_seconds=max_clock_skew_seconds,
    )

    if proof.method.upper() != request.method.upper():
        raise ActionProofInvalidError("Action proof method does not match request")
    if proof.path != request.path:
        raise ActionProofInvalidError("Action proof path does not match request")
    if proof.jti != token_payload.jti:
        raise ActionProofInvalidError("Action proof jti does not match token")
    if proof.body_sha256 != hash_request_body(raw_body):
        raise ActionProofInvalidError("Action proof body hash does not match request body")
    if token_payload.device_id and proof.device_id != token_payload.device_id:
        raise ActionProofInvalidError("Action proof device_id does not match token")
    if await async_is_token_revoked(hass, token_payload.jti):
        raise TokenRevokedError("Token jti has been revoked")

    metadata = await async_get_issued_token_metadata(hass, token_payload.jti)
    if not isinstance(metadata, dict):
        raise ActionProofInvalidError("Issued token metadata was not found")

    device_public_key = metadata.get("device_public_key")
    if not isinstance(device_public_key, str) or not device_public_key:
        raise ActionProofInvalidError("Device public key is not registered for this token")

    public_key_raw, jkt = canonicalize_public_key(device_public_key)
    expected_jkt = token_payload.cnf_jkt or metadata.get("cnf_jkt")
    if isinstance(expected_jkt, str) and expected_jkt and jkt != expected_jkt:
        raise ActionProofInvalidError("Device key thumbprint does not match token binding")

    nonce_store = _get_nonce_store(domain_data)
    if nonce_store is None:
        raise ActionProofInvalidError("Action nonce store is not initialized")
    _nonce_record, nonce_failure_reason = nonce_store.consume(
        nonce=proof.nonce,
        jti=token_payload.jti,
    )
    if nonce_failure_reason == "expired":
        raise ActionProofNonceExpiredError("Action proof nonce has expired")
    if nonce_failure_reason in {"used", "wrong_jti"}:
        raise ActionProofReplayError("Action proof nonce has already been used")
    if _nonce_record is None:
        raise ActionProofInvalidError("Action proof nonce is invalid")

    verify_ed25519_signature(
        public_key_raw,
        build_proof_signing_input(proof),
        signature,
    )

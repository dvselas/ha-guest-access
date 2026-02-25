"""Service registration for HA Easy Control."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast
from urllib.parse import urlencode

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.util import dt as dt_util

from .const import (
    ALLOWED_ENTITY_DOMAINS,
    CONF_ACTIVE_KID,
    CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL,
    CONF_ENTITIES,
    CONF_EXPIRATION_TIME,
    CONF_REQUIRE_ADMIN_APPROVAL,
    CONF_SHOW_QR_NOTIFICATION,
    CONF_SIGNING_KEYS,
    CONF_TOKEN_VERSION,
    DATA_CONFIG_ENTRIES,
    DATA_PAIRING_STORE,
    DATA_TOKEN_MANAGER,
    DOMAIN,
    DOMAIN_ACTION_MAP,
    EVENT_PAIRING_APPROVED,
    EVENT_PAIRING_REJECTED,
    EVENT_REVOKE_ALL,
    EVENT_REVOKE_PASS,
    SERVICE_APPROVE_PAIRING,
    SERVICE_CREATE_PASS,
    SERVICE_REJECT_PAIRING,
    SERVICE_REVOKE_ALL,
    SERVICE_REVOKE_PASS,
)
from .pairing import PairingStore
from .storage import (
    async_get_signing_keyring,
    async_increment_token_version,
    async_revoke_guest_tokens_by_guest_id,
    async_revoke_token_jti,
    async_rotate_signing_key,
)
from .token import GuestTokenManager

SERVICE_CREATE_PASS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ENTITIES): vol.All(cv.ensure_list, [cv.entity_id]),
        vol.Required(CONF_EXPIRATION_TIME): vol.Any(cv.positive_int, cv.datetime),
        vol.Optional(CONF_SHOW_QR_NOTIFICATION, default=True): bool,
        vol.Optional(CONF_REQUIRE_ADMIN_APPROVAL): bool,
    }
)

SERVICE_REVOKE_ALL_SCHEMA = vol.Schema({})
SERVICE_REVOKE_PASS_SCHEMA = vol.Schema(
    {
        vol.Exclusive("jti", "target"): cv.string,
        vol.Exclusive("guest_id", "target"): cv.string,
    }
)
SERVICE_PAIRING_DECISION_SCHEMA = vol.Schema({vol.Required("pairing_code"): cv.string})


def async_register_services(hass: HomeAssistant) -> None:
    """Register HA Easy Control services once per Home Assistant instance."""
    async def _handle_create_pass(call: ServiceCall) -> ServiceResponse:
        return await async_handle_create_pass(hass, call)

    async def _handle_revoke_all(call: ServiceCall) -> ServiceResponse:
        return await async_handle_revoke_all(hass, call)

    async def _handle_revoke_pass(call: ServiceCall) -> ServiceResponse:
        return await async_handle_revoke_pass(hass, call)

    async def _handle_approve_pairing(call: ServiceCall) -> ServiceResponse:
        return await async_handle_approve_pairing(hass, call)

    async def _handle_reject_pairing(call: ServiceCall) -> ServiceResponse:
        return await async_handle_reject_pairing(hass, call)

    if not hass.services.has_service(DOMAIN, SERVICE_CREATE_PASS):
        hass.services.async_register(
            DOMAIN,
            SERVICE_CREATE_PASS,
            _handle_create_pass,
            schema=SERVICE_CREATE_PASS_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_REVOKE_ALL):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REVOKE_ALL,
            _handle_revoke_all,
            schema=SERVICE_REVOKE_ALL_SCHEMA,
            supports_response=SupportsResponse.OPTIONAL,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_REVOKE_PASS):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REVOKE_PASS,
            _handle_revoke_pass,
            schema=SERVICE_REVOKE_PASS_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_APPROVE_PAIRING):
        hass.services.async_register(
            DOMAIN,
            SERVICE_APPROVE_PAIRING,
            _handle_approve_pairing,
            schema=SERVICE_PAIRING_DECISION_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_REJECT_PAIRING):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REJECT_PAIRING,
            _handle_reject_pairing,
            schema=SERVICE_PAIRING_DECISION_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )


def async_unregister_services(hass: HomeAssistant) -> None:
    """Remove HA Easy Control services."""
    if hass.services.has_service(DOMAIN, SERVICE_CREATE_PASS):
        hass.services.async_remove(DOMAIN, SERVICE_CREATE_PASS)
    if hass.services.has_service(DOMAIN, SERVICE_REVOKE_ALL):
        hass.services.async_remove(DOMAIN, SERVICE_REVOKE_ALL)
    if hass.services.has_service(DOMAIN, SERVICE_REVOKE_PASS):
        hass.services.async_remove(DOMAIN, SERVICE_REVOKE_PASS)
    if hass.services.has_service(DOMAIN, SERVICE_APPROVE_PAIRING):
        hass.services.async_remove(DOMAIN, SERVICE_APPROVE_PAIRING)
    if hass.services.has_service(DOMAIN, SERVICE_REJECT_PAIRING):
        hass.services.async_remove(DOMAIN, SERVICE_REJECT_PAIRING)


async def async_handle_create_pass(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """Create a short-lived pairing code and return QR payload."""
    domain_data = hass.data.get(DOMAIN, {})
    pairing_store = domain_data.get(DATA_PAIRING_STORE)
    if not isinstance(pairing_store, PairingStore):
        raise HomeAssistantError("Pairing store is not initialized")

    entity_ids_raw: list[str] = call.data[CONF_ENTITIES]
    expiration_time = call.data[CONF_EXPIRATION_TIME]
    show_qr_notification = bool(call.data[CONF_SHOW_QR_NOTIFICATION])
    entry_data = _get_active_entry_data(domain_data)
    default_require_admin_approval = False
    if isinstance(entry_data, dict):
        default_require_admin_approval = bool(
            entry_data.get(CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL, False)
        )
    require_admin_approval = bool(
        call.data.get(CONF_REQUIRE_ADMIN_APPROVAL, default_require_admin_approval)
    )

    entities = _validate_and_resolve_entities(entity_ids_raw)
    pass_expires_at = _resolve_pass_expiration(hass, expiration_time)

    pairing = pairing_store.create_pairing(
        entities=entities,
        pass_expires_at=pass_expires_at,
        require_admin_approval=require_admin_approval,
    )

    base_url = _resolve_home_assistant_url(hass)
    entity_ids_csv = ",".join(e["entity_id"] for e in entities)
    pair_query = urlencode(
        {
            "pairing_code": pairing.pairing_code,
            "code": pairing.pairing_code,
            "base_url": base_url,
            "entity_ids": entity_ids_csv,
            # Backward-compat singular fields (first entity):
            "entity_id": pairing.entity_id,
            "allowed_action": pairing.allowed_action,
            "scan_ack_token": pairing.scan_ack_token,
        }
    )
    qr_query = urlencode(
        {"code": pairing.pairing_code, "qr_token": pairing.qr_access_token}
    )
    qr_string = f"easy-control://pair?{pair_query}"
    qr_image_path = f"/api/easy_control/qr?{qr_query}"
    qr_image_url = qr_image_path

    if show_qr_notification and hass.services.has_service(
        "persistent_notification", "create"
    ):
        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "HA Easy Control Pairing",
                "message": (
                    "Scanne den QR-Code mit der Gast-App.\n\n"
                    f"![HA Easy Control QR]({qr_image_url})\n\n"
                    f"[QR-Link öffnen]({qr_image_url})\n\n"
                    f"Fallback pairing_code: `{pairing.pairing_code}`\n"
                    f"Pairing expires_at: `{pairing.pairing_expires_at}`"
                ),
                "notification_id": f"easy_control_pairing_{pairing.pairing_code.lower()}",
            },
            blocking=False,
        )

    return {
        **pairing.to_dict(),
        "qr_string": qr_string,
        "qr_image_path": qr_image_path,
        "qr_image_url": qr_image_url,
        "base_url": base_url,
    }


async def async_handle_revoke_all(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """Emergency-revoke all guest passes by rotating signing key."""
    del call
    domain_data = hass.data.get(DOMAIN, {})
    entry_ids: set[str] = domain_data.get(DATA_CONFIG_ENTRIES, set())
    if not entry_ids:
        raise HomeAssistantError("HA Easy Control has no active config entries")

    await async_rotate_signing_key(hass)
    new_token_version = await async_increment_token_version(hass, clear_uses=True)
    signing_keys, active_kid = await async_get_signing_keyring(hass)

    updated_entries = 0
    for entry_id in list(entry_ids):
        entry_data = domain_data.get(entry_id)
        if not isinstance(entry_data, dict):
            continue

        entry_data[CONF_SIGNING_KEYS] = signing_keys
        entry_data[CONF_ACTIVE_KID] = active_kid
        entry_data[CONF_TOKEN_VERSION] = new_token_version
        entry_data[DATA_TOKEN_MANAGER] = GuestTokenManager(
            signing_keys=signing_keys,
            active_kid=active_kid,
        )
        updated_entries += 1

    pairing_store = domain_data.get(DATA_PAIRING_STORE)
    cleared_pairings = 0
    if isinstance(pairing_store, PairingStore):
        cleared_pairings = pairing_store.clear()

    event_data = {
        "revoked_at": dt_util.utcnow().isoformat(),
        "updated_entries": updated_entries,
        "cleared_pairings": cleared_pairings,
        "token_version": new_token_version,
    }
    hass.bus.async_fire(EVENT_REVOKE_ALL, event_data)
    if hass.services.has_service("logbook", "log"):
        await hass.services.async_call(
            "logbook",
            "log",
            {
                "name": "HA Easy Control",
                "message": "Emergency revoke_all executed",
                "domain": DOMAIN,
            },
            blocking=False,
        )

    revoked_at = event_data["revoked_at"]
    return cast(
        ServiceResponse,
        {
        "status": "revoked",
        "revoked_at": str(revoked_at),
        "updated_entries": updated_entries,
        "cleared_pairings": cleared_pairings,
        "token_version": new_token_version,
    },
    )


async def async_handle_revoke_pass(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """Revoke a specific guest pass by jti or guest_id."""
    jti = call.data.get("jti")
    guest_id = call.data.get("guest_id")
    if jti:
        revoked = await async_revoke_token_jti(hass, str(jti))
        revoked_jtis = [str(jti)] if revoked else []
    elif guest_id:
        revoked_jtis = await async_revoke_guest_tokens_by_guest_id(hass, str(guest_id))
    else:
        raise HomeAssistantError("Either jti or guest_id is required")

    event_data = {
        "revoked_at": dt_util.utcnow().isoformat(),
        "revoked_jtis": revoked_jtis,
        "target_guest_id": str(guest_id) if guest_id else None,
    }
    hass.bus.async_fire(EVENT_REVOKE_PASS, event_data)
    if hass.services.has_service("logbook", "log"):
        await hass.services.async_call(
            "logbook",
            "log",
            {
                "name": "HA Easy Control",
                "message": (
                    f"Revoked {len(revoked_jtis)} guest pass(es)"
                    + (f" for guest {guest_id}" if guest_id else "")
                ),
                "domain": DOMAIN,
            },
            blocking=False,
        )
    revoked_at = event_data["revoked_at"]
    target_guest_id = event_data["target_guest_id"]
    return cast(
        ServiceResponse,
        {
        "status": "revoked",
        "revoked_at": str(revoked_at),
        "revoked_jtis": [str(revoked_jti) for revoked_jti in revoked_jtis],
        "target_guest_id": str(target_guest_id) if target_guest_id is not None else None,
    },
    )


async def async_handle_approve_pairing(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """Approve a pending pairing request by pairing code."""
    return await _async_handle_pairing_decision(hass, call, approve=True)


async def async_handle_reject_pairing(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """Reject a pending pairing request by pairing code."""
    return await _async_handle_pairing_decision(hass, call, approve=False)


def _validate_and_resolve_entities(
    entity_ids: list[str],
) -> list[dict[str, Any]]:
    """Validate entity domains and auto-resolve allowed actions.

    Returns a list of ``{"entity_id": ..., "allowed_actions": [...]}`` dicts.
    """
    if not entity_ids:
        raise HomeAssistantError("At least one entity is required")

    entities: list[dict[str, Any]] = []
    for eid in entity_ids:
        entity_domain = eid.split(".", maxsplit=1)[0]
        if entity_domain not in ALLOWED_ENTITY_DOMAINS:
            allowed_domains = ", ".join(ALLOWED_ENTITY_DOMAINS)
            raise HomeAssistantError(
                f"Unsupported entity domain '{entity_domain}'. "
                f"Allowed: {allowed_domains}"
            )
        actions = DOMAIN_ACTION_MAP.get(entity_domain)
        if actions is None:
            raise HomeAssistantError(
                f"No action mapping for domain '{entity_domain}'"
            )
        entities.append({"entity_id": eid, "allowed_actions": actions})
    return entities


def _resolve_pass_expiration(hass: HomeAssistant, expiration_value: Any) -> int:
    """Convert expiration input to Unix timestamp, ensuring future expiry."""
    now_timestamp = int(dt_util.utcnow().timestamp())

    if isinstance(expiration_value, (int, float)):
        pass_expires_at = now_timestamp + int(expiration_value)
    elif isinstance(expiration_value, datetime):
        expiration_datetime = expiration_value
        if expiration_datetime.tzinfo is None:
            local_timezone = dt_util.get_time_zone(hass.config.time_zone)
            expiration_datetime = expiration_datetime.replace(tzinfo=local_timezone)
        pass_expires_at = int(expiration_datetime.timestamp())
    else:
        raise HomeAssistantError(
            "expiration_time must be either a positive number of seconds or datetime"
        )

    if pass_expires_at <= now_timestamp:
        raise HomeAssistantError("expiration_time must point to a future time")

    return pass_expires_at


def _resolve_home_assistant_url(hass: HomeAssistant) -> str:
    """Resolve best available base URL for app deep links."""
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
    return ""


def _get_active_entry_data(domain_data: dict[str, Any]) -> dict[str, Any] | None:
    """Return first active config-entry data block for this integration."""
    entry_ids: set[str] = domain_data.get(DATA_CONFIG_ENTRIES, set())
    for entry_id in entry_ids:
        entry_data = domain_data.get(entry_id)
        if isinstance(entry_data, dict):
            return entry_data
    return None


async def _async_handle_pairing_decision(
    hass: HomeAssistant,
    call: ServiceCall,
    *,
    approve: bool,
) -> ServiceResponse:
    """Approve or reject a pending pairing request."""
    domain_data = hass.data.get(DOMAIN, {})
    pairing_store = domain_data.get(DATA_PAIRING_STORE)
    if not isinstance(pairing_store, PairingStore):
        raise HomeAssistantError("Pairing store is not initialized")

    pairing_code = str(call.data["pairing_code"]).strip()
    if not pairing_code:
        raise HomeAssistantError("pairing_code must be a non-empty string")

    if approve:
        record, reason = pairing_store.approve_pairing(pairing_code)
        status = "approved"
        event_name = EVENT_PAIRING_APPROVED
    else:
        record, reason = pairing_store.reject_pairing(pairing_code)
        status = "rejected"
        event_name = EVENT_PAIRING_REJECTED

    if record is None:
        if reason == "expired":
            raise HomeAssistantError("Pairing code has expired")
        raise HomeAssistantError("Pairing code was not found")

    entity_ids = [e["entity_id"] for e in record.entities]
    event_data = {
        "pairing_code": pairing_code,
        "status": status,
        "decision_reason": reason,
        "entities": list(record.entities),
        "entity_id": record.entity_id,
        "timestamp": dt_util.utcnow().isoformat(),
    }
    hass.bus.async_fire(event_name, event_data)
    if hass.services.has_service("logbook", "log"):
        entity_summary = ", ".join(entity_ids[:3])
        if len(entity_ids) > 3:
            entity_summary += f" (+{len(entity_ids) - 3} more)"
        await hass.services.async_call(
            "logbook",
            "log",
            {
                "name": "HA Easy Control",
                "message": f"Pairing {pairing_code} {status} for {entity_summary}",
                "domain": DOMAIN,
                "entity_id": entity_ids[0] if entity_ids else "",
            },
            blocking=False,
        )

    return {
        "pairing_code": pairing_code,
        "status": status,
        "reason": reason,
        **record.to_dict(),
    }

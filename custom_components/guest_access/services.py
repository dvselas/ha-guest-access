"""Service registration for Guest Access."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlencode

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
import homeassistant.helpers.config_validation as cv
from homeassistant.util import dt as dt_util

from .const import (
    ALLOWED_ACTIONS,
    ALLOWED_ENTITY_DOMAINS,
    CONF_ALLOWED_ACTION,
    CONF_ENTITY,
    CONF_EXPIRATION_TIME,
    CONF_SHOW_QR_NOTIFICATION,
    CONF_SIGNING_KEY,
    CONF_TOKEN_VERSION,
    DATA_CONFIG_ENTRIES,
    DATA_PAIRING_STORE,
    DATA_TOKEN_MANAGER,
    DOMAIN,
    SERVICE_CREATE_PASS,
    SERVICE_REVOKE_ALL,
    EVENT_REVOKE_ALL,
)
from .pairing import PairingStore
from .storage import async_increment_token_version, async_rotate_signing_key
from .token import GuestTokenManager

SERVICE_CREATE_PASS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ENTITY): cv.entity_id,
        vol.Required(CONF_ALLOWED_ACTION): vol.In(ALLOWED_ACTIONS),
        vol.Required(CONF_EXPIRATION_TIME): vol.Any(cv.positive_int, cv.datetime),
        vol.Optional(CONF_SHOW_QR_NOTIFICATION, default=True): bool,
    }
)

SERVICE_REVOKE_ALL_SCHEMA = vol.Schema({})


def async_register_services(hass: HomeAssistant) -> None:
    """Register Guest Access services once per Home Assistant instance."""
    async def _handle_create_pass(call: ServiceCall) -> ServiceResponse:
        return await async_handle_create_pass(hass, call)

    async def _handle_revoke_all(call: ServiceCall) -> ServiceResponse:
        return await async_handle_revoke_all(hass, call)

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


def async_unregister_services(hass: HomeAssistant) -> None:
    """Remove Guest Access services."""
    if hass.services.has_service(DOMAIN, SERVICE_CREATE_PASS):
        hass.services.async_remove(DOMAIN, SERVICE_CREATE_PASS)
    if hass.services.has_service(DOMAIN, SERVICE_REVOKE_ALL):
        hass.services.async_remove(DOMAIN, SERVICE_REVOKE_ALL)


async def async_handle_create_pass(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """Create a short-lived pairing code and return QR payload."""
    domain_data = hass.data.get(DOMAIN, {})
    pairing_store = domain_data.get(DATA_PAIRING_STORE)
    if not isinstance(pairing_store, PairingStore):
        raise HomeAssistantError("Pairing store is not initialized")

    entity_id = call.data[CONF_ENTITY]
    allowed_action = call.data[CONF_ALLOWED_ACTION]
    expiration_time = call.data[CONF_EXPIRATION_TIME]
    show_qr_notification = bool(call.data[CONF_SHOW_QR_NOTIFICATION])

    _validate_entity_action_scope(entity_id, allowed_action)
    pass_expires_at = _resolve_pass_expiration(hass, expiration_time)

    pairing = pairing_store.create_pairing(
        entity_id=entity_id,
        allowed_action=allowed_action,
        pass_expires_at=pass_expires_at,
    )

    pair_query = urlencode(
        {"pairing_code": pairing.pairing_code, "code": pairing.pairing_code}
    )
    qr_query = urlencode(
        {"code": pairing.pairing_code, "qr_token": pairing.qr_access_token}
    )
    qr_string = f"guest-access://pair?{pair_query}"
    qr_image_path = f"/api/guest_access/qr?{qr_query}"
    qr_image_url = qr_image_path

    if show_qr_notification and hass.services.has_service(
        "persistent_notification", "create"
    ):
        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "Guest Access Pairing",
                "message": (
                    "Scanne den QR-Code mit der Gast-App.\n\n"
                    f"![Guest Access QR]({qr_image_url})\n\n"
                    f"[QR-Link öffnen]({qr_image_url})\n\n"
                    f"Fallback pairing_code: `{pairing.pairing_code}`\n"
                    f"Pairing expires_at: `{pairing.pairing_expires_at}`"
                ),
                "notification_id": f"guest_access_pairing_{pairing.pairing_code.lower()}",
            },
            blocking=False,
        )

    return {
        **pairing.to_dict(),
        "qr_string": qr_string,
        "qr_image_path": qr_image_path,
        "qr_image_url": qr_image_url,
    }


async def async_handle_revoke_all(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """Emergency-revoke all guest passes by rotating signing key."""
    del call
    domain_data = hass.data.get(DOMAIN, {})
    entry_ids: set[str] = domain_data.get(DATA_CONFIG_ENTRIES, set())
    if not entry_ids:
        raise HomeAssistantError("Guest Access has no active config entries")

    new_signing_key = await async_rotate_signing_key(hass)
    new_token_version = await async_increment_token_version(hass, clear_uses=True)

    updated_entries = 0
    for entry_id in list(entry_ids):
        entry_data = domain_data.get(entry_id)
        if not isinstance(entry_data, dict):
            continue

        entry_data[CONF_SIGNING_KEY] = new_signing_key
        entry_data[CONF_TOKEN_VERSION] = new_token_version
        entry_data[DATA_TOKEN_MANAGER] = GuestTokenManager(new_signing_key)
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
                "name": "Guest Access",
                "message": "Emergency revoke_all executed",
                "domain": DOMAIN,
            },
            blocking=False,
        )

    return {
        "status": "revoked",
        **event_data,
    }


def _validate_entity_action_scope(entity_id: str, allowed_action: str) -> None:
    """Limit pass scopes to door and garage control only."""
    entity_domain = entity_id.split(".", maxsplit=1)[0]
    if entity_domain not in ALLOWED_ENTITY_DOMAINS:
        allowed_domains = ", ".join(ALLOWED_ENTITY_DOMAINS)
        raise HomeAssistantError(
            f"Unsupported entity domain '{entity_domain}'. Allowed: {allowed_domains}"
        )

    if entity_domain == "lock" and allowed_action != "door.open":
        raise HomeAssistantError(
            "allowed_action must be 'door.open' when entity is a lock.* door"
        )
    if entity_domain == "cover" and allowed_action != "garage.open":
        raise HomeAssistantError(
            "allowed_action must be 'garage.open' when entity is a cover.* garage"
        )


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

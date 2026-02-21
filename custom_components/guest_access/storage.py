"""Storage helpers for Guest Access."""

from __future__ import annotations

import secrets
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import CONF_SECRET_KEY, CONF_SIGNING_KEY, STORAGE_KEY, STORAGE_VERSION


def _build_store(hass: HomeAssistant) -> Store[dict[str, Any]]:
    """Return the integration key store."""
    return Store(hass, STORAGE_VERSION, STORAGE_KEY, private=True)


async def async_get_or_create_signing_key(hass: HomeAssistant) -> str:
    """Return an existing signing key or create and persist a new one."""
    store = _build_store(hass)
    data = await store.async_load() or {}

    existing_signing_key = data.get(CONF_SIGNING_KEY)
    if isinstance(existing_signing_key, str) and existing_signing_key:
        return existing_signing_key

    # Backward compatibility for pre-1.2 scaffold that stored "secret_key".
    legacy_secret_key = data.get(CONF_SECRET_KEY)
    if isinstance(legacy_secret_key, str) and legacy_secret_key:
        await store.async_save({CONF_SIGNING_KEY: legacy_secret_key})
        return legacy_secret_key

    signing_key = secrets.token_urlsafe(64)
    await store.async_save({CONF_SIGNING_KEY: signing_key})
    return signing_key


async def async_rotate_signing_key(hass: HomeAssistant) -> str:
    """Generate a new signing key and persist it, invalidating old token signatures."""
    store = _build_store(hass)
    signing_key = secrets.token_urlsafe(64)
    await store.async_save({CONF_SIGNING_KEY: signing_key})
    return signing_key

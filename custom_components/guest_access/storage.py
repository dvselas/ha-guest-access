"""Storage helpers for HA Easy Control."""

from __future__ import annotations

import asyncio
import secrets
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import (
    CONF_SECRET_KEY,
    CONF_SIGNING_KEY,
    CONF_TOKEN_USES,
    CONF_TOKEN_VERSION,
    DATA_STORAGE_LOCK,
    DEFAULT_TOKEN_VERSION,
    DOMAIN,
    STORAGE_KEY,
    STORAGE_VERSION,
)


def _build_store(hass: HomeAssistant) -> Store[dict[str, Any]]:
    """Return the integration key store."""
    return Store(hass, STORAGE_VERSION, STORAGE_KEY, private=True)


def _build_default_state(signing_key: str | None = None) -> dict[str, Any]:
    """Build default persisted security state."""
    return {
        CONF_SIGNING_KEY: signing_key or secrets.token_urlsafe(64),
        CONF_TOKEN_VERSION: DEFAULT_TOKEN_VERSION,
        CONF_TOKEN_USES: {},
    }


def _get_storage_lock(hass: HomeAssistant) -> asyncio.Lock:
    """Get integration-level lock for storage updates."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    lock = domain_data.get(DATA_STORAGE_LOCK)
    if isinstance(lock, asyncio.Lock):
        return lock

    new_lock = asyncio.Lock()
    domain_data[DATA_STORAGE_LOCK] = new_lock
    return new_lock


def _normalize_state(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Validate and normalize persisted state. Returns (state, changed)."""
    changed = False

    signing_key = data.get(CONF_SIGNING_KEY)
    if not isinstance(signing_key, str) or not signing_key:
        legacy_secret_key = data.get(CONF_SECRET_KEY)
        if isinstance(legacy_secret_key, str) and legacy_secret_key:
            signing_key = legacy_secret_key
        else:
            signing_key = secrets.token_urlsafe(64)
        changed = True

    token_version = data.get(CONF_TOKEN_VERSION)
    if not isinstance(token_version, int) or token_version < 1:
        token_version = DEFAULT_TOKEN_VERSION
        changed = True

    raw_token_uses = data.get(CONF_TOKEN_USES)
    token_uses: dict[str, int] = {}
    if isinstance(raw_token_uses, dict):
        for jti, count in raw_token_uses.items():
            if isinstance(jti, str) and isinstance(count, int) and count >= 0:
                token_uses[jti] = count
            else:
                changed = True
    elif raw_token_uses is not None:
        changed = True

    return (
        {
            CONF_SIGNING_KEY: signing_key,
            CONF_TOKEN_VERSION: token_version,
            CONF_TOKEN_USES: token_uses,
        },
        changed,
    )


async def async_get_or_create_security_state(hass: HomeAssistant) -> dict[str, Any]:
    """Return normalized security state from storage."""
    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
            await store.async_save(state)
            return state

        state, changed = _normalize_state(loaded)
        if changed:
            await store.async_save(state)
        return state


async def async_get_or_create_signing_key(hass: HomeAssistant) -> str:
    """Return an existing signing key or create and persist a new one."""
    state = await async_get_or_create_security_state(hass)
    return state[CONF_SIGNING_KEY]


async def async_get_token_version(hass: HomeAssistant) -> int:
    """Return current global token version."""
    state = await async_get_or_create_security_state(hass)
    return state[CONF_TOKEN_VERSION]


async def async_rotate_signing_key(hass: HomeAssistant) -> str:
    """Generate a new signing key and persist it."""
    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
        else:
            state, _ = _normalize_state(loaded)

        state[CONF_SIGNING_KEY] = secrets.token_urlsafe(64)
        await store.async_save(state)
        return state[CONF_SIGNING_KEY]


async def async_increment_token_version(hass: HomeAssistant, clear_uses: bool = True) -> int:
    """Increment global token version and optionally clear token usage counters."""
    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
        else:
            state, _ = _normalize_state(loaded)

        state[CONF_TOKEN_VERSION] = int(state[CONF_TOKEN_VERSION]) + 1
        if clear_uses:
            state[CONF_TOKEN_USES] = {}
        await store.async_save(state)
        return state[CONF_TOKEN_VERSION]


async def async_get_token_use_count(hass: HomeAssistant, jti: str) -> int:
    """Return usage count for a token id (jti)."""
    if not jti:
        return 0

    state = await async_get_or_create_security_state(hass)
    uses = state.get(CONF_TOKEN_USES, {})
    if not isinstance(uses, dict):
        return 0
    count = uses.get(jti, 0)
    if not isinstance(count, int) or count < 0:
        return 0
    return count


async def async_record_token_use(hass: HomeAssistant, jti: str) -> int:
    """Increase usage count for a token id and persist."""
    if not jti:
        return 0

    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
        else:
            state, _ = _normalize_state(loaded)

        uses: dict[str, int] = state.setdefault(CONF_TOKEN_USES, {})
        new_count = int(uses.get(jti, 0)) + 1
        uses[jti] = new_count
        await store.async_save(state)
        return new_count

"""Storage helpers for HA Easy Control."""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import (
    CONF_ACTIVE_KID,
    CONF_ISSUED_TOKENS,
    CONF_REVOKED_TOKEN_JTIS,
    CONF_SECRET_KEY,
    CONF_SIGNING_KEY,
    CONF_SIGNING_KEYS,
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
    token_version = DEFAULT_TOKEN_VERSION
    key_value = signing_key or secrets.token_urlsafe(64)
    active_kid = f"v{token_version}"
    return {
        CONF_SIGNING_KEY: key_value,
        CONF_SIGNING_KEYS: {active_kid: key_value},
        CONF_ACTIVE_KID: active_kid,
        CONF_TOKEN_VERSION: token_version,
        CONF_TOKEN_USES: {},
        CONF_REVOKED_TOKEN_JTIS: {},
        CONF_ISSUED_TOKENS: {},
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

    raw_signing_keys = data.get(CONF_SIGNING_KEYS)
    signing_keys: dict[str, str] = {}
    if isinstance(raw_signing_keys, dict):
        for kid, key in raw_signing_keys.items():
            if isinstance(kid, str) and kid and isinstance(key, str) and key:
                signing_keys[kid] = key
            else:
                changed = True
    elif raw_signing_keys is not None:
        changed = True

    active_kid = data.get(CONF_ACTIVE_KID)
    if not signing_keys:
        derived_kid = f"v{token_version}"
        signing_keys = {derived_kid: signing_key}
        active_kid = derived_kid
        changed = True
    elif not isinstance(active_kid, str) or not active_kid or active_kid not in signing_keys:
        active_kid = next(iter(signing_keys))
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

    raw_revoked = data.get(CONF_REVOKED_TOKEN_JTIS)
    revoked_token_jtis: dict[str, int] = {}
    if isinstance(raw_revoked, dict):
        for jti, revoked_at in raw_revoked.items():
            if isinstance(jti, str) and jti and isinstance(revoked_at, int) and revoked_at >= 0:
                revoked_token_jtis[jti] = revoked_at
            else:
                changed = True
    elif raw_revoked is not None:
        changed = True

    raw_issued_tokens = data.get(CONF_ISSUED_TOKENS)
    issued_tokens: dict[str, dict[str, Any]] = {}
    if isinstance(raw_issued_tokens, dict):
        for jti, metadata in raw_issued_tokens.items():
            if not isinstance(jti, str) or not jti or not isinstance(metadata, dict):
                changed = True
                continue
            guest_id = metadata.get("guest_id")
            exp = metadata.get("exp")
            if not isinstance(guest_id, str) or not guest_id or not isinstance(exp, int):
                changed = True
                continue
            normalized_metadata: dict[str, Any] = {
                "guest_id": guest_id,
                "exp": exp,
            }
            for optional_key in ("device_id", "cnf_jkt", "device_public_key"):
                optional_value = metadata.get(optional_key)
                if isinstance(optional_value, str) and optional_value:
                    normalized_metadata[optional_key] = optional_value
                elif optional_value is not None:
                    changed = True
            issued_tokens[jti] = normalized_metadata
    elif raw_issued_tokens is not None:
        changed = True

    now = int(time.time())
    expired_jtis = [
        jti for jti, metadata in issued_tokens.items() if int(metadata.get("exp", 0)) <= now
    ]
    for jti in expired_jtis:
        issued_tokens.pop(jti, None)
        token_uses.pop(jti, None)
        revoked_token_jtis.pop(jti, None)
        changed = True

    return (
        {
            CONF_SIGNING_KEY: signing_key,
            CONF_SIGNING_KEYS: signing_keys,
            CONF_ACTIVE_KID: active_kid,
            CONF_TOKEN_VERSION: token_version,
            CONF_TOKEN_USES: token_uses,
            CONF_REVOKED_TOKEN_JTIS: revoked_token_jtis,
            CONF_ISSUED_TOKENS: issued_tokens,
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
    """Generate a new signing key, rotate key ring, and return active key."""
    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
        else:
            state, _ = _normalize_state(loaded)

        token_version = int(state.get(CONF_TOKEN_VERSION, DEFAULT_TOKEN_VERSION))
        new_signing_key = secrets.token_urlsafe(64)
        signing_keys = state.setdefault(CONF_SIGNING_KEYS, {})
        if not isinstance(signing_keys, dict):
            signing_keys = {}
            state[CONF_SIGNING_KEYS] = signing_keys
        new_kid = f"v{token_version + 1}"
        signing_keys[new_kid] = new_signing_key
        state[CONF_ACTIVE_KID] = new_kid
        state[CONF_SIGNING_KEY] = new_signing_key
        await store.async_save(state)
        return new_signing_key


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
        state.setdefault(CONF_REVOKED_TOKEN_JTIS, {})
        await store.async_save(state)
        return state[CONF_TOKEN_VERSION]


async def async_get_signing_keyring(
    hass: HomeAssistant,
) -> tuple[dict[str, str], str]:
    """Return normalized signing key ring and active kid."""
    state = await async_get_or_create_security_state(hass)
    signing_keys = state.get(CONF_SIGNING_KEYS, {})
    active_kid = state.get(CONF_ACTIVE_KID)
    if not isinstance(signing_keys, dict) or not isinstance(active_kid, str):
        raise ValueError("Invalid signing keyring state")
    return {
        str(kid): str(key)
        for kid, key in signing_keys.items()
        if isinstance(kid, str) and isinstance(key, str)
    }, active_kid


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


async def async_register_issued_token(
    hass: HomeAssistant,
    *,
    jti: str,
    guest_id: str,
    exp: int,
    device_id: str | None = None,
    cnf_jkt: str | None = None,
    device_public_key: str | None = None,
) -> None:
    """Persist metadata for an issued token for revocation and device binding."""
    if not jti:
        return
    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
        else:
            state, _ = _normalize_state(loaded)
        issued_tokens: dict[str, dict[str, Any]] = state.setdefault(CONF_ISSUED_TOKENS, {})
        metadata: dict[str, Any] = {"guest_id": guest_id, "exp": int(exp)}
        if device_id:
            metadata["device_id"] = device_id
        if cnf_jkt:
            metadata["cnf_jkt"] = cnf_jkt
        if device_public_key:
            metadata["device_public_key"] = device_public_key
        issued_tokens[jti] = metadata
        await store.async_save(state)


async def async_get_issued_token_metadata(hass: HomeAssistant, jti: str) -> dict[str, Any] | None:
    """Return issued token metadata by jti."""
    if not jti:
        return None
    state = await async_get_or_create_security_state(hass)
    issued_tokens = state.get(CONF_ISSUED_TOKENS, {})
    if not isinstance(issued_tokens, dict):
        return None
    metadata = issued_tokens.get(jti)
    if not isinstance(metadata, dict):
        return None
    return metadata


async def async_is_token_revoked(hass: HomeAssistant, jti: str) -> bool:
    """Return whether a token jti is explicitly revoked."""
    if not jti:
        return False
    state = await async_get_or_create_security_state(hass)
    revoked = state.get(CONF_REVOKED_TOKEN_JTIS, {})
    return isinstance(revoked, dict) and jti in revoked


async def async_revoke_token_jti(hass: HomeAssistant, jti: str) -> bool:
    """Add a token jti to the revoked set."""
    if not jti:
        return False
    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
        else:
            state, _ = _normalize_state(loaded)
        revoked: dict[str, int] = state.setdefault(CONF_REVOKED_TOKEN_JTIS, {})
        if jti in revoked:
            return False
        revoked[jti] = int(time.time())
        await store.async_save(state)
        return True


async def async_revoke_guest_tokens_by_guest_id(hass: HomeAssistant, guest_id: str) -> list[str]:
    """Revoke all currently tracked tokens for a guest_id."""
    if not guest_id:
        return []
    lock = _get_storage_lock(hass)
    async with lock:
        store = _build_store(hass)
        loaded = await store.async_load()
        if not isinstance(loaded, dict):
            state = _build_default_state()
        else:
            state, _ = _normalize_state(loaded)
        issued = state.setdefault(CONF_ISSUED_TOKENS, {})
        revoked = state.setdefault(CONF_REVOKED_TOKEN_JTIS, {})
        revoked_now = int(time.time())
        revoked_jtis: list[str] = []
        if isinstance(issued, dict) and isinstance(revoked, dict):
            for jti, metadata in issued.items():
                if isinstance(metadata, dict) and metadata.get("guest_id") == guest_id:
                    if jti not in revoked:
                        revoked[jti] = revoked_now
                    revoked_jtis.append(jti)
        await store.async_save(state)
        return revoked_jtis

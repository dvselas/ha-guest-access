"""The HA Easy Control integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import async_register_api
from .const import (
    CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
    CONF_ACTION_RATE_LIMIT_PER_MIN,
    CONF_ALLOWED_CIDRS,
    CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL,
    CONF_LOCAL_ONLY,
    CONF_NONCE_TTL_SECONDS,
    CONF_PAIR_RATE_LIMIT_PER_MIN,
    CONF_QR_RATE_LIMIT_PER_MIN,
    CONF_REQUIRE_ACTION_PROOF,
    CONF_REQUIRE_DEVICE_BINDING,
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
    DEFAULT_REQUIRE_ADMIN_APPROVAL,
    DEFAULT_REQUIRE_DEVICE_BINDING,
    DOMAIN,
)
from .network import normalize_allowed_cidrs
from .pairing import PairingStore
from .runtime_security import ActionNonceStore, FixedWindowRateLimiter
from .services import async_register_services, async_unregister_services
from .storage import async_get_or_create_security_state, async_get_signing_keyring
from .token import GuestTokenManager

GuestAccessConfigEntry = ConfigEntry


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the integration from YAML (not used, kept for HA bootstrap)."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data.setdefault(DATA_PAIRING_STORE, PairingStore())
    domain_data.setdefault(DATA_CONFIG_ENTRIES, set())
    domain_data.setdefault(DATA_API_REGISTERED, False)
    domain_data.setdefault(DATA_NONCE_STORE, ActionNonceStore())
    domain_data.setdefault(DATA_RATE_LIMITER, FixedWindowRateLimiter())
    async_register_api(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: GuestAccessConfigEntry) -> bool:
    """Set up HA Easy Control from a config entry."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data.setdefault(DATA_PAIRING_STORE, PairingStore())
    domain_data.setdefault(DATA_NONCE_STORE, ActionNonceStore())
    domain_data.setdefault(DATA_RATE_LIMITER, FixedWindowRateLimiter())
    config_entries: set[str] = domain_data.setdefault(DATA_CONFIG_ENTRIES, set())

    security_state = await async_get_or_create_security_state(hass)
    signing_keys, active_kid = await async_get_signing_keyring(hass)
    token_version = security_state[CONF_TOKEN_VERSION]
    local_only = _get_entry_value(entry, CONF_LOCAL_ONLY, DEFAULT_LOCAL_ONLY)
    allowed_cidrs_raw = _get_entry_value(entry, CONF_ALLOWED_CIDRS, DEFAULT_ALLOWED_CIDRS)
    require_device_binding = _get_entry_value(
        entry,
        CONF_REQUIRE_DEVICE_BINDING,
        DEFAULT_REQUIRE_DEVICE_BINDING,
    )
    require_action_proof = _get_entry_value(
        entry,
        CONF_REQUIRE_ACTION_PROOF,
        DEFAULT_REQUIRE_ACTION_PROOF,
    )
    default_require_admin_approval = _get_entry_value(
        entry,
        CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL,
        DEFAULT_REQUIRE_ADMIN_APPROVAL,
    )
    pair_rate_limit_per_min = _get_entry_value(
        entry, CONF_PAIR_RATE_LIMIT_PER_MIN, DEFAULT_PAIR_RATE_LIMIT_PER_MIN
    )
    action_rate_limit_per_min = _get_entry_value(
        entry, CONF_ACTION_RATE_LIMIT_PER_MIN, DEFAULT_ACTION_RATE_LIMIT_PER_MIN
    )
    qr_rate_limit_per_min = _get_entry_value(
        entry, CONF_QR_RATE_LIMIT_PER_MIN, DEFAULT_QR_RATE_LIMIT_PER_MIN
    )
    nonce_ttl_seconds = _get_entry_value(
        entry, CONF_NONCE_TTL_SECONDS, DEFAULT_NONCE_TTL_SECONDS
    )
    proof_clock_skew = _get_entry_value(
        entry,
        CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
        DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS,
    )
    try:
        allowed_cidrs = normalize_allowed_cidrs(allowed_cidrs_raw)
    except ValueError:
        allowed_cidrs = list(DEFAULT_ALLOWED_CIDRS)

    domain_data[entry.entry_id] = {
        CONF_TOKEN_VERSION: token_version,
        CONF_LOCAL_ONLY: bool(local_only),
        CONF_ALLOWED_CIDRS: allowed_cidrs,
        CONF_REQUIRE_DEVICE_BINDING: bool(require_device_binding),
        CONF_REQUIRE_ACTION_PROOF: bool(require_action_proof),
        CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL: bool(default_require_admin_approval),
        CONF_PAIR_RATE_LIMIT_PER_MIN: int(pair_rate_limit_per_min),
        CONF_ACTION_RATE_LIMIT_PER_MIN: int(action_rate_limit_per_min),
        CONF_QR_RATE_LIMIT_PER_MIN: int(qr_rate_limit_per_min),
        CONF_NONCE_TTL_SECONDS: int(nonce_ttl_seconds),
        CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS: int(proof_clock_skew),
        DATA_TOKEN_MANAGER: GuestTokenManager(signing_keys=signing_keys, active_kid=active_kid),
    }
    config_entries.add(entry.entry_id)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    async_register_services(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: GuestAccessConfigEntry) -> bool:
    """Unload HA Easy Control config entry."""
    domain_data = hass.data.get(DOMAIN)
    if not domain_data:
        return True

    domain_data.pop(entry.entry_id, None)
    config_entries: set[str] = domain_data.get(DATA_CONFIG_ENTRIES, set())
    config_entries.discard(entry.entry_id)

    if not config_entries:
        async_unregister_services(hass)
        hass.data.pop(DOMAIN, None)
    return True


async def async_reload_entry(hass: HomeAssistant, entry: GuestAccessConfigEntry) -> None:
    """Reload integration when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


def _get_entry_value(entry: GuestAccessConfigEntry, key: str, default: object) -> object:
    """Read option override first, then fallback to data/default."""
    if key in entry.options:
        return entry.options[key]
    return entry.data.get(key, default)

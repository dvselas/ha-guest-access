"""The Guest Access integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import async_register_api
from .const import (
    CONF_ALLOWED_CIDRS,
    CONF_LOCAL_ONLY,
    CONF_SIGNING_KEY,
    DEFAULT_ALLOWED_CIDRS,
    DEFAULT_LOCAL_ONLY,
    DATA_API_REGISTERED,
    DATA_CONFIG_ENTRIES,
    DATA_PAIRING_STORE,
    DATA_TOKEN_MANAGER,
    DOMAIN,
)
from .network import normalize_allowed_cidrs
from .pairing import PairingStore
from .services import async_register_services, async_unregister_services
from .storage import async_get_or_create_signing_key
from .token import GuestTokenManager

GuestAccessConfigEntry = ConfigEntry


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the integration from YAML (not used, kept for HA bootstrap)."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data.setdefault(DATA_PAIRING_STORE, PairingStore())
    domain_data.setdefault(DATA_CONFIG_ENTRIES, set())
    domain_data.setdefault(DATA_API_REGISTERED, False)
    async_register_api(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: GuestAccessConfigEntry) -> bool:
    """Set up Guest Access from a config entry."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data.setdefault(DATA_PAIRING_STORE, PairingStore())
    config_entries: set[str] = domain_data.setdefault(DATA_CONFIG_ENTRIES, set())

    signing_key = await async_get_or_create_signing_key(hass)
    local_only = _get_entry_value(entry, CONF_LOCAL_ONLY, DEFAULT_LOCAL_ONLY)
    allowed_cidrs_raw = _get_entry_value(entry, CONF_ALLOWED_CIDRS, DEFAULT_ALLOWED_CIDRS)
    try:
        allowed_cidrs = normalize_allowed_cidrs(allowed_cidrs_raw)
    except ValueError:
        allowed_cidrs = list(DEFAULT_ALLOWED_CIDRS)

    domain_data[entry.entry_id] = {
        CONF_SIGNING_KEY: signing_key,
        CONF_LOCAL_ONLY: bool(local_only),
        CONF_ALLOWED_CIDRS: allowed_cidrs,
        DATA_TOKEN_MANAGER: GuestTokenManager(signing_key),
    }
    config_entries.add(entry.entry_id)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    async_register_services(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: GuestAccessConfigEntry) -> bool:
    """Unload Guest Access config entry."""
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

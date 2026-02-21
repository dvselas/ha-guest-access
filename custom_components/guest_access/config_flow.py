"""Config flow for Guest Access."""

from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_ALLOWED_CIDRS,
    CONF_LOCAL_ONLY,
    DEFAULT_ALLOWED_CIDRS,
    DEFAULT_ENTRY_TITLE,
    DEFAULT_LOCAL_ONLY,
    DOMAIN,
)
from .network import normalize_allowed_cidrs, parse_allowed_cidrs_text
from .storage import async_get_or_create_security_state


class GuestAccessConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Guest Access."""

    VERSION = 1

    async def async_step_user(self, user_input: dict | None = None) -> FlowResult:
        """Handle the initial step."""
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()

        await async_get_or_create_security_state(self.hass)

        return self.async_create_entry(
            title=DEFAULT_ENTRY_TITLE,
            data={
                CONF_LOCAL_ONLY: DEFAULT_LOCAL_ONLY,
                CONF_ALLOWED_CIDRS: list(DEFAULT_ALLOWED_CIDRS),
            },
        )

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> GuestAccessOptionsFlow:
        """Return options flow handler."""
        return GuestAccessOptionsFlow(config_entry)


class GuestAccessOptionsFlow(config_entries.OptionsFlow):
    """Handle Guest Access options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Store config entry for options updates."""
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict | None = None) -> FlowResult:
        """Handle options form."""
        errors: dict[str, str] = {}

        if user_input is not None:
            local_only = bool(user_input[CONF_LOCAL_ONLY])
            cidr_text = str(user_input[CONF_ALLOWED_CIDRS])
            try:
                allowed_cidrs = parse_allowed_cidrs_text(cidr_text)
            except ValueError:
                errors["base"] = "invalid_cidr"
            else:
                return self.async_create_entry(
                    title="",
                    data={
                        CONF_LOCAL_ONLY: local_only,
                        CONF_ALLOWED_CIDRS: allowed_cidrs,
                    },
                )

        current_local_only = self._get_entry_value(CONF_LOCAL_ONLY, DEFAULT_LOCAL_ONLY)
        current_allowed_cidrs_raw = self._get_entry_value(
            CONF_ALLOWED_CIDRS, list(DEFAULT_ALLOWED_CIDRS)
        )
        try:
            current_allowed_cidrs = normalize_allowed_cidrs(current_allowed_cidrs_raw)
        except ValueError:
            current_allowed_cidrs = list(DEFAULT_ALLOWED_CIDRS)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_LOCAL_ONLY, default=current_local_only): bool,
                    vol.Required(
                        CONF_ALLOWED_CIDRS,
                        default=", ".join(current_allowed_cidrs),
                    ): str,
                }
            ),
            errors=errors,
        )

    def _get_entry_value(self, key: str, default: object) -> object:
        """Read option override first, then fallback to entry data."""
        if key in self._config_entry.options:
            return self._config_entry.options[key]
        return self._config_entry.data.get(key, default)

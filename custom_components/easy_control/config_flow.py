"""Config flow for HA Easy Control."""

from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

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
    DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS,
    DEFAULT_ACTION_RATE_LIMIT_PER_MIN,
    DEFAULT_ALLOWED_CIDRS,
    DEFAULT_ENTRY_TITLE,
    DEFAULT_LOCAL_ONLY,
    DEFAULT_NONCE_TTL_SECONDS,
    DEFAULT_PAIR_RATE_LIMIT_PER_MIN,
    DEFAULT_QR_RATE_LIMIT_PER_MIN,
    DEFAULT_REQUIRE_ACTION_PROOF,
    DEFAULT_REQUIRE_ADMIN_APPROVAL,
    DEFAULT_REQUIRE_DEVICE_BINDING,
    DOMAIN,
)
from .network import normalize_allowed_cidrs, parse_allowed_cidrs_text
from .storage import async_get_or_create_security_state


class GuestAccessConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for HA Easy Control."""

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
                CONF_REQUIRE_DEVICE_BINDING: DEFAULT_REQUIRE_DEVICE_BINDING,
                CONF_REQUIRE_ACTION_PROOF: DEFAULT_REQUIRE_ACTION_PROOF,
                CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL: DEFAULT_REQUIRE_ADMIN_APPROVAL,
                CONF_PAIR_RATE_LIMIT_PER_MIN: DEFAULT_PAIR_RATE_LIMIT_PER_MIN,
                CONF_ACTION_RATE_LIMIT_PER_MIN: DEFAULT_ACTION_RATE_LIMIT_PER_MIN,
                CONF_QR_RATE_LIMIT_PER_MIN: DEFAULT_QR_RATE_LIMIT_PER_MIN,
                CONF_NONCE_TTL_SECONDS: DEFAULT_NONCE_TTL_SECONDS,
                CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS: DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS,
            },
        )

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> GuestAccessOptionsFlow:
        """Return options flow handler."""
        return GuestAccessOptionsFlow(config_entry)


class GuestAccessOptionsFlow(config_entries.OptionsFlow):
    """Handle HA Easy Control options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Store config entry for options updates."""
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict | None = None) -> FlowResult:
        """Handle options form."""
        errors: dict[str, str] = {}

        if user_input is not None:
            local_only = bool(user_input[CONF_LOCAL_ONLY])
            cidr_text = str(user_input[CONF_ALLOWED_CIDRS])
            require_device_binding = bool(user_input[CONF_REQUIRE_DEVICE_BINDING])
            require_action_proof = bool(user_input[CONF_REQUIRE_ACTION_PROOF])
            default_require_admin_approval = bool(
                user_input[CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL]
            )
            pair_rate_limit = int(user_input[CONF_PAIR_RATE_LIMIT_PER_MIN])
            action_rate_limit = int(user_input[CONF_ACTION_RATE_LIMIT_PER_MIN])
            qr_rate_limit = int(user_input[CONF_QR_RATE_LIMIT_PER_MIN])
            nonce_ttl_seconds = int(user_input[CONF_NONCE_TTL_SECONDS])
            proof_clock_skew = int(user_input[CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS])
            try:
                allowed_cidrs = parse_allowed_cidrs_text(cidr_text)
            except ValueError:
                errors["base"] = "invalid_cidr"
            else:
                if (
                    pair_rate_limit < 1
                    or action_rate_limit < 1
                    or qr_rate_limit < 1
                    or nonce_ttl_seconds < 1
                    or proof_clock_skew < 0
                ):
                    errors["base"] = "invalid_security_limits"
                else:
                    return self.async_create_entry(
                        title="",
                        data={
                            CONF_LOCAL_ONLY: local_only,
                            CONF_ALLOWED_CIDRS: allowed_cidrs,
                            CONF_REQUIRE_DEVICE_BINDING: require_device_binding,
                            CONF_REQUIRE_ACTION_PROOF: require_action_proof,
                            CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL: (
                                default_require_admin_approval
                            ),
                            CONF_PAIR_RATE_LIMIT_PER_MIN: pair_rate_limit,
                            CONF_ACTION_RATE_LIMIT_PER_MIN: action_rate_limit,
                            CONF_QR_RATE_LIMIT_PER_MIN: qr_rate_limit,
                            CONF_NONCE_TTL_SECONDS: nonce_ttl_seconds,
                            CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS: proof_clock_skew,
                        },
                    )

        current_local_only = self._get_entry_value(CONF_LOCAL_ONLY, DEFAULT_LOCAL_ONLY)
        current_allowed_cidrs_raw = self._get_entry_value(
            CONF_ALLOWED_CIDRS, list(DEFAULT_ALLOWED_CIDRS)
        )
        current_require_device_binding = self._get_entry_value(
            CONF_REQUIRE_DEVICE_BINDING, DEFAULT_REQUIRE_DEVICE_BINDING
        )
        current_require_action_proof = self._get_entry_value(
            CONF_REQUIRE_ACTION_PROOF, DEFAULT_REQUIRE_ACTION_PROOF
        )
        current_default_require_admin_approval = self._get_entry_value(
            CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL, DEFAULT_REQUIRE_ADMIN_APPROVAL
        )
        current_pair_rate_limit = self._get_entry_value(
            CONF_PAIR_RATE_LIMIT_PER_MIN, DEFAULT_PAIR_RATE_LIMIT_PER_MIN
        )
        current_action_rate_limit = self._get_entry_value(
            CONF_ACTION_RATE_LIMIT_PER_MIN, DEFAULT_ACTION_RATE_LIMIT_PER_MIN
        )
        current_qr_rate_limit = self._get_entry_value(
            CONF_QR_RATE_LIMIT_PER_MIN, DEFAULT_QR_RATE_LIMIT_PER_MIN
        )
        current_nonce_ttl_seconds = self._get_entry_value(
            CONF_NONCE_TTL_SECONDS, DEFAULT_NONCE_TTL_SECONDS
        )
        current_proof_clock_skew = self._get_entry_value(
            CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
            DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS,
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
                        CONF_REQUIRE_DEVICE_BINDING,
                        default=current_require_device_binding,
                    ): bool,
                    vol.Required(
                        CONF_REQUIRE_ACTION_PROOF,
                        default=current_require_action_proof,
                    ): bool,
                    vol.Required(
                        CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL,
                        default=current_default_require_admin_approval,
                    ): bool,
                    vol.Required(
                        CONF_ALLOWED_CIDRS,
                        default=", ".join(current_allowed_cidrs),
                    ): str,
                    vol.Required(
                        CONF_PAIR_RATE_LIMIT_PER_MIN,
                        default=current_pair_rate_limit,
                    ): vol.Coerce(int),
                    vol.Required(
                        CONF_ACTION_RATE_LIMIT_PER_MIN,
                        default=current_action_rate_limit,
                    ): vol.Coerce(int),
                    vol.Required(
                        CONF_QR_RATE_LIMIT_PER_MIN,
                        default=current_qr_rate_limit,
                    ): vol.Coerce(int),
                    vol.Required(
                        CONF_NONCE_TTL_SECONDS,
                        default=current_nonce_ttl_seconds,
                    ): vol.Coerce(int),
                    vol.Required(
                        CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
                        default=current_proof_clock_skew,
                    ): vol.Coerce(int),
                }
            ),
            errors=errors,
        )

    def _get_entry_value(self, key: str, default: object) -> object:
        """Read option override first, then fallback to entry data."""
        if key in self._config_entry.options:
            return self._config_entry.options[key]
        return self._config_entry.data.get(key, default)

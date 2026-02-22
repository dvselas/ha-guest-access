"""Integration-test blueprint for /api/easy_control/action."""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.skip(
    reason=(
        "Blueprint test file: requires Home Assistant test harness "
        "(hass fixture, hass_client, async_mock_service)."
    )
)


async def test_valid_unlock_executes_service() -> None:
    """TODO: use async_mock_service(hass, 'lock', 'unlock') and assert call count."""


async def test_wrong_action_rejected_before_service_call() -> None:
    """TODO: assert 403 and no service invocation."""


async def test_outside_ip_rejected_with_403() -> None:
    """TODO: set request.remote to public IP and assert policy rejection."""

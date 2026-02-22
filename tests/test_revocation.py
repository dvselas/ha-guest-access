"""Integration-test blueprint for revoke lifecycle."""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.skip(
    reason=(
        "Blueprint test file: requires Home Assistant integration test runtime "
        "to validate revoke_all and token_version behavior."
    )
)


async def test_revoke_all_invalidates_existing_tokens() -> None:
    """TODO: create token, call easy_control.revoke_all_guest_pass, expect 401 on action endpoint."""


async def test_new_token_after_revoke_all_is_valid() -> None:
    """TODO: issue new pairing/token after revoke and ensure action can execute."""

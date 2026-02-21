"""Test fixtures for Guest Access integration."""

from __future__ import annotations

import time

import pytest


@pytest.fixture
def now_ts() -> int:
    """Return current unix timestamp for deterministic token tests."""
    return int(time.time())

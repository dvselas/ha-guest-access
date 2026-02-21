"""Test fixtures for Guest Access integration."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

# Ensure project root is importable so tests can load custom_components.*
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def now_ts() -> int:
    """Return current unix timestamp for deterministic token tests."""
    return int(time.time())

"""Security-focused unit tests."""

from __future__ import annotations

import pytest

from custom_components.guest_access.network import (
    is_remote_allowed,
    normalize_allowed_cidrs,
    parse_allowed_cidrs_text,
)


def test_only_rfc1918_cidrs_are_accepted() -> None:
    normalized = normalize_allowed_cidrs(["10.0.0.0/8", "192.168.1.0/24"])
    assert normalized == ["10.0.0.0/8", "192.168.1.0/24"]

    with pytest.raises(ValueError):
        normalize_allowed_cidrs(["8.8.8.0/24"])


def test_remote_ip_policy_check() -> None:
    cidrs = parse_allowed_cidrs_text("10.0.0.0/8,192.168.0.0/16")
    assert is_remote_allowed("10.2.3.4", cidrs) is True
    assert is_remote_allowed("192.168.1.22", cidrs) is True
    assert is_remote_allowed("8.8.8.8", cidrs) is False

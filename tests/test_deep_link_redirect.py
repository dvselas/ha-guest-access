"""Tests for the /api/easy_control/link deep link redirect endpoint."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from homeassistant.components.http import KEY_HASS

from custom_components.easy_control.api import GuestAccessDeepLinkRedirectView
from custom_components.easy_control.const import (
    CONF_QR_RATE_LIMIT_PER_MIN,
    DATA_CONFIG_ENTRIES,
    DATA_RATE_LIMITER,
    DOMAIN,
)
from custom_components.easy_control.runtime_security import FixedWindowRateLimiter

# ---------------------------------------------------------------------------
# Fake collaborators (same pattern as test_api_views.py)
# ---------------------------------------------------------------------------


class _FakeBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def async_fire(self, event_name: str, event_data: dict[str, Any]) -> None:
        self.events.append((event_name, event_data))


class _FakeHass:
    def __init__(self, domain_data: dict[str, Any]) -> None:
        self.data = {DOMAIN: domain_data}
        self.bus = _FakeBus()
        self.config = SimpleNamespace(
            external_url="https://ha.example.local",
            internal_url="http://ha.local",
            time_zone="UTC",
            api=None,
        )


class _FakeRequest:
    def __init__(
        self,
        *,
        hass: _FakeHass,
        query: dict[str, str] | None = None,
        remote: str = "192.168.1.10",
    ) -> None:
        self.app = {KEY_HASS: hass}
        self.query = query or {}
        self.remote = remote
        self.method = "GET"
        self.path = "/api/easy_control/link"
        self.scheme = "https"
        self.host = "ha.example.local"


def _build_domain_data() -> dict[str, Any]:
    entry_data = {
        CONF_QR_RATE_LIMIT_PER_MIN: 20,
    }
    return {
        DATA_RATE_LIMITER: FixedWindowRateLimiter(),
        DATA_CONFIG_ENTRIES: {"entry-1"},
        "entry-1": entry_data,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def view() -> GuestAccessDeepLinkRedirectView:
    return GuestAccessDeepLinkRedirectView()


@pytest.fixture
def domain_data() -> dict[str, Any]:
    return _build_domain_data()


@pytest.fixture
def fake_hass(domain_data: dict[str, Any]) -> _FakeHass:
    return _FakeHass(domain_data)


async def test_missing_code_returns_400(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """Request without code query param returns 400."""
    req = _FakeRequest(hass=fake_hass, query={})
    resp = await view.get(req)
    assert resp.status == 400
    assert "code" in resp.text.lower()


async def test_redirect_html_contains_deep_link(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """Redirect page embeds the correct easy-control:// deep link."""
    req = _FakeRequest(
        hass=fake_hass,
        query={
            "code": "ABC123",
            "base_url": "https://ha.example.local",
            "scan_ack_token": "tok123",
            "entity_ids": "lock.front_door",
            "allowed_action": "door.unlock",
        },
    )
    resp = await view.get(req)
    assert resp.status == 200
    assert resp.content_type == "text/html"
    body = resp.text
    assert "easy-control://pair?" in body
    assert "ABC123" in body


async def test_redirect_html_contains_pairing_code_fallback(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """Redirect page shows the pairing code as a manual fallback."""
    req = _FakeRequest(
        hass=fake_hass,
        query={"code": "XYZ789"},
    )
    resp = await view.get(req)
    assert resp.status == 200
    assert "XYZ789" in resp.text


async def test_redirect_html_javascript_redirect(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """Redirect page includes a JavaScript window.location redirect."""
    req = _FakeRequest(
        hass=fake_hass,
        query={"code": "TEST01", "base_url": "https://ha.local"},
    )
    resp = await view.get(req)
    assert "window.location.href=" in resp.text


async def test_redirect_html_no_store_cache(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """Response includes Cache-Control: no-store header."""
    req = _FakeRequest(hass=fake_hass, query={"code": "C1"})
    resp = await view.get(req)
    assert "no-store" in resp.headers.get("Cache-Control", "")


async def test_redirect_includes_all_query_params_in_deep_link(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """All provided query params are forwarded into the deep link."""
    req = _FakeRequest(
        hass=fake_hass,
        query={
            "code": "CODE1",
            "base_url": "https://ha.local:8123",
            "scan_ack_token": "ack-tok",
            "entity_ids": "lock.a,cover.b",
            "allowed_action": "door.unlock",
        },
    )
    resp = await view.get(req)
    body = resp.text
    assert "base_url=" in body
    assert "scan_ack_token=ack-tok" in body
    assert "entity_ids=" in body
    assert "allowed_action=door.unlock" in body


async def test_redirect_minimal_params(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """Only code is required; other params are optional."""
    req = _FakeRequest(hass=fake_hass, query={"code": "MIN1"})
    resp = await view.get(req)
    assert resp.status == 200
    assert "easy-control://pair?" in resp.text
    assert "MIN1" in resp.text


async def test_redirect_html_escapes_pairing_code(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """HTML-special characters in pairing code are properly escaped in fallback."""
    req = _FakeRequest(hass=fake_hass, query={"code": '<img onerror="alert(1)">'})
    resp = await view.get(req)
    assert resp.status == 200
    # The fallback code display must be HTML-escaped
    assert "&lt;img onerror=" in resp.text
    # The raw malicious string must NOT appear unescaped in the fallback section
    assert '<img onerror="alert(1)">' not in resp.text.split("</script>", 1)[-1]


async def test_rate_limited(
    view: GuestAccessDeepLinkRedirectView, fake_hass: _FakeHass
) -> None:
    """Requests are rate-limited using the QR bucket."""
    # Exhaust the rate limit
    for _ in range(25):
        req = _FakeRequest(hass=fake_hass, query={"code": "RL1"})
        await view.get(req)

    req = _FakeRequest(hass=fake_hass, query={"code": "RL1"})
    resp = await view.get(req)
    assert resp.status == 429

"""Tests for email delivery of guest access passes."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.easy_control.const import (
    CONF_EMAIL_GUEST_NAME,
    CONF_EMAIL_NOTIFY_SERVICE,
    CONF_EMAIL_RECIPIENT,
    CONF_ENTITIES,
    CONF_EXPIRATION_TIME,
    CONF_SHOW_QR_NOTIFICATION,
    DATA_PAIRING_STORE,
    DOMAIN,
)
from custom_components.easy_control.pairing import PairingStore
from custom_components.easy_control.services import (
    _build_email_html,
    _generate_qr_png_base64,
    async_handle_create_pass,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_hass() -> MagicMock:
    """Create a minimal mock HomeAssistant instance for service tests."""
    hass = MagicMock()
    pairing_store = PairingStore()
    hass.data = {
        DOMAIN: {
            DATA_PAIRING_STORE: pairing_store,
            "config_entries": set(),
        },
    }
    hass.config.external_url = "https://ha.example.com"
    hass.config.internal_url = None
    hass.services.has_service = MagicMock(return_value=True)
    hass.services.async_call = AsyncMock()
    return hass


@pytest.fixture
def base_call_data(now_ts: int) -> dict:
    """Minimal valid call data for create_guest_pass."""
    return {
        CONF_ENTITIES: ["lock.front_door"],
        CONF_EXPIRATION_TIME: now_ts + 3600,
        CONF_SHOW_QR_NOTIFICATION: False,
    }


def _make_call(data: dict) -> MagicMock:
    """Create a mock ServiceCall with the given data."""
    call = MagicMock()
    call.data = data
    return call


# ---------------------------------------------------------------------------
# _generate_qr_png_base64 tests
# ---------------------------------------------------------------------------


def test_generate_qr_png_base64_returns_base64_string() -> None:
    """QR PNG helper returns a non-empty base64 string when segno is available."""
    fake_png = b"\x89PNG\r\n\x1a\nfake-png-data"
    mock_qr = MagicMock()
    mock_qr.save = MagicMock(side_effect=lambda buf, **kw: buf.write(fake_png))
    mock_segno = MagicMock()
    mock_segno.make.return_value = mock_qr

    with patch.dict("sys.modules", {"segno": mock_segno}):
        result = _generate_qr_png_base64("easy-control://pair?code=TEST")

    assert result is not None
    import base64 as _b64
    assert _b64.b64decode(result) == fake_png


def test_generate_qr_png_base64_without_segno() -> None:
    """QR PNG helper returns None when segno is not available."""
    with patch.dict("sys.modules", {"segno": None}):
        result = _generate_qr_png_base64("easy-control://pair?code=TEST")
    assert result is None


# ---------------------------------------------------------------------------
# _build_email_html tests
# ---------------------------------------------------------------------------


def test_email_html_contains_email_link() -> None:
    """HTML body contains the clickable HTTPS redirect link."""
    link = "https://ha.local/api/easy_control/link?code=ABC123"
    html = _build_email_html(
        qr_base64=None,
        email_link=link,
        guest_name=None,
        entity_ids=["lock.front_door"],
        expires_at=int(time.time()) + 3600,
        pairing_code="ABC123",
    )
    assert link in html
    assert "Open in Easy Control" in html


def test_email_html_contains_qr_image() -> None:
    """HTML body embeds the QR code as data URI when provided."""
    html = _build_email_html(
        qr_base64="AAAA1234",
        email_link="easy-control://pair?code=X",
        guest_name=None,
        entity_ids=["lock.front_door"],
        expires_at=int(time.time()) + 3600,
        pairing_code="X",
    )
    assert "data:image/png;base64,AAAA1234" in html


def test_email_html_omits_qr_when_none() -> None:
    """HTML body has no img tag when qr_base64 is None."""
    html = _build_email_html(
        qr_base64=None,
        email_link="easy-control://pair?code=X",
        guest_name=None,
        entity_ids=["lock.front_door"],
        expires_at=int(time.time()) + 3600,
        pairing_code="X",
    )
    assert "<img" not in html


def test_email_html_contains_entity_ids() -> None:
    """HTML body lists all granted entity IDs."""
    html = _build_email_html(
        qr_base64=None,
        email_link="easy-control://pair?code=X",
        guest_name=None,
        entity_ids=["lock.front_door", "cover.garage", "light.porch"],
        expires_at=int(time.time()) + 3600,
        pairing_code="X",
    )
    assert "lock.front_door" in html
    assert "cover.garage" in html
    assert "light.porch" in html


def test_email_html_personalized_with_guest_name() -> None:
    """HTML greeting uses the guest name when provided."""
    html = _build_email_html(
        qr_base64=None,
        email_link="easy-control://pair?code=X",
        guest_name="Alice",
        entity_ids=["lock.front_door"],
        expires_at=int(time.time()) + 3600,
        pairing_code="X",
    )
    assert "Hi Alice," in html


def test_email_html_generic_greeting_without_guest_name() -> None:
    """HTML greeting is generic when guest name is not provided."""
    html = _build_email_html(
        qr_base64=None,
        email_link="easy-control://pair?code=X",
        guest_name=None,
        entity_ids=["lock.front_door"],
        expires_at=int(time.time()) + 3600,
        pairing_code="X",
    )
    assert "Hi," in html
    assert "Hi None" not in html


def test_email_html_contains_pairing_code() -> None:
    """HTML body includes the fallback pairing code."""
    html = _build_email_html(
        qr_base64=None,
        email_link="easy-control://pair?code=X",
        guest_name=None,
        entity_ids=["lock.front_door"],
        expires_at=int(time.time()) + 3600,
        pairing_code="MYCODE99",
    )
    assert "MYCODE99" in html


# ---------------------------------------------------------------------------
# async_handle_create_pass email integration tests
# ---------------------------------------------------------------------------


async def test_create_pass_without_email_sets_email_sent_false(
    mock_hass: MagicMock, base_call_data: dict
) -> None:
    """Service response includes email_sent=False when no email params given."""
    result = await async_handle_create_pass(mock_hass, _make_call(base_call_data))
    assert result is not None
    assert result["email_sent"] is False


async def test_create_pass_with_email_calls_notify_service(
    mock_hass: MagicMock, base_call_data: dict
) -> None:
    """When email params are provided, the notify service is called."""
    base_call_data[CONF_EMAIL_RECIPIENT] = "guest@example.com"
    base_call_data[CONF_EMAIL_NOTIFY_SERVICE] = "email"
    base_call_data[CONF_EMAIL_GUEST_NAME] = "Bob"

    result = await async_handle_create_pass(mock_hass, _make_call(base_call_data))
    assert result is not None
    assert result["email_sent"] is True

    # Find the notify call (may be after persistent_notification call)
    notify_calls = [
        c for c in mock_hass.services.async_call.call_args_list
        if c[0][0] == "notify"
    ]
    assert len(notify_calls) == 1
    call_args = notify_calls[0]
    assert call_args[0][1] == "email"  # service name
    payload = call_args[0][2]
    assert payload["target"] == "guest@example.com"
    assert "html" in payload["data"]
    assert "/api/easy_control/link?" in payload["data"]["html"]
    assert "Bob" in payload["data"]["html"]


async def test_email_recipient_without_service_raises(
    mock_hass: MagicMock, base_call_data: dict
) -> None:
    """Providing email_recipient without email_notify_service raises."""
    base_call_data[CONF_EMAIL_RECIPIENT] = "guest@example.com"

    with pytest.raises(Exception, match="must be provided together"):
        await async_handle_create_pass(mock_hass, _make_call(base_call_data))


async def test_email_service_without_recipient_raises(
    mock_hass: MagicMock, base_call_data: dict
) -> None:
    """Providing email_notify_service without email_recipient raises."""
    base_call_data[CONF_EMAIL_NOTIFY_SERVICE] = "email"

    with pytest.raises(Exception, match="must be provided together"):
        await async_handle_create_pass(mock_hass, _make_call(base_call_data))


async def test_email_notify_service_not_found_logs_warning(
    mock_hass: MagicMock, base_call_data: dict
) -> None:
    """When notify service doesn't exist, warning is logged and pass still created."""

    def _has_service(domain: str, service: str) -> bool:
        return domain != "notify"

    mock_hass.services.has_service = MagicMock(side_effect=_has_service)
    base_call_data[CONF_EMAIL_RECIPIENT] = "guest@example.com"
    base_call_data[CONF_EMAIL_NOTIFY_SERVICE] = "nonexistent"

    result = await async_handle_create_pass(mock_hass, _make_call(base_call_data))
    assert result is not None
    assert result["email_sent"] is False
    # Verify no notify call was made
    notify_calls = [
        c for c in mock_hass.services.async_call.call_args_list
        if c[0][0] == "notify"
    ]
    assert len(notify_calls) == 0


async def test_email_send_failure_does_not_fail_service(
    mock_hass: MagicMock, base_call_data: dict
) -> None:
    """When notify service raises, create_pass still succeeds."""

    async def _failing_call(domain: str, service: str, data: dict, **kw: object) -> None:
        if domain == "notify":
            raise RuntimeError("SMTP connection refused")

    mock_hass.services.async_call = AsyncMock(side_effect=_failing_call)
    base_call_data[CONF_EMAIL_RECIPIENT] = "guest@example.com"
    base_call_data[CONF_EMAIL_NOTIFY_SERVICE] = "email"

    result = await async_handle_create_pass(mock_hass, _make_call(base_call_data))
    assert result is not None
    assert result["email_sent"] is False
    assert "qr_string" in result  # pass was still created


async def test_email_notify_service_with_prefix_normalized(
    mock_hass: MagicMock, base_call_data: dict
) -> None:
    """Service name 'notify.email' is normalized to 'email'."""
    base_call_data[CONF_EMAIL_RECIPIENT] = "guest@example.com"
    base_call_data[CONF_EMAIL_NOTIFY_SERVICE] = "notify.email"

    result = await async_handle_create_pass(mock_hass, _make_call(base_call_data))
    assert result is not None
    assert result["email_sent"] is True

    notify_calls = [
        c for c in mock_hass.services.async_call.call_args_list
        if c[0][0] == "notify"
    ]
    assert len(notify_calls) == 1
    assert notify_calls[0][0][1] == "email"  # normalized, not "notify.email"

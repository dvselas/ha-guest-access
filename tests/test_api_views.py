"""Endpoint-level tests for API views using lightweight fake requests."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace
from typing import Any

import pytest
from homeassistant.components.http import KEY_HASS

from custom_components.easy_control.api import (
    GuestAccessActionNonceView,
    GuestAccessActionView,
    GuestAccessEntityStatesView,
    GuestAccessPairScannedView,
    GuestAccessPairView,
    GuestAccessQrView,
    GuestAccessTokenValidateView,
)
from custom_components.easy_control.const import (
    CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
    CONF_ACTION_RATE_LIMIT_PER_MIN,
    CONF_NONCE_TTL_SECONDS,
    CONF_PAIR_RATE_LIMIT_PER_MIN,
    CONF_QR_RATE_LIMIT_PER_MIN,
    CONF_REQUIRE_ACTION_PROOF,
    CONF_REQUIRE_DEVICE_BINDING,
    CONF_STATES_RATE_LIMIT_PER_MIN,
    CONF_TOKEN_VERSION,
    DATA_CONFIG_ENTRIES,
    DATA_NONCE_STORE,
    DATA_PAIRING_STORE,
    DATA_RATE_LIMITER,
    DATA_TOKEN_MANAGER,
    DOMAIN,
)
from custom_components.easy_control.pairing import PairingStore
from custom_components.easy_control.runtime_security import ActionNonceStore, FixedWindowRateLimiter
from custom_components.easy_control.token import GuestTokenManager


class _FakeBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def async_fire(self, event_name: str, event_data: dict[str, Any]) -> None:
        self.events.append((event_name, event_data))


class _FakeServices:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def has_service(self, domain: str, service: str) -> bool:
        return False

    async def async_call(
        self,
        domain: str,
        service: str,
        service_data: dict[str, Any] | None = None,
        *,
        blocking: bool = False,
    ) -> None:
        del blocking
        self.calls.append((domain, service, service_data))


class _FakeHass:
    def __init__(self, domain_data: dict[str, Any]) -> None:
        self.data = {DOMAIN: domain_data}
        self.bus = _FakeBus()
        self.services = _FakeServices()
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
        json_payload: Any | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        remote: str = "192.168.1.10",
        method: str = "POST",
        path: str = "/api/easy_control/action",
        scheme: str = "https",
        host: str = "ha.example.local",
    ) -> None:
        self.app = {KEY_HASS: hass}
        self._json_payload = json_payload
        self._raw_body = raw_body
        self.headers = headers or {}
        self.query = query or {}
        self.remote = remote
        self.method = method
        self.path = path
        self.scheme = scheme
        self.host = host

    async def json(self) -> Any:
        if isinstance(self._json_payload, Exception):
            raise self._json_payload
        return self._json_payload

    async def read(self) -> bytes:
        if self._raw_body is not None:
            return self._raw_body
        if self._json_payload is None:
            return b""
        return json.dumps(self._json_payload).encode("utf-8")


def _build_domain_data(
    *,
    require_action_proof: bool = False,
    require_device_binding: bool = False,
) -> dict[str, Any]:
    token_manager = GuestTokenManager("test-signing-key")
    entry_data = {
        CONF_TOKEN_VERSION: 1,
        CONF_REQUIRE_ACTION_PROOF: require_action_proof,
        CONF_REQUIRE_DEVICE_BINDING: require_device_binding,
        CONF_PAIR_RATE_LIMIT_PER_MIN: 20,
        CONF_ACTION_RATE_LIMIT_PER_MIN: 20,
        CONF_QR_RATE_LIMIT_PER_MIN: 20,
        CONF_NONCE_TTL_SECONDS: 45,
        CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS: 30,
        DATA_TOKEN_MANAGER: token_manager,
    }
    return {
        DATA_PAIRING_STORE: PairingStore(),
        DATA_NONCE_STORE: ActionNonceStore(),
        DATA_RATE_LIMITER: FixedWindowRateLimiter(),
        DATA_CONFIG_ENTRIES: {"entry-1"},
        "entry-1": entry_data,
    }


def _json_body(response) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    assert response.text is not None
    return json.loads(response.text)


@pytest.mark.asyncio
async def test_pair_view_returns_pending_approval_202(monkeypatch: pytest.MonkeyPatch) -> None:
    domain_data = _build_domain_data()
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=2_000_000_000,
        require_admin_approval=True,
    )
    hass = _FakeHass(domain_data)
    request = _FakeRequest(
        hass=hass,
        json_payload={"pairing_code": pairing.pairing_code},
        path="/api/easy_control/pair",
    )

    async def _noop_register_issued_token(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return None

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_register_issued_token",
        _noop_register_issued_token,
    )

    response = await GuestAccessPairView().post(request)
    payload = _json_body(response)

    assert response.status == 202
    assert payload["error"] == "pending_approval"


@pytest.mark.asyncio
async def test_pair_view_requires_device_binding_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    domain_data = _build_domain_data(require_device_binding=True)
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="cover.garage",
        allowed_action="garage.open",
        pass_expires_at=2_000_000_000,
    )
    hass = _FakeHass(domain_data)
    request = _FakeRequest(
        hass=hass,
        json_payload={"pairing_code": pairing.pairing_code},
        path="/api/easy_control/pair",
    )

    async def _noop_register_issued_token(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return None

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_register_issued_token",
        _noop_register_issued_token,
    )

    response = await GuestAccessPairView().post(request)
    payload = _json_body(response)

    assert response.status == 400
    assert payload["error"] == "device_binding_required"
    # Code should still be available because pairing was not consumed.
    assert pairing_store.get_pairing(pairing.pairing_code) is not None


@pytest.mark.asyncio
async def test_action_nonce_view_issues_nonce(monkeypatch: pytest.MonkeyPatch, now_ts: int) -> None:
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, payload = token_manager.create_guest_token(
        guest_id="guest-1",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)
    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
        path="/api/easy_control/action/nonce",
    )

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )

    response = await GuestAccessActionNonceView().get(request)
    body = _json_body(response)

    assert response.status == 200
    assert body["jti"] == payload.jti
    assert isinstance(body["nonce"], str) and body["nonce"]


@pytest.mark.asyncio
async def test_action_view_requires_proof_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    domain_data = _build_domain_data(require_action_proof=True)
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-1",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)
    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={"action": "door.open"},
        path="/api/easy_control/action",
    )

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )

    response = await GuestAccessActionView().post(request)
    body = _json_body(response)

    assert response.status == 401
    assert body["error"] == "action_proof_required"
    assert hass.services.calls == []


@pytest.mark.asyncio
async def test_pair_scanned_view_acknowledges_and_is_idempotent() -> None:
    domain_data = _build_domain_data()
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="cover.garage",
        allowed_action="garage.open",
        pass_expires_at=2_000_000_000,
    )
    hass = _FakeHass(domain_data)

    request1 = _FakeRequest(
        hass=hass,
        json_payload={
            "pairing_code": pairing.pairing_code,
            "scan_ack_token": pairing.scan_ack_token,
        },
        path="/api/easy_control/pair/scanned",
    )
    request2 = _FakeRequest(
        hass=hass,
        json_payload={
            "pairing_code": pairing.pairing_code,
            "scan_ack_token": pairing.scan_ack_token,
        },
        path="/api/easy_control/pair/scanned",
    )

    response1 = await GuestAccessPairScannedView().post(request1)
    response2 = await GuestAccessPairScannedView().post(request2)
    body1 = _json_body(response1)
    body2 = _json_body(response2)

    assert response1.status == 200
    assert body1["status"] == "acknowledged"
    assert body1["qr_scanned_at"] is not None
    assert response2.status == 200
    assert body2["status"] == "already_acknowledged"


@pytest.mark.asyncio
async def test_qr_view_allows_repeated_render_until_scan_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    domain_data = _build_domain_data()
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="cover.garage",
        allowed_action="garage.open",
        pass_expires_at=2_000_000_000,
    )
    hass = _FakeHass(domain_data)

    class _FakeQr:
        def save(self, out: io.BytesIO, **kwargs) -> None:  # type: ignore[no-untyped-def]
            del kwargs
            out.write(b"<svg/>")

    class _FakeSegno:
        @staticmethod
        def make(*args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            return _FakeQr()

    monkeypatch.setattr("custom_components.easy_control.api.segno", _FakeSegno, raising=False)
    import sys

    monkeypatch.setitem(sys.modules, "segno", _FakeSegno)  # local import path in view

    request1 = _FakeRequest(
        hass=hass,
        method="GET",
        path="/api/easy_control/qr",
        query={"code": pairing.pairing_code, "qr_token": pairing.qr_access_token},
    )
    request2 = _FakeRequest(
        hass=hass,
        method="GET",
        path="/api/easy_control/qr",
        query={"code": pairing.pairing_code, "qr_token": pairing.qr_access_token},
    )

    response1 = await GuestAccessQrView().get(request1)
    response2 = await GuestAccessQrView().get(request2)
    ack_response = await GuestAccessPairScannedView().post(
        _FakeRequest(
            hass=hass,
            json_payload={
                "pairing_code": pairing.pairing_code,
                "scan_ack_token": pairing.scan_ack_token,
            },
            path="/api/easy_control/pair/scanned",
        )
    )
    response3 = await GuestAccessQrView().get(
        _FakeRequest(
            hass=hass,
            method="GET",
            path="/api/easy_control/qr",
            query={"code": pairing.pairing_code, "qr_token": pairing.qr_access_token},
        )
    )

    assert response1.status == 200
    assert response1.content_type == "image/svg+xml"
    assert response2.status == 200
    assert ack_response.status == 200
    assert response3.status == 410


# --- Multi-use (max_uses=0 unlimited) token tests ---


@pytest.mark.asyncio
async def test_unlimited_token_allows_repeated_actions(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """A token with max_uses=0 can execute the same action repeatedly."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, payload = token_manager.create_guest_token(
        guest_id="guest-unlimited",
        entity_id="cover.garage",
        allowed_action="garage.open",
        expires_at=now_ts + 3600,
        token_version=1,
        max_uses=0,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    call_count = 0

    async def _incrementing_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        return call_count

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal call_count
        return call_count

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _incrementing_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    responses = []
    for _ in range(5):
        request = _FakeRequest(
            hass=hass,
            headers={"Authorization": f"Bearer {token}"},
            json_payload={"action": "garage.open"},
            path="/api/easy_control/action",
        )
        response = await GuestAccessActionView().post(request)
        responses.append(response)

    for resp in responses:
        body = _json_body(resp)
        assert resp.status == 200
        assert body["success"] is True
        assert body["remaining_uses"] == -1

    assert len(hass.services.calls) == 5


@pytest.mark.asyncio
async def test_finite_max_uses_blocks_after_limit(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """A token with max_uses=2 must block on the 3rd action call."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-finite",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 3600,
        token_version=1,
        max_uses=2,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    call_count = 0

    async def _incrementing_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        return call_count

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        return call_count

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _incrementing_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    # First two actions succeed
    for i in range(2):
        request = _FakeRequest(
            hass=hass,
            headers={"Authorization": f"Bearer {token}"},
            json_payload={"action": "door.open"},
            path="/api/easy_control/action",
        )
        response = await GuestAccessActionView().post(request)
        body = _json_body(response)
        assert response.status == 200, f"Action {i + 1} should succeed"
        assert body["success"] is True
        assert body["remaining_uses"] == max(2 - (i + 1), 0)

    # Third action is blocked
    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={"action": "door.open"},
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    body = _json_body(response)
    assert response.status == 401
    assert body["error"] == "token_max_uses_exceeded"


@pytest.mark.asyncio
async def test_validate_unlimited_token_returns_remaining_uses_minus_one(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """Token validate endpoint returns remaining_uses=-1 for unlimited tokens."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-unlimited",
        entity_id="cover.garage",
        allowed_action="garage.open",
        expires_at=now_ts + 3600,
        token_version=1,
        max_uses=0,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 42

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )

    request = _FakeRequest(
        hass=hass,
        json_payload={"guest_token": token},
        path="/api/easy_control/token/validate",
    )
    response = await GuestAccessTokenValidateView().post(request)
    body = _json_body(response)

    assert response.status == 200
    assert body["remaining_uses"] == -1


@pytest.mark.asyncio
async def test_pair_response_includes_scan_ack_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pairing response must include scan_ack_supported=True for backward compat."""
    domain_data = _build_domain_data()
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="cover.garage",
        allowed_action="garage.open",
        pass_expires_at=2_000_000_000,
    )
    hass = _FakeHass(domain_data)
    request = _FakeRequest(
        hass=hass,
        json_payload={"pairing_code": pairing.pairing_code},
        path="/api/easy_control/pair",
    )

    async def _noop_register_issued_token(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return None

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_register_issued_token",
        _noop_register_issued_token,
    )

    response = await GuestAccessPairView().post(request)
    body = _json_body(response)

    assert response.status == 200
    assert body["scan_ack_supported"] is True


# ---------------------------------------------------------------------------
# Brightness: light.set_brightness action
# ---------------------------------------------------------------------------


class _FakeState:
    """Minimal HA state object for testing."""

    def __init__(self, state: str, attributes: dict[str, Any] | None = None) -> None:
        self.state = state
        self.attributes = attributes or {}


class _FakeStates:
    """Minimal HA states registry for testing."""

    def __init__(self, states: dict[str, _FakeState] | None = None) -> None:
        self._states = states or {}

    def get(self, entity_id: str) -> _FakeState | None:
        return self._states.get(entity_id)


class _FakeHassWithStates(_FakeHass):
    """_FakeHass extended with a states registry."""

    def __init__(
        self,
        domain_data: dict[str, Any],
        states: dict[str, _FakeState] | None = None,
    ) -> None:
        super().__init__(domain_data)
        self.states = _FakeStates(states)


@pytest.mark.asyncio
async def test_brightness_action_passes_brightness_pct(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """light.set_brightness passes brightness_pct to light.turn_on service."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-dimmer",
        entities=[
            {
                "entity_id": "light.living_room",
                "allowed_actions": ["light.on", "light.off", "light.set_brightness"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 1

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "light.set_brightness",
            "entity_id": "light.living_room",
            "brightness_pct": 64,
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    body = _json_body(response)

    assert response.status == 200
    assert body["success"] is True
    assert body["action"] == "light.set_brightness"
    assert len(hass.services.calls) == 1
    domain, service, data = hass.services.calls[0]
    assert domain == "light"
    assert service == "turn_on"
    assert data == {"entity_id": "light.living_room", "brightness_pct": 64}


@pytest.mark.asyncio
async def test_brightness_pct_clamped_to_0_100(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """brightness_pct is clamped to [0, 100]."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-clamp",
        entities=[
            {
                "entity_id": "light.living_room",
                "allowed_actions": ["light.set_brightness"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 1

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    # Test value > 100 → clamped to 100
    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "light.set_brightness",
            "entity_id": "light.living_room",
            "brightness_pct": 150,
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    assert response.status == 200
    _, _, data = hass.services.calls[0]
    assert data["brightness_pct"] == 100

    # Test value < 0 → clamped to 0
    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "light.set_brightness",
            "entity_id": "light.living_room",
            "brightness_pct": -20,
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    assert response.status == 200
    _, _, data = hass.services.calls[1]
    assert data["brightness_pct"] == 0


@pytest.mark.asyncio
async def test_brightness_action_without_pct_omits_brightness(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """light.set_brightness without brightness_pct only passes entity_id."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-no-pct",
        entities=[
            {
                "entity_id": "light.living_room",
                "allowed_actions": ["light.set_brightness"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 1

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "light.set_brightness",
            "entity_id": "light.living_room",
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    assert response.status == 200
    _, _, data = hass.services.calls[0]
    assert data == {"entity_id": "light.living_room"}


# ---------------------------------------------------------------------------
# States: brightness attributes for light entities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_states_view_returns_brightness_attributes_for_lights(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """States endpoint includes brightness attrs for light entities."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    domain_data["entry-1"][CONF_STATES_RATE_LIMIT_PER_MIN] = 60
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-states",
        entities=[
            {
                "entity_id": "light.living_room",
                "allowed_actions": ["light.on", "light.off", "light.set_brightness"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )

    fake_states = {
        "light.living_room": _FakeState(
            state="on",
            attributes={
                "friendly_name": "Living Room",
                "brightness": 191,
                "supported_color_modes": ["brightness"],
                "supported_features": 0,
            },
        ),
    }
    hass = _FakeHassWithStates(domain_data, states=fake_states)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        path="/api/easy_control/states",
        method="GET",
    )
    response = await GuestAccessEntityStatesView().get(request)
    body = _json_body(response)

    assert response.status == 200
    entities = body["entities"]
    assert len(entities) == 1
    light = entities[0]
    assert light["entity_id"] == "light.living_room"
    assert light["state"] == "on"
    assert light["brightness"] == 191
    assert light["supported_color_modes"] == ["brightness"]
    assert "brightness_pct" not in light  # not set in HA attributes


@pytest.mark.asyncio
async def test_states_view_omits_brightness_for_non_light(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """States endpoint does not include brightness attrs for non-light entities."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    domain_data["entry-1"][CONF_STATES_RATE_LIMIT_PER_MIN] = 60
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-states-switch",
        entities=[
            {
                "entity_id": "switch.porch",
                "allowed_actions": ["switch.on", "switch.off"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )

    fake_states = {
        "switch.porch": _FakeState(
            state="off",
            attributes={"friendly_name": "Porch Switch"},
        ),
    }
    hass = _FakeHassWithStates(domain_data, states=fake_states)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        path="/api/easy_control/states",
        method="GET",
    )
    response = await GuestAccessEntityStatesView().get(request)
    body = _json_body(response)

    assert response.status == 200
    switch = body["entities"][0]
    assert "brightness" not in switch
    assert "supported_color_modes" not in switch


# ---------------------------------------------------------------------------
# Climate: climate.set_temperature action
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_climate_set_temperature_passes_temperature(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """climate.set_temperature passes temperature to climate.set_temperature service."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-climate",
        entities=[
            {
                "entity_id": "climate.living_room",
                "allowed_actions": ["climate.read", "climate.set_temperature"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 1

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "climate.set_temperature",
            "entity_id": "climate.living_room",
            "temperature": 22.5,
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    body = _json_body(response)

    assert response.status == 200
    assert body["success"] is True
    assert body["action"] == "climate.set_temperature"
    assert len(hass.services.calls) == 1
    domain, service, data = hass.services.calls[0]
    assert domain == "climate"
    assert service == "set_temperature"
    assert data == {"entity_id": "climate.living_room", "temperature": 22.5}


@pytest.mark.asyncio
async def test_climate_set_temperature_without_temp_omits_it(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """climate.set_temperature without temperature only passes entity_id."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-climate-no-temp",
        entities=[
            {
                "entity_id": "climate.living_room",
                "allowed_actions": ["climate.set_temperature"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 1

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "climate.set_temperature",
            "entity_id": "climate.living_room",
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    assert response.status == 200
    _, _, data = hass.services.calls[0]
    assert data == {"entity_id": "climate.living_room"}


@pytest.mark.asyncio
async def test_states_view_returns_climate_attributes(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """States endpoint includes climate-specific attributes."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    domain_data["entry-1"][CONF_STATES_RATE_LIMIT_PER_MIN] = 60
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-states-climate",
        entities=[
            {
                "entity_id": "climate.living_room",
                "allowed_actions": ["climate.read", "climate.set_temperature"],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )

    fake_states = {
        "climate.living_room": _FakeState(
            state="heat",
            attributes={
                "friendly_name": "Living Room",
                "current_temperature": 21.5,
                "temperature": 23.0,
                "hvac_modes": ["off", "heat", "cool", "heat_cool"],
                "hvac_action": "heating",
                "min_temp": 7,
                "max_temp": 35,
                "target_temp_step": 0.5,
            },
        ),
    }
    hass = _FakeHassWithStates(domain_data, states=fake_states)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        path="/api/easy_control/states",
        method="GET",
    )
    response = await GuestAccessEntityStatesView().get(request)
    body = _json_body(response)

    assert response.status == 200
    climate = body["entities"][0]
    assert climate["entity_id"] == "climate.living_room"
    assert climate["state"] == "heat"
    assert climate["current_temperature"] == 21.5
    assert climate["temperature"] == 23.0
    assert climate["hvac_modes"] == ["off", "heat", "cool", "heat_cool"]
    assert climate["hvac_action"] == "heating"
    assert climate["min_temp"] == 7
    assert climate["max_temp"] == 35
    assert climate["target_temp_step"] == 0.5


@pytest.mark.asyncio
async def test_set_position_passes_position_pct(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """garage.set_position passes position to cover.set_cover_position service."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-cover-pos",
        entities=[
            {
                "entity_id": "cover.shade",
                "allowed_actions": [
                    "garage.open",
                    "garage.close",
                    "garage.set_position",
                    "garage.set_tilt",
                ],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 1

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "garage.set_position",
            "entity_id": "cover.shade",
            "position_pct": 42,
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    body = _json_body(response)

    assert response.status == 200
    assert body["success"] is True
    assert body["action"] == "garage.set_position"
    assert len(hass.services.calls) == 1
    domain, service, data = hass.services.calls[0]
    assert domain == "cover"
    assert service == "set_cover_position"
    assert data == {"entity_id": "cover.shade", "position": 42}


@pytest.mark.asyncio
async def test_set_tilt_passes_tilt_pct(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """garage.set_tilt passes tilt_position to cover.set_cover_tilt_position service."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-cover-tilt",
        entities=[
            {
                "entity_id": "cover.shade",
                "allowed_actions": [
                    "garage.open",
                    "garage.close",
                    "garage.set_position",
                    "garage.set_tilt",
                ],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    hass = _FakeHass(domain_data)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    async def _fake_record_use(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 1

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_record_token_use",
        _fake_record_use,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        json_payload={
            "action": "garage.set_tilt",
            "entity_id": "cover.shade",
            "tilt_pct": 75,
        },
        path="/api/easy_control/action",
    )
    response = await GuestAccessActionView().post(request)
    body = _json_body(response)

    assert response.status == 200
    assert body["success"] is True
    assert body["action"] == "garage.set_tilt"
    assert len(hass.services.calls) == 1
    domain, service, data = hass.services.calls[0]
    assert domain == "cover"
    assert service == "set_cover_tilt_position"
    assert data == {"entity_id": "cover.shade", "tilt_position": 75}


@pytest.mark.asyncio
async def test_states_view_returns_cover_attributes(
    monkeypatch: pytest.MonkeyPatch,
    now_ts: int,
) -> None:
    """States endpoint includes cover-specific attributes."""
    domain_data = _build_domain_data()
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    domain_data["entry-1"][CONF_STATES_RATE_LIMIT_PER_MIN] = 60
    token, _payload = token_manager.create_guest_token(
        guest_id="guest-states-cover",
        entities=[
            {
                "entity_id": "cover.shade",
                "allowed_actions": [
                    "garage.open",
                    "garage.close",
                    "garage.set_position",
                    "garage.set_tilt",
                ],
            },
        ],
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )

    fake_states = {
        "cover.shade": _FakeState(
            state="open",
            attributes={
                "friendly_name": "Living Room Shade",
                "current_position": 65,
                "current_tilt_position": 30,
                "supported_features": 255,
            },
        ),
    }
    hass = _FakeHassWithStates(domain_data, states=fake_states)

    async def _fake_use_count(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return 0

    async def _fake_is_revoked(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        return False

    monkeypatch.setattr(
        "custom_components.easy_control.api.async_get_token_use_count",
        _fake_use_count,
    )
    monkeypatch.setattr(
        "custom_components.easy_control.api.async_is_token_revoked",
        _fake_is_revoked,
    )

    request = _FakeRequest(
        hass=hass,
        headers={"Authorization": f"Bearer {token}"},
        path="/api/easy_control/states",
        method="GET",
    )
    response = await GuestAccessEntityStatesView().get(request)
    body = _json_body(response)

    assert response.status == 200
    cover = body["entities"][0]
    assert cover["entity_id"] == "cover.shade"
    assert cover["state"] == "open"
    assert cover["current_position"] == 65
    assert cover["current_tilt_position"] == 30
    assert cover["supported_features"] == 255

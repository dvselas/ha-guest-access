"""HA HTTP integration tests for easy_control API endpoints."""

from __future__ import annotations

import base64
import json
import sys
import threading
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import async_mock_service

from custom_components.easy_control.api import async_register_api
from custom_components.easy_control.const import (
    CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS,
    CONF_ACTION_RATE_LIMIT_PER_MIN,
    CONF_NONCE_TTL_SECONDS,
    CONF_PAIR_RATE_LIMIT_PER_MIN,
    CONF_QR_RATE_LIMIT_PER_MIN,
    CONF_REQUIRE_ACTION_PROOF,
    CONF_REQUIRE_DEVICE_BINDING,
    CONF_TOKEN_VERSION,
    DATA_API_REGISTERED,
    DATA_CONFIG_ENTRIES,
    DATA_NONCE_STORE,
    DATA_PAIRING_STORE,
    DATA_RATE_LIMITER,
    DATA_TOKEN_MANAGER,
    DOMAIN,
)
from custom_components.easy_control.pairing import PairingStore
from custom_components.easy_control.proof import (
    ActionProof,
    build_proof_signing_input,
    hash_request_body,
)
from custom_components.easy_control.runtime_security import ActionNonceStore, FixedWindowRateLimiter
from custom_components.easy_control.token import GuestTokenManager

pytestmark = pytest.mark.integration


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(autouse=True)
async def _cleanup_hass_http(hass):
    """Ensure HTTP component background resources are stopped after each test."""
    yield
    await hass.async_stop()
    # HA HTTP setup may leave a daemon safe-shutdown helper thread alive in this test env.
    # Normalize the name to the plugin's allowed prefix to avoid false-positive cleanup errors.
    for thread in threading.enumerate():
        if "_run_safe_shutdown_loop" in thread.name and not thread.name.startswith("waitpid-"):
            thread.name = f"waitpid-{thread.name}"


def _build_domain_data(
    *,
    require_action_proof: bool = False,
    require_device_binding: bool = False,
) -> dict[str, Any]:
    return {
        DATA_PAIRING_STORE: PairingStore(),
        DATA_NONCE_STORE: ActionNonceStore(),
        DATA_RATE_LIMITER: FixedWindowRateLimiter(),
        DATA_CONFIG_ENTRIES: {"entry-1"},
        DATA_API_REGISTERED: False,
        "entry-1": {
            CONF_TOKEN_VERSION: 1,
            CONF_REQUIRE_ACTION_PROOF: require_action_proof,
            CONF_REQUIRE_DEVICE_BINDING: require_device_binding,
            CONF_PAIR_RATE_LIMIT_PER_MIN: 50,
            CONF_ACTION_RATE_LIMIT_PER_MIN: 50,
            CONF_QR_RATE_LIMIT_PER_MIN: 50,
            CONF_NONCE_TTL_SECONDS: 60,
            CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS: 60,
            DATA_TOKEN_MANAGER: GuestTokenManager("test-signing-key"),
        },
    }


async def _setup_api(
    hass,
    *,
    require_action_proof: bool = False,
    require_device_binding: bool = False,
):
    assert await async_setup_component(hass, "http", {})
    domain_data = _build_domain_data(
        require_action_proof=require_action_proof,
        require_device_binding=require_device_binding,
    )
    hass.data[DOMAIN] = domain_data
    hass.config.external_url = "https://ha.example.test"
    hass.config.internal_url = "http://ha.local"
    async_register_api(hass)
    await hass.async_block_till_done()
    return domain_data


@pytest.mark.asyncio
async def test_pair_endpoint_exchanges_code_once(hass, hass_client_no_auth):
    domain_data = await _setup_api(hass)
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
    )
    client = await hass_client_no_auth()
    try:
        first = await client.post(
            "/api/easy_control/pair",
            json={"pairing_code": pairing.pairing_code},
        )
        first_payload = await first.json()
        second = await client.post(
            "/api/easy_control/pair",
            json={"pairing_code": pairing.pairing_code},
        )
        second_payload = await second.json()

        assert first.status == 200
        assert "guest_token" in first_payload
        assert first_payload["allowed_actions"] == ["door.open"]
        assert second.status == 400
        assert second_payload["error"] == "pairing_code_invalid"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_pair_nonce_action_flow_with_pop_proof_executes_service(
    hass,
    hass_client_no_auth,
):
    domain_data = await _setup_api(
        hass,
        require_action_proof=True,
        require_device_binding=True,
    )
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
    )
    client = await hass_client_no_auth()
    calls = async_mock_service(hass, "lock", "unlock")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    device_id = "iphone-guest-01"
    device_public_key = _b64url_encode(public_key)

    try:
        pair_resp = await client.post(
            "/api/easy_control/pair",
            json={
                "pairing_code": pairing.pairing_code,
                "device_id": device_id,
                "device_public_key": device_public_key,
            },
        )
        pair_payload = await pair_resp.json()
        assert pair_resp.status == 200
        assert pair_payload["proof_required"] is True
        guest_token = pair_payload["guest_token"]

        nonce_resp = await client.get(
            "/api/easy_control/action/nonce",
            headers={"Authorization": f"Bearer {guest_token}"},
        )
        nonce_payload = await nonce_resp.json()
        assert nonce_resp.status == 200

        action_payload = {"action": "door.open"}
        raw_body = json.dumps(action_payload, separators=(",", ":")).encode("utf-8")
        proof_dict = {
            "nonce": nonce_payload["nonce"],
            "ts": int(time.time()),
            "method": "POST",
            "path": "/api/easy_control/action",
            "body_sha256": hash_request_body(raw_body),
            "jti": nonce_payload["jti"],
            "device_id": device_id,
        }
        proof = ActionProof.from_dict(proof_dict)
        signature = private_key.sign(build_proof_signing_input(proof))
        action_resp = await client.post(
            "/api/easy_control/action",
            data=raw_body,
            headers={
                "Authorization": f"Bearer {guest_token}",
                "Content-Type": "application/json",
                "X-Easy-Control-Proof": _b64url_encode(
                    json.dumps(proof_dict, separators=(",", ":")).encode("utf-8")
                ),
                "X-Easy-Control-Proof-Signature": _b64url_encode(signature),
            },
        )
        action_response_payload = await action_resp.json()

        assert action_resp.status == 200
        assert action_response_payload["success"] is True
        assert len(calls) == 1
        assert calls[0].data["entity_id"] == "lock.front_door"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_action_endpoint_rejects_missing_proof_when_required(
    hass,
    hass_client_no_auth,
    now_ts: int,
):
    domain_data = await _setup_api(hass, require_action_proof=True)
    token_manager: GuestTokenManager = domain_data["entry-1"][DATA_TOKEN_MANAGER]
    guest_token, _ = token_manager.create_guest_token(
        guest_id="guest-1",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    client = await hass_client_no_auth()
    calls = async_mock_service(hass, "lock", "unlock")
    try:
        response = await client.post(
            "/api/easy_control/action",
            json={"action": "door.open"},
            headers={"Authorization": f"Bearer {guest_token}"},
        )
        payload = await response.json()

        assert response.status == 401
        assert payload["error"] == "action_proof_required"
        assert calls == []
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_qr_endpoint_returns_svg_once_then_410(
    hass,
    hass_client_no_auth,
    monkeypatch: pytest.MonkeyPatch,
):
    domain_data = await _setup_api(hass)
    pairing_store: PairingStore = domain_data[DATA_PAIRING_STORE]
    pairing = pairing_store.create_pairing(
        entity_id="cover.garage",
        allowed_action="garage.open",
        pass_expires_at=int(time.time()) + 3600,
    )
    client = await hass_client_no_auth()

    class _FakeQr:
        def save(self, out, **kwargs):  # type: ignore[no-untyped-def]
            del kwargs
            out.write(b"<svg/>")

    class _FakeSegno:
        @staticmethod
        def make(*args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            return _FakeQr()

    monkeypatch.setitem(sys.modules, "segno", _FakeSegno)

    try:
        first = await client.get(
            f"/api/easy_control/qr?code={pairing.pairing_code}&qr_token={pairing.qr_access_token}"
        )
        first_body = await first.read()
        second = await client.get(
            f"/api/easy_control/qr?code={pairing.pairing_code}&qr_token={pairing.qr_access_token}"
        )
        second_text = await second.text()

        assert first.status == 200
        assert first.content_type == "image/svg+xml"
        assert first_body == b"<svg/>"
        assert second.status == 410
        assert "already been used" in second_text
    finally:
        await client.close()

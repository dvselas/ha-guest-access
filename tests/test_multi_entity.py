"""Tests for multi-entity and multi-action support."""

from __future__ import annotations

import time

import pytest

from custom_components.easy_control.const import (
    ACTION_SERVICE_MAP,
    ALLOWED_ENTITY_DOMAINS,
    DOMAIN_ACTION_MAP,
    READ_ONLY_DOMAINS,
)
from custom_components.easy_control.pairing import PairingStore
from custom_components.easy_control.token import (
    GuestTokenManager,
    GuestTokenPayload,
    InvalidTokenError,
)

# ---------------------------------------------------------------------------
# Token: multi-entity creation & verification (allowed_actions lists)
# ---------------------------------------------------------------------------


def test_multi_entity_token_creation_and_verification(now_ts: int) -> None:
    """Token with multiple entities round-trips through create → verify."""
    manager = GuestTokenManager("test-key")
    entities = [
        {"entity_id": "lock.front_door", "allowed_actions": ["door.lock", "door.unlock"]},
        {"entity_id": "cover.garage", "allowed_actions": ["garage.open", "garage.close"]},
        {"entity_id": "switch.porch", "allowed_actions": ["switch.on", "switch.off"]},
        {"entity_id": "light.living_room", "allowed_actions": ["light.on", "light.off"]},
    ]
    token, payload = manager.create_guest_token(
        guest_id="guest-multi",
        entities=entities,
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    verified = manager.verify_token(token, now_timestamp=now_ts)
    assert len(verified.entities) == 4
    assert verified.entity_ids() == [
        "lock.front_door",
        "cover.garage",
        "switch.porch",
        "light.living_room",
    ]
    # Backward-compat property returns first action of first entity
    assert verified.entity_id == "lock.front_door"
    assert verified.allowed_action == "door.lock"


def test_multi_action_allowed_actions_for_lookup(now_ts: int) -> None:
    """allowed_actions_for() returns full list of actions per entity."""
    manager = GuestTokenManager("test-key")
    entities = [
        {"entity_id": "lock.front", "allowed_actions": ["door.lock", "door.unlock"]},
        {"entity_id": "cover.garage", "allowed_actions": ["garage.open", "garage.close"]},
    ]
    _token, payload = manager.create_guest_token(
        guest_id="g1",
        entities=entities,
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    assert payload.allowed_actions_for("lock.front") == ["door.lock", "door.unlock"]
    assert payload.allowed_actions_for("cover.garage") == ["garage.open", "garage.close"]
    assert payload.allowed_actions_for("switch.unknown") == []
    # allowed_action_for returns first action (backward compat)
    assert payload.allowed_action_for("lock.front") == "door.lock"


def test_token_to_dict_includes_allowed_actions(now_ts: int) -> None:
    """to_dict() entities include allowed_actions list AND singular allowed_action."""
    manager = GuestTokenManager("test-key")
    entities = [
        {"entity_id": "lock.a", "allowed_actions": ["door.lock", "door.unlock"]},
        {"entity_id": "cover.b", "allowed_actions": ["garage.open", "garage.close"]},
    ]
    _token, payload = manager.create_guest_token(
        guest_id="g1",
        entities=entities,
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    d = payload.to_dict()
    # Each entity dict has both allowed_actions and allowed_action
    assert d["entities"][0]["allowed_actions"] == ["door.lock", "door.unlock"]
    assert d["entities"][0]["allowed_action"] == "door.lock"
    assert d["entities"][1]["allowed_actions"] == ["garage.open", "garage.close"]
    # Top-level backward-compat
    assert d["entity_id"] == "lock.a"
    assert d["allowed_action"] == "door.lock"


def test_from_dict_parses_allowed_actions_array(now_ts: int) -> None:
    """from_dict() parses entities with allowed_actions lists."""
    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "g1",
        "entities": [
            {"entity_id": "lock.a", "allowed_actions": ["door.lock", "door.unlock"]},
            {"entity_id": "switch.b", "allowed_actions": ["switch.on", "switch.off"]},
        ],
        "iat": now_ts,
        "nbf": now_ts,
        "exp": now_ts + 600,
        "max_uses": 0,
        "token_version": 1,
    }
    payload = GuestTokenPayload.from_dict(data)
    assert len(payload.entities) == 2
    assert payload.allowed_actions_for("lock.a") == ["door.lock", "door.unlock"]
    assert payload.entity_id == "lock.a"


def test_from_dict_parses_legacy_allowed_action_string(now_ts: int) -> None:
    """from_dict() wraps legacy allowed_action string into list."""
    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "g1",
        "entities": [
            {"entity_id": "lock.a", "allowed_action": "door.open"},
            {"entity_id": "switch.b", "allowed_action": "switch.toggle"},
        ],
        "iat": now_ts,
        "nbf": now_ts,
        "exp": now_ts + 600,
        "max_uses": 0,
        "token_version": 1,
    }
    payload = GuestTokenPayload.from_dict(data)
    assert len(payload.entities) == 2
    assert payload.allowed_actions_for("lock.a") == ["door.open"]
    assert payload.entity_id == "lock.a"


def test_from_dict_falls_back_to_legacy_singular_fields(now_ts: int) -> None:
    """from_dict() constructs single-item entities from legacy token."""
    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "g1",
        "entity_id": "cover.garage",
        "allowed_action": "garage.open",
        "iat": now_ts,
        "nbf": now_ts,
        "exp": now_ts + 600,
        "max_uses": 5,
        "token_version": 1,
    }
    payload = GuestTokenPayload.from_dict(data)
    assert len(payload.entities) == 1
    assert payload.entity_id == "cover.garage"
    assert payload.allowed_action == "garage.open"
    assert payload.allowed_actions_for("cover.garage") == ["garage.open"]


def test_from_dict_rejects_empty_entities_array(now_ts: int) -> None:
    """from_dict() rejects empty entities array."""
    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "g1",
        "entities": [],
        "iat": now_ts,
        "nbf": now_ts,
        "exp": now_ts + 600,
        "max_uses": 0,
        "token_version": 1,
    }
    with pytest.raises(InvalidTokenError, match="non-empty list"):
        GuestTokenPayload.from_dict(data)


def test_from_dict_rejects_malformed_entity_entry(now_ts: int) -> None:
    """from_dict() rejects entity entry missing entity_id."""
    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "g1",
        "entities": [{"allowed_actions": ["door.lock"]}],
        "iat": now_ts,
        "nbf": now_ts,
        "exp": now_ts + 600,
        "max_uses": 0,
        "token_version": 1,
    }
    with pytest.raises(InvalidTokenError, match="entity_id"):
        GuestTokenPayload.from_dict(data)


def test_create_guest_token_requires_at_least_one_entity(now_ts: int) -> None:
    """create_guest_token() raises when no entities are provided."""
    manager = GuestTokenManager("test-key")
    with pytest.raises(ValueError, match="at least one grant"):
        manager.create_guest_token(
            guest_id="g1",
            entities=[],
            expires_at=now_ts + 600,
            token_version=1,
            now_timestamp=now_ts,
        )


def test_legacy_allowed_action_wrapped_in_create(now_ts: int) -> None:
    """create_guest_token() wraps legacy allowed_action into list."""
    manager = GuestTokenManager("test-key")
    entities = [
        {"entity_id": "lock.a", "allowed_action": "door.open"},
    ]
    _token, payload = manager.create_guest_token(
        guest_id="g1",
        entities=entities,
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    assert payload.allowed_actions_for("lock.a") == ["door.open"]


# ---------------------------------------------------------------------------
# Pairing: multi-entity creation
# ---------------------------------------------------------------------------


def test_multi_entity_pairing_creation() -> None:
    """PairingStore.create_pairing() stores multiple entities."""
    store = PairingStore()
    entities = [
        {"entity_id": "lock.front", "allowed_actions": ["door.lock", "door.unlock"]},
        {"entity_id": "cover.garage", "allowed_actions": ["garage.open", "garage.close"]},
        {"entity_id": "sensor.temp", "allowed_actions": ["sensor.read"]},
    ]
    record = store.create_pairing(
        entities=entities,
        pass_expires_at=int(time.time()) + 3600,
    )
    assert len(record.entities) == 3
    assert record.entity_id == "lock.front"  # backward-compat
    assert record.allowed_action == "door.lock"  # first action of first entity


def test_pairing_to_dict_includes_entities() -> None:
    """PairingRecord.to_dict() includes entities array and singular fields."""
    store = PairingStore()
    entities = [
        {"entity_id": "lock.a", "allowed_actions": ["door.lock", "door.unlock"]},
        {"entity_id": "switch.b", "allowed_actions": ["switch.on", "switch.off"]},
    ]
    record = store.create_pairing(
        entities=entities,
        pass_expires_at=int(time.time()) + 3600,
    )
    d = record.to_dict()
    assert d["entities"][0]["allowed_actions"] == ["door.lock", "door.unlock"]
    assert d["entity_id"] == "lock.a"
    assert d["allowed_action"] == "door.lock"


def test_pairing_legacy_single_entity_still_works() -> None:
    """create_pairing() with legacy entity_id/allowed_action creates single-item entities."""
    store = PairingStore()
    record = store.create_pairing(
        entity_id="cover.garage",
        allowed_action="garage.open",
        pass_expires_at=int(time.time()) + 3600,
    )
    assert len(record.entities) == 1
    assert record.entity_id == "cover.garage"
    assert record.allowed_action == "garage.open"


def test_pairing_legacy_allowed_action_in_entities() -> None:
    """create_pairing() wraps legacy allowed_action string in entities."""
    store = PairingStore()
    entities = [
        {"entity_id": "lock.a", "allowed_action": "door.open"},
    ]
    record = store.create_pairing(
        entities=entities,
        pass_expires_at=int(time.time()) + 3600,
    )
    assert record.allowed_action == "door.open"


# ---------------------------------------------------------------------------
# Constants: domain → action mapping
# ---------------------------------------------------------------------------


def test_domain_action_map_covers_all_allowed_domains() -> None:
    """Every allowed domain has a mapping in DOMAIN_ACTION_MAP."""
    for domain in ALLOWED_ENTITY_DOMAINS:
        assert domain in DOMAIN_ACTION_MAP, f"Missing DOMAIN_ACTION_MAP for {domain}"


def test_domain_action_map_returns_lists() -> None:
    """DOMAIN_ACTION_MAP values are lists of actions."""
    for domain, actions in DOMAIN_ACTION_MAP.items():
        assert isinstance(actions, list), f"{domain} should map to a list"
        assert len(actions) >= 1, f"{domain} must have at least one action"


def test_bidirectional_lock_actions() -> None:
    """Lock domain has lock and unlock actions."""
    assert DOMAIN_ACTION_MAP["lock"] == ["door.lock", "door.unlock"]
    assert ACTION_SERVICE_MAP["door.lock"] == ("lock", "lock")
    assert ACTION_SERVICE_MAP["door.unlock"] == ("lock", "unlock")


def test_bidirectional_cover_actions() -> None:
    """Cover domain has open and close actions."""
    assert DOMAIN_ACTION_MAP["cover"] == ["garage.open", "garage.close"]
    assert ACTION_SERVICE_MAP["garage.open"] == ("cover", "open_cover")
    assert ACTION_SERVICE_MAP["garage.close"] == ("cover", "close_cover")


def test_bidirectional_switch_actions() -> None:
    """Switch domain has on and off actions."""
    assert DOMAIN_ACTION_MAP["switch"] == ["switch.on", "switch.off"]
    assert ACTION_SERVICE_MAP["switch.on"] == ("switch", "turn_on")
    assert ACTION_SERVICE_MAP["switch.off"] == ("switch", "turn_off")


def test_bidirectional_light_actions() -> None:
    """Light domain has on, off, and set_brightness actions."""
    assert DOMAIN_ACTION_MAP["light"] == ["light.on", "light.off", "light.set_brightness"]
    assert ACTION_SERVICE_MAP["light.on"] == ("light", "turn_on")
    assert ACTION_SERVICE_MAP["light.off"] == ("light", "turn_off")
    assert ACTION_SERVICE_MAP["light.set_brightness"] == ("light", "turn_on")
    assert "light" not in READ_ONLY_DOMAINS


def test_climate_actions() -> None:
    """Climate domain has read and set_temperature actions."""
    assert DOMAIN_ACTION_MAP["climate"] == ["climate.read", "climate.set_temperature"]
    assert ACTION_SERVICE_MAP["climate.set_temperature"] == ("climate", "set_temperature")
    assert "climate" not in READ_ONLY_DOMAINS


def test_legacy_actions_in_service_map() -> None:
    """Legacy actions remain in ACTION_SERVICE_MAP for backward compat."""
    assert ACTION_SERVICE_MAP["door.open"] == ("lock", "unlock")
    assert ACTION_SERVICE_MAP["switch.toggle"] == ("switch", "toggle")
    assert ACTION_SERVICE_MAP["light.toggle"] == ("light", "toggle")


def test_read_only_domains_are_not_in_action_service_map() -> None:
    """Read-only domains should NOT have entries in ACTION_SERVICE_MAP."""
    for domain in READ_ONLY_DOMAINS:
        actions = DOMAIN_ACTION_MAP[domain]
        for action in actions:
            assert action not in ACTION_SERVICE_MAP, (
                f"Read-only domain {domain} action {action} "
                "should not be in ACTION_SERVICE_MAP"
            )

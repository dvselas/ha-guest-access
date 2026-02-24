"""Tests for multi-entity support across token, pairing, and API layers."""

from __future__ import annotations

import time

import pytest

from custom_components.easy_control.const import DOMAIN_ACTION_MAP, READ_ONLY_DOMAINS
from custom_components.easy_control.pairing import PairingStore
from custom_components.easy_control.token import (
    GuestTokenManager,
    GuestTokenPayload,
    InvalidTokenError,
)


# ---------------------------------------------------------------------------
# Token: multi-entity creation & verification
# ---------------------------------------------------------------------------


def test_multi_entity_token_creation_and_verification(now_ts: int) -> None:
    """Token with multiple entities round-trips through create → verify."""
    manager = GuestTokenManager("test-key")
    entities = [
        {"entity_id": "lock.front_door", "allowed_action": "door.open"},
        {"entity_id": "cover.garage", "allowed_action": "garage.open"},
        {"entity_id": "switch.porch", "allowed_action": "switch.toggle"},
    ]
    token, payload = manager.create_guest_token(
        guest_id="guest-multi",
        entities=entities,
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    verified = manager.verify_token(token, now_timestamp=now_ts)
    assert len(verified.entities) == 3
    assert verified.entity_ids() == [
        "lock.front_door",
        "cover.garage",
        "switch.porch",
    ]
    # Backward-compat property returns first entity
    assert verified.entity_id == "lock.front_door"
    assert verified.allowed_action == "door.open"


def test_multi_entity_allowed_action_for_lookup(now_ts: int) -> None:
    """allowed_action_for() returns correct action per entity."""
    manager = GuestTokenManager("test-key")
    entities = [
        {"entity_id": "lock.front", "allowed_action": "door.open"},
        {"entity_id": "cover.garage", "allowed_action": "garage.open"},
    ]
    _token, payload = manager.create_guest_token(
        guest_id="g1",
        entities=entities,
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    assert payload.allowed_action_for("lock.front") == "door.open"
    assert payload.allowed_action_for("cover.garage") == "garage.open"
    assert payload.allowed_action_for("switch.unknown") is None


def test_token_to_dict_includes_entities_and_backward_compat(now_ts: int) -> None:
    """to_dict() includes entities array AND singular backward-compat fields."""
    manager = GuestTokenManager("test-key")
    entities = [
        {"entity_id": "lock.a", "allowed_action": "door.open"},
        {"entity_id": "cover.b", "allowed_action": "garage.open"},
    ]
    _token, payload = manager.create_guest_token(
        guest_id="g1",
        entities=entities,
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    d = payload.to_dict()
    assert d["entities"] == entities
    assert d["entity_id"] == "lock.a"
    assert d["allowed_action"] == "door.open"


def test_from_dict_parses_entities_array(now_ts: int) -> None:
    """from_dict() parses the new entities array claim."""
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
        "entities": [{"allowed_action": "door.open"}],
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


# ---------------------------------------------------------------------------
# Pairing: multi-entity creation
# ---------------------------------------------------------------------------


def test_multi_entity_pairing_creation() -> None:
    """PairingStore.create_pairing() stores multiple entities."""
    store = PairingStore()
    entities = [
        {"entity_id": "lock.front", "allowed_action": "door.open"},
        {"entity_id": "cover.garage", "allowed_action": "garage.open"},
        {"entity_id": "sensor.temp", "allowed_action": "sensor.read"},
    ]
    record = store.create_pairing(
        entities=entities,
        pass_expires_at=int(time.time()) + 3600,
    )
    assert len(record.entities) == 3
    assert record.entity_id == "lock.front"  # backward-compat
    assert record.allowed_action == "door.open"


def test_pairing_to_dict_includes_entities() -> None:
    """PairingRecord.to_dict() includes entities array and singular fields."""
    store = PairingStore()
    entities = [
        {"entity_id": "lock.a", "allowed_action": "door.open"},
        {"entity_id": "switch.b", "allowed_action": "switch.toggle"},
    ]
    record = store.create_pairing(
        entities=entities,
        pass_expires_at=int(time.time()) + 3600,
    )
    d = record.to_dict()
    assert d["entities"] == entities
    assert d["entity_id"] == "lock.a"
    assert d["allowed_action"] == "door.open"


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


# ---------------------------------------------------------------------------
# Constants: domain → action mapping
# ---------------------------------------------------------------------------


def test_domain_action_map_covers_all_allowed_domains() -> None:
    """Every allowed domain has a mapping in DOMAIN_ACTION_MAP."""
    from custom_components.easy_control.const import ALLOWED_ENTITY_DOMAINS

    for domain in ALLOWED_ENTITY_DOMAINS:
        assert domain in DOMAIN_ACTION_MAP, f"Missing DOMAIN_ACTION_MAP for {domain}"


def test_read_only_domains_are_not_in_action_service_map() -> None:
    """Read-only domains should NOT have entries in ACTION_SERVICE_MAP."""
    from custom_components.easy_control.const import ACTION_SERVICE_MAP

    for domain in READ_ONLY_DOMAINS:
        action = DOMAIN_ACTION_MAP[domain]
        assert action not in ACTION_SERVICE_MAP, (
            f"Read-only domain {domain} action {action} should not be in ACTION_SERVICE_MAP"
        )

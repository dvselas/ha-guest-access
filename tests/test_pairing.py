"""Unit tests for pairing lifecycle."""

from __future__ import annotations

import time

from custom_components.guest_access.pairing import PairingRecord, PairingStore


def test_pairing_valid_once_then_rejected() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
    )

    first_record, first_reason = store.consume_pairing(record.pairing_code)
    second_record, second_reason = store.consume_pairing(record.pairing_code)

    assert first_record is not None
    assert first_reason is None
    assert second_record is None
    assert second_reason is None


def test_expired_pairing_is_rejected() -> None:
    store = PairingStore()
    now_ts = int(time.time())
    record = store.create_pairing(
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        pass_expires_at=now_ts + 3600,
    )

    # Force expiry to avoid waiting for TTL.
    store._records[record.pairing_code] = PairingRecord(  # noqa: SLF001
        pairing_code=record.pairing_code,
        qr_access_token=record.qr_access_token,
        entity_id=record.entity_id,
        allowed_action=record.allowed_action,
        pass_expires_at=record.pass_expires_at,
        pairing_expires_at=now_ts - 1,
        created_at=record.created_at,
    )
    consumed, reason = store.consume_pairing(record.pairing_code)

    assert consumed is None
    assert reason == "expired"


def test_qr_access_requires_matching_qr_token() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
    )

    assert store.validate_qr_access(record.pairing_code, "") is None
    assert store.validate_qr_access(record.pairing_code, "wrong") is None
    assert (
        store.validate_qr_access(record.pairing_code, record.qr_access_token)
        is not None
    )

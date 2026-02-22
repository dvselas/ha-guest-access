"""Unit tests for pairing lifecycle."""

from __future__ import annotations

import asyncio
import time

import pytest

from custom_components.easy_control.pairing import PairingRecord, PairingStore


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


def test_qr_access_token_is_single_use() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        pass_expires_at=int(time.time()) + 3600,
    )

    first_record, first_reason = store.consume_qr_access(
        record.pairing_code, record.qr_access_token
    )
    second_record, second_reason = store.consume_qr_access(
        record.pairing_code, record.qr_access_token
    )

    assert first_record is not None
    assert first_reason is None
    assert second_record is None
    assert second_reason == "used"


def test_pairing_code_still_single_use_after_qr_render() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
    )

    rendered_record, render_reason = store.consume_qr_access(
        record.pairing_code, record.qr_access_token
    )
    first_pair_record, first_pair_reason = store.consume_pairing(record.pairing_code)
    second_pair_record, second_pair_reason = store.consume_pairing(record.pairing_code)

    assert rendered_record is not None
    assert render_reason is None
    assert first_pair_record is not None
    assert first_pair_reason is None
    assert second_pair_record is None
    assert second_pair_reason is None


def test_pairing_requires_admin_approval_when_enabled() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
        require_admin_approval=True,
    )

    pending_record, pending_reason = store.consume_pairing(record.pairing_code)
    assert pending_record is None
    assert pending_reason == "pending_approval"

    approved_record, approve_reason = store.approve_pairing(record.pairing_code)
    assert approved_record is not None
    assert approve_reason is None
    assert approved_record.approval_status == "approved"

    consumed_record, consumed_reason = store.consume_pairing(record.pairing_code)
    assert consumed_record is not None
    assert consumed_reason is None


def test_rejected_pairing_cannot_be_consumed() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        pass_expires_at=int(time.time()) + 3600,
        require_admin_approval=True,
    )

    rejected_record, reject_reason = store.reject_pairing(record.pairing_code)
    consumed_record, consumed_reason = store.consume_pairing(record.pairing_code)

    assert rejected_record is not None
    assert reject_reason is None
    assert consumed_record is None
    assert consumed_reason == "rejected"


@pytest.mark.asyncio
async def test_concurrent_pairing_consume_allows_exactly_one_success() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
    )

    async def _consume():
        return store.consume_pairing(record.pairing_code)

    results = await asyncio.gather(_consume(), _consume())
    success_count = sum(1 for pairing, _reason in results if pairing is not None)
    assert success_count == 1


@pytest.mark.asyncio
async def test_concurrent_qr_consume_allows_exactly_one_success() -> None:
    store = PairingStore()
    record = store.create_pairing(
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        pass_expires_at=int(time.time()) + 3600,
    )

    async def _consume():
        return store.consume_qr_access(record.pairing_code, record.qr_access_token)

    results = await asyncio.gather(_consume(), _consume())
    success_count = sum(1 for pairing, _reason in results if pairing is not None)
    used_count = sum(1 for _pairing, reason in results if reason == "used")
    assert success_count == 1
    assert used_count == 1

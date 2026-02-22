"""Additional edge-case coverage for security helpers."""

from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest

from custom_components.easy_control.network import is_remote_allowed, normalize_allowed_cidrs
from custom_components.easy_control.pairing import PairingStore
from custom_components.easy_control.proof import (
    ActionProof,
    ActionProofInvalidError,
    b64url_decode,
    b64url_encode,
    canonicalize_public_key,
    decode_action_proof_headers,
    parse_cnf_jkt,
)
from custom_components.easy_control.runtime_security import ActionNonceRecord, ActionNonceStore
from custom_components.easy_control.token import InvalidTokenError


def test_network_helpers_handle_invalid_inputs() -> None:
    assert normalize_allowed_cidrs(["  ", "10.0.0.0/8"]) == ["10.0.0.0/8"]

    with pytest.raises(ValueError):
        normalize_allowed_cidrs([])

    with pytest.raises(ValueError):
        normalize_allowed_cidrs(["10.0.0.0/8", 123])  # type: ignore[list-item]

    assert is_remote_allowed(None, ["10.0.0.0/8"]) is False
    assert is_remote_allowed("not-an-ip", ["10.0.0.0/8"]) is False
    assert is_remote_allowed("10.1.2.3", ["not-a-cidr", "10.0.0.0/8"]) is True


def test_pairing_store_approval_rejection_and_qr_edge_paths() -> None:
    store = PairingStore()

    assert store.approve_pairing("missing") == (None, None)
    assert store.reject_pairing("missing") == (None, None)
    assert store.consume_qr_access("missing", "x") == (None, None)
    assert store.validate_qr_access("missing", "x") is None

    record = store.create_pairing(
        entity_id="lock.front_door",
        allowed_action="door.open",
        pass_expires_at=int(time.time()) + 3600,
        require_admin_approval=True,
    )

    serialized = record.to_dict()
    assert serialized["pairing_code"] == record.pairing_code
    assert serialized["approval_status"] == "pending"

    approved, reason = store.approve_pairing(record.pairing_code)
    assert approved is not None
    assert reason is None

    approved_again, second_reason = store.approve_pairing(record.pairing_code)
    assert approved_again is not None
    assert second_reason == "already_approved"

    invalid_qr_record, invalid_qr_reason = store.consume_qr_access(record.pairing_code, "wrong")
    assert invalid_qr_record is None
    assert invalid_qr_reason == "invalid"

    first_qr_record, first_qr_reason = store.consume_qr_access(
        record.pairing_code, record.qr_access_token
    )
    assert first_qr_record is not None
    assert first_qr_reason is None
    assert store.validate_qr_access(record.pairing_code, record.qr_access_token) is None

    rejected, reject_reason = store.reject_pairing(record.pairing_code)
    assert rejected is not None
    assert reject_reason is None

    rejected_again, reject_again_reason = store.reject_pairing(record.pairing_code)
    assert rejected_again is not None
    assert reject_again_reason == "already_rejected"


def test_pairing_store_expired_paths_delete_and_clear() -> None:
    store = PairingStore()
    now_ts = int(time.time())
    record = store.create_pairing(
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        pass_expires_at=now_ts + 3600,
        require_admin_approval=True,
    )
    store._records[record.pairing_code] = replace(record, pairing_expires_at=now_ts - 1)  # noqa: SLF001

    assert store.approve_pairing(record.pairing_code) == (None, "expired")
    assert store.reject_pairing(record.pairing_code) == (None, None)

    second = store.create_pairing(
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        pass_expires_at=now_ts + 3600,
    )
    store._records[second.pairing_code] = replace(second, pairing_expires_at=now_ts - 1)  # noqa: SLF001
    assert store.consume_qr_access(second.pairing_code, second.qr_access_token) == (
        None,
        "expired",
    )

    third = store.create_pairing(
        entity_id="lock.back_door",
        allowed_action="door.open",
        pass_expires_at=now_ts + 3600,
    )
    assert store.delete_pairing(third.pairing_code) is True
    assert store.delete_pairing(third.pairing_code) is False

    extra_one = store.create_pairing(
        entity_id="lock.side_door",
        allowed_action="door.open",
        pass_expires_at=now_ts + 3600,
    )
    extra_two = store.create_pairing(
        entity_id="cover.garage_aux",
        allowed_action="garage.open",
        pass_expires_at=now_ts + 3600,
    )
    assert extra_one.pairing_code != extra_two.pairing_code
    assert store.clear() >= 2


def test_proof_helpers_reject_malformed_payloads() -> None:
    with pytest.raises(ActionProofInvalidError):
        b64url_decode("a$")

    with pytest.raises(ActionProofInvalidError):
        canonicalize_public_key("AQ")  # decodes to 1 byte, not 32

    proof_header_non_object = "WyJhIiwgImIiXQ"  # ["a", "b"]
    signature_header = "eA"  # b"x" -> wrong length for Ed25519 signature
    with pytest.raises(ActionProofInvalidError, match="JSON object"):
        decode_action_proof_headers(proof_header_non_object, signature_header)

    valid_proof_header = b64url_encode(
        json.dumps(
            {
                "nonce": "n",
                "ts": 1,
                "method": "POST",
                "path": "/x",
                "body_sha256": "a" * 64,
                "jti": "j",
                "device_id": "d",
            }
        ).encode("utf-8")
    )
    with pytest.raises(ActionProofInvalidError, match="64 bytes"):
        decode_action_proof_headers(valid_proof_header, signature_header)


@pytest.mark.parametrize(
    ("field", "value", "message_fragment"),
    [
        ("nonce", "", "nonce must be"),
        ("ts", "1", "ts must be"),
        ("method", "", "method must be"),
        ("path", "relative", "absolute request path"),
        ("body_sha256", "abc", "sha256 hex digest"),
        ("jti", "", "jti must be"),
        ("device_id", "", "device_id must be"),
    ],
)
def test_action_proof_from_dict_field_validation(
    field: str, value: object, message_fragment: str
) -> None:
    payload: dict[str, object] = {
        "nonce": "nonce-1",
        "ts": 1700000000,
        "method": "POST",
        "path": "/api/easy_control/action",
        "body_sha256": "a" * 64,
        "jti": "jti-1",
        "device_id": "device-1",
    }
    payload[field] = value
    with pytest.raises(ActionProofInvalidError, match=message_fragment):
        ActionProof.from_dict(payload)


def test_action_proof_from_dict_missing_fields() -> None:
    with pytest.raises(ActionProofInvalidError, match="Missing proof fields"):
        ActionProof.from_dict({"nonce": "n"})


def test_parse_cnf_jkt_validates_structure() -> None:
    assert parse_cnf_jkt({}) is None
    assert parse_cnf_jkt({"cnf": {"jkt": "thumbprint"}}) == "thumbprint"
    assert parse_cnf_jkt({"cnf": {"other": "x"}}) is None

    with pytest.raises(InvalidTokenError, match="cnf must be"):
        parse_cnf_jkt({"cnf": "bad"})
    with pytest.raises(InvalidTokenError, match="cnf.jkt must be"):
        parse_cnf_jkt({"cnf": {"jkt": ""}})


def test_action_nonce_store_unknown_and_expired_paths() -> None:
    store = ActionNonceStore()
    assert store.consume(nonce="missing", jti="jti-1") == (None, None)

    record = store.issue(jti="jti-1", ttl_seconds=30)
    store._records[record.nonce] = ActionNonceRecord(  # noqa: SLF001
        nonce=record.nonce,
        jti=record.jti,
        created_at=record.created_at,
        expires_at=record.created_at - 1,
        used_at=None,
    )
    assert store.consume(nonce=record.nonce, jti="jti-1") == (None, "expired")

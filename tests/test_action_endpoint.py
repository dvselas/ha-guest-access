"""Unit tests for action endpoint helper logic."""

from __future__ import annotations

from custom_components.easy_control.api import _proof_failure_response, _resolve_service_target
from custom_components.easy_control.proof import (
    ActionProofClockSkewError,
    ActionProofInvalidError,
    ActionProofMissingError,
    ActionProofNonceExpiredError,
    ActionProofReplayError,
)
from custom_components.easy_control.token import TokenRevokedError


class _FakeView:
    def json(self, payload, status_code=200):  # type: ignore[no-untyped-def]
        return {"payload": payload, "status_code": status_code}


def test_valid_unlock_and_open_cover_service_mapping() -> None:
    assert _resolve_service_target("door.open", "lock.front_door") == ("lock", "unlock")
    assert _resolve_service_target("garage.open", "cover.garage") == ("cover", "open_cover")


def test_invalid_scope_mapping_rejected() -> None:
    assert _resolve_service_target("door.open", "cover.garage") is None
    assert _resolve_service_target("garage.open", "lock.front_door") is None


def test_proof_failure_response_maps_explicit_error_codes() -> None:
    view = _FakeView()
    cases = [
        (ActionProofMissingError("missing"), "action_proof_required"),
        (ActionProofReplayError("replay"), "action_proof_replay"),
        (ActionProofNonceExpiredError("expired"), "action_nonce_expired"),
        (ActionProofClockSkewError("skew"), "action_proof_clock_skew"),
        (TokenRevokedError("revoked"), "token_revoked"),
        (ActionProofInvalidError("invalid"), "action_proof_invalid"),
    ]

    for err, expected_error in cases:
        response = _proof_failure_response(view, err)
        assert response["payload"]["error"] == expected_error

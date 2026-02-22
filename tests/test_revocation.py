"""Unit tests for revocation-related storage normalization."""

from __future__ import annotations

import time

from custom_components.easy_control.storage import _normalize_state


def test_normalize_state_preserves_revoked_jtis_and_issued_tokens() -> None:
    now = int(time.time())
    state, changed = _normalize_state(
        {
            "signing_key": "legacy-key",
            "token_version": 2,
            "token_uses": {"jti-1": 1},
            "revoked_token_jtis": {"jti-1": now},
            "issued_tokens": {
                "jti-1": {"guest_id": "guest-1", "exp": now + 3600},
            },
        }
    )

    assert changed is True  # legacy state is upgraded to key ring fields
    assert state["revoked_token_jtis"]["jti-1"] == now
    assert state["issued_tokens"]["jti-1"]["guest_id"] == "guest-1"
    assert "signing_keys" in state
    assert "active_kid" in state


def test_normalize_state_prunes_expired_issued_tokens_and_related_state() -> None:
    now = int(time.time())
    state, changed = _normalize_state(
        {
            "signing_key": "legacy-key",
            "token_version": 1,
            "token_uses": {"jti-expired": 2, "jti-valid": 1},
            "revoked_token_jtis": {"jti-expired": now - 10, "jti-valid": now - 5},
            "issued_tokens": {
                "jti-expired": {"guest_id": "guest-old", "exp": now - 1},
                "jti-valid": {"guest_id": "guest-new", "exp": now + 3600},
            },
        }
    )

    assert changed is True
    assert "jti-expired" not in state["issued_tokens"]
    assert "jti-expired" not in state["token_uses"]
    assert "jti-expired" not in state["revoked_token_jtis"]
    assert "jti-valid" in state["issued_tokens"]

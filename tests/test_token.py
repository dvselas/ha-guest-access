"""Unit tests for token security model."""

from __future__ import annotations

import pytest

from custom_components.easy_control.token import (
    GuestTokenManager,
    InvalidTokenError,
    TokenAudienceMismatchError,
    TokenExpiredError,
    TokenVersionMismatchError,
)


def _issue_token(
    *,
    now_ts: int,
    audience: str = "localkey_ios",
    token_version: int = 1,
) -> str:
    manager = GuestTokenManager("test-signing-key")
    token, _payload = manager.create_guest_token(
        guest_id="guest-1",
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        expires_at=now_ts + 600,
        token_version=token_version,
        max_uses=10,
        now_timestamp=now_ts,
    )
    if audience == "localkey_ios":
        return token

    # Tamper audience by re-signing with same key through payload decode/re-encode path.
    # For audience mismatch test we generate a second token manager and custom payload.
    bad_manager = GuestTokenManager("test-signing-key")
    bad_token, _ = bad_manager.create_guest_token(
        guest_id="guest-1",
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        expires_at=now_ts + 600,
        token_version=token_version,
        max_uses=10,
        now_timestamp=now_ts,
    )
    header, payload, sig = bad_token.split(".")
    # Replace payload aud by reconstructing JSON would duplicate implementation logic.
    # Keep this test deterministic by asserting verify with wrong expected audience instead.
    return f"{header}.{payload}.{sig}"


def test_valid_token_is_accepted(now_ts: int) -> None:
    manager = GuestTokenManager("test-signing-key")
    token, _ = manager.create_guest_token(
        guest_id="guest-1",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 600,
        token_version=2,
        max_uses=5,
        now_timestamp=now_ts,
    )

    payload = manager.verify_token(
        token,
        expected_token_version=2,
        now_timestamp=now_ts + 1,
    )
    assert payload.guest_id == "guest-1"
    assert payload.allowed_action == "door.open"
    assert payload.max_uses == 5


def test_expired_token_is_rejected(now_ts: int) -> None:
    manager = GuestTokenManager("test-signing-key")
    token, _ = manager.create_guest_token(
        guest_id="guest-1",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 10,
        token_version=1,
        now_timestamp=now_ts,
    )

    with pytest.raises(TokenExpiredError):
        manager.verify_token(token, now_timestamp=now_ts + 11)


def test_tampered_token_is_rejected(now_ts: int) -> None:
    manager = GuestTokenManager("test-signing-key")
    token, _ = manager.create_guest_token(
        guest_id="guest-1",
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    parts = token.split(".")
    tampered_payload = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    tampered_token = ".".join([parts[0], tampered_payload, parts[2]])

    with pytest.raises(InvalidTokenError):
        manager.verify_token(tampered_token, now_timestamp=now_ts + 1)


def test_wrong_audience_is_rejected(now_ts: int) -> None:
    manager = GuestTokenManager("test-signing-key")
    token = _issue_token(now_ts=now_ts)

    with pytest.raises(TokenAudienceMismatchError):
        manager.verify_token(
            token,
            expected_audience="some_other_app",
            now_timestamp=now_ts + 1,
        )


def test_token_version_mismatch_is_rejected(now_ts: int) -> None:
    manager = GuestTokenManager("test-signing-key")
    token = _issue_token(now_ts=now_ts, token_version=1)

    with pytest.raises(TokenVersionMismatchError):
        manager.verify_token(
            token,
            expected_token_version=2,
            now_timestamp=now_ts + 1,
        )

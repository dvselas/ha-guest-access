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


def test_token_can_include_device_binding_claim(now_ts: int) -> None:
    manager = GuestTokenManager("test-signing-key")
    token, _ = manager.create_guest_token(
        guest_id="guest-1",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 60,
        token_version=1,
        device_id="device-123",
        cnf_jkt="thumbprint-abc",
        now_timestamp=now_ts,
    )

    payload = manager.verify_token(token, now_timestamp=now_ts + 1)
    assert payload.device_id == "device-123"
    assert payload.cnf_jkt == "thumbprint-abc"


def test_token_manager_verifies_old_tokens_after_key_rotation(now_ts: int) -> None:
    rotating_manager = GuestTokenManager(
        signing_keys={"v1": "key-one", "v2": "key-two"},
        active_kid="v2",
    )
    old_manager = GuestTokenManager(signing_keys={"v1": "key-one"}, active_kid="v1")

    old_token, _ = old_manager.create_guest_token(
        guest_id="guest-old",
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        expires_at=now_ts + 120,
        token_version=1,
        now_timestamp=now_ts,
    )
    new_token, _ = rotating_manager.create_guest_token(
        guest_id="guest-new",
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        expires_at=now_ts + 120,
        token_version=2,
        now_timestamp=now_ts,
    )

    old_payload = rotating_manager.verify_token(old_token, now_timestamp=now_ts + 1)
    new_payload = rotating_manager.verify_token(new_token, now_timestamp=now_ts + 1)
    assert old_payload.guest_id == "guest-old"
    assert new_payload.guest_id == "guest-new"


def test_unknown_kid_is_rejected(now_ts: int) -> None:
    manager = GuestTokenManager("test-signing-key")
    token, _ = manager.create_guest_token(
        guest_id="guest-1",
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        expires_at=now_ts + 600,
        token_version=1,
        now_timestamp=now_ts,
    )
    header, payload, sig = token.split(".")
    mutated_header = "eyJhbGciOiJIUzI1NiIsImtpZCI6InY5OTkiLCJ0eXAiOiJKV1QifQ"
    tampered = ".".join([mutated_header, payload, sig])

    with pytest.raises(InvalidTokenError):
        manager.verify_token(tampered, now_timestamp=now_ts + 1)


# --- Multi-use (max_uses=0 unlimited) token tests ---


def test_unlimited_token_creation_and_verification(now_ts: int) -> None:
    """max_uses=0 tokens can be created and verified without error."""
    manager = GuestTokenManager("test-signing-key")
    token, payload = manager.create_guest_token(
        guest_id="guest-unlimited",
        entity_id="cover.garage_main",
        allowed_action="garage.open",
        expires_at=now_ts + 3600,
        token_version=1,
        max_uses=0,
        now_timestamp=now_ts,
    )
    assert payload.max_uses == 0

    verified = manager.verify_token(token, now_timestamp=now_ts + 1)
    assert verified.max_uses == 0
    assert verified.guest_id == "guest-unlimited"


def test_unlimited_token_payload_roundtrip(now_ts: int) -> None:
    """max_uses=0 survives to_dict/from_dict serialization."""
    from custom_components.easy_control.token import GuestTokenPayload

    manager = GuestTokenManager("test-signing-key")
    _token, payload = manager.create_guest_token(
        guest_id="guest-rt",
        entity_id="lock.front_door",
        allowed_action="door.open",
        expires_at=now_ts + 600,
        token_version=1,
        max_uses=0,
        now_timestamp=now_ts,
    )
    data = payload.to_dict()
    assert data["max_uses"] == 0

    restored = GuestTokenPayload.from_dict(data)
    assert restored.max_uses == 0


def test_negative_max_uses_rejected_on_creation(now_ts: int) -> None:
    """Negative max_uses values must be rejected."""
    manager = GuestTokenManager("test-signing-key")
    with pytest.raises(ValueError, match="non-negative"):
        manager.create_guest_token(
            guest_id="guest-bad",
            entity_id="lock.front_door",
            allowed_action="door.open",
            expires_at=now_ts + 600,
            token_version=1,
            max_uses=-1,
            now_timestamp=now_ts,
        )


def test_negative_max_uses_rejected_on_deserialization() -> None:
    """Negative max_uses in token payload is rejected during from_dict."""
    from custom_components.easy_control.token import GuestTokenPayload

    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "guest-bad",
        "entity_id": "lock.front_door",
        "allowed_action": "door.open",
        "iat": 1000,
        "nbf": 1000,
        "exp": 2000,
        "max_uses": -5,
        "token_version": 1,
    }
    with pytest.raises(InvalidTokenError, match="non-negative"):
        GuestTokenPayload.from_dict(data)


@pytest.mark.parametrize(
    "field,bad_value,expected_match",
    [
        ("iss", "", "iss must be"),
        ("iss", 42, "iss must be"),
        ("aud", "", "aud must be"),
        ("jti", "", "jti must be"),
        ("guest_id", "", "guest_id must be"),
        ("entity_id", None, "entity_id must be"),
        ("allowed_action", "", "allowed_action must be"),
        ("iat", "not-int", "iat must be"),
        ("nbf", "not-int", "nbf must be"),
        ("exp", "not-int", "exp must be"),
        ("max_uses", "not-int", "non-negative"),
        ("token_version", 0, "token_version must be"),
        ("token_version", "bad", "token_version must be"),
    ],
)
def test_from_dict_rejects_invalid_claims(
    field: str, bad_value: object, expected_match: str
) -> None:
    """Each claim in GuestTokenPayload.from_dict() validates properly."""
    from custom_components.easy_control.token import GuestTokenPayload

    valid_data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "guest-1",
        "entity_id": "lock.front_door",
        "allowed_action": "door.open",
        "iat": 1000,
        "nbf": 1000,
        "exp": 2000,
        "max_uses": 5,
        "token_version": 1,
    }
    invalid_data = {**valid_data, field: bad_value}
    with pytest.raises(InvalidTokenError, match=expected_match):
        GuestTokenPayload.from_dict(invalid_data)


def test_from_dict_rejects_nbf_before_iat() -> None:
    """nbf < iat is rejected."""
    from custom_components.easy_control.token import GuestTokenPayload

    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "guest-1",
        "entity_id": "lock.front_door",
        "allowed_action": "door.open",
        "iat": 2000,
        "nbf": 1000,
        "exp": 3000,
        "max_uses": 5,
        "token_version": 1,
    }
    with pytest.raises(InvalidTokenError, match="nbf must be greater"):
        GuestTokenPayload.from_dict(data)


def test_from_dict_rejects_exp_not_after_nbf() -> None:
    """exp <= nbf is rejected."""
    from custom_components.easy_control.token import GuestTokenPayload

    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "guest-1",
        "entity_id": "lock.front_door",
        "allowed_action": "door.open",
        "iat": 1000,
        "nbf": 1000,
        "exp": 1000,
        "max_uses": 5,
        "token_version": 1,
    }
    with pytest.raises(InvalidTokenError, match="exp must be greater"):
        GuestTokenPayload.from_dict(data)


def test_from_dict_rejects_invalid_device_id() -> None:
    """device_id, if present, must be a non-empty string."""
    from custom_components.easy_control.token import GuestTokenPayload

    data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "guest-1",
        "entity_id": "lock.front_door",
        "allowed_action": "door.open",
        "iat": 1000,
        "nbf": 1000,
        "exp": 2000,
        "max_uses": 5,
        "token_version": 1,
        "device_id": "",
    }
    with pytest.raises(InvalidTokenError, match="device_id must be"):
        GuestTokenPayload.from_dict(data)


def test_from_dict_rejects_invalid_cnf_structure() -> None:
    """cnf must be a dict with a non-empty jkt string."""
    from custom_components.easy_control.token import GuestTokenPayload

    base_data = {
        "iss": "easy_control",
        "aud": "localkey_ios",
        "jti": "abc123",
        "guest_id": "guest-1",
        "entity_id": "lock.front_door",
        "allowed_action": "door.open",
        "iat": 1000,
        "nbf": 1000,
        "exp": 2000,
        "max_uses": 5,
        "token_version": 1,
    }
    with pytest.raises(InvalidTokenError, match="cnf must be"):
        GuestTokenPayload.from_dict({**base_data, "cnf": "not-a-dict"})

    with pytest.raises(InvalidTokenError, match="cnf.jkt must be"):
        GuestTokenPayload.from_dict({**base_data, "cnf": {"jkt": ""}})

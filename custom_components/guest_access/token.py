"""Guest token model and signing helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


class GuestTokenError(Exception):
    """Base exception for guest token errors."""


class InvalidTokenError(GuestTokenError):
    """Raised when a token is malformed or the signature is invalid."""


class TokenExpiredError(GuestTokenError):
    """Raised when a token has passed its expiration time."""


def _b64url_encode(raw: bytes) -> str:
    """Base64 URL-safe encode without trailing padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    """Decode Base64 URL-safe string with optional missing padding."""
    padded = encoded + ("=" * (-len(encoded) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as err:
        raise InvalidTokenError("Token contains invalid base64 data") from err


def _json_dump(data: dict[str, Any]) -> bytes:
    """Serialize JSON in a deterministic compact format."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _decode_json_segment(segment: str) -> dict[str, Any]:
    """Decode token segment into a JSON object."""
    try:
        value = json.loads(_b64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise InvalidTokenError("Token contains invalid JSON") from err

    if not isinstance(value, dict):
        raise InvalidTokenError("Token payload must be a JSON object")

    return value


@dataclass(frozen=True)
class GuestTokenPayload:
    """Typed payload for guest access tokens."""

    guest_id: str
    allowed_actions: list[str]
    entity_id: str
    exp: int
    device_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert payload to serializable dictionary."""
        payload: dict[str, Any] = {
            "guest_id": self.guest_id,
            "allowed_actions": self.allowed_actions,
            "entity_id": self.entity_id,
            "exp": self.exp,
        }
        if self.device_id:
            payload["device_id"] = self.device_id
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuestTokenPayload:
        """Validate and construct payload from dictionary."""
        guest_id = data.get("guest_id")
        entity_id = data.get("entity_id")
        exp = data.get("exp")
        allowed_actions = data.get("allowed_actions")
        device_id = data.get("device_id")

        if not isinstance(guest_id, str) or not guest_id:
            raise InvalidTokenError("guest_id must be a non-empty string")
        if not isinstance(entity_id, str) or not entity_id:
            raise InvalidTokenError("entity_id must be a non-empty string")
        if not isinstance(exp, int):
            raise InvalidTokenError("exp must be an integer Unix timestamp")

        if not isinstance(allowed_actions, list) or not allowed_actions:
            raise InvalidTokenError("allowed_actions must be a non-empty list")
        if any(not isinstance(action, str) or not action for action in allowed_actions):
            raise InvalidTokenError("allowed_actions must contain non-empty strings")

        if device_id is not None and (not isinstance(device_id, str) or not device_id):
            raise InvalidTokenError("device_id must be a non-empty string when set")

        return cls(
            guest_id=guest_id,
            allowed_actions=allowed_actions,
            entity_id=entity_id,
            exp=exp,
            device_id=device_id,
        )


class GuestTokenManager:
    """Issue and verify signed guest access tokens."""

    def __init__(self, signing_key: str) -> None:
        """Create a token manager bound to a signing key."""
        if not isinstance(signing_key, str) or not signing_key:
            raise ValueError("signing_key must be a non-empty string")
        self._key = signing_key.encode("utf-8")

    def create_token(self, payload: GuestTokenPayload) -> str:
        """Create a signed token from payload data."""
        header_segment = _b64url_encode(_json_dump({"alg": "HS256", "typ": "JWT"}))
        payload_segment = _b64url_encode(_json_dump(payload.to_dict()))
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature = hmac.new(self._key, signing_input, hashlib.sha256).digest()
        signature_segment = _b64url_encode(signature)
        return f"{header_segment}.{payload_segment}.{signature_segment}"

    def create_guest_token(
        self,
        guest_id: str,
        allowed_actions: list[str],
        entity_id: str,
        expires_in_seconds: int,
        device_id: str | None = None,
    ) -> str:
        """Create a token with expiration based on current time."""
        if expires_in_seconds <= 0:
            raise ValueError("expires_in_seconds must be greater than 0")

        payload = GuestTokenPayload(
            guest_id=guest_id,
            allowed_actions=allowed_actions,
            entity_id=entity_id,
            exp=int(time.time()) + expires_in_seconds,
            device_id=device_id,
        )
        return self.create_token(payload)

    def verify_token(self, token: str, now_timestamp: int | None = None) -> GuestTokenPayload:
        """Verify signature and expiration, then return validated payload."""
        if not isinstance(token, str) or not token:
            raise InvalidTokenError("Token must be a non-empty string")

        segments = token.split(".")
        if len(segments) != 3:
            raise InvalidTokenError("Token must contain exactly three segments")

        header_segment, payload_segment, signature_segment = segments
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        expected_signature = hmac.new(self._key, signing_input, hashlib.sha256).digest()
        actual_signature = _b64url_decode(signature_segment)

        if not hmac.compare_digest(actual_signature, expected_signature):
            raise InvalidTokenError("Token signature is invalid")

        header = _decode_json_segment(header_segment)
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise InvalidTokenError("Unsupported token header")

        payload = GuestTokenPayload.from_dict(_decode_json_segment(payload_segment))

        current_timestamp = int(time.time()) if now_timestamp is None else now_timestamp
        if payload.exp <= current_timestamp:
            raise TokenExpiredError("Token has expired")

        return payload

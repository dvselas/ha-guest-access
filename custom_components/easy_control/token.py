"""Guest token model and signing helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .const import (
    DEFAULT_TOKEN_MAX_USES,
    TOKEN_AUDIENCE,
    TOKEN_ISSUER,
)


class GuestTokenError(Exception):
    """Base exception for guest token errors."""


class InvalidTokenError(GuestTokenError):
    """Raised when token is malformed or signature is invalid."""


class TokenExpiredError(GuestTokenError):
    """Raised when token has passed expiration time."""


class TokenNotYetValidError(GuestTokenError):
    """Raised when token nbf is in the future."""


class TokenVersionMismatchError(GuestTokenError):
    """Raised when token version is older/newer than expected."""


class TokenAudienceMismatchError(GuestTokenError):
    """Raised when token audience does not match expected client."""


class TokenIssuerMismatchError(GuestTokenError):
    """Raised when token issuer does not match integration."""


class TokenMaxUsesExceededError(GuestTokenError):
    """Raised when token has reached its max_uses replay limit."""


class TokenRevokedError(GuestTokenError):
    """Raised when token jti has been revoked explicitly."""


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
    """Serialize JSON in deterministic compact format."""
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

    iss: str
    aud: str
    jti: str
    guest_id: str
    entity_id: str
    allowed_action: str
    iat: int
    nbf: int
    exp: int
    max_uses: int
    token_version: int
    device_id: str | None = None
    cnf_jkt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert payload to serializable dictionary."""
        payload: dict[str, Any] = {
            "iss": self.iss,
            "aud": self.aud,
            "jti": self.jti,
            "guest_id": self.guest_id,
            "entity_id": self.entity_id,
            "allowed_action": self.allowed_action,
            "iat": self.iat,
            "nbf": self.nbf,
            "exp": self.exp,
            "max_uses": self.max_uses,
            "token_version": self.token_version,
        }
        if self.device_id:
            payload["device_id"] = self.device_id
        if self.cnf_jkt:
            payload["cnf"] = {"jkt": self.cnf_jkt}
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuestTokenPayload:
        """Validate and construct payload from dictionary."""
        iss = data.get("iss")
        aud = data.get("aud")
        jti = data.get("jti")
        guest_id = data.get("guest_id")
        entity_id = data.get("entity_id")
        allowed_action = data.get("allowed_action")
        iat = data.get("iat")
        nbf = data.get("nbf")
        exp = data.get("exp")
        max_uses = data.get("max_uses")
        token_version = data.get("token_version")
        device_id = data.get("device_id")
        cnf = data.get("cnf")
        cnf_jkt: str | None = None

        if not isinstance(iss, str) or not iss:
            raise InvalidTokenError("iss must be a non-empty string")
        if not isinstance(aud, str) or not aud:
            raise InvalidTokenError("aud must be a non-empty string")
        if not isinstance(jti, str) or not jti:
            raise InvalidTokenError("jti must be a non-empty string")
        if not isinstance(guest_id, str) or not guest_id:
            raise InvalidTokenError("guest_id must be a non-empty string")
        if not isinstance(entity_id, str) or not entity_id:
            raise InvalidTokenError("entity_id must be a non-empty string")
        if not isinstance(allowed_action, str) or not allowed_action:
            raise InvalidTokenError("allowed_action must be a non-empty string")
        if not isinstance(iat, int):
            raise InvalidTokenError("iat must be an integer Unix timestamp")
        if not isinstance(nbf, int):
            raise InvalidTokenError("nbf must be an integer Unix timestamp")
        if not isinstance(exp, int):
            raise InvalidTokenError("exp must be an integer Unix timestamp")
        if not isinstance(max_uses, int) or max_uses < 0:
            raise InvalidTokenError("max_uses must be a non-negative integer")
        if not isinstance(token_version, int) or token_version < 1:
            raise InvalidTokenError("token_version must be a positive integer")
        if nbf < iat:
            raise InvalidTokenError("nbf must be greater than or equal to iat")
        if exp <= nbf:
            raise InvalidTokenError("exp must be greater than nbf")
        if device_id is not None and (not isinstance(device_id, str) or not device_id):
            raise InvalidTokenError("device_id must be a non-empty string when set")
        if cnf is not None:
            if not isinstance(cnf, dict):
                raise InvalidTokenError("cnf must be a JSON object when set")
            cnf_jkt = cnf.get("jkt")
            if cnf_jkt is None or not isinstance(cnf_jkt, str) or not cnf_jkt:
                raise InvalidTokenError("cnf.jkt must be a non-empty string when set")

        return cls(
            iss=iss,
            aud=aud,
            jti=jti,
            guest_id=guest_id,
            entity_id=entity_id,
            allowed_action=allowed_action,
            iat=iat,
            nbf=nbf,
            exp=exp,
            max_uses=max_uses,
            token_version=token_version,
            device_id=device_id,
            cnf_jkt=cnf_jkt,
        )


class GuestTokenManager:
    """Issue and verify signed guest access tokens."""

    def __init__(
        self,
        signing_key: str | None = None,
        *,
        signing_keys: dict[str, str] | None = None,
        active_kid: str | None = None,
    ) -> None:
        """Create token manager bound to a signing key or key ring."""
        if signing_keys is not None:
            normalized_keys = {
                kid: key
                for kid, key in signing_keys.items()
                if isinstance(kid, str)
                and kid
                and isinstance(key, str)
                and key
            }
            if not normalized_keys:
                raise ValueError("signing_keys must contain at least one non-empty key")
            chosen_kid = active_kid or next(iter(normalized_keys))
            if chosen_kid not in normalized_keys:
                raise ValueError("active_kid must exist in signing_keys")
            self._keys = {kid: value.encode("utf-8") for kid, value in normalized_keys.items()}
            self._active_kid = chosen_kid
            return

        if not isinstance(signing_key, str) or not signing_key:
            raise ValueError("signing_key must be a non-empty string")
        self._keys = {"v1": signing_key.encode("utf-8")}
        self._active_kid = "v1"

    def create_token(self, payload: GuestTokenPayload, kid: str) -> str:
        """Create signed JWT-like token from payload."""
        key = self._keys.get(kid)
        if key is None:
            raise ValueError(f"Unknown signing kid '{kid}'")
        header_segment = _b64url_encode(
            _json_dump({"alg": "HS256", "typ": "JWT", "kid": kid})
        )
        payload_segment = _b64url_encode(_json_dump(payload.to_dict()))
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature = hmac.new(key, signing_input, hashlib.sha256).digest()
        signature_segment = _b64url_encode(signature)
        return f"{header_segment}.{payload_segment}.{signature_segment}"

    def create_guest_token(
        self,
        *,
        guest_id: str,
        entity_id: str,
        allowed_action: str,
        expires_at: int,
        token_version: int,
        max_uses: int = DEFAULT_TOKEN_MAX_USES,
        device_id: str | None = None,
        cnf_jkt: str | None = None,
        now_timestamp: int | None = None,
    ) -> tuple[str, GuestTokenPayload]:
        """Create token with full hardened payload."""
        now = int(time.time()) if now_timestamp is None else now_timestamp
        if expires_at <= now:
            raise ValueError("expires_at must be in the future")
        if max_uses < 0:
            raise ValueError("max_uses must be non-negative (0 = unlimited)")
        if token_version < 1:
            raise ValueError("token_version must be greater than 0")

        payload = GuestTokenPayload(
            iss=TOKEN_ISSUER,
            aud=TOKEN_AUDIENCE,
            jti=uuid.uuid4().hex,
            guest_id=guest_id,
            entity_id=entity_id,
            allowed_action=allowed_action,
            iat=now,
            nbf=now,
            exp=expires_at,
            max_uses=max_uses,
            token_version=token_version,
            device_id=device_id,
            cnf_jkt=cnf_jkt,
        )
        token = self.create_token(payload=payload, kid=self._active_kid)
        return token, payload

    def verify_token(
        self,
        token: str,
        *,
        expected_issuer: str = TOKEN_ISSUER,
        expected_audience: str = TOKEN_AUDIENCE,
        expected_token_version: int | None = None,
        now_timestamp: int | None = None,
    ) -> GuestTokenPayload:
        """Verify signature and standard claims."""
        if not isinstance(token, str) or not token:
            raise InvalidTokenError("Token must be a non-empty string")

        segments = token.split(".")
        if len(segments) != 3:
            raise InvalidTokenError("Token must contain exactly three segments")

        header_segment, payload_segment, signature_segment = segments
        header = _decode_json_segment(header_segment)
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise InvalidTokenError("Unsupported token header")
        if "kid" not in header or not isinstance(header["kid"], str) or not header["kid"]:
            raise InvalidTokenError("Token header is missing kid")
        kid = header["kid"]
        signing_key = self._keys.get(kid)
        if signing_key is None:
            raise InvalidTokenError("Token kid is unknown")

        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        expected_signature = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
        actual_signature = _b64url_decode(signature_segment)
        if not hmac.compare_digest(actual_signature, expected_signature):
            raise InvalidTokenError("Token signature is invalid")

        payload = GuestTokenPayload.from_dict(_decode_json_segment(payload_segment))
        current_timestamp = int(time.time()) if now_timestamp is None else now_timestamp

        if payload.iss != expected_issuer:
            raise TokenIssuerMismatchError("Token issuer is invalid")
        if payload.aud != expected_audience:
            raise TokenAudienceMismatchError("Token audience is invalid")
        if payload.nbf > current_timestamp:
            raise TokenNotYetValidError("Token is not valid yet")
        if payload.exp <= current_timestamp:
            raise TokenExpiredError("Token has expired")
        if expected_token_version is not None and payload.token_version != expected_token_version:
            raise TokenVersionMismatchError("Token version has been revoked")

        return payload

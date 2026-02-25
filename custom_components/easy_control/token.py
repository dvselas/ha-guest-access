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
    """Typed payload for guest access tokens.

    ``entities`` is a tuple of dicts, each with ``entity_id`` and
    ``allowed_actions`` (list of action strings).  Backward-compat
    properties ``entity_id`` and ``allowed_action`` return the first
    entry's values.
    """

    iss: str
    aud: str
    jti: str
    guest_id: str
    entities: tuple[dict[str, Any], ...]
    iat: int
    nbf: int
    exp: int
    max_uses: int
    token_version: int
    device_id: str | None = None
    cnf_jkt: str | None = None

    # -- backward-compat properties (first entity) --------------------------

    @property
    def entity_id(self) -> str:
        """Return entity_id of the first entity grant."""
        return self.entities[0]["entity_id"]

    @property
    def allowed_action(self) -> str:
        """Return first allowed_action of the first entity grant."""
        actions = self.entities[0].get("allowed_actions", [])
        if actions:
            return actions[0]
        # Legacy fallback
        return self.entities[0].get("allowed_action", "")

    # -- helpers -------------------------------------------------------------

    def entity_ids(self) -> list[str]:
        """Return all entity IDs in this token."""
        return [e["entity_id"] for e in self.entities]

    def allowed_actions_for(self, entity_id: str) -> list[str]:
        """Return list of allowed actions for *entity_id*."""
        for grant in self.entities:
            if grant["entity_id"] == entity_id:
                actions = grant.get("allowed_actions")
                if isinstance(actions, list):
                    return actions
                # Legacy single-action fallback
                act = grant.get("allowed_action", "")
                return [act] if act else []
        return []

    def allowed_action_for(self, entity_id: str) -> str | None:
        """Return the first allowed action for *entity_id*, or ``None``."""
        actions = self.allowed_actions_for(entity_id)
        return actions[0] if actions else None

    def to_dict(self) -> dict[str, Any]:
        """Convert payload to serializable dictionary."""
        # Normalize entities to always include allowed_actions
        serialized_entities = []
        for grant in self.entities:
            entry: dict[str, Any] = {"entity_id": grant["entity_id"]}
            actions = grant.get("allowed_actions")
            if isinstance(actions, list):
                entry["allowed_actions"] = actions
                # Backward-compat: singular field = first action
                entry["allowed_action"] = actions[0] if actions else ""
            else:
                # Legacy grant
                act = grant.get("allowed_action", "")
                entry["allowed_actions"] = [act] if act else []
                entry["allowed_action"] = act
            serialized_entities.append(entry)

        payload: dict[str, Any] = {
            "iss": self.iss,
            "aud": self.aud,
            "jti": self.jti,
            "guest_id": self.guest_id,
            "entities": serialized_entities,
            # Backward-compat singular fields (first entity):
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
        """Validate and construct payload from dictionary.

        Supports multi-entity with ``allowed_actions`` (list), legacy
        multi-entity with ``allowed_action`` (string), and legacy
        single-entity (``entity_id`` + ``allowed_action``) tokens.
        """
        iss = data.get("iss")
        aud = data.get("aud")
        jti = data.get("jti")
        guest_id = data.get("guest_id")
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

        # --- entities: prefer new array, fall back to singular fields -------
        raw_entities = data.get("entities")
        if raw_entities is not None:
            if not isinstance(raw_entities, list) or not raw_entities:
                raise InvalidTokenError("entities must be a non-empty list")
            parsed: list[dict[str, Any]] = []
            for idx, entry in enumerate(raw_entities):
                if not isinstance(entry, dict):
                    raise InvalidTokenError(f"entities[{idx}] must be a dict")
                eid = entry.get("entity_id")
                if not isinstance(eid, str) or not eid:
                    raise InvalidTokenError(
                        f"entities[{idx}].entity_id must be a non-empty string"
                    )
                # Prefer allowed_actions (list), fall back to allowed_action (str)
                raw_actions = entry.get("allowed_actions")
                if isinstance(raw_actions, list) and raw_actions:
                    for aidx, a in enumerate(raw_actions):
                        if not isinstance(a, str) or not a:
                            raise InvalidTokenError(
                                f"entities[{idx}].allowed_actions[{aidx}] "
                                "must be a non-empty string"
                            )
                    parsed.append({"entity_id": eid, "allowed_actions": raw_actions})
                else:
                    eact = entry.get("allowed_action")
                    if not isinstance(eact, str) or not eact:
                        raise InvalidTokenError(
                            f"entities[{idx}].allowed_action must be a "
                            "non-empty string"
                        )
                    parsed.append({"entity_id": eid, "allowed_actions": [eact]})
            entities = tuple(parsed)
        else:
            # Legacy single-entity token
            entity_id = data.get("entity_id")
            allowed_action = data.get("allowed_action")
            if not isinstance(entity_id, str) or not entity_id:
                raise InvalidTokenError("entity_id must be a non-empty string")
            if not isinstance(allowed_action, str) or not allowed_action:
                raise InvalidTokenError("allowed_action must be a non-empty string")
            entities = (
                {"entity_id": entity_id, "allowed_actions": [allowed_action]},
            )

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
            entities=entities,
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
        entities: list[dict[str, Any]] | None = None,
        expires_at: int,
        token_version: int,
        max_uses: int = DEFAULT_TOKEN_MAX_USES,
        device_id: str | None = None,
        cnf_jkt: str | None = None,
        now_timestamp: int | None = None,
        # Legacy single-entity convenience (used when entities is empty):
        entity_id: str | None = None,
        allowed_action: str | None = None,
    ) -> tuple[str, GuestTokenPayload]:
        """Create token with full hardened payload.

        Pass ``entities`` as a list of dicts with ``entity_id`` and either
        ``allowed_actions`` (list) or ``allowed_action`` (string, wrapped to
        list).  For backward compatibility, ``entity_id`` + ``allowed_action``
        can be provided instead (converted to a single-item entities list).
        """
        now = int(time.time()) if now_timestamp is None else now_timestamp
        if expires_at <= now:
            raise ValueError("expires_at must be in the future")
        if max_uses < 0:
            raise ValueError("max_uses must be non-negative (0 = unlimited)")
        if token_version < 1:
            raise ValueError("token_version must be greater than 0")

        # Resolve entities from either new or legacy params
        resolved_entities: list[dict[str, Any]] = []
        if entities:
            for e in entities:
                eid = e["entity_id"]
                actions = e.get("allowed_actions")
                if isinstance(actions, list):
                    resolved_entities.append(
                        {"entity_id": eid, "allowed_actions": actions}
                    )
                else:
                    # Legacy: wrap singular allowed_action in list
                    act = e.get("allowed_action", "")
                    resolved_entities.append(
                        {"entity_id": eid, "allowed_actions": [act] if act else []}
                    )
        if not resolved_entities and entity_id and allowed_action:
            resolved_entities = [
                {"entity_id": entity_id, "allowed_actions": [allowed_action]}
            ]
        if not resolved_entities:
            raise ValueError("entities must contain at least one grant")

        payload = GuestTokenPayload(
            iss=TOKEN_ISSUER,
            aud=TOKEN_AUDIENCE,
            jti=uuid.uuid4().hex,
            guest_id=guest_id,
            entities=tuple(resolved_entities),
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

"""Device binding and action proof helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from .token import InvalidTokenError


class ActionProofError(Exception):
    """Base action proof validation error."""


class ActionProofMissingError(ActionProofError):
    """Raised when a proof is required but missing."""


class ActionProofInvalidError(ActionProofError):
    """Raised when a proof cannot be parsed or validated."""


class ActionProofReplayError(ActionProofError):
    """Raised when a nonce/proof has already been used."""


class ActionProofNonceExpiredError(ActionProofError):
    """Raised when nonce has expired."""


class ActionProofClockSkewError(ActionProofError):
    """Raised when proof timestamp is outside allowed skew."""


def b64url_encode(raw: bytes) -> str:
    """Base64 URL-safe encode without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Base64 URL-safe decode with auto padding."""
    try:
        padded = value + ("=" * (-len(value) % 4))
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as err:
        raise ActionProofInvalidError("Invalid base64url value") from err


def canonicalize_public_key(public_key_b64: str) -> tuple[bytes, str]:
    """Validate raw Ed25519 public key and return bytes + thumbprint."""
    raw = b64url_decode(public_key_b64)
    if len(raw) != 32:
        raise ActionProofInvalidError("Ed25519 public key must be 32 bytes")
    thumbprint = b64url_encode(hashlib.sha256(raw).digest())
    return raw, thumbprint


@dataclass(frozen=True)
class ActionProof:
    """Parsed action proof envelope."""

    nonce: str
    ts: int
    method: str
    path: str
    body_sha256: str
    jti: str
    device_id: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ActionProof:
        """Validate proof JSON payload."""
        required_fields = (
            "nonce",
            "ts",
            "method",
            "path",
            "body_sha256",
            "jti",
            "device_id",
        )
        missing = [field for field in required_fields if field not in payload]
        if missing:
            raise ActionProofInvalidError(
                f"Missing proof fields: {', '.join(sorted(missing))}"
            )
        nonce = payload["nonce"]
        ts = payload["ts"]
        method = payload["method"]
        path = payload["path"]
        body_sha256 = payload["body_sha256"]
        jti = payload["jti"]
        device_id = payload["device_id"]
        if not isinstance(nonce, str) or not nonce:
            raise ActionProofInvalidError("nonce must be a non-empty string")
        if not isinstance(ts, int):
            raise ActionProofInvalidError("ts must be an integer")
        if not isinstance(method, str) or not method:
            raise ActionProofInvalidError("method must be a non-empty string")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ActionProofInvalidError("path must be an absolute request path")
        if not isinstance(body_sha256, str) or len(body_sha256) != 64:
            raise ActionProofInvalidError("body_sha256 must be a sha256 hex digest")
        if not isinstance(jti, str) or not jti:
            raise ActionProofInvalidError("jti must be a non-empty string")
        if not isinstance(device_id, str) or not device_id:
            raise ActionProofInvalidError("device_id must be a non-empty string")
        return cls(
            nonce=nonce,
            ts=ts,
            method=method,
            path=path,
            body_sha256=body_sha256.lower(),
            jti=jti,
            device_id=device_id,
        )


def decode_action_proof_headers(
    proof_header: str | None,
    signature_header: str | None,
) -> tuple[ActionProof, bytes]:
    """Decode proof JSON and signature from request headers."""
    if not proof_header or not signature_header:
        raise ActionProofMissingError("Missing action proof headers")
    try:
        raw_proof = b64url_decode(proof_header)
        proof_payload = json.loads(raw_proof.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ActionProofInvalidError("Invalid proof payload") from err
    if not isinstance(proof_payload, dict):
        raise ActionProofInvalidError("Proof payload must be a JSON object")
    proof = ActionProof.from_dict(proof_payload)
    signature = b64url_decode(signature_header)
    if len(signature) != 64:
        raise ActionProofInvalidError("Ed25519 signature must be 64 bytes")
    return proof, signature


def build_proof_signing_input(proof: ActionProof) -> bytes:
    """Build canonical bytes for signed proof verification."""
    canonical = (
        f"{proof.method.upper()}\n"
        f"{proof.path}\n"
        f"{proof.ts}\n"
        f"{proof.nonce}\n"
        f"{proof.jti}\n"
        f"{proof.device_id}\n"
        f"{proof.body_sha256}"
    )
    return canonical.encode("utf-8")


def hash_request_body(body_bytes: bytes) -> str:
    """Return sha256 hex digest for request body bytes."""
    return hashlib.sha256(body_bytes).hexdigest()


def verify_ed25519_signature(public_key_raw: bytes, message: bytes, signature: bytes) -> None:
    """Verify Ed25519 signature using cryptography."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ModuleNotFoundError as err:
        raise ActionProofInvalidError("cryptography dependency is missing") from err

    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
    except Exception as err:  # noqa: BLE001
        raise ActionProofInvalidError("Action proof signature is invalid") from err


def validate_proof_clock(proof: ActionProof, *, max_skew_seconds: int, now_timestamp: int | None = None) -> None:
    """Validate proof timestamp is within allowed skew."""
    now = int(time.time()) if now_timestamp is None else now_timestamp
    max_skew_seconds = max(int(max_skew_seconds), 0)
    if abs(proof.ts - now) > max_skew_seconds:
        raise ActionProofClockSkewError("Action proof timestamp is outside allowed skew")


def parse_cnf_jkt(payload_dict: dict[str, Any]) -> str | None:
    """Extract cnf.jkt from a JWT payload dictionary."""
    cnf = payload_dict.get("cnf")
    if cnf is None:
        return None
    if not isinstance(cnf, dict):
        raise InvalidTokenError("cnf must be a JSON object when present")
    jkt = cnf.get("jkt")
    if jkt is None:
        return None
    if not isinstance(jkt, str) or not jkt:
        raise InvalidTokenError("cnf.jkt must be a non-empty string")
    return jkt


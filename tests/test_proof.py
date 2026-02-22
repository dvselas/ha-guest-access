"""Unit tests for action proof helpers."""

from __future__ import annotations

import base64
import json

import pytest

from custom_components.easy_control.proof import (
    ActionProofClockSkewError,
    ActionProofInvalidError,
    ActionProofMissingError,
    build_proof_signing_input,
    canonicalize_public_key,
    decode_action_proof_headers,
    hash_request_body,
    validate_proof_clock,
    verify_ed25519_signature,
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_canonicalize_public_key_returns_thumbprint() -> None:
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    private_key = crypto.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    raw, jkt = canonicalize_public_key(_b64url(public_key))

    assert raw == public_key
    assert isinstance(jkt, str)
    assert jkt


def test_decode_action_proof_headers_and_signature_roundtrip() -> None:
    proof_dict = {
        "nonce": "nonce-1",
        "ts": 1700000000,
        "method": "POST",
        "path": "/api/easy_control/action",
        "body_sha256": "a" * 64,
        "jti": "jti-1",
        "device_id": "device-1",
    }
    signature = b"x" * 64

    proof_header = _b64url(json.dumps(proof_dict).encode("utf-8"))
    signature_header = _b64url(signature)

    proof, decoded_signature = decode_action_proof_headers(proof_header, signature_header)

    assert proof.nonce == "nonce-1"
    assert decoded_signature == signature


def test_missing_proof_headers_rejected() -> None:
    with pytest.raises(ActionProofMissingError):
        decode_action_proof_headers(None, None)


def test_hash_request_body_matches_sha256_hex() -> None:
    digest = hash_request_body(b'{"action":"door.open"}')
    assert len(digest) == 64
    assert digest == hash_request_body(b'{"action":"door.open"}')


def test_proof_clock_skew_rejected() -> None:
    proof_dict = {
        "nonce": "nonce-1",
        "ts": 1700000100,
        "method": "POST",
        "path": "/api/easy_control/action",
        "body_sha256": "a" * 64,
        "jti": "jti-1",
        "device_id": "device-1",
    }
    proof_header = _b64url(json.dumps(proof_dict).encode("utf-8"))
    signature_header = _b64url(b"x" * 64)
    proof, _ = decode_action_proof_headers(proof_header, signature_header)

    with pytest.raises(ActionProofClockSkewError):
        validate_proof_clock(proof, max_skew_seconds=10, now_timestamp=1700000000)


def test_ed25519_signature_verification_roundtrip() -> None:
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    private_key = crypto.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    message = build_proof_signing_input(
        decode_action_proof_headers(
            _b64url(
                json.dumps(
                    {
                        "nonce": "nonce-1",
                        "ts": 1700000000,
                        "method": "POST",
                        "path": "/api/easy_control/action",
                        "body_sha256": "a" * 64,
                        "jti": "jti-1",
                        "device_id": "device-1",
                    }
                ).encode("utf-8")
            ),
            _b64url(b"x" * 64),
        )[0]
    )
    signature = private_key.sign(message)

    verify_ed25519_signature(public_key, message, signature)

    with pytest.raises(ActionProofInvalidError):
        verify_ed25519_signature(public_key, message + b"!", signature)

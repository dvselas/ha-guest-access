"""Property-based robustness tests for token/proof parsing."""

from __future__ import annotations

from contextlib import suppress

import pytest

from custom_components.easy_control.proof import (
    ActionProofInvalidError,
    ActionProofMissingError,
    decode_action_proof_headers,
)
from custom_components.easy_control.token import GuestTokenError, GuestTokenManager

hypothesis = pytest.importorskip("hypothesis")
st = pytest.importorskip("hypothesis.strategies")

given = hypothesis.given
settings = hypothesis.settings


@given(st.text(min_size=0, max_size=256))
@settings(max_examples=100)
def test_random_token_strings_never_crash_verify(random_token: str) -> None:
    manager = GuestTokenManager("test-signing-key")
    with suppress(GuestTokenError):
        manager.verify_token(random_token, now_timestamp=1700000000)


@given(st.text(min_size=0, max_size=256), st.text(min_size=0, max_size=256))
@settings(max_examples=100)
def test_random_proof_headers_never_crash_decode(
    proof_header: str,
    signature_header: str,
) -> None:
    with suppress(ActionProofInvalidError, ActionProofMissingError):
        decode_action_proof_headers(proof_header, signature_header)

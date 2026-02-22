"""Unit tests for runtime security helpers (nonce + rate limiting)."""

from __future__ import annotations

from custom_components.easy_control.runtime_security import (
    ActionNonceStore,
    FixedWindowRateLimiter,
)


def test_action_nonce_is_single_use() -> None:
    store = ActionNonceStore()
    nonce = store.issue(jti="jti-1", ttl_seconds=30)

    first_record, first_reason = store.consume(nonce=nonce.nonce, jti="jti-1")
    second_record, second_reason = store.consume(nonce=nonce.nonce, jti="jti-1")

    assert first_record is not None
    assert first_reason is None
    assert second_record is None
    assert second_reason == "used"


def test_action_nonce_wrong_jti_rejected() -> None:
    store = ActionNonceStore()
    nonce = store.issue(jti="jti-1", ttl_seconds=30)

    consumed, reason = store.consume(nonce=nonce.nonce, jti="jti-2")

    assert consumed is None
    assert reason == "wrong_jti"


def test_rate_limiter_blocks_after_limit_with_retry_after() -> None:
    limiter = FixedWindowRateLimiter()

    first = limiter.check(
        bucket="pair",
        key="ip:1.2.3.4",
        limit=2,
        window_seconds=60,
        now_timestamp=100,
    )
    second = limiter.check(
        bucket="pair",
        key="ip:1.2.3.4",
        limit=2,
        window_seconds=60,
        now_timestamp=101,
    )
    third = limiter.check(
        bucket="pair",
        key="ip:1.2.3.4",
        limit=2,
        window_seconds=60,
        now_timestamp=102,
    )

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert third.retry_after > 0


def test_rate_limiter_resets_next_window() -> None:
    limiter = FixedWindowRateLimiter()
    blocked = limiter.check(
        bucket="qr",
        key="ip:1.2.3.4",
        limit=1,
        window_seconds=60,
        now_timestamp=10,
    )
    blocked_again = limiter.check(
        bucket="qr",
        key="ip:1.2.3.4",
        limit=1,
        window_seconds=60,
        now_timestamp=20,
    )
    allowed_next_window = limiter.check(
        bucket="qr",
        key="ip:1.2.3.4",
        limit=1,
        window_seconds=60,
        now_timestamp=61,
    )

    assert blocked.allowed is True
    assert blocked_again.allowed is False
    assert allowed_next_window.allowed is True

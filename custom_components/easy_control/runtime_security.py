"""Runtime-only security helpers (nonces, rate limiting)."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ActionNonceRecord:
    """Single-use action nonce metadata."""

    nonce: str
    jti: str
    expires_at: int
    created_at: int
    used_at: int | None = None


class ActionNonceStore:
    """In-memory single-use nonce store for action proof validation."""

    def __init__(self) -> None:
        self._records: dict[str, ActionNonceRecord] = {}

    def issue(self, *, jti: str, ttl_seconds: int) -> ActionNonceRecord:
        """Create a nonce bound to a token jti."""
        now = int(time.time())
        self._purge(now)
        nonce = secrets.token_urlsafe(24)
        record = ActionNonceRecord(
            nonce=nonce,
            jti=jti,
            created_at=now,
            expires_at=now + max(ttl_seconds, 1),
        )
        self._records[nonce] = record
        return record

    def consume(self, *, nonce: str, jti: str) -> tuple[ActionNonceRecord | None, str | None]:
        """Consume a nonce exactly once.

        Returns `(record, failure_reason)` where failure_reason may be:
        `expired`, `used`, `wrong_jti`, `invalid`, or `None` for unknown nonce.
        """
        now = int(time.time())
        record = self._records.get(nonce)
        if record is None:
            self._purge(now)
            return None, None

        if record.expires_at <= now:
            self._records.pop(nonce, None)
            self._purge(now)
            return None, "expired"

        if record.used_at is not None:
            return None, "used"

        if record.jti != jti:
            return None, "wrong_jti"

        used_record = ActionNonceRecord(
            nonce=record.nonce,
            jti=record.jti,
            created_at=record.created_at,
            expires_at=record.expires_at,
            used_at=now,
        )
        self._records[nonce] = used_record
        return used_record, None

    def _purge(self, now: int) -> None:
        expired = [
            nonce
            for nonce, record in self._records.items()
            if record.expires_at <= now
        ]
        for nonce in expired:
            self._records.pop(nonce, None)


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of a rate limit check."""

    allowed: bool
    retry_after: int
    remaining: int
    limit: int
    window_seconds: int


class FixedWindowRateLimiter:
    """Simple fixed-window in-memory limiter."""

    def __init__(self) -> None:
        self._windows: dict[str, tuple[int, int]] = {}

    def check(
        self,
        *,
        bucket: str,
        key: str,
        limit: int,
        window_seconds: int,
        now_timestamp: int | None = None,
    ) -> RateLimitDecision:
        """Check and record a hit in a bucket/key pair."""
        now = int(time.time()) if now_timestamp is None else now_timestamp
        window_seconds = max(int(window_seconds), 1)
        limit = max(int(limit), 1)
        composite_key = f"{bucket}:{key}"
        window_start = (now // window_seconds) * window_seconds
        current = self._windows.get(composite_key)
        if current is None or current[0] != window_start:
            count = 0
        else:
            count = current[1]

        if count >= limit:
            retry_after = (window_start + window_seconds) - now
            return RateLimitDecision(
                allowed=False,
                retry_after=max(retry_after, 1),
                remaining=0,
                limit=limit,
                window_seconds=window_seconds,
            )

        new_count = count + 1
        self._windows[composite_key] = (window_start, new_count)
        return RateLimitDecision(
            allowed=True,
            retry_after=0,
            remaining=max(limit - new_count, 0),
            limit=limit,
            window_seconds=window_seconds,
        )


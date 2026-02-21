"""In-memory lifecycle for short-lived guest pairing codes."""

from __future__ import annotations

import secrets
import string
import time
from hmac import compare_digest
from dataclasses import dataclass
from typing import Any

from .const import PAIRING_CODE_TTL_SECONDS

PAIRING_CODE_ALPHABET = string.ascii_uppercase + string.digits
PAIRING_CODE_LENGTH = 10


@dataclass(frozen=True)
class PairingRecord:
    """Server-side pairing record referenced by a short-lived code."""

    pairing_code: str
    qr_access_token: str
    entity_id: str
    allowed_action: str
    pass_expires_at: int
    pairing_expires_at: int
    created_at: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to API/service response structure."""
        return {
            "pairing_code": self.pairing_code,
            "entity_id": self.entity_id,
            "allowed_action": self.allowed_action,
            "pass_expires_at": self.pass_expires_at,
            "pairing_expires_at": self.pairing_expires_at,
            "created_at": self.created_at,
        }


class PairingStore:
    """Store and manage short-lived pairing records."""

    def __init__(self) -> None:
        """Initialize empty in-memory pairing store."""
        self._records: dict[str, PairingRecord] = {}

    def create_pairing(
        self, entity_id: str, allowed_action: str, pass_expires_at: int
    ) -> PairingRecord:
        """Create and store a pairing record with a 5-minute pairing window."""
        now_timestamp = int(time.time())
        self._purge_expired(now_timestamp)

        pairing_code = self._generate_unique_code()
        record = PairingRecord(
            pairing_code=pairing_code,
            qr_access_token=self._generate_qr_access_token(),
            entity_id=entity_id,
            allowed_action=allowed_action,
            pass_expires_at=pass_expires_at,
            pairing_expires_at=now_timestamp + PAIRING_CODE_TTL_SECONDS,
            created_at=now_timestamp,
        )
        self._records[pairing_code] = record
        return record

    def get_pairing(self, pairing_code: str) -> PairingRecord | None:
        """Return active pairing record for code, if it still exists and is valid."""
        now_timestamp = int(time.time())
        self._purge_expired(now_timestamp)
        return self._records.get(pairing_code)

    def consume_pairing(self, pairing_code: str) -> tuple[PairingRecord | None, str | None]:
        """Return and delete active pairing code in one operation.

        Returns a tuple of (record, failure_reason). `failure_reason` can be:
        - "expired" when code exists but is no longer valid
        - None when code is unknown or when record is returned
        """
        now_timestamp = int(time.time())
        record = self._records.get(pairing_code)
        if record is None:
            self._purge_expired(now_timestamp)
            return None, None

        if record.pairing_expires_at <= now_timestamp:
            self._records.pop(pairing_code, None)
            self._purge_expired(now_timestamp)
            return None, "expired"

        self._records.pop(pairing_code, None)
        self._purge_expired(now_timestamp)
        return record, None

    def validate_qr_access(
        self, pairing_code: str, qr_access_token: str
    ) -> PairingRecord | None:
        """Return active pairing record if code and qr token are both valid."""
        now_timestamp = int(time.time())
        self._purge_expired(now_timestamp)

        record = self._records.get(pairing_code)
        if record is None:
            return None
        if not qr_access_token:
            return None
        if not compare_digest(record.qr_access_token, qr_access_token):
            return None
        return record

    def _purge_expired(self, now_timestamp: int) -> None:
        """Delete codes whose pairing lifetime has ended."""
        expired_codes = [
            code
            for code, record in self._records.items()
            if record.pairing_expires_at <= now_timestamp
        ]
        for code in expired_codes:
            self._records.pop(code, None)

    def clear(self) -> int:
        """Delete all active pairing records and return removed count."""
        removed_count = len(self._records)
        self._records.clear()
        return removed_count

    def _generate_unique_code(self) -> str:
        """Generate a random code that does not collide with active records."""
        while True:
            pairing_code = "".join(
                secrets.choice(PAIRING_CODE_ALPHABET) for _ in range(PAIRING_CODE_LENGTH)
            )
            if pairing_code not in self._records:
                return pairing_code

    def _generate_qr_access_token(self) -> str:
        """Generate high-entropy token for unauthenticated QR image retrieval."""
        return secrets.token_urlsafe(32)

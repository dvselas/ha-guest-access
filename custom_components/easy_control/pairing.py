"""In-memory lifecycle for short-lived guest pairing codes."""

from __future__ import annotations

import secrets
import string
import time
from dataclasses import dataclass, replace
from hmac import compare_digest
from typing import Any

from .const import PAIRING_CODE_TTL_SECONDS

PAIRING_CODE_ALPHABET = string.ascii_uppercase + string.digits
PAIRING_CODE_LENGTH = 10


@dataclass(frozen=True)
class PairingRecord:
    """Server-side pairing record referenced by a short-lived code."""

    pairing_code: str
    qr_access_token: str
    scan_ack_token: str
    entities: tuple[dict[str, Any], ...]
    pass_expires_at: int
    pairing_expires_at: int
    created_at: int
    require_admin_approval: bool = False
    approval_status: str = "approved"
    approved_at: int | None = None
    rejected_at: int | None = None
    qr_access_used_at: int | None = None
    qr_scanned_at: int | None = None

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
        return self.entities[0].get("allowed_action", "")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to API/service response structure."""
        return {
            "pairing_code": self.pairing_code,
            "entities": list(self.entities),
            # Backward-compat singular fields (first entity):
            "entity_id": self.entity_id,
            "allowed_action": self.allowed_action,
            "pass_expires_at": self.pass_expires_at,
            "pairing_expires_at": self.pairing_expires_at,
            "created_at": self.created_at,
            "require_admin_approval": self.require_admin_approval,
            "approval_status": self.approval_status,
        }


class PairingStore:
    """Store and manage short-lived pairing records."""

    def __init__(self) -> None:
        """Initialize empty in-memory pairing store."""
        self._records: dict[str, PairingRecord] = {}

    def create_pairing(
        self,
        *,
        pass_expires_at: int,
        entities: list[dict[str, Any]] | None = None,
        require_admin_approval: bool = False,
        # Legacy single-entity convenience:
        entity_id: str | None = None,
        allowed_action: str | None = None,
    ) -> PairingRecord:
        """Create and store a pairing record with a 5-minute pairing window.

        Pass *entities* as a list of dicts with ``entity_id`` and either
        ``allowed_actions`` (list) or ``allowed_action`` (string).  For
        backward compat, ``entity_id`` + ``allowed_action`` can be used.
        """
        now_timestamp = int(time.time())
        self._purge_expired(now_timestamp)

        resolved: list[dict[str, Any]] = []
        if entities:
            for e in entities:
                eid = e["entity_id"]
                actions = e.get("allowed_actions")
                if isinstance(actions, list):
                    resolved.append({"entity_id": eid, "allowed_actions": actions})
                else:
                    act = e.get("allowed_action", "")
                    resolved.append(
                        {"entity_id": eid, "allowed_actions": [act] if act else []}
                    )
        if not resolved and entity_id and allowed_action:
            resolved = [{"entity_id": entity_id, "allowed_actions": [allowed_action]}]
        if not resolved:
            raise ValueError("entities must contain at least one grant")

        pairing_code = self._generate_unique_code()
        record = PairingRecord(
            pairing_code=pairing_code,
            qr_access_token=self._generate_qr_access_token(),
            scan_ack_token=self._generate_scan_ack_token(),
            entities=tuple(resolved),
            pass_expires_at=pass_expires_at,
            pairing_expires_at=now_timestamp + PAIRING_CODE_TTL_SECONDS,
            created_at=now_timestamp,
            require_admin_approval=require_admin_approval,
            approval_status="pending" if require_admin_approval else "approved",
            approved_at=None if require_admin_approval else now_timestamp,
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
        - "pending_approval" when code exists but awaits admin approval
        - "rejected" when code exists but was rejected
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

        if record.approval_status == "pending":
            return None, "pending_approval"
        if record.approval_status == "rejected":
            return None, "rejected"

        self._records.pop(pairing_code, None)
        self._purge_expired(now_timestamp)
        return record, None

    def approve_pairing(self, pairing_code: str) -> tuple[PairingRecord | None, str | None]:
        """Approve a pending pairing request."""
        now_timestamp = int(time.time())
        record = self._records.get(pairing_code)
        if record is None:
            self._purge_expired(now_timestamp)
            return None, None
        if record.pairing_expires_at <= now_timestamp:
            self._records.pop(pairing_code, None)
            self._purge_expired(now_timestamp)
            return None, "expired"
        if record.approval_status == "rejected":
            return None, "rejected"
        if record.approval_status == "approved":
            return record, "already_approved"
        updated_record = replace(
            record,
            approval_status="approved",
            approved_at=now_timestamp,
        )
        self._records[pairing_code] = updated_record
        return updated_record, None

    def reject_pairing(self, pairing_code: str) -> tuple[PairingRecord | None, str | None]:
        """Reject a pending pairing request."""
        now_timestamp = int(time.time())
        record = self._records.get(pairing_code)
        if record is None:
            self._purge_expired(now_timestamp)
            return None, None
        if record.pairing_expires_at <= now_timestamp:
            self._records.pop(pairing_code, None)
            self._purge_expired(now_timestamp)
            return None, "expired"
        if record.approval_status == "rejected":
            return record, "already_rejected"
        updated_record = replace(
            record,
            approval_status="rejected",
            rejected_at=now_timestamp,
        )
        self._records[pairing_code] = updated_record
        return updated_record, None

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
        if record.qr_scanned_at is not None:
            return None
        if record.qr_access_used_at is not None:
            return None
        if not compare_digest(record.qr_access_token, qr_access_token):
            return None
        return record

    def consume_qr_access(
        self, pairing_code: str, qr_access_token: str
    ) -> tuple[PairingRecord | None, str | None]:
        """Validate and mark the QR-image access token as used once.

        Returns a tuple of (record, failure_reason). `failure_reason` can be:
        - "expired" when the pairing record exists but has expired
        - "used" when the QR token for this pairing was already used once
        - "invalid" when qr_access_token does not match
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

        if not qr_access_token or not compare_digest(record.qr_access_token, qr_access_token):
            return None, "invalid"

        if record.qr_access_used_at is not None:
            return None, "used"

        updated_record = replace(record, qr_access_used_at=now_timestamp)
        self._records[pairing_code] = updated_record
        return updated_record, None

    def acknowledge_qr_scan(
        self, pairing_code: str, scan_ack_token: str
    ) -> tuple[PairingRecord | None, str | None]:
        """Mark a pairing QR as scanned exactly once without consuming pairing."""
        now_timestamp = int(time.time())
        record = self._records.get(pairing_code)
        if record is None:
            self._purge_expired(now_timestamp)
            return None, None

        if record.pairing_expires_at <= now_timestamp:
            self._records.pop(pairing_code, None)
            self._purge_expired(now_timestamp)
            return None, "expired"

        if not scan_ack_token or not compare_digest(record.scan_ack_token, scan_ack_token):
            return None, "invalid"

        if record.qr_scanned_at is not None:
            return record, "already_scanned"

        updated_record = replace(record, qr_scanned_at=now_timestamp)
        self._records[pairing_code] = updated_record
        return updated_record, None

    def delete_pairing(self, pairing_code: str) -> bool:
        """Delete a pairing record by code."""
        now_timestamp = int(time.time())
        self._purge_expired(now_timestamp)
        return self._records.pop(pairing_code, None) is not None

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

    def _generate_scan_ack_token(self) -> str:
        """Generate high-entropy token for one-time scan acknowledgement."""
        return secrets.token_urlsafe(32)

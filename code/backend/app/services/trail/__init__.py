"""Central tamper-evident audit trail (hash chain over append-only rows)."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.platform import AuditTrail

GENESIS = "0" * 64
FIELDS = ("audit_id", "category", "provider", "scope", "actor", "action", "target", "previous_state", "new_state",
          "approval_reference", "execution_result", "verification_result", "evidence_reference", "created_at", "prev_hash")


def _norm(v):
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(v, date):
        return v.isoformat()
    return v


def _digest(row: dict) -> str:
    payload = json.dumps({k: _norm(row.get(k)) for k in FIELDS}, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _clean(d):
    if d is None:
        return None
    return json.loads(json.dumps(d, default=lambda o: _norm(o) if isinstance(o, (date, datetime)) else str(o)))


def record(db: Session, *, category: str, actor: str, action: str, provider: str | None = None, scope: str | None = None,
           target: str | None = None, previous_state: dict | None = None, new_state: dict | None = None,
           approval_reference: str | None = None, execution_result: str | None = None, verification_result: str | None = None,
           evidence_reference: str | None = None) -> AuditTrail:
    """Append one entry. The caller commits. Rows are chained in id order, so writes are serialised per database session."""
    db.flush()
    last = db.scalar(select(AuditTrail).order_by(AuditTrail.id.desc()).limit(1))
    row = {"audit_id": str(uuid.uuid4()), "category": category[:32], "provider": provider, "scope": (scope or "")[:512] or None,
           "actor": (actor or "system")[:512], "action": action[:96], "target": (target or "")[:512] or None,
           "previous_state": _clean(previous_state), "new_state": _clean(new_state), "approval_reference": approval_reference,
           "execution_result": execution_result, "verification_result": verification_result,
           "evidence_reference": evidence_reference, "created_at": datetime.now(UTC).replace(microsecond=0),
           "prev_hash": last.row_hash if last else GENESIS}
    entry = AuditTrail(**row, row_hash=_digest(row))
    db.add(entry)
    db.flush()
    return entry


def verify(db: Session, limit: int | None = None) -> dict:
    """Recompute the chain. Returns the first broken row, if any."""
    prev, n = GENESIS, 0
    for e in db.scalars(select(AuditTrail).order_by(AuditTrail.id)):
        row = {k: getattr(e, k) for k in FIELDS}
        if e.prev_hash != prev or _digest(row) != e.row_hash:
            return {"valid": False, "checked": n, "broken_at": e.audit_id, "id": e.id}
        prev, n = e.row_hash, n + 1
        if limit and n >= limit:
            break
    return {"valid": True, "checked": n, "broken_at": None}

"""Business metadata of assets. Written only by people (UI or bulk import), never by a sync. Every changed field is
kept in asset_metadata_history (append-only) and in the central audit trail."""
from __future__ import annotations

import re
from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import MANUAL_COLUMNS, MANUAL_FIELDS, AssetMetadata, AssetMetadataHistory, resource_key

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
FIELD = {c: (label, kind, allowed) for c, label, kind, allowed in MANUAL_FIELDS}
MAX_TEXT = 2000


class MetadataError(ValueError):
    pass


def _date(v) -> date | None:
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    s = str(v).strip()
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%d-%b-%Y", "%d %b %Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    raise MetadataError(f"not a date: {s} (use YYYY-MM-DD or DD-MM-YYYY)")


def clean(raw: dict) -> dict:
    """Validate manual fields. Unknown fields are rejected; empty strings clear a field."""
    unknown = set(raw) - set(MANUAL_COLUMNS)
    if unknown:
        raise MetadataError(f"Not an editable field: {', '.join(sorted(unknown))}")
    out: dict = {}
    for col, value in raw.items():
        label, kind, allowed = FIELD[col]
        if kind == "date":
            try:
                out[col] = _date(value)
            except MetadataError as exc:
                raise MetadataError(f"{label}: {exc}") from exc
            continue
        v = None if value is None else str(value).strip()
        v = v or None
        if v is None:
            out[col] = None
            continue
        if len(v) > MAX_TEXT:
            raise MetadataError(f"{label}: longer than {MAX_TEXT} characters")
        if kind == "email":
            if not EMAIL.match(v):
                raise MetadataError(f"{label}: not an e-mail address")
            v = v.lower()
        elif kind == "choice":
            match = next((a for a in allowed if a.lower() == v.lower()), None)
            if match is None:
                raise MetadataError(f"{label}: must be one of {', '.join(allowed)}")
            v = match
        out[col] = v
    return out


def get(db: Session, provider: str, resource_id: str) -> AssetMetadata | None:
    return db.scalar(select(AssetMetadata).where(AssetMetadata.resource_key == resource_key(provider, resource_id)))


def to_dict(row: AssetMetadata | None) -> dict:
    return {c: (getattr(row, c).isoformat() if row is not None and isinstance(getattr(row, c), date) else getattr(row, c) if row else None)
            for c in MANUAL_COLUMNS}


def save(db: Session, provider: str, scope: str, resource_id: str, fields: dict, actor: str, source: str = "ui") -> tuple[AssetMetadata, dict]:
    """Apply validated fields. Returns (row, {field: (old, new)}) for the fields that actually changed."""
    data = clean(fields)
    key = resource_key(provider, resource_id)
    row = db.scalar(select(AssetMetadata).where(AssetMetadata.resource_key == key))
    if row is None:
        row = AssetMetadata(resource_key=key, provider=provider, scope_external_id=scope, resource_id=resource_id)
        db.add(row)
    changed: dict = {}
    for col, new in data.items():
        old = getattr(row, col)
        if (old.isoformat() if isinstance(old, date) else old) != (new.isoformat() if isinstance(new, date) else new):
            changed[col] = (old, new)
            setattr(row, col, new)
            db.add(AssetMetadataHistory(resource_key=key, provider=provider, field=col, source=source, changed_by=actor,
                                        old_value=None if old is None else str(old), new_value=None if new is None else str(new)))
    if changed:
        row.updated_by = actor
        from app.services.trail import record
        record(db, category="asset", actor=actor, action=f"asset.metadata.{source}", provider=provider, scope=scope, target=resource_id[:255],
               previous_state={k: None if v[0] is None else str(v[0]) for k, v in changed.items()},
               new_state={k: None if v[1] is None else str(v[1]) for k, v in changed.items()})
    return row, changed


def history(db: Session, provider: str, resource_id: str, limit: int = 200) -> list[dict]:
    from app.api.serializers import iso
    rows = db.scalars(select(AssetMetadataHistory).where(AssetMetadataHistory.resource_key == resource_key(provider, resource_id))
                      .order_by(AssetMetadataHistory.id.desc()).limit(limit))
    return [{"field": r.field, "label": FIELD.get(r.field, (r.field,))[0], "old": r.old_value, "new": r.new_value, "source": r.source,
             "by": r.changed_by, "at": iso(r.changed_at)} for r in rows]

"""Account ownership: read / save with a per-field change history, and the approved budget from the budget tracker."""
from __future__ import annotations

import re
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.models import OWNERSHIP_FIELDS, SCOPE_MODELS, AccountOwnership, AccountOwnershipHistory, CloudBudget

EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
EMAIL_FIELDS = {f for f in OWNERSHIP_FIELDS if f.endswith("_email")}
LIMITS = {"notes": 2000, "cost_centre": 128}


class OwnershipError(ValueError):
    """Invalid input; the message is safe to show."""


def scope_name(db: Session, provider: str, scope: str) -> str | None:
    model = SCOPE_MODELS.get(provider)
    if model is None:
        return None
    row = db.scalar(select(model).where(model.external_id == scope))
    return row.name if row else None


def approved_budget(db: Session, provider: str, scope: str) -> dict:
    """Active budgets in the budget tracker that cover exactly this account (single-scope or multi-scope budgets)."""
    hits = []
    for b in db.scalars(select(CloudBudget).where(CloudBudget.status == "ACTIVE")):
        extra = {(x.get("provider"), x.get("scope")) for x in (b.scopes or []) if isinstance(x, dict)}
        if (b.provider == provider and b.scope_external_id == scope) or (provider, scope) in extra:
            hits.append(b)
    total = sum((Decimal(b.current_monthly_usd) for b in hits), Decimal(0))
    return {"monthly_usd": float(total) if hits else None, "budgets": [{"key": b.budget_key, "name": b.name, "monthly_usd": float(b.current_monthly_usd),
                                                                       "shared": bool(b.scopes)} for b in hits],
            "source": "LV NEXUS budget tracker (active budgets for this account)"}


def to_dict(db: Session, provider: str, scope: str, row: AccountOwnership | None) -> dict:
    data = {f: getattr(row, f) if row else None for f in OWNERSHIP_FIELDS}
    return {"provider": provider, "scope": scope, "name": scope_name(db, provider, scope), **data,
            "approved_budget": approved_budget(db, provider, scope),
            "updated_by": row.updated_by if row else None, "updated_at": iso(row.updated_at) if row else None}


def get(db: Session, provider: str, scope: str) -> AccountOwnership | None:
    return db.scalar(select(AccountOwnership).where(AccountOwnership.provider == provider, AccountOwnership.scope_external_id == scope))


def clean(raw: dict) -> dict:
    unknown = set(raw) - set(OWNERSHIP_FIELDS)
    if unknown:
        raise OwnershipError(f"Unknown field: {', '.join(sorted(unknown))}")
    out = {}
    for f in OWNERSHIP_FIELDS:
        if f not in raw:
            continue
        v = (raw[f] or "").strip() or None
        if v and f in EMAIL_FIELDS:
            v = v.lower()
            if not EMAIL.match(v):
                raise OwnershipError(f"{f.replace('_', ' ')}: not a valid e-mail address")
        if v and len(v) > LIMITS.get(f, 255):
            raise OwnershipError(f"{f.replace('_', ' ')}: too long")
        out[f] = v
    return out


def save(db: Session, provider: str, scope: str, raw: dict, actor: str) -> tuple[AccountOwnership, int]:
    """Saves the submitted fields; every changed field gets a history row. Returns (row, number of changed fields)."""
    if provider not in SCOPE_MODELS:
        raise OwnershipError("Unknown cloud provider")
    if scope_name(db, provider, scope) is None:
        raise OwnershipError("This account / subscription / project has not been discovered")
    data = clean(raw)
    row = get(db, provider, scope)
    if row is None:
        row = AccountOwnership(provider=provider, scope_external_id=scope)
        db.add(row)
        db.flush()
    changed = 0
    for f, new in data.items():
        old = getattr(row, f)
        if old != new:
            db.add(AccountOwnershipHistory(ownership_id=row.id, provider=provider, scope_external_id=scope, field=f,
                                           old_value=old, new_value=new, changed_by=actor))
            setattr(row, f, new)
            changed += 1
    if changed:
        row.updated_by = actor
    return row, changed


def history(db: Session, provider: str, scope: str, limit: int = 200) -> list[dict]:
    rows = db.scalars(select(AccountOwnershipHistory).where(AccountOwnershipHistory.provider == provider,
                                                            AccountOwnershipHistory.scope_external_id == scope)
                      .order_by(AccountOwnershipHistory.id.desc()).limit(limit))
    return [{"field": r.field, "old": r.old_value, "new": r.new_value, "by": r.changed_by, "at": iso(r.changed_at)} for r in rows]


def recipients(row: AccountOwnership | None) -> tuple[str | None, list[str]]:
    """(TO, CC) for the monthly audit e-mail: TO = account SPOC; CC = entity lead, owner, cloud admin, FinOps SPOC."""
    if row is None or not row.spoc_email:
        return None, []
    cc = []
    for e in (row.entity_lead_email, row.owner_email, row.cloud_admin_email, row.finops_spoc_email):
        if e and e != row.spoc_email and e not in cc:
            cc.append(e)
    return row.spoc_email, cc

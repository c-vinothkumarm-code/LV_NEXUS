from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import SCOPE_LABEL, SCOPE_MODELS


def iso(dt):
    return dt.isoformat() if dt else None


def scope_dict(row) -> dict:
    return {
        "provider": row.provider, "scope_type": SCOPE_LABEL[row.provider], "external_id": row.external_id,
        "name": row.name, "provider_state": row.provider_state, "parent": row.parent,
        "environment": row.environment, "onboarding_status": row.onboarding_status, "checks": row.checks or {},
        "monitoring_enabled": row.monitoring_enabled, "first_discovered_at": iso(row.first_discovered_at),
        "last_seen_at": iso(row.last_seen_at), "last_validated_at": iso(row.last_validated_at),
    }


def query_scopes(db: Session, provider: str | None = None, status: str | None = None,
                 search: str | None = None, environment: str | None = None) -> list:
    rows = []
    for prov, model in SCOPE_MODELS.items():
        if provider and provider != prov:
            continue
        stmt = select(model)
        if status:
            stmt = stmt.where(model.onboarding_status == status)
        if environment:
            stmt = stmt.where(model.environment == environment)
        if search:
            like = f"%{search.lower()}%"
            stmt = stmt.where(or_(model.name.ilike(like), model.external_id.ilike(like)))
        rows += list(db.scalars(stmt.order_by(model.name)))
    return rows


def execution_dict(e) -> dict:
    return {"id": e.id, "job_name": e.job_name, "trigger": e.trigger, "triggered_by": e.triggered_by,
            "status": e.status, "started_at": iso(e.started_at), "finished_at": iso(e.finished_at),
            "scopes_total": e.scopes_total, "scopes_failed": e.scopes_failed, "summary": e.summary or {},
            "failures": e.failures or [], "error": e.error}


def task_dict(t) -> dict:
    return {"id": t.id, "category": t.category, "provider": t.provider, "scope_external_id": t.scope_external_id,
            "title": t.title, "description": t.description, "proposed_action": t.proposed_action,
            "status": t.status, "decided_by": t.decided_by, "decided_at": iso(t.decided_at),
            "decision_notes": t.decision_notes, "created_at": iso(t.created_at), "resolved_at": iso(t.resolved_at)}


_NAMES: dict = {"at": 0.0, "map": {}}


def scope_label(db, provider: str | None, sid: str | None) -> str | None:
    """Display name of an account / subscription / project (or the Entra tenant), cached for a minute.
    Returns None when unknown so callers can fall back to the ID."""
    import time

    from sqlalchemy import select

    from app.core.config import get_settings
    from app.models import SCOPE_MODELS
    if not sid:
        return None
    if time.monotonic() - _NAMES["at"] > 60:
        _NAMES["map"] = {(p, i): n for p, m in SCOPE_MODELS.items() for i, n in db.execute(select(m.external_id, m.name)).all() if n}
        _NAMES["at"] = time.monotonic()
    name = _NAMES["map"].get((provider, sid)) or next((n for (p, i), n in _NAMES["map"].items() if i == sid), None)
    if name is None and provider == "azure" and sid == (get_settings().azure_tenant_id or "").strip():
        return "Microsoft Entra ID (tenant)"
    return name

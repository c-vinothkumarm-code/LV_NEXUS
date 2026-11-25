"""Cloud Services & Asset Management API.

Read: assets:read (scoped users - e.g. Project Owners - only see their assigned accounts / subscriptions / projects).
Edit business metadata: assets:edit. Bulk import: assets:import. Activity thresholds: assets:configure.
Nothing here calls a cloud API or changes a cloud resource; collection runs in the scheduled jobs."""
from __future__ import annotations

import base64
import binascii
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import log_action, require_any
from app.api.serializers import iso
from app.database.session import get_db
from app.models import MANUAL_FIELDS, AccessAssignment, AssetActivitySnapshot, AssetInventoryChange, User, resource_key
from app.services.assets import catalog
from app.services.assets import io as AIO
from app.services.assets import metadata as M
from app.services.assets import policy as P

router = APIRouter(prefix="/api/v1/assets", tags=["cloud services & assets"])
READ = require_any("assets:read")
EDIT = require_any("assets:edit")
IMPORT = require_any("assets:import")
CONFIGURE = require_any("assets:configure")
SORTS = {"name", "provider", "scope_name", "region", "activity_status", "last_activity_at", "department", "server_spoc_email",
         "estimated_monthly_cost_usd", "create_date", "server_status", "cpu_avg"}


def _filtered(db: Session, user: User, **f) -> list[dict]:
    return catalog.filter_rows(catalog.build(db, user, include_deleted=f.pop("include_deleted", False)), **f)


def _public(r: dict) -> dict:
    return {k: v for k, v in r.items() if k != "key"}


@router.get("")
def list_assets(provider: str | None = None, scope: str | None = None, kind: str | None = None, department: str | None = None,
                spoc: str | None = None, activity: str | None = None, backup: str | None = None, environment: str | None = None,
                missing_spoc: bool = False, include_deleted: bool = False, q: str | None = None, sort: str = "name", order: str = "asc",
                page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500), db: Session = Depends(get_db), user: User = Depends(READ)):
    all_rows = catalog.build(db, user, include_deleted=include_deleted)
    rows = catalog.filter_rows(all_rows, provider=provider, scope=scope, kind=kind, department=department, spoc=spoc, activity=activity,
                               backup=backup, environment=environment, missing_spoc=missing_spoc, q=q)
    key = sort if sort in SORTS else "name"
    rows.sort(key=lambda r: (r.get(key) is None, str(r.get(key) or "").lower() if not isinstance(r.get(key), (int, float)) else r.get(key)),
              reverse=order == "desc")
    return {"total": len(rows), "page": page, "size": size, "kpis": catalog.kpis(rows), "facets": catalog.facets(all_rows),
            "manual_fields": [{"field": c, "label": label, "kind": kind_, "options": list(allowed or [])} for c, label, kind_, allowed in MANUAL_FIELDS],
            "items": [_public(r) for r in rows[(page - 1) * size: page * size]]}


@router.get("/kpis")
def asset_kpis(db: Session = Depends(get_db), user: User = Depends(READ)):
    rows = catalog.build(db, user)
    from app.services.assets.activity import CLASSES
    return {**catalog.kpis(rows), "classes": list(CLASSES)}


def _find(db: Session, user: User, provider: str, resource_id: str) -> dict:
    key = resource_key(provider, resource_id)
    row = next((r for r in catalog.build(db, user) if r["key"] == key), None)
    if row is None:
        raise HTTPException(404, "Asset not found")
    return row


@router.get("/item")
def asset_detail(provider: str, resource_id: str, db: Session = Depends(get_db), user: User = Depends(READ)):
    row = _find(db, user, provider, resource_id)
    key = row["key"]
    snaps = list(db.scalars(select(AssetActivitySnapshot).where(AssetActivitySnapshot.resource_key == key)
                            .order_by(AssetActivitySnapshot.day.desc()).limit(90)))
    changes = list(db.scalars(select(AssetInventoryChange).where(AssetInventoryChange.resource_key == key)
                              .order_by(AssetInventoryChange.id.desc()).limit(200)))
    access = []
    if "access:read" in user.permission_names:
        rid = resource_id.lower()
        for a in db.scalars(select(AccessAssignment).where(AccessAssignment.provider == provider, AccessAssignment.removed_at.is_(None),
                                                           AccessAssignment.scope_external_id == row["scope"])):
            path, lvl = (a.scope_path or "").lower(), (a.scope_level or "").lower()
            if lvl == "resource" and (rid in path or (a.resource_name or "").lower() == row["name"].lower()):
                level = "This resource (direct)"
            elif lvl == "resource_group" and a.resource_group and f"/resourcegroups/{a.resource_group.lower()}/" in rid:
                level = f"Resource group {a.resource_group} (inherited)"
            elif lvl in ("subscription", "account", "project"):
                level = f"{lvl.title()} (inherited)"
            elif lvl in ("management_group", "organization", "folder"):
                level = f"{lvl.replace('_', ' ').title()} {a.inherited_from or ''} (inherited)".replace("  ", " ")
            else:
                continue
            access.append({"principal_id": a.principal_id, "principal_type": a.principal_type, "role": a.role_name, "privileged": a.privileged,
                           "level": level, "access_type": a.access_type, "expires_at": iso(a.expires_at)})
    return {**_public(row), "can_edit": "assets:edit" in user.permission_names,
            "manual_fields": [{"field": c, "label": label, "kind": k, "options": list(allowed or [])} for c, label, k, allowed in MANUAL_FIELDS],
            "metadata_history": M.history(db, provider, resource_id),
            "activity_history": [{"day": s.day.isoformat(), "classification": s.classification, "reason": s.reason, "state": s.state,
                                  "cpu_avg": s.cpu_avg, "network_mb_per_day": s.network_mb_per_day} for s in snaps],
            "inventory_changes": [{"field": c.field, "old": c.old_value, "new": c.new_value, "at": iso(c.observed_at), "source": c.source} for c in changes],
            "access": access[:500], "access_total": len(access), "access_visible": "access:read" in user.permission_names}


class MetadataBody(BaseModel):
    provider: str
    resource_id: str = Field(min_length=1, max_length=4096)
    fields: dict


@router.put("/metadata")
def update_metadata(body: MetadataBody, db: Session = Depends(get_db), user: User = Depends(EDIT)):
    row = _find(db, user, body.provider, body.resource_id)
    try:
        _m, changed = M.save(db, body.provider, row["scope"], row["resource_id"], body.fields, user.email, source="ui")
    except M.MetadataError as exc:
        raise HTTPException(422, str(exc)) from exc
    log_action(db, user.email, "asset.metadata.update", f"{body.provider}:{row['resource_id'][:200]}", {"fields": sorted(changed)})
    db.commit()
    return {"changed": sorted(changed), **_public(_find(db, user, body.provider, body.resource_id))}


@router.get("/export")
def export_assets(format: str = "xlsx", provider: str | None = None, scope: str | None = None, kind: str | None = None,
                  department: str | None = None, spoc: str | None = None, activity: str | None = None, backup: str | None = None,
                  environment: str | None = None, missing_spoc: bool = False, include_deleted: bool = False, q: str | None = None,
                  db: Session = Depends(get_db), user: User = Depends(READ)):
    if format not in ("csv", "xlsx"):
        raise HTTPException(422, "format must be csv or xlsx")
    rows = _filtered(db, user, provider=provider, scope=scope, kind=kind, department=department, spoc=spoc, activity=activity, backup=backup,
                     environment=environment, missing_spoc=missing_spoc, include_deleted=include_deleted, q=q)
    rows.sort(key=lambda r: (r["provider"], r["scope_name"] or "", r["name"] or ""))
    log_action(db, user.email, "asset.export", format, {"rows": len(rows)})
    db.commit()
    name = f"LV-NEXUS-cloud-assets-{date.today().isoformat()}.{format}"
    if format == "csv":
        return Response(AIO.export_csv(rows), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})
    return Response(AIO.export_xlsx(rows), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


class ImportBody(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str
    apply: bool = False


@router.post("/import")
def import_metadata(body: ImportBody, db: Session = Depends(get_db), user: User = Depends(IMPORT)):
    try:
        data = base64.b64decode(body.content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(422, "content_base64 is not valid base64") from exc
    try:
        table = AIO.read_table(body.filename, data)
        known = {(r["provider"], r["resource_id"].lower()): r for r in catalog.build(db, user)}
        plan = AIO.plan_import(table, known)
    except AIO.ImportError_ as exc:
        raise HTTPException(422, str(exc)) from exc
    applied = 0
    if body.apply:
        if plan["invalid"]:
            raise HTTPException(422, f"{plan['invalid']} row(s) have errors: fix them (see the dry run) before applying")
        if "assets:edit" not in user.permission_names:
            raise HTTPException(403, "Missing permission: assets:edit")
        for e in plan["rows"]:
            if e["status"] == "ok" and e["changes"]:
                _m, changed = M.save(db, e["provider"], e["scope"], e["resource_id"], {k: e["fields"][k] for k in e["changes"]}, user.email,
                                     source="import")
                applied += len(changed)
        log_action(db, user.email, "asset.metadata.import", body.filename[:120], {"rows": len(plan["rows"]), "fields_changed": applied})
        db.commit()
    for e in plan["rows"]:
        e.pop("fields", None)
        e.pop("scope", None)
    return {**plan, "applied": body.apply, "fields_changed": applied, "rows": plan["rows"][:1000]}


@router.get("/import/template")
def import_template(format: str = "xlsx", db: Session = Depends(get_db), user: User = Depends(IMPORT)):
    """The current register as the import template (same columns; edit the business-metadata columns only)."""
    return export_assets(format=format, db=db, user=user)


class PolicyBody(BaseModel):
    values: dict


@router.get("/policy")
def get_policy(db: Session = Depends(get_db), _: User = Depends(READ)):
    return {"values": P.get(db), "defaults": P.DEFAULTS, "limits": P.LIMITS}


@router.put("/policy")
def put_policy(body: PolicyBody, db: Session = Depends(get_db), user: User = Depends(CONFIGURE)):
    try:
        values, before = P.save(db, body.values, user.email)
    except P.PolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    from app.services.trail import record
    record(db, category="asset", actor=user.email, action="asset.policy.update", target="activity", previous_state=before,
           new_state={k: values[k] for k in before})
    db.commit()
    return {"values": values}

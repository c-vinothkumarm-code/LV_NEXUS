"""Cloud Access Management API: identities, actual assignments, the approval register, reconciliation, requests
(grant / extension / revocation) with verification, and access reviews. LV NEXUS never changes cloud access itself."""
from __future__ import annotations

from collections import Counter
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import access_workflows, log_action, require_any
from app.api.serializers import iso
from app.core.security import require
from app.database.session import get_db
from app.models import SCOPE_MODELS, AutomationExecutionLog, JobStatus, User
from app.models.access import AccessApproval, AccessAssignment, AccessAuditEvent, AccessGrant, AccessRequest, AccessReview, AccessReviewItem, CloudIdentity
from app.services.access import engine as A
from app.services.access.collectors import is_privileged

router = APIRouter(prefix="/api/v1/access", tags=["cloud access management"])
LIMITATIONS = {
    "azure": "Collected when permitted: Azure RBAC at management group, subscription, resource group and resource scope (incl. inherited); "
             "Microsoft Graph users, guests, groups (transitive members), service principals, managed identities and app credential "
             "metadata; Entra directory roles; PIM eligible assignments (directory and Azure RBAC). Not evaluated: deny assignments and "
             "conditional access.",
    "aws": "Collected when permitted: IAM users (with last password use and access-key metadata), groups, roles with trust relationships, "
           "attached managed and inline policies, permission boundaries; IAM Identity Center users, groups, memberships and permission-set "
           "assignments. Not evaluated: SCPs and resource policies, so this is not a full effective-permission calculation.",
    "gcp": "Collected when permitted: project IAM bindings, organization and folder bindings inherited by each project, conditions, "
           "service accounts and user-managed key metadata, principals the provider marks as deleted. Not collected: resource-level IAM "
           "and Cloud Identity group membership.",
}


def _last_coverage(db: Session) -> tuple[dict, str | None]:
    """Per-provider source states from the latest access_inventory run (what actually worked, not what is supported)."""
    from app.models import AutomationExecutionLog
    run = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == "access_inventory")
                    .order_by(AutomationExecutionLog.id.desc()).limit(1))
    if run is None:
        return {}, None
    out: dict[str, dict[str, dict]] = {}
    summary = run.summary or {}
    for key, cov in (summary.get("coverage") or {}).items():
        provider = key.split(":", 1)[0]
        for c in cov or []:
            out.setdefault(provider, {}).setdefault(c["source"], c)
    for provider, dirs in (summary.get("directory") or {}).items():
        for d in dirs or []:
            for c in d.get("coverage") or []:
                src = c["source"].split(":", 1)[0]
                prev = out.setdefault(provider, {}).get(src)
                if prev is None or prev.get("state") == "OK":  # keep the worst state per source
                    out[provider][src] = {**c, "source": src}
    return {p: sorted(v.values(), key=lambda x: x["source"]) for p, v in out.items()}, iso(run.finished_at or run.started_at)


def _scope_names(db: Session) -> dict[tuple[str, str], tuple[str, str | None]]:
    return {(p, s.external_id): (s.name or s.external_id, s.environment) for p, m in SCOPE_MODELS.items() for s in db.scalars(select(m))}


def _assignment(a: AccessAssignment, st: dict | None, names) -> dict:
    ident = (st or {}).get("identity")
    g = (st or {}).get("grant")
    nm, env = names.get((a.provider, a.scope_external_id), (a.scope_external_id, None))
    return {"id": a.id, "provider": a.provider, "source": a.source, "environment": env, "account_name": nm, "account_id": a.scope_external_id,
            "scope_level": a.scope_level, "scope_path": a.scope_path, "resource_group": a.resource_group, "resource_name": a.resource_name,
            "principal_id": a.principal_id, "display_name": ident.display_name if ident else None, "sign_in_name": ident.sign_in_name if ident else None,
            "identity_type": a.principal_type, "access_details": a.role_name, "access_type": a.access_type, "privileged": a.privileged,
            "condition": a.condition, "pim_state": a.pim_state, "first_seen_at": iso(a.first_seen_at), "last_synced": iso(a.last_seen_at),
            "removed_at": iso(a.removed_at), "last_sign_in": iso(ident.last_sign_in_at) if ident and ident.last_sign_in_at else None,
            "inherited_from": a.inherited_from, "expires_at": iso(a.expires_at), "identity_status": ident.lifecycle_status if ident else None,
            "identity_id": ident.id if ident else None,
            "approval_status": (st or {}).get("status", "REMOVED" if a.removed_at else "UNAPPROVED"),
            "grant": None if g is None else {"id": g.id, "grant_key": g.grant_key, "expiry": iso(g.access_expiry_date),
                                             "manager_approved_by": g.manager_approved_by, "it_manager_approved_by": g.it_manager_approved_by}}


def _grant(g: AccessGrant, present: bool | None = None) -> dict:
    today = date.today()
    status = {"REQUESTED": "Pending", "APPROVED": "Pending", "PROVISIONED": "Pending", "ACTIVE": "Active", "EXPIRED": "Expired", "REVOKED": "Revoked",
              "REVOKE_REQUESTED": "Active", "REJECTED": "Rejected"}[g.state]
    return {"id": g.id, "grant_key": g.grant_key, "provider": g.provider, "environment": g.environment, "account_name": g.account_name,
            "account_id": g.scope_external_id, "resource_group": g.resource_group, "resource_name": g.resource_name, "display_name": g.display_name,
            "access_details": g.access_details, "sign_in_name": g.sign_in_name, "identity_type": g.identity_type, "access_scope": g.access_scope,
            "manager_approved_by": g.manager_approved_by, "it_manager_approved_by": g.it_manager_approved_by,
            "access_given_date": iso(g.access_given_date), "access_extended_date": iso(g.access_extended_date),
            "access_expiry_date": iso(g.access_expiry_date), "access_revocation_date": iso(g.access_revocation_date),
            "email_subject": g.email_subject, "approval_reference": g.approval_reference, "access_status": status, "state": g.state,
            "privileged": is_privileged(g.access_details), "observed_in_provider": present, "verified_at": iso(g.verified_at),
            "expires_in_days": (g.access_expiry_date - today).days if g.access_expiry_date else None, "source": g.source,
            "created_by": g.created_by, "created_at": iso(g.created_at)}


# ------------------------------------------------------------------ dashboard
@router.get("/summary")
def summary(db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    st = A.assignment_status(db)
    live = [db.get(AccessAssignment, i) for i in st]
    today = date.today()
    grants = list(db.scalars(select(AccessGrant)))
    active_g = [g for g in grants if g.state == "ACTIVE"]
    exp = lambda d: sum(1 for g in active_g if g.access_expiry_date and today <= g.access_expiry_date <= today + timedelta(days=d))  # noqa: E731
    reqs = Counter((r.request_type, r.status) for r in db.scalars(select(AccessRequest)))
    idents = list(db.scalars(select(CloudIdentity)))
    last = db.scalar(select(func.max(AutomationExecutionLog.finished_at)).where(
        AutomationExecutionLog.job_name == "access_inventory", AutomationExecutionLog.status.in_([JobStatus.SUCCESS.value, JobStatus.PARTIAL.value])))
    collected = bool(live) or last is not None
    coverage, coverage_at = _last_coverage(db)
    # inactive = no sign-in for 90 days, counted only over identities whose provider reports sign-in data (never guessed)
    known = [i for i in idents if i.last_sign_in_at is not None and i.missing_since is None and i.enabled is not False]
    cutoff = datetime.now(UTC) - timedelta(days=90)
    inactive = sum(1 for i in known if (i.last_sign_in_at if i.last_sign_in_at.tzinfo else i.last_sign_in_at.replace(tzinfo=UTC)) < cutoff) if known else None
    inactive_note = (f"No sign-in for 90 days, among {len(known)} identities whose provider reports last use (AWS IAM password / role last "
                     "used). Entra sign-in activity needs AuditLog.Read.All and an Entra ID P1/P2 licence." if known else
                     "Not collected yet: needs AWS IAM last-used data or Entra sign-in activity (AuditLog.Read.All + P1/P2).")
    return {"collected": collected, "last_synced": iso(last),
            "identities": len(idents), "service_accounts": sum(1 for i in idents if i.principal_type in ("ServicePrincipal", "ServiceAccount", "Role", "ManagedIdentity")),
            "active_assignments": len(live), "privileged": sum(1 for a in live if a.privileged),
            "unapproved": sum(1 for v in st.values() if v["status"] == "UNAPPROVED"),
            "expired_still_active": sum(1 for v in st.values() if v["status"] == "EXPIRED_STILL_ACTIVE"),
            "expired_grants": sum(1 for g in grants if g.state == "EXPIRED"),
            "expiring": {"7": exp(7), "15": exp(15), "30": exp(30)},
            "approved_not_provisioned": len(A.missing_assignments(db)),
            "pending_requests": sum(n for (t, s), n in reqs.items() if t == "grant" and s in ("PENDING", "MORE_INFO")),
            "pending_extensions": sum(n for (t, s), n in reqs.items() if t == "extension" and s in ("PENDING", "MORE_INFO")),
            "pending_revocations": sum(n for (t, s), n in reqs.items() if t == "revocation" and s in ("PENDING", "MORE_INFO", "APPROVED", "EXECUTED")),
            "awaiting_execution": sum(n for (_, s), n in reqs.items() if s == "APPROVED"),
            "verification_failed": sum(n for (_, s), n in reqs.items() if s == "VERIFICATION_FAILED"),
            "inactive_identities": inactive, "inactive_note": inactive_note,
            "by_provider": dict(Counter(a.provider for a in live)), "by_access_type": dict(Counter(a.access_type for a in live)),
            "by_scope_level": dict(Counter(a.scope_level for a in live)),
            "by_account": Counter(f"{a.provider}:{a.scope_external_id}" for a in live).most_common(20),
            "limitations": LIMITATIONS, "coverage": coverage, "coverage_as_of": coverage_at}


# ------------------------------------------------------------------ actual assignments
@router.get("/activity")
def identity_activity(month: str | None = Query(None, pattern=r"^\d{4}-\d{2}$"), provider: str | None = None, scope: str | None = None,
                      kind: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    """Users added / deleted and access granted / removed in a calendar month (IST), from the collected cloud audit logs.
    A role assignment is never counted as a new user; failed or denied calls are listed but not counted."""
    from app.services.access import identity_activity as IA
    start, end, label, complete = IA.month_bounds(month)
    names = {k: v[0] for k, v in _scope_names(db).items()}
    data = IA.activity(db, start, end, provider, scope, names)
    events = [e for e in data["events"] if not kind or e["kind"] == kind]
    return {"period": {"label": label, "start": iso(start), "end": iso(end), "complete": complete,
                       "note": None if complete else f"{label} so far (month not finished)"},
            "counts": data["counts"], "failed_attempts": data["failed_attempts"], "kinds": IA.KINDS,
            "coverage": IA.coverage(db, start, end), "total_events": len(events), "events": events[:500],
            "basis": "Successful IAM events in the collected audit logs (CloudTrail, Azure Activity Log, Entra ID audit, GCP Cloud Audit Logs). "
                     "Users = human user identities; service accounts and role assignments are counted separately."}


@router.get("/assignments")
def assignments(provider: str | None = None, scope: str | None = None, status: str | None = None, privileged: bool | None = None,
                access_type: str | None = None, role: str | None = None, q: str | None = None, include_removed: bool = False,
                page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500), db: Session = Depends(get_db),
                _: User = Depends(require("access:read"))):
    st = A.assignment_status(db)
    stmt = select(AccessAssignment)
    if not include_removed:
        stmt = stmt.where(AccessAssignment.removed_at.is_(None))
    for col, val in ((AccessAssignment.provider, provider), (AccessAssignment.scope_external_id, scope), (AccessAssignment.access_type, access_type)):
        if val:
            stmt = stmt.where(col == val)
    if privileged is not None:
        stmt = stmt.where(AccessAssignment.privileged.is_(privileged))
    if role:
        stmt = stmt.where(AccessAssignment.role_name.ilike(f"%{role}%"))
    names = _scope_names(db)
    rows = [_assignment(a, st.get(a.id), names) for a in db.scalars(stmt.order_by(AccessAssignment.privileged.desc(), AccessAssignment.role_name))]
    if status:
        rows = [r for r in rows if r["approval_status"] == status]
    if q:
        ql = q.lower()
        rows = [r for r in rows if any(ql in (r.get(k) or "").lower() for k in ("principal_id", "display_name", "sign_in_name", "access_details", "account_name"))]
    return {"total": len(rows), "items": rows[(page - 1) * size: page * size],
            "statuses": ["APPROVED", "UNAPPROVED", "EXPIRED_STILL_ACTIVE", "REVOCATION_PENDING"]}


@router.get("/reconciliation", dependencies=[Depends(access_workflows)])
def reconciliation(db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    """Internal approvals compared with actual provider assignments."""
    st = A.assignment_status(db)
    names = _scope_names(db)
    rows = {k: [] for k in ("UNAPPROVED", "EXPIRED_STILL_ACTIVE", "REVOCATION_PENDING")}
    for aid, v in st.items():
        if v["status"] in rows:
            rows[v["status"]].append(_assignment(db.get(AccessAssignment, aid), v, names))
    excessive = [r for r in (_assignment(db.get(AccessAssignment, aid), v, names) for aid, v in st.items() if v["status"] == "APPROVED")
                 if r["privileged"] and r["grant"] and not is_privileged(v["grant"].access_details)]
    return {"unapproved": rows["UNAPPROVED"], "expired_still_active": rows["EXPIRED_STILL_ACTIVE"], "revocation_pending": rows["REVOCATION_PENDING"],
            "approved_not_provisioned": [_grant(g, False) for g in A.missing_assignments(db)], "excessive": excessive,
            "note": "An approval record never proves the access exists, and an assignment never proves it was approved."}


# ------------------------------------------------------------------ approval register
class GrantBody(BaseModel):
    provider: str
    environment: str | None = None
    account_name: str | None = None
    scope_external_id: str
    resource_group: str | None = None
    resource_name: str | None = None
    display_name: str | None = None
    sign_in_name: str = Field(min_length=2, max_length=255)
    identity_type: str = "User"
    access_details: str = Field(min_length=2, max_length=255)
    access_scope: str = "subscription"
    manager_approved_by: str | None = None
    it_manager_approved_by: str | None = None
    access_given_date: date | None = None
    access_expiry_date: date | None = None
    email_subject: str | None = None
    approval_reference: str | None = None
    notes: str | None = None


@router.get("/register", dependencies=[Depends(access_workflows)])
def register(provider: str | None = None, status: str | None = None, q: str | None = None, expiring_days: int | None = None,
             db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    live, idents = A._index(db)
    out = []
    for g in db.scalars(select(AccessGrant).order_by(AccessGrant.grant_key)):
        if provider and g.provider != provider:
            continue
        present = any(A.matches(g, a, idents.get((a.provider, a.principal_id))) for a in live)
        d = _grant(g, present)
        if status and d["access_status"] != status:
            continue
        if expiring_days is not None and not (d["expires_in_days"] is not None and 0 <= d["expires_in_days"] <= expiring_days):
            continue
        if q and q.lower() not in " ".join(str(d.get(k) or "") for k in ("sign_in_name", "display_name", "access_details", "account_name", "account_id")).lower():
            continue
        out.append(d)
    return {"items": out, "statuses": ["Pending", "Active", "Expired", "Revoked", "Rejected"], "columns": list(A.IMPORT_COLUMNS)}


@router.post("/register", status_code=201, dependencies=[Depends(access_workflows)])
def add_record(body: GrantBody, db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    """Record an approval granted outside LV NEXUS (e.g. from the existing e-mail process). It is an approval record only."""
    if body.provider not in SCOPE_MODELS:
        raise HTTPException(422, "provider must be aws, azure or gcp")
    g = AccessGrant(grant_key=A.next_key(db, AccessGrant, AccessGrant.grant_key, "ACG"), source="import", created_by=user.email, state="APPROVED",
                    **body.model_dump())
    db.add(g)
    db.flush()
    A.audit(db, user.email, "grant.recorded", g.id)
    A.reconcile(db)
    log_action(db, user.email, "access.record", g.grant_key)
    db.commit()
    return _grant(g)


class ImportBody(BaseModel):
    csv_text: str = Field(min_length=10, max_length=5_000_000)
    default_provider: str | None = None


@router.post("/register/import", dependencies=[Depends(access_workflows)])
def import_csv(body: ImportBody, db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    result = A.import_register(db, body.csv_text, user.email, body.default_provider)
    log_action(db, user.email, "access.import", None, {"imported": result["imported"], "errors": len(result["errors"])})
    db.commit()
    return result


# ------------------------------------------------------------------ requests
class RequestBody(BaseModel):
    request_type: str
    grant_id: int | None = None
    assignment_id: int | None = None
    provider: str | None = None
    environment: str | None = None
    scope_external_id: str | None = None
    resource_group: str | None = None
    resource_name: str | None = None
    sign_in_name: str | None = None
    display_name: str | None = None
    identity_type: str = "User"
    role_name: str | None = None
    justification: str = Field(min_length=10)
    requested_expiry: date | None = None
    reason: str | None = None
    email_subject: str | None = None
    approval_reference: str | None = None


def _request(r: AccessRequest) -> dict:
    s = r.steps[r.current_step] if r.status == "PENDING" and r.current_step < len(r.steps) else None
    return {"id": r.id, "request_key": r.request_key, "request_type": r.request_type, "status": r.status, "grant_id": r.grant_id,
            "assignment_id": r.assignment_id, "steps": r.steps, "current_step": r.current_step, "waiting_for": s["label"] if s else None,
            "waiting_permission": s["permission"] if s else None, "provider": r.provider, "environment": r.environment,
            "scope_external_id": r.scope_external_id, "resource_group": r.resource_group, "sign_in_name": r.sign_in_name,
            "display_name": r.display_name, "identity_type": r.identity_type, "role_name": r.role_name, "privileged": r.privileged,
            "justification": r.justification, "requested_expiry": iso(r.requested_expiry), "reason": r.reason, "requester": r.requester,
            "email_subject": r.email_subject, "approval_reference": r.approval_reference, "executed_by": r.executed_by,
            "executed_at": iso(r.executed_at), "execution_note": r.execution_note, "verified_at": iso(r.verified_at),
            "verification_result": r.verification_result, "created_at": iso(r.created_at)}


@router.post("/requests", status_code=201, dependencies=[Depends(access_workflows)])
def create_request(body: RequestBody, db: Session = Depends(get_db), user: User = Depends(require_any("access:request", "access:manage"))):
    g = db.get(AccessGrant, body.grant_id) if body.grant_id else None
    a = db.get(AccessAssignment, body.assignment_id) if body.assignment_id else None
    if body.request_type == "grant":
        if not (body.provider and body.scope_external_id and body.sign_in_name and body.role_name):
            raise HTTPException(422, "A grant needs provider, account / subscription / project, the identity and the role")
        model = SCOPE_MODELS.get(body.provider)
        if model is None or not db.scalar(select(model.id).where(model.external_id == body.scope_external_id)):
            raise HTTPException(422, "The account / subscription / project must be in the discovered inventory")
        if body.requested_expiry is None or body.requested_expiry <= date.today():
            raise HTTPException(422, "Access needs a future expiry date")
        g = AccessGrant(grant_key=A.next_key(db, AccessGrant, AccessGrant.grant_key, "ACG"), provider=body.provider, environment=body.environment,
                        scope_external_id=body.scope_external_id, resource_group=body.resource_group, resource_name=body.resource_name,
                        display_name=body.display_name, sign_in_name=body.sign_in_name, identity_type=body.identity_type, access_details=body.role_name,
                        access_scope="resource_group" if body.resource_group else ("resource" if body.resource_name else "subscription"),
                        access_expiry_date=body.requested_expiry, email_subject=body.email_subject, state="REQUESTED", created_by=user.email,
                        notes="Awaiting approval")
        db.add(g)
        db.flush()
        target = dict(provider=g.provider, environment=g.environment, scope_external_id=g.scope_external_id, resource_group=g.resource_group,
                      resource_name=g.resource_name, sign_in_name=g.sign_in_name, display_name=g.display_name, identity_type=g.identity_type,
                      role_name=g.access_details)
    elif body.request_type == "extension":
        if g is None or g.state not in ("ACTIVE", "EXPIRED"):
            raise HTTPException(422, "Extensions apply to active (or recently expired) approved access")
        if body.requested_expiry is None or (g.access_expiry_date and body.requested_expiry <= g.access_expiry_date):
            raise HTTPException(422, "The requested expiry must be later than the current expiry")
        target = dict(provider=g.provider, environment=g.environment, scope_external_id=g.scope_external_id, resource_group=g.resource_group,
                      resource_name=g.resource_name, sign_in_name=g.sign_in_name, display_name=g.display_name, identity_type=g.identity_type,
                      role_name=g.access_details)
    elif body.request_type == "revocation":
        if body.reason not in A.REVOCATION_REASONS:
            raise HTTPException(422, f"reason must be one of {', '.join(A.REVOCATION_REASONS)}")
        if g is None and a is None:
            raise HTTPException(422, "Revocation needs an approved access record or an actual assignment")
        if g is not None:
            target = dict(provider=g.provider, environment=g.environment, scope_external_id=g.scope_external_id, resource_group=g.resource_group,
                          resource_name=g.resource_name, sign_in_name=g.sign_in_name, display_name=g.display_name, identity_type=g.identity_type,
                          role_name=g.access_details)
        else:
            ident = db.scalar(select(CloudIdentity).where(CloudIdentity.provider == a.provider, CloudIdentity.principal_id == a.principal_id))
            target = dict(provider=a.provider, environment=None, scope_external_id=a.scope_external_id, resource_group=a.resource_group,
                          resource_name=a.resource_name, sign_in_name=(ident.sign_in_name if ident and ident.sign_in_name else a.principal_id),
                          display_name=ident.display_name if ident else None, identity_type=a.principal_type, role_name=a.role_name)
    else:
        raise HTTPException(422, "request_type must be grant, extension or revocation")
    privileged = is_privileged(target["role_name"])
    r = AccessRequest(request_key=A.next_key(db, AccessRequest, AccessRequest.request_key, "ACR"), request_type=body.request_type,
                      grant_id=g.id if g else None, assignment_id=a.id if a else None, status="PENDING",
                      steps=A.chain(db, body.request_type, privileged), privileged=privileged, justification=body.justification,
                      requested_expiry=body.requested_expiry, reason=body.reason, requester=user.email, email_subject=body.email_subject,
                      approval_reference=body.approval_reference, **target)
    db.add(r)
    db.flush()
    db.add(AccessApproval(request_id=r.id, step_key="submitted", step_label="Submitted", decision="SUBMITTED", actor=user.email, notes=body.justification[:2000]))
    A.audit(db, user.email, f"request.{body.request_type}", r.grant_id, r.id, privileged=privileged)
    log_action(db, user.email, f"access_request.{body.request_type}", r.request_key)
    db.commit()
    return _request(r)


@router.get("/requests", dependencies=[Depends(access_workflows)])
def list_requests(status: str | None = None, request_type: str | None = None, awaiting_me: bool = False, db: Session = Depends(get_db),
                  user: User = Depends(require_any("access:read", "access:request"))):
    stmt = select(AccessRequest)
    if "access:read" not in user.permission_names:  # people without access:read see their own requests only
        stmt = stmt.where(or_(AccessRequest.requester == user.email, AccessRequest.sign_in_name == user.email))
    if status:
        stmt = stmt.where(AccessRequest.status == status)
    if request_type:
        stmt = stmt.where(AccessRequest.request_type == request_type)
    rows = list(db.scalars(stmt.order_by(AccessRequest.id.desc()).limit(500)))
    if awaiting_me:
        done = {r for (r,) in db.execute(select(AccessApproval.request_id).where(AccessApproval.actor == user.email, AccessApproval.decision == "APPROVED"))}
        rows = [r for r in rows if (r.status == "PENDING" and r.requester != user.email and r.id not in done
                                    and r.steps[r.current_step]["permission"] in user.permission_names)
                or (r.status == "APPROVED" and "access:manage" in user.permission_names and r.requester != user.email)]
    return {"items": [_request(r) for r in rows]}


def _get(db: Session, rid: int) -> AccessRequest:
    r = db.get(AccessRequest, rid)
    if r is None:
        raise HTTPException(404, "Request not found")
    return r


@router.get("/requests/{rid}", dependencies=[Depends(access_workflows)])
def get_request(rid: int, db: Session = Depends(get_db), user: User = Depends(require_any("access:read", "access:request"))):
    r = _get(db, rid)
    if "access:read" not in user.permission_names and user.email not in (r.requester, r.sign_in_name):
        raise HTTPException(404, "Request not found")
    hist = db.scalars(select(AccessApproval).where(AccessApproval.request_id == r.id).order_by(AccessApproval.id))
    return {**_request(r), "history": [{"step": h.step_label, "decision": h.decision, "actor": h.actor, "notes": h.notes, "evidence": h.evidence,
                                        "at": iso(h.created_at)} for h in hist]}


class DecisionBody(BaseModel):
    decision: str
    notes: str | None = Field(default=None, max_length=4000)
    evidence: str | None = Field(default=None, max_length=512)


def _err(exc: A.WorkflowError):
    msg = str(exc)
    raise HTTPException(403 if any(w in msg for w in ("permission", "segregation", "different person", "yourself", "cannot execute")) else 409, msg)


@router.post("/requests/{rid}/decision", dependencies=[Depends(access_workflows)])
def decide(rid: int, body: DecisionBody, db: Session = Depends(get_db), user: User = Depends(require_any("access:approve", "access:manage", "governance:manage"))):
    r = _get(db, rid)
    try:
        A.decide(db, r, user.email, user.permission_names, body.decision, body.notes, body.evidence)
    except A.WorkflowError as exc:
        _err(exc)
    if r.request_type == "grant" and r.status == "APPROVED":
        g = db.get(AccessGrant, r.grant_id)
        g.notes = None
    db.commit()
    return _request(r)


@router.post("/requests/{rid}/respond", dependencies=[Depends(access_workflows)])
def respond(rid: int, body: DecisionBody, db: Session = Depends(get_db), user: User = Depends(require_any("access:request", "access:manage"))):
    r = _get(db, rid)
    if r.status != "MORE_INFO" or r.requester != user.email or not (body.notes or "").strip():
        raise HTTPException(409, "Only the requester can answer an information request, with notes")
    db.add(AccessApproval(request_id=r.id, step_key=r.steps[r.current_step]["key"], step_label="Information provided", decision="INFO_PROVIDED",
                          actor=user.email, notes=body.notes))
    r.status = "PENDING"
    db.commit()
    return _request(r)


@router.post("/requests/{rid}/execute", dependencies=[Depends(access_workflows)])
def execute(rid: int, body: DecisionBody, db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    """Record that the change was made in the provider by an authorized administrator. Verification follows."""
    r = _get(db, rid)
    if not (body.notes or "").strip():
        raise HTTPException(422, "Describe what was changed in the provider (and where)")
    try:
        A.execute(db, r, user.email, body.notes)
    except A.WorkflowError as exc:
        _err(exc)
    log_action(db, user.email, "access_request.executed", r.request_key)
    db.commit()
    return _request(r)


@router.post("/requests/{rid}/withdraw", dependencies=[Depends(access_workflows)])
def withdraw(rid: int, db: Session = Depends(get_db), user: User = Depends(require_any("access:request", "access:manage"))):
    r = _get(db, rid)
    if r.requester != user.email or r.status not in ("PENDING", "MORE_INFO"):
        raise HTTPException(409, "Only the requester can withdraw a pending request")
    r.status = "WITHDRAWN"
    db.add(AccessApproval(request_id=r.id, step_key="withdrawn", step_label="Withdrawn", decision="WITHDRAWN", actor=user.email))
    db.commit()
    return _request(r)


@router.post("/reconcile", dependencies=[Depends(access_workflows)])
def reconcile_now(db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    """Re-run verification against the inventory already collected (no cloud call)."""
    res = A.reconcile(db)
    db.commit()
    return res


# ------------------------------------------------------------------ reviews
class ReviewBody(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    provider: str | None = None
    scope_external_id: str | None = None
    privileged_only: bool = False
    reviewer: str = Field(min_length=3, max_length=255)
    due_date: date


class ItemDecision(BaseModel):
    decision: str
    comment: str | None = Field(default=None, max_length=4000)
    remediation_owner: str | None = None


@router.post("/reviews", status_code=201, dependencies=[Depends(access_workflows)])
def create_review(body: ReviewBody, db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    stmt = select(AccessAssignment).where(AccessAssignment.removed_at.is_(None))
    if body.provider:
        stmt = stmt.where(AccessAssignment.provider == body.provider)
    if body.scope_external_id:
        stmt = stmt.where(AccessAssignment.scope_external_id == body.scope_external_id)
    if body.privileged_only:
        stmt = stmt.where(AccessAssignment.privileged.is_(True))
    rows = list(db.scalars(stmt))
    if not rows:
        raise HTTPException(409, "No collected assignments match this review scope")
    rv = AccessReview(**body.model_dump(), created_by=user.email)
    db.add(rv)
    db.flush()
    st = A.assignment_status(db)
    names = _scope_names(db)
    for a in rows:
        db.add(AccessReviewItem(review_id=rv.id, assignment_id=a.id, snapshot=_assignment(a, st.get(a.id), names) | {"grant": None}))
    A.audit(db, user.email, "review.created", None, None, review=rv.id, items=len(rows))
    db.commit()
    return {"id": rv.id, "items": len(rows)}


@router.get("/reviews", dependencies=[Depends(access_workflows)])
def list_reviews(db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    out = []
    for rv in db.scalars(select(AccessReview).order_by(AccessReview.id.desc())):
        items = list(db.scalars(select(AccessReviewItem).where(AccessReviewItem.review_id == rv.id)))
        out.append({"id": rv.id, "name": rv.name, "reviewer": rv.reviewer, "due_date": iso(rv.due_date), "status": rv.status,
                    "items": len(items), "decided": sum(1 for i in items if i.decision), "overdue": rv.status == "OPEN" and rv.due_date < date.today(),
                    "decisions": dict(Counter(i.decision or "PENDING" for i in items)), "created_by": rv.created_by})
    return {"items": out}


@router.get("/reviews/{review_id}", dependencies=[Depends(access_workflows)])
def get_review(review_id: int, db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    rv = db.get(AccessReview, review_id)
    if rv is None:
        raise HTTPException(404, "Review not found")
    items = db.scalars(select(AccessReviewItem).where(AccessReviewItem.review_id == rv.id).order_by(AccessReviewItem.id))
    return {"id": rv.id, "name": rv.name, "reviewer": rv.reviewer, "due_date": iso(rv.due_date), "status": rv.status,
            "items": [{"id": i.id, "assignment": i.snapshot, "decision": i.decision, "comment": i.comment, "remediation_owner": i.remediation_owner,
                       "decided_by": i.decided_by, "decided_at": iso(i.decided_at), "follow_up_request_id": i.follow_up_request_id} for i in items]}


@router.post("/reviews/{review_id}/items/{item_id}", dependencies=[Depends(access_workflows)])
def decide_item(review_id: int, item_id: int, body: ItemDecision, db: Session = Depends(get_db),
                user: User = Depends(require_any("access:manage", "access:approve"))):
    rv = db.get(AccessReview, review_id)
    it = db.get(AccessReviewItem, item_id)
    if rv is None or it is None or it.review_id != rv.id:
        raise HTTPException(404, "Review item not found")
    if rv.status != "OPEN":
        raise HTTPException(409, "This review is completed")
    if user.email != rv.reviewer and "access:manage" not in user.permission_names:
        raise HTTPException(403, "Only the assigned reviewer can record decisions")
    if body.decision not in ("KEEP", "REMOVE", "REDUCE", "INVESTIGATE"):
        raise HTTPException(422, "decision must be KEEP, REMOVE, REDUCE or INVESTIGATE")
    if body.decision != "KEEP" and not (body.comment or "").strip():
        raise HTTPException(422, "A comment is required unless the access is confirmed")
    it.decision, it.comment, it.remediation_owner, it.decided_by, it.decided_at = body.decision, body.comment, body.remediation_owner, user.email, A.now()
    if body.decision in ("REMOVE", "REDUCE") and it.follow_up_request_id is None:
        a = db.get(AccessAssignment, it.assignment_id)
        ident = db.scalar(select(CloudIdentity).where(CloudIdentity.provider == a.provider, CloudIdentity.principal_id == a.principal_id))
        r = AccessRequest(request_key=A.next_key(db, AccessRequest, AccessRequest.request_key, "ACR"), request_type="revocation", assignment_id=a.id,
                          status="PENDING", steps=A.chain(db, "revocation", a.privileged), privileged=a.privileged, provider=a.provider,
                          scope_external_id=a.scope_external_id, resource_group=a.resource_group, resource_name=a.resource_name,
                          sign_in_name=(ident.sign_in_name if ident and ident.sign_in_name else a.principal_id), display_name=ident.display_name if ident else None,
                          identity_type=a.principal_type, role_name=a.role_name, reason="review", requester=user.email,
                          justification=f"Access review '{rv.name}': {body.decision.lower()} - {body.comment}")
        db.add(r)
        db.flush()
        it.follow_up_request_id = r.id
    A.audit(db, user.email, "review.decision", None, it.follow_up_request_id, review=rv.id, item=it.id, decision=body.decision)
    db.commit()
    return {"id": it.id, "decision": it.decision, "follow_up_request_id": it.follow_up_request_id}


@router.post("/reviews/{review_id}/complete", dependencies=[Depends(access_workflows)])
def complete_review(review_id: int, db: Session = Depends(get_db), user: User = Depends(require_any("access:manage", "access:approve"))):
    rv = db.get(AccessReview, review_id)
    if rv is None:
        raise HTTPException(404, "Review not found")
    open_items = db.scalar(select(func.count()).select_from(AccessReviewItem).where(AccessReviewItem.review_id == rv.id, AccessReviewItem.decision.is_(None)))
    if open_items:
        raise HTTPException(409, f"{open_items} item(s) still need a decision")
    rv.status, rv.completed_at = "COMPLETED", A.now()
    A.audit(db, user.email, "review.completed", None, None, review=rv.id)
    db.commit()
    return {"status": "COMPLETED"}


@router.get("/history", dependencies=[Depends(access_workflows)])
def history(limit: int = 200, db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    return {"items": [{"action": e.action, "actor": e.actor, "grant_id": e.grant_id, "request_id": e.request_id, "detail": e.detail,
                       "at": iso(e.created_at)} for e in db.scalars(select(AccessAuditEvent).order_by(AccessAuditEvent.id.desc()).limit(min(limit, 1000)))]}

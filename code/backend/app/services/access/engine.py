"""Access inventory storage, approval-vs-actual reconciliation, and the access request workflow.

- Actual assignments are written only by the collectors. A scope whose collection was incomplete never has
  assignments marked removed.
- A grant becomes ACTIVE only when a matching provider assignment is observed; a revocation becomes REVOKED only when
  the assignment is no longer returned. Recording "executed" by an administrator is not proof.
- LV NEXUS never grants or revokes cloud access itself: execution is done by an authorized administrator in the
  provider, then verified against the next inventory."""
from __future__ import annotations

import csv
import io
import logging
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import JobStatus
from app.models.access import AccessApproval, AccessAssignment, AccessAuditEvent, AccessGrant, AccessRequest, CloudIdentity
from app.models.budget import ApprovalWorkflow
from app.scheduler.engine import JobContext, JobResult
from app.services import reliability as rel  # noqa: E402
from app.services.access.collectors import AwsIamCollector, AzureRbacCollector, Found, GcpIamCollector, Result, h, is_privileged
from app.services.scopes import check_passed, eligible_scopes

log = logging.getLogger(__name__)
STEP = {
    "manager": ("Business manager approval", "access:approve"),
    "it_manager": ("IT manager / cloud approver", "access:manage"),
    "privileged": ("Privileged access approval (governance)", "governance:manage"),
}
DEFAULT_CHAINS = {"access_grant": ["manager", "it_manager"], "access_grant_privileged": ["manager", "it_manager", "privileged"],
                  "access_extension": ["manager", "it_manager"], "access_revocation": ["it_manager"]}
VERIFY_WINDOW_HOURS = 48
# stored under a subscription / account / project but written by a separate collector pass
SUPPLEMENTARY_SOURCES = ("azure_pim_eligible", "aws_iam_inline", "gcp_iam_inherited", "aws_resource_policy", "gcp_resource_iam")
REVOCATION_REASONS = ("expired", "offboarding", "project_completed", "unapproved", "excessive", "inactive", "security_incident", "review")


def now() -> datetime:
    return datetime.now(UTC)


def audit(db: Session, actor: str, action: str, grant_id: int | None = None, request_id: int | None = None, **detail) -> None:
    db.add(AccessAuditEvent(actor=actor, action=action, grant_id=grant_id, request_id=request_id,
                            detail={k: (v.isoformat() if isinstance(v, (date, datetime)) else v) for k, v in detail.items()}))


def next_key(db: Session, model, column, prefix: str) -> str:
    n = (db.scalar(select(func.count()).select_from(model)) or 0) + 1
    while db.scalar(select(model.id).where(column == f"{prefix}-{n:04d}")):
        n += 1
    return f"{prefix}-{n:04d}"


# ------------------------------------------------------------------ inventory
def store(db: Session, provider: str, scope_id: str, res: Result, sources: set[str] | None = None) -> dict:
    """Upsert one scope's assignments. `sources` limits which stored rows this result is authoritative for (a scope can be
    filled by several collectors: RBAC, PIM eligibility, inline policies, inherited bindings)."""
    t = now()
    q = select(AccessAssignment).where(AccessAssignment.provider == provider, AccessAssignment.scope_external_id == scope_id)
    if sources is not None:
        q = q.where(AccessAssignment.source.in_(sources))
    elif provider in ("azure", "aws", "gcp"):
        q = q.where(AccessAssignment.source.not_in(SUPPLEMENTARY_SOURCES))
    existing = {a.source_id_hash: a for a in db.scalars(q)}
    seen, new = set(), 0
    for f in res.assignments:
        key = h(f.source, f.source_id)
        if key in seen:
            continue
        seen.add(key)
        a = existing.get(key)
        if a is None:
            a = AccessAssignment(provider=provider, source=f.source, source_id=f.source_id, source_id_hash=key, scope_external_id=scope_id, first_seen_at=t)
            db.add(a)
            new += 1
        a.scope_level, a.scope_path, a.resource_group, a.resource_name = f.scope_level, f.scope_path, f.resource_group, f.resource_name
        a.principal_id, a.principal_type, a.role_name, a.role_id = f.principal_id, f.principal_type, f.role_name[:255], f.role_id
        a.access_type, a.condition, a.pim_state, a.privileged = f.access_type, f.condition, f.pim_state, is_privileged(f.role_name)
        a.inherited_from, a.expires_at = f.inherited_from, f.expires_at
        a.last_seen_at, a.removed_at = t, None
        ident = db.scalar(select(CloudIdentity).where(CloudIdentity.provider == provider, CloudIdentity.principal_id == f.principal_id[:255]))
        if ident is None:
            ident = CloudIdentity(provider=provider, principal_id=f.principal_id[:255], principal_type=f.principal_type, first_seen_at=t)
            db.add(ident)
            db.flush()
        if f.principal_type != "Unknown" or not ident.principal_type:
            ident.principal_type = f.principal_type
        elif ident.principal_type != "Unknown":
            a.principal_type = ident.principal_type  # directory knows the type (Entra role assignments do not say)
        ident.last_seen_at = t
        if f.display_name:
            ident.display_name = f.display_name[:255]
        if f.sign_in_name:
            ident.sign_in_name = f.sign_in_name[:255]
    removed = 0
    if res.complete:  # only a complete collection can show that an assignment is gone
        for key, a in existing.items():
            if key not in seen and a.removed_at is None:
                a.removed_at = t
                removed += 1
    return {"assignments": len(seen), "new": new, "removed": removed, "complete": res.complete}


def run_access_inventory(ctx: JobContext, settings: Settings, connectors: dict) -> JobResult:
    db = ctx.db
    summary: dict = {"by_provider": {}, "coverage": {}}
    failures, total, failed = [], 0, 0
    collectors = []
    if "azure" in connectors:
        collectors.append(AzureRbacCollector(connectors["azure"]))
    if "aws" in connectors:
        collectors.append(AwsIamCollector(connectors["aws"]))
    if "gcp" in connectors:
        collectors.append(GcpIamCollector(connectors["gcp"]))
    from app.services.access import lifecycle as lc
    before = {c.provider: lc.snapshot(db, c.provider) for c in collectors}
    complete: dict[str, set[str]] = {c.provider: set() for c in collectors}
    for c in collectors:
        info = summary["by_provider"].setdefault(c.provider, {"scopes": 0, "assignments": 0, "removed": 0})
        ic = c.identity_center() if c.provider == "aws" else {}
        for scope in eligible_scopes(db, c.provider):
            total += 1
            if not check_passed(scope, "permissions"):
                failed += 1
                failures.append({"provider": c.provider, "scope": scope.external_id, "reason": "Read permissions not validated"})
                continue
            _skip = rel.scope_gate(c.provider)
            if _skip:
                failed += 1
                failures.append({"provider": c.provider, "scope": scope.external_id, "reason": _skip})
                continue
            try:
                res = c.collect(scope.external_id, scope.is_management) if c.provider == "aws" else c.collect(scope.external_id)
                if c.provider == "aws":
                    extra = ic.get(scope.external_id)
                    if extra:
                        res.assignments += extra.assignments
                        res.coverage += extra.coverage
                    if "*" in ic:
                        res.coverage += ic["*"].coverage
                stats = store(db, c.provider, scope.external_id, res)
                db.commit()
                rel.scope_ok(c.provider)
                summary["coverage"][f"{c.provider}:{scope.external_id}"] = res.coverage
                info["scopes"] += 1
                info["assignments"] += stats["assignments"]
                info["removed"] += stats["removed"]
                if res.complete:
                    complete[c.provider].add(scope.external_id)
                if not res.complete:
                    failed += 1
                    failures.append({"provider": c.provider, "scope": scope.external_id,
                                     "reason": "; ".join(f"{x['source']}: {x['message']}" for x in res.coverage if x["state"] != "OK")})
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                failed += 1
                failures.append({"provider": c.provider, "scope": scope.external_id, "reason": rel.scope_failed(c.provider, exc)})
    try:
        summary["directory"] = run_directories(db, settings, connectors, complete, failures)
    except Exception as exc:  # noqa: BLE001 - directory enrichment failing must not lose the RBAC inventory
        db.rollback()
        failures.append({"provider": "*", "scope": "directory", "reason": safe_error(exc)})
    try:
        from app.services.access.resource_iam import run_resource_access
        run_resource_access(db, settings, connectors, complete, summary, failures)
    except Exception as exc:  # noqa: BLE001 - resource-level access failing must not lose the account-level inventory
        db.rollback()
        failures.append({"provider": "*", "scope": "resource_access", "reason": safe_error(exc)})
    summary["changes"] = {p: lc.diff_assignments(db, p, before[p], complete[p]) for p in before}
    summary["effective_rows"] = lc.rebuild_effective(db)
    summary["reconciliation"] = reconcile(db)
    summary["revocations_verified"] = lc.verify_plans(db)
    lc.refresh_status(db)
    summary["exceptions"] = lc.compute_exceptions(db)
    summary["reminders"] = expiry_reminders(db)
    summary["alerts"] = lifecycle_alerts(db)
    db.commit()
    if total == 0:
        failures.append({"provider": "*", "scope": "*", "reason": "No onboarded scope with validated read permissions"})
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures)
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if failed == total else JobStatus.PARTIAL
    return JobResult(status, total, failed, summary, failures)


DIRECTORY_KEY_SOURCES = {"tenant": ("entra_directory_roles", "entra_pim_eligible"), "mg": ("azure_management_groups",),
                         "org": ("gcp_org_iam",), "folder": ("gcp_folder_iam",)}


def _key_complete(d, key: str) -> bool:
    bad = {c["source"] for c in d.coverage if c["state"] != "OK"}
    prefix = key.split(":", 1)[0] if ":" in key else None
    if prefix in DIRECTORY_KEY_SOURCES:
        return not (bad & set(DIRECTORY_KEY_SOURCES[prefix]))
    if d.provider == "azure":
        return f"azure_pim_eligible:{key}" not in bad
    if d.provider == "aws":
        return not (bad & {"aws_iam_users", "aws_iam_roles", "aws_iam_directory"})
    return not bad


def _store_directory(db: Session, d, complete: set[str], sources: set[str] | None = None) -> None:
    for key, res in d.assignments.items():
        res.complete = _key_complete(d, key)
        is_scope = ":" not in key
        store(db, d.provider, key, res, sources if is_scope else None)
        if res.complete:
            complete.add(key)


def run_directories(db: Session, settings: Settings, connectors: dict, complete: dict[str, set[str]], failures: list) -> dict:
    """Directory objects, hierarchy-level assignments, PIM eligibility, credentials and group membership."""
    from app.services.access import lifecycle as lc
    from app.services.access.directory import AwsDirectory, AzureDirectory, GcpDirectory
    out: dict = {}

    def note(d):
        from app.services.azure.permissions import fix_for_source
        for c in d.coverage:
            if c["state"] != "OK":
                fix = fix_for_source(settings, c["source"], c.get("message")) if d.provider == "azure" else None
                if fix:
                    c["fix"] = fix
                what = "unavailable – missing permission" if c["state"] == "ACCESS_DENIED" else "failed"
                failures.append({"provider": d.provider, "scope": d.directory_scope,
                                 "reason": f"{c['source']}: {what}: {str(c.get('message', ''))[:160]}" + (f" Fix: {fix}" if fix else "")})
        out.setdefault(d.provider, []).append({"directory": d.directory_scope, "coverage": d.coverage})

    if "azure" in connectors:
        subs = [s.external_id for s in eligible_scopes(db, "azure") if check_passed(s, "permissions")]
        groups = {a.principal_id for a in db.scalars(select(AccessAssignment).where(
            AccessAssignment.provider == "azure", AccessAssignment.principal_type == "Group", AccessAssignment.removed_at.is_(None)))}
        d = AzureDirectory(settings).collect(subs, groups)
        _store_directory(db, d, complete.setdefault("azure", set()), {"azure_pim_eligible"})
        lc.apply_directory(db, d)
        note(d)
        db.commit()
    if "aws" in connectors:
        ad = AwsDirectory(connectors["aws"])
        for scope in eligible_scopes(db, "aws"):
            if not check_passed(scope, "permissions"):
                continue
            d = ad.collect(scope.external_id, scope.is_management)
            _store_directory(db, d, complete.setdefault("aws", set()), {"aws_iam_inline"})
            lc.apply_directory(db, d)
            note(d)
            db.commit()
        d = ad.identity_center()
        lc.apply_directory(db, d)
        note(d)
        db.commit()
    if "gcp" in connectors:
        projects = [p for p in eligible_scopes(db, "gcp") if check_passed(p, "permissions")]
        d, chains = GcpDirectory(settings, connectors["gcp"]).collect(projects)
        _store_directory(db, d, complete.setdefault("gcp", set()))
        org_key = f"org:{settings.gcp_organization_id}"
        for pid, chain in chains.items():
            inherited = Result()
            keys = [f"folder:{c.split('/')[-1]}" if c.startswith("folders/") else org_key for c in chain]
            inherited.complete = all(_key_complete(d, k) for k in keys)
            for k in keys:
                for f in d.assignments.get(k, Result()).assignments:
                    inherited.assignments.append(Found("gcp_iam_inherited", f"{f.source_id}|via:{pid}", "project", f"projects/{pid}", f.principal_id,
                                                       f.principal_type, f.role_name, f.role_id, "Inherited", condition=f.condition,
                                                       display_name=f.display_name, sign_in_name=f.sign_in_name, inherited_from=f.scope_path))
            store(db, "gcp", pid, inherited, {"gcp_iam_inherited"})
            if inherited.complete:
                complete["gcp"].add(pid)
        lc.apply_directory(db, d)
        note(d)
        db.commit()
    return out


def lifecycle_alerts(db: Session) -> int:
    """Alerts (deduplicated per change) for new privileged access, deleted identities that still hold access, and
    privileged changes without an approval."""
    from app.models.iam import IamException, IdentityChangeEvent
    from app.services.vuln.notify import notify
    n = 0
    since = now() - timedelta(hours=26)
    for ev in db.scalars(select(IdentityChangeEvent).where(IdentityChangeEvent.detected_at >= since, IdentityChangeEvent.privileged.is_(True),
                                                           IdentityChangeEvent.change_type.in_(["PERMISSION_ADDED", "ROLE_CHANGED"]))):
        role = (ev.new_state or {}).get("role")
        if notify(db, "iam_privileged_change", f"chg:{ev.id}", f"[LV NEXUS] Privileged access added: {ev.principal_name or ev.principal_id}",
                  f"{ev.principal_name or ev.principal_id} now holds {role} at {(ev.new_state or {}).get('scope')} ({ev.provider}). "
                  f"Approval: {ev.approval_reference or 'none found'}. Initiated by: {ev.initiated_by or 'not identified from audit logs'}. "
                  "Review in Cloud Access Management > IAM change audit trail. Nothing has been changed in the cloud."):
            n += 1
    for e in db.scalars(select(IamException).where(IamException.category == "DELETED_IDENTITY_WITH_ACCESS", IamException.status == "OPEN")):
        if notify(db, "iam_deleted_with_access", e.exception_key, f"[LV NEXUS] Deleted / disabled identity still has access: {e.principal_name or e.principal_id}",
                  f"{e.actual}. Create a revocation plan in Cloud Access Management > Deleted / disabled identities ({e.exception_key})."):
            n += 1
    return n


# ------------------------------------------------------------------ reconciliation
def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def matches(grant: AccessGrant, a: AccessAssignment, ident: CloudIdentity | None) -> bool:
    if grant.provider != a.provider or grant.scope_external_id != a.scope_external_id or _norm(grant.access_details) != _norm(a.role_name):
        return False
    if grant.resource_group and _norm(grant.resource_group) != _norm(a.resource_group):
        return False
    names = {_norm(a.principal_id)} | ({_norm(ident.sign_in_name), _norm(ident.display_name)} if ident else set())
    names.discard("")
    return _norm(grant.principal_id) in names or _norm(grant.sign_in_name) in names or any(_norm(grant.sign_in_name) == n.split(":", 1)[-1] for n in names)


def _index(db: Session):
    live = list(db.scalars(select(AccessAssignment).where(AccessAssignment.removed_at.is_(None))))
    idents = {(i.provider, i.principal_id): i for i in db.scalars(select(CloudIdentity))}
    return live, idents


def reconcile(db: Session, today: date | None = None) -> dict:
    """Advance grants from what the provider shows, and classify every live assignment. Returns counts."""
    today = today or now().date()
    live, idents = _index(db)
    grants = list(db.scalars(select(AccessGrant).where(AccessGrant.state.not_in(["REJECTED", "REQUESTED"]))))
    changed = 0
    for g in grants:
        present = [a for a in live if matches(g, a, idents.get((a.provider, a.principal_id)))]
        if present and not g.principal_id:
            g.principal_id = present[0].principal_id
        if g.state in ("APPROVED", "PROVISIONED") and present:
            g.state, g.verified_at = "ACTIVE", now()
            changed += 1
        elif g.state == "REVOKE_REQUESTED" and not present:
            g.state, g.access_revocation_date, g.verified_at = "REVOKED", today, now()
            changed += 1
        if g.state == "ACTIVE" and g.access_expiry_date and g.access_expiry_date < today:
            g.state = "EXPIRED"
            changed += 1
    # requests waiting for verification
    for r in db.scalars(select(AccessRequest).where(AccessRequest.status == "EXECUTED")):
        g = db.get(AccessGrant, r.grant_id) if r.grant_id else None
        if r.request_type == "revocation":
            a = db.get(AccessAssignment, r.assignment_id) if r.assignment_id else None
            gone = (a is not None and a.removed_at is not None) or (g is not None and not any(matches(g, x, idents.get((x.provider, x.principal_id))) for x in live))
            if gone:
                r.status, r.verified_at, r.verification_result = "VERIFIED", now(), "The assignment is no longer returned by the provider."
                if g is not None:
                    g.state, g.access_revocation_date, g.verified_at = "REVOKED", today, now()
        elif g is not None and any(matches(g, x, idents.get((x.provider, x.principal_id))) for x in live):
            r.status, r.verified_at = "VERIFIED", now()
            r.verification_result = ("Assignment observed in the provider." if r.request_type == "grant" else
                                     "Assignment still present; the approved expiry date is recorded here (provider RBAC has no expiry unless PIM is used).")
            if g.state in ("APPROVED", "PROVISIONED"):
                g.state, g.verified_at = "ACTIVE", now()
        if r.status == "EXECUTED" and r.executed_at and r.executed_at < now() - timedelta(hours=VERIFY_WINDOW_HOURS):
            r.status = "VERIFICATION_FAILED"
            r.verification_result = f"Not observed in the provider inventory within {VERIFY_WINDOW_HOURS} hours of execution."
    return {"grants_updated": changed}


def assignment_status(db: Session, today: date | None = None) -> dict[int, dict]:
    """For each live assignment: approval status and the matching grant."""
    today = today or now().date()
    live, idents = _index(db)
    grants = list(db.scalars(select(AccessGrant).where(AccessGrant.state.not_in(["REJECTED", "REVOKED", "REQUESTED"]))))
    out = {}
    for a in live:
        ident = idents.get((a.provider, a.principal_id))
        g = next((g for g in grants if matches(g, a, ident)), None)
        if g is None:
            st = "UNAPPROVED"
        elif g.state == "REVOKE_REQUESTED":
            st = "REVOCATION_PENDING"
        elif g.access_expiry_date and g.access_expiry_date < today:
            st = "EXPIRED_STILL_ACTIVE"
        else:
            st = "APPROVED"
        out[a.id] = {"status": st, "grant": g, "identity": ident}
    return out


def missing_assignments(db: Session) -> list[AccessGrant]:
    """Approved / provisioned grants not (yet) observed in the provider."""
    live, idents = _index(db)
    return [g for g in db.scalars(select(AccessGrant).where(AccessGrant.state.in_(["APPROVED", "PROVISIONED"])))
            if not any(matches(g, a, idents.get((a.provider, a.principal_id))) for a in live)]


def expiry_reminders(db: Session) -> int:
    from app.services.vuln.notify import notify
    soon = now().date() + timedelta(days=7)
    n = 0
    for g in db.scalars(select(AccessGrant).where(AccessGrant.state == "ACTIVE", AccessGrant.access_expiry_date.is_not(None),
                                                  AccessGrant.access_expiry_date <= soon)):
        if notify(db, "access_expiry", f"{g.grant_key}:{g.access_expiry_date}", f"[LV NEXUS] Access expires {g.access_expiry_date}: {g.sign_in_name}",
                  f"{g.sign_in_name} has {g.access_details} on {g.provider} {g.scope_external_id} until {g.access_expiry_date}. "
                  "Request an extension or a revocation in Cloud Access Management. Nothing has been changed in the cloud."):
            n += 1
    return n


# ------------------------------------------------------------------ workflow
def seed_access_defaults(db: Session) -> None:
    existing = {w.request_type for w in db.scalars(select(ApprovalWorkflow))}
    for rtype, keys in DEFAULT_CHAINS.items():
        if rtype not in existing:
            db.add(ApprovalWorkflow(request_type=rtype, min_amount_usd=0, steps=[step(k) for k in keys], updated_by="system default"))
    from app.models import NotificationRule
    for event_type, desc in (("access_expiry", "Approved cloud access expiring within 7 days"),
                             ("iam_privileged_change", "Privileged cloud access added or changed (new admin, owner, editor ...)"),
                             ("iam_deleted_with_access", "Deleted or disabled identity that still holds cloud access"),
                             ("connection_failure", "Cloud connection or synchronization failure")):
        if db.scalar(select(NotificationRule).where(NotificationRule.event_type == event_type)) is None:
            db.add(NotificationRule(event_type=event_type, description=desc, enabled=True, channels="email,google_chat", updated_by="system default"))


def step(key: str, label: str | None = None) -> dict:
    d_label, perm = STEP[key]
    return {"key": key, "label": label or d_label, "permission": perm}


def chain(db: Session, request_type: str, privileged: bool) -> list[dict]:
    key = {"grant": "access_grant_privileged" if privileged else "access_grant", "extension": "access_extension",
           "revocation": "access_revocation"}[request_type]
    w = db.scalar(select(ApprovalWorkflow).where(ApprovalWorkflow.request_type == key, ApprovalWorkflow.enabled.is_(True)))
    return w.steps if w else [step(k) for k in DEFAULT_CHAINS[key]]


class WorkflowError(ValueError):
    pass


def decide(db: Session, r: AccessRequest, actor: str, perms: set[str], decision: str, notes: str | None, evidence: str | None) -> None:
    if r.status != "PENDING":
        raise WorkflowError(f"Request is {r.status.lower().replace('_', ' ')}")
    if actor == r.requester:
        raise WorkflowError("The requester cannot approve their own request (segregation of duties)")
    if actor.lower() == r.sign_in_name.lower():
        raise WorkflowError("You cannot approve access for yourself")
    s = r.steps[r.current_step]
    if s["permission"] not in perms:
        raise WorkflowError(f"{s['label']} requires the permission {s['permission']}")
    if any(a.actor == actor for a in db.scalars(select(AccessApproval).where(AccessApproval.request_id == r.id, AccessApproval.decision == "APPROVED"))):
        raise WorkflowError("You have already approved another step of this request; a different person must approve this step")
    if decision not in ("APPROVED", "REJECTED", "MORE_INFO"):
        raise WorkflowError("decision must be APPROVED, REJECTED or MORE_INFO")
    if decision != "APPROVED" and not (notes or "").strip():
        raise WorkflowError("Notes are required to reject or to ask for more information")
    db.add(AccessApproval(request_id=r.id, step_key=s["key"], step_label=s["label"], decision=decision, actor=actor, notes=notes, evidence=evidence))
    audit(db, actor, f"request.{decision.lower()}", r.grant_id, r.id, step=s["key"])
    if decision == "REJECTED":
        r.status = "REJECTED"
        if r.request_type == "grant" and r.grant_id:
            db.get(AccessGrant, r.grant_id).state = "REJECTED"
        return
    if decision == "MORE_INFO":
        r.status = "MORE_INFO"
        return
    if s["key"] == "manager":
        _set_approver(db, r, "manager_approved_by", actor)
    elif s["key"] == "it_manager":
        _set_approver(db, r, "it_manager_approved_by", actor)
    r.current_step += 1
    if r.current_step >= len(r.steps):
        _approved(db, r, actor)


def _set_approver(db: Session, r: AccessRequest, field: str, actor: str) -> None:
    if r.request_type == "grant" and r.grant_id:
        setattr(db.get(AccessGrant, r.grant_id), field, actor)


def _approved(db: Session, r: AccessRequest, actor: str) -> None:
    """Approval complete: the request now waits for an administrator to make the change in the provider."""
    r.status = "APPROVED"
    g = db.get(AccessGrant, r.grant_id) if r.grant_id else None
    if r.request_type == "grant" and g is not None:
        g.state = "APPROVED"
        g.approval_reference = g.approval_reference or r.request_key
    elif r.request_type == "extension" and g is not None:
        g.access_expiry_date, g.access_extended_date = r.requested_expiry, now().date()
        if g.state == "EXPIRED":
            g.state = "ACTIVE"
        audit(db, actor, "grant.extended", g.id, r.id, new_expiry=r.requested_expiry)
    elif r.request_type == "revocation" and g is not None:
        g.state = "REVOKE_REQUESTED"


def execute(db: Session, r: AccessRequest, actor: str, note: str) -> None:
    """An administrator records that they made the change in the provider. Verification follows from the inventory."""
    if r.status != "APPROVED":
        raise WorkflowError("Only approved requests can be marked as executed")
    if actor == r.requester:
        raise WorkflowError("The requester cannot execute their own request")
    r.status, r.executed_by, r.executed_at, r.execution_note = "EXECUTED", actor, now(), note
    if r.request_type == "grant" and r.grant_id:
        g = db.get(AccessGrant, r.grant_id)
        g.state = "PROVISIONED"
        g.access_given_date = g.access_given_date or now().date()
    db.add(AccessApproval(request_id=r.id, step_key="execution", step_label="Executed in provider", decision="EXECUTED", actor=actor, notes=note))
    audit(db, actor, "request.executed", r.grant_id, r.id)
    reconcile(db)


# ------------------------------------------------------------------ business register import
IMPORT_COLUMNS = {"cloud provider": "provider", "environment": "environment", "env": "environment", "account name": "account_name",
                  "account id": "scope_external_id", "subscription id": "scope_external_id", "resource group": "resource_group",
                  "resource name": "resource_name", "displayname": "display_name", "display name": "display_name",
                  "access details": "access_details", "role": "access_details", "signinname": "sign_in_name", "sign in name": "sign_in_name",
                  "identity type": "identity_type", "access scope": "access_scope", "manager approved by": "manager_approved_by",
                  "it manager approved by": "it_manager_approved_by", "access given date": "access_given_date",
                  "access extended date": "access_extended_date", "access expiry date": "access_expiry_date",
                  "access revocation date": "access_revocation_date", "email subject": "email_subject", "approval reference": "approval_reference"}
DATE_FIELDS = {"access_given_date", "access_extended_date", "access_expiry_date", "access_revocation_date"}


def _parse_date(v: str) -> date | None:
    v = (v or "").strip()
    if not v:
        return None
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%m/%d/%Y", "%d-%b-%Y", "%d %b %Y"):
        try:
            return datetime.strptime(v, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"unrecognised date {v!r}")


def import_register(db: Session, text: str, actor: str, default_provider: str | None = None) -> dict:
    """Import the existing business access-tracking sheet (CSV). Imported rows are approval records only: they become
    ACTIVE only when the provider shows a matching assignment."""
    reader = csv.DictReader(io.StringIO(text))
    created, errors = 0, []
    for i, row in enumerate(reader, start=2):
        rec = {}
        for k, v in row.items():
            field = IMPORT_COLUMNS.get((k or "").strip().lower())
            if field:
                rec[field] = (v or "").strip()
        try:
            for f in DATE_FIELDS & rec.keys():
                rec[f] = _parse_date(rec[f])
            rec["provider"] = (rec.get("provider") or default_provider or "").lower()
            if rec["provider"] not in ("aws", "azure", "gcp"):
                raise ValueError("cloud provider must be AWS, Azure or GCP")
            for need in ("scope_external_id", "sign_in_name", "access_details"):
                if not rec.get(need):
                    raise ValueError(f"missing {need.replace('_', ' ')}")
        except ValueError as exc:
            errors.append({"row": i, "error": str(exc)})
            continue
        state = "REVOKED" if rec.get("access_revocation_date") else "APPROVED"
        g = AccessGrant(grant_key=next_key(db, AccessGrant, AccessGrant.grant_key, "ACG"), source="import", created_by=actor, state=state,
                        **{k: (v or None) for k, v in rec.items() if k not in ("provider",)}, provider=rec["provider"])
        g.identity_type = g.identity_type or "User"
        g.access_scope = g.access_scope or ("resource_group" if g.resource_group else "subscription")
        db.add(g)
        db.flush()
        audit(db, actor, "grant.imported", g.id, row=i)
        created += 1
    summary = reconcile(db)
    return {"imported": created, "errors": errors, **summary}

"""Identity lifecycle, permission-change detection, effective access, revocation plans and reconciliation exceptions.

Rules that keep this honest:
- Change events are derived only by comparing two inventories. The very first inventory of a directory or a provider is a
  baseline: nothing in it is reported as "new" except identities whose provider creation date is within 30 days.
- "Deleted" needs a complete identity listing in which the identity is absent; a failed or partial listing changes nothing.
- A revocation plan never executes anything. Items are verified against the next complete inventory.
- Shared and service identities are never placed in a plan as automatic removals: they are listed for human review."""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.models.access import AccessAssignment, AccessGrant, CloudIdentity
from app.models.iam import (
    AccessRevocationItem,
    AccessRevocationPlan,
    IamCredential,
    IamEffectiveAccess,
    IamException,
    IdentityChangeEvent,
    IdentityGroupMember,
)
from app.services.access.collectors import h, is_privileged
from app.services.access.directory import Directory

log = logging.getLogger(__name__)
NEW_DAYS = 30
SERVICE_TYPES = {"ServicePrincipal", "ManagedIdentity", "ServiceAccount", "Role", "Application"}
GRANT_EVENT_NAMES = ("microsoft.authorization/roleassignments/write", "microsoft.authorization/roleassignments/delete",
                     "attachuserpolicy", "attachrolepolicy", "attachgrouppolicy", "putuserpolicy", "putrolepolicy", "addusertogroup",
                     "createuser", "deleteuser", "setiampolicy", "createaccountassignment", "deleteaccountassignment",
                     "add member to role", "add user", "delete user", "disable account", "add member to group")


def now() -> datetime:
    return datetime.now(UTC)


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def semantic(a) -> tuple:
    return (a.principal_id, (a.role_name or "").lower(), (a.scope_path or "").lower(), a.pim_state or "active")


def is_new(i: CloudIdentity, today: datetime | None = None) -> bool:
    t = today or now()
    attrs = i.attributes or {}
    if i.provider_created_at:
        since = _aware(i.provider_created_at)
    elif i.directory_scope and not attrs.get("baseline"):
        since = _aware(i.first_seen_at)  # first listed by its directory after the baseline
    elif attrs.get("new_from_assignment"):
        since = _aware(i.first_seen_at)  # no directory (e.g. GCP members): first role assignment appeared after the baseline
    else:
        since = None
    return since is not None and since >= t - timedelta(days=NEW_DAYS)


def _json_safe(v):
    """State snapshots are stored as JSON: dates become ISO-8601 text (UTC), nested values are converted the same way."""
    if isinstance(v, datetime):
        return _aware(v).isoformat()
    if isinstance(v, dict):
        return {str(k): _json_safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_json_safe(x) for x in v]
    return v


def _event(db: Session, provider: str, change_type: str, principal_id: str, *, name=None, ptype=None, scope=None, privileged=False,
           previous=None, new=None) -> IdentityChangeEvent:
    ev = IdentityChangeEvent(provider=provider, scope_external_id=scope, principal_id=principal_id[:255], principal_name=(name or "")[:255] or None,
                             principal_type=ptype, change_type=change_type, privileged=privileged,
                             previous_state=_json_safe(previous), new_state=_json_safe(new))
    _link(db, ev)
    db.add(ev)
    return ev


def _link(db: Session, ev: IdentityChangeEvent) -> None:
    """Attach the provider audit event that most likely caused the change (same provider, last 48 h, mentions the principal)."""
    pid = ev.principal_id.split(":", 1)[-1].lower()
    short = pid.rsplit("/", 1)[-1]
    since = now() - timedelta(hours=48)
    q = select(AuditEvent).where(AuditEvent.provider == ev.provider, AuditEvent.event_timestamp >= since,
                                 or_(*[func.lower(AuditEvent.event_name).contains(n) for n in GRANT_EVENT_NAMES])).order_by(
        AuditEvent.event_timestamp.desc()).limit(200)
    for a in db.scalars(q):
        blob = f"{a.resource_id or ''} {a.raw or ''}".lower()
        if short and short in blob:
            ev.source_event_id, ev.initiated_by = a.id, (a.principal or "")[:512] or None
            return


# ------------------------------------------------------------------ directory
def apply_directory(db: Session, d: Directory) -> dict:
    t = now()
    stats = defaultdict(int)
    known = {i.principal_id: i for i in db.scalars(select(CloudIdentity).where(CloudIdentity.provider == d.provider))}
    baseline = not any(i.directory_scope == d.directory_scope for i in known.values())
    seen: set[str] = set()
    for di in d.identities:
        seen.add(di.principal_id)
        i = known.get(di.principal_id)
        created = _aware(di.created_at) if isinstance(di.created_at, datetime) else None
        if i is None:
            i = CloudIdentity(provider=d.provider, principal_id=di.principal_id[:255], principal_type=di.principal_type, first_seen_at=t,
                              attributes={"baseline": True} if baseline else {})
            db.add(i)
            known[di.principal_id] = i
            if not baseline or (created and created >= t - timedelta(days=NEW_DAYS)):
                kind = "NEW_SERVICE_PRINCIPAL" if di.principal_type in SERVICE_TYPES else "NEW_IDENTITY"
                _event(db, d.provider, kind, di.principal_id, name=di.sign_in_name or di.display_name, ptype=di.principal_type,
                       scope=d.directory_scope, new={"type": di.principal_type, "user_type": di.user_type, "created": created})
                stats["new"] += 1
        elif i.directory_scope is None:
            # first time this identity is listed by its directory (it may already exist from a role assignment stored earlier
            # in this run). Outside the baseline, an identity first seen within the last day is new.
            fresh = i.first_seen_at is None or _aware(i.first_seen_at) >= t - timedelta(days=1)
            i.first_seen_at = i.first_seen_at or t
            if baseline:
                i.attributes = {**(i.attributes or {}), "baseline": True}
            elif fresh:
                kind = "NEW_SERVICE_PRINCIPAL" if di.principal_type in SERVICE_TYPES else "NEW_IDENTITY"
                _event(db, d.provider, kind, di.principal_id, name=di.sign_in_name or di.display_name, ptype=di.principal_type,
                       scope=d.directory_scope, new={"type": di.principal_type, "user_type": di.user_type, "created": created})
                stats["new"] += 1
        if i.enabled is not None and di.enabled is not None and i.enabled != di.enabled:
            _event(db, d.provider, "IDENTITY_ENABLED" if di.enabled else "IDENTITY_DISABLED", di.principal_id, name=di.sign_in_name,
                   ptype=di.principal_type, scope=d.directory_scope, previous={"enabled": i.enabled}, new={"enabled": di.enabled})
            i.status_changed_at = t
            stats["status_changed"] += 1
        i.principal_type = di.principal_type
        i.directory_scope = d.directory_scope
        i.enabled, i.user_type, i.missing_since = di.enabled, di.user_type, None
        i.provider_created_at = created or i.provider_created_at
        if di.last_sign_in_at:
            i.last_sign_in_at = _aware(di.last_sign_in_at)
        if di.display_name:
            i.display_name = di.display_name[:255]
        if di.sign_in_name:
            i.sign_in_name = di.sign_in_name[:255]
        i.attributes = {**(i.attributes or {}), **{k: v for k, v in di.attrs.items() if v is not None}}
        i.last_seen_at = t
    if d.identities_complete:
        for pid, i in known.items():
            if i.directory_scope == d.directory_scope and pid not in seen and i.missing_since is None:
                i.missing_since, i.status_changed_at = t, t
                _event(db, d.provider, "IDENTITY_DELETED", pid, name=i.sign_in_name or i.display_name, ptype=i.principal_type,
                       scope=d.directory_scope, previous={"enabled": i.enabled}, new={"present_in_directory": False})
                stats["deleted"] += 1
    stats["members"] = _apply_members(db, d, baseline, t)
    stats["credentials"] = _apply_credentials(db, d, baseline, t)
    return dict(stats)


def _apply_members(db: Session, d: Directory, baseline: bool, t: datetime) -> int:
    rows = {(m.group_id, m.member_id): m for m in db.scalars(select(IdentityGroupMember).where(IdentityGroupMember.provider == d.provider))}
    groups_listed = {m.group_id for m in d.members}
    seen = set()
    for m in d.members:
        key = (m.group_id, m.member_id)
        if key in seen:
            continue
        seen.add(key)
        r = rows.get(key)
        if r is None:
            r = IdentityGroupMember(provider=d.provider, group_id=m.group_id[:255], member_id=m.member_id[:255], member_type=m.member_type,
                                    first_seen_at=t)
            db.add(r)
            if not baseline and rows:
                _event(db, d.provider, "GROUP_MEMBER_ADDED", m.member_id, ptype=m.member_type, scope=d.directory_scope,
                       new={"group": m.group_name or m.group_id})
        r.group_name, r.last_seen_at, r.removed_at = (m.group_name or r.group_name), t, None
    if d.members_complete:
        for key, r in rows.items():
            if key not in seen and r.removed_at is None and (r.group_id in groups_listed or d.provider == "aws"):
                r.removed_at = t
                _event(db, d.provider, "GROUP_MEMBER_REMOVED", r.member_id, ptype=r.member_type, scope=d.directory_scope,
                       previous={"group": r.group_name or r.group_id})
    return len(seen)


def _apply_credentials(db: Session, d: Directory, baseline: bool, t: datetime) -> int:
    rows = {c.credential_id: c for c in db.scalars(select(IamCredential).where(IamCredential.provider == d.provider))}
    seen = set()
    for c in d.credentials:
        if not c.credential_id or c.credential_id in seen:
            continue
        seen.add(c.credential_id)
        r = rows.get(c.credential_id)
        if r is None:
            r = IamCredential(provider=d.provider, credential_id=c.credential_id[:255], principal_id=c.principal_id[:255], kind=c.kind)
            db.add(r)
            if not baseline:
                _event(db, d.provider, "CREDENTIAL_ADDED", c.principal_id, scope=c.scope or d.directory_scope, new={"kind": c.kind})
        r.scope_external_id, r.status = c.scope or d.directory_scope, c.status
        r.created_at_provider, r.expires_at = _aware(c.created_at), _aware(c.expires_at)
        r.last_used_at, r.last_seen_at, r.removed_at = _aware(c.last_used_at), t, None
    if d.credentials_complete:
        scope_ids = {c.scope or d.directory_scope for c in d.credentials} | {d.directory_scope}
        for cid, r in rows.items():
            if cid not in seen and r.removed_at is None and r.scope_external_id in scope_ids:
                r.removed_at = t
    return len(seen)


# ------------------------------------------------------------------ assignment changes
def snapshot(db: Session, provider: str) -> dict[tuple, dict]:
    return {semantic(a): {"scope": a.scope_external_id, "privileged": a.privileged, "type": a.principal_type}
            for a in db.scalars(select(AccessAssignment).where(AccessAssignment.provider == provider, AccessAssignment.removed_at.is_(None)))}


def diff_assignments(db: Session, provider: str, before: dict[tuple, dict], complete_scopes: set[str]) -> dict:
    """Compare before/after for scopes whose collection was complete. Same principal + scope with one role removed and another
    added is reported as a role change."""
    if not before:
        return {"baseline": True}
    after = snapshot(db, provider)
    added = [k for k in after if k not in before and after[k]["scope"] in complete_scopes]
    removed = [k for k in before if k not in after and before[k]["scope"] in complete_scopes]
    names = {i.principal_id: i for i in db.scalars(select(CloudIdentity).where(CloudIdentity.provider == provider))}
    grants = list(db.scalars(select(AccessGrant).where(AccessGrant.provider == provider, AccessGrant.state.in_(["APPROVED", "PROVISIONED", "ACTIVE"]))))
    by_pair = defaultdict(list)
    for k in removed:
        by_pair[(k[0], k[2])].append(k)
    n = 0
    for k in added:
        pid, role, scope_path, pim = k
        ident = names.get(pid)
        if ident is not None and ident.directory_scope is None and not (ident.attributes or {}).get("new_from_assignment") \
                and ident.first_seen_at and _aware(ident.first_seen_at) >= now() - timedelta(days=1):
            ident.attributes = {**(ident.attributes or {}), "new_from_assignment": True}
            _event(db, provider, "NEW_SERVICE_PRINCIPAL" if after[k]["type"] in SERVICE_TYPES else "NEW_IDENTITY", pid,
                   name=ident.sign_in_name or ident.display_name, ptype=after[k]["type"], scope=after[k]["scope"], new={"first_role": role})
        old = by_pair.get((pid, scope_path))
        prev = old.pop(0) if old else None
        ev = _event(db, provider, "ROLE_CHANGED" if prev else "PERMISSION_ADDED", pid, name=ident.sign_in_name if ident else None,
                    ptype=after[k]["type"], scope=after[k]["scope"], privileged=after[k]["privileged"] or is_privileged(role),
                    previous={"role": prev[1]} if prev else None, new={"role": role, "scope": scope_path, "pim": pim})
        who = {(ident.sign_in_name or "").lower()} - {""} if ident else set()
        g = next((g for g in grants if (g.access_details or "").lower() == role and
                  (g.principal_id == pid or (g.sign_in_name or "").lower() in who)), None)
        ev.approval_reference = g.grant_key if g else None
        n += 1
    for lst in by_pair.values():
        for k in lst:
            ident = names.get(k[0])
            _event(db, provider, "PERMISSION_REMOVED", k[0], name=ident.sign_in_name if ident else None, ptype=before[k]["type"],
                   scope=before[k]["scope"], privileged=before[k]["privileged"], previous={"role": k[1], "scope": k[2], "pim": k[3]})
            n += 1
    return {"changes": n}


# ------------------------------------------------------------------ effective access
def rebuild_effective(db: Session) -> int:
    db.execute(delete(IamEffectiveAccess))
    members = defaultdict(list)
    for m in db.scalars(select(IdentityGroupMember).where(IdentityGroupMember.removed_at.is_(None))):
        members[(m.provider, m.group_id)].append(m)
    n = 0
    for a in db.scalars(select(AccessAssignment).where(AccessAssignment.removed_at.is_(None))):
        via = "Inherited" if a.inherited_from else "Direct"
        if a.principal_type == "Group" and members.get((a.provider, a.principal_id)):
            for m in members[(a.provider, a.principal_id)]:
                db.add(IamEffectiveAccess(provider=a.provider, principal_id=m.member_id, principal_type=m.member_type, assignment_id=a.id,
                                          scope_external_id=a.scope_external_id, scope_level=a.scope_level, scope_path=a.scope_path,
                                          role_name=a.role_name, privileged=a.privileged, via="Group", via_group=m.group_name or a.principal_id,
                                          inherited_from=a.inherited_from))
                n += 1
        else:
            db.add(IamEffectiveAccess(provider=a.provider, principal_id=a.principal_id, principal_type=a.principal_type, assignment_id=a.id,
                                      scope_external_id=a.scope_external_id, scope_level=a.scope_level, scope_path=a.scope_path,
                                      role_name=a.role_name, privileged=a.privileged, via="Group" if a.access_type == "Group" else via,
                                      inherited_from=a.inherited_from))
            n += 1
    return n


def effective_for(db: Session, provider: str, principal_id: str) -> list[IamEffectiveAccess]:
    return list(db.scalars(select(IamEffectiveAccess).where(IamEffectiveAccess.provider == provider, IamEffectiveAccess.principal_id == principal_id)))


# ------------------------------------------------------------------ lifecycle status
def refresh_status(db: Session) -> None:
    holding = {(e.provider, e.principal_id) for e in db.scalars(select(IamEffectiveAccess))}
    plans = {(p.provider, p.principal_id): p for p in db.scalars(select(AccessRevocationPlan).where(AccessRevocationPlan.status != "CANCELLED")
                                                                 .order_by(AccessRevocationPlan.id))}
    for i in db.scalars(select(CloudIdentity)):
        gone = i.missing_since is not None or i.principal_type == "Deleted" or i.principal_id.startswith("deleted:")
        disabled = i.enabled is False
        plan = plans.get((i.provider, i.principal_id))
        has = (i.provider, i.principal_id) in holding
        if gone or disabled:
            if plan and plan.status == "VERIFIED" and not has:
                st = "Access Revoked"
            elif plan and plan.status in ("APPROVAL_REQUESTED", "APPROVED", "EXECUTING", "PARTIALLY_VERIFIED"):
                st = "Access Revocation Pending"
            elif has:
                st = "Reconciliation Required"
            else:
                st = "Deleted" if gone else "Disabled"
        else:
            st = "New" if is_new(i) else "Active"
        if i.lifecycle_status != st:
            i.lifecycle_status = st


# ------------------------------------------------------------------ revocation plans
def build_plan(db: Session, identity: CloudIdentity, reason: str, actor: str) -> AccessRevocationPlan:
    from app.services.access.engine import next_key
    plan = AccessRevocationPlan(plan_key=next_key(db, AccessRevocationPlan, AccessRevocationPlan.plan_key, "REV"), provider=identity.provider,
                                principal_id=identity.principal_id, principal_name=identity.sign_in_name or identity.display_name, reason=reason,
                                created_by=actor, status="DRAFT")
    db.add(plan)
    db.flush()
    service = identity.principal_type in SERVICE_TYPES or identity.shared
    snap = []
    for e in effective_for(db, identity.provider, identity.principal_id):
        a = db.get(AccessAssignment, e.assignment_id)
        if e.via == "Group":
            kind, action, desc = "group_membership", "remove", f"Remove from group {e.via_group} (grants {e.role_name} at {e.scope_path})"
            mem = db.scalar(select(IdentityGroupMember).where(IdentityGroupMember.provider == identity.provider,
                                                              IdentityGroupMember.member_id == identity.principal_id,
                                                              IdentityGroupMember.removed_at.is_(None),
                                                              or_(IdentityGroupMember.group_name == e.via_group, IdentityGroupMember.group_id == a.principal_id if a else False)))
            target = mem.id if mem else None
        elif e.via == "Inherited":
            kind, action, target = "inherited", "remove_at_parent", e.assignment_id
            desc = f"Remove {e.role_name} at {e.inherited_from} (inherited by {e.scope_path})"
        else:
            kind, action, target, desc = "assignment", "remove", e.assignment_id, f"Remove {e.role_name} at {e.scope_path}"
        db.add(AccessRevocationItem(plan_id=plan.id, kind=kind, target_id=target, description=desc[:2000], scope_path=e.inherited_from or e.scope_path,
                                    action="review_shared" if service else action, auto_allowed=not service))
        snap.append({"role": e.role_name, "scope": e.scope_path, "via": e.via, "group": e.via_group})
    for c in db.scalars(select(IamCredential).where(IamCredential.provider == identity.provider, IamCredential.principal_id == identity.principal_id,
                                                    IamCredential.removed_at.is_(None))):
        db.add(AccessRevocationItem(plan_id=plan.id, kind="credential", target_id=c.id, description=f"Deactivate {c.kind} {c.credential_id}",
                                    scope_path=c.scope_external_id, action="review_shared" if service else "disable", auto_allowed=not service))
        snap.append({"credential": c.credential_id, "kind": c.kind, "status": c.status})
    plan.before_snapshot = snap
    return plan


def verify_plans(db: Session) -> int:
    """After an inventory: items whose target is gone are VERIFIED; a plan is VERIFIED when all non-skipped items are."""
    n = 0
    for plan in db.scalars(select(AccessRevocationPlan).where(AccessRevocationPlan.status.in_(["EXECUTING", "PARTIALLY_VERIFIED"]))):
        items = list(db.scalars(select(AccessRevocationItem).where(AccessRevocationItem.plan_id == plan.id)))
        for it in items:
            if it.status in ("SKIPPED", "VERIFIED"):
                continue
            model = {"assignment": AccessAssignment, "inherited": AccessAssignment, "group_membership": IdentityGroupMember, "credential": IamCredential}[it.kind]
            obj = db.get(model, it.target_id) if it.target_id else None
            gone = obj is None or obj.removed_at is not None or (it.kind == "credential" and obj.status in ("Inactive", "Disabled"))
            it.status = "VERIFIED" if gone else "STILL_PRESENT"
            if gone:
                it.verified_at = now()
        open_items = [i for i in items if i.status not in ("SKIPPED", "VERIFIED")]
        if not open_items:
            plan.status, plan.verified_at = "VERIFIED", now()
            plan.after_snapshot = [{"item": i.description, "status": i.status} for i in items]
            n += 1
        elif len(open_items) < len([i for i in items if i.status != "SKIPPED"]):
            plan.status = "PARTIALLY_VERIFIED"
        if plan.executed_at and plan.status != "VERIFIED" and _aware(plan.executed_at) < now() - timedelta(hours=48):
            plan.status = "VERIFICATION_FAILED"
    return n


# ------------------------------------------------------------------ reconciliation exceptions
RISK = {"PROVISIONED_WITHOUT_APPROVAL": "High", "DELETED_IDENTITY_WITH_ACCESS": "Critical", "EXPIRED_STILL_ACTIVE": "High",
        "UNAUTHORIZED_PRIVILEGE_CHANGE": "Critical", "APPROVED_NOT_PROVISIONED": "Low", "SCOPE_MISMATCH": "Medium", "EXCESSIVE_ACCESS": "High"}


def compute_exceptions(db: Session) -> dict:
    from app.services.access.engine import assignment_status, missing_assignments, next_key
    found: dict[str, dict] = {}

    def add(cat, provider, pid, name, scope, expected, actual, evidence, privileged=False):
        key = h(cat, provider, pid, scope or "", actual or "")
        risk = RISK[cat] if not (cat == "PROVISIONED_WITHOUT_APPROVAL" and privileged) else "Critical"
        found[key] = {"category": cat, "provider": provider, "principal_id": pid, "principal_name": name, "scope_path": scope,
                      "expected": expected, "actual": actual, "risk": risk, "evidence": evidence}

    statuses = assignment_status(db)
    idents = {(i.provider, i.principal_id): i for i in db.scalars(select(CloudIdentity))}
    grants_by_person = defaultdict(list)
    for g in db.scalars(select(AccessGrant).where(AccessGrant.state.in_(["APPROVED", "PROVISIONED", "ACTIVE"]))):
        grants_by_person[(g.provider, (g.sign_in_name or "").lower())].append(g)
    for a in db.scalars(select(AccessAssignment).where(AccessAssignment.removed_at.is_(None))):
        st = statuses.get(a.id, {}).get("status")
        ident = idents.get((a.provider, a.principal_id))
        name = (ident.sign_in_name or ident.display_name) if ident else None
        ev = {"assignment_id": a.id, "source": a.source, "last_seen": a.last_seen_at}
        if ident and (ident.missing_since or ident.enabled is False or a.principal_type == "Deleted"):
            add("DELETED_IDENTITY_WITH_ACCESS", a.provider, a.principal_id, name, a.scope_path, "No access (identity deleted or disabled)",
                f"{a.role_name} at {a.scope_path}", ev)
            continue
        if a.principal_type == "Deleted" or a.principal_id.startswith("deleted:"):
            add("DELETED_IDENTITY_WITH_ACCESS", a.provider, a.principal_id, name, a.scope_path, "No access (principal deleted)",
                f"{a.role_name} at {a.scope_path}", ev)
            continue
        if st == "EXPIRED_STILL_ACTIVE":
            g = statuses[a.id]["grant"]
            add("EXPIRED_STILL_ACTIVE", a.provider, a.principal_id, name, a.scope_path, f"Expired {g.access_expiry_date} ({g.grant_key})",
                f"{a.role_name} still assigned", {**ev, "grant": g.grant_key})
        elif st == "UNAPPROVED" and a.principal_type not in SERVICE_TYPES:
            approved = grants_by_person.get((a.provider, (name or "").lower()), [])
            same_role = [g for g in approved if (g.access_details or "").lower() == a.role_name.lower()]
            if same_role:
                add("SCOPE_MISMATCH", a.provider, a.principal_id, name, a.scope_path,
                    "; ".join(f"{g.access_details} on {g.scope_external_id}{'/' + g.resource_group if g.resource_group else ''}" for g in same_role),
                    f"{a.role_name} at {a.scope_path}", {**ev, "grants": [g.grant_key for g in same_role]})
            elif approved and a.privileged and not any(is_privileged(g.access_details or "") for g in approved):
                add("EXCESSIVE_ACCESS", a.provider, a.principal_id, name, a.scope_path, "; ".join(g.access_details or "" for g in approved),
                    f"{a.role_name} (privileged)", {**ev, "grants": [g.grant_key for g in approved]}, True)
            else:
                add("PROVISIONED_WITHOUT_APPROVAL", a.provider, a.principal_id, name, a.scope_path, "An approved request",
                    f"{a.role_name} at {a.scope_path}", ev, a.privileged)
    for g in missing_assignments(db):
        add("APPROVED_NOT_PROVISIONED", g.provider, g.principal_id or g.sign_in_name, g.sign_in_name, g.scope_external_id,
            f"{g.access_details} ({g.grant_key})", "Not found in the provider inventory", {"grant": g.grant_key})
    since = now() - timedelta(days=30)
    for ev in db.scalars(select(IdentityChangeEvent).where(IdentityChangeEvent.privileged.is_(True), IdentityChangeEvent.detected_at >= since,
                                                           IdentityChangeEvent.change_type.in_(["PERMISSION_ADDED", "ROLE_CHANGED"]),
                                                           IdentityChangeEvent.approval_reference.is_(None))):
        add("UNAUTHORIZED_PRIVILEGE_CHANGE", ev.provider, ev.principal_id, ev.principal_name, (ev.new_state or {}).get("scope"),
            "A privileged change with an approval", f"{(ev.new_state or {}).get('role')} added", {"change_event": ev.id, "initiated_by": ev.initiated_by})
    existing = {e.dedup_key: e for e in db.scalars(select(IamException))}
    t, created = now(), 0
    for key, f in found.items():
        e = existing.get(key)
        if e is None:
            e = IamException(exception_key=next_key(db, IamException, IamException.exception_key, "IAMX"), dedup_key=key, **{
                k: (v[:255] if isinstance(v, str) and k in ("principal_id", "principal_name") else v) for k, v in f.items() if k != "evidence"})
            db.add(e)
            db.flush()
            created += 1
        e.evidence = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in f["evidence"].items()}
        e.last_detected_at, e.cleared_at = t, None
        if e.status == "CLEARED":
            e.status = "OPEN"
    cleared = 0
    for key, e in existing.items():
        if key not in found and e.cleared_at is None and e.status in ("OPEN", "IN_PROGRESS"):
            e.cleared_at, e.status = t, "CLEARED"
            cleared += 1
    return {"open": len(found), "new": created, "cleared": cleared}

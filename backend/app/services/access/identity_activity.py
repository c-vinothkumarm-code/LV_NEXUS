"""Identity lifecycle from the collected cloud audit logs (CloudTrail, Azure Activity Log, Entra ID audit, GCP Cloud Audit Logs).

Each successful IAM event is classified as exactly one of:
  user_created / user_deleted              - a HUMAN user identity was created or deleted
  service_identity_created / _deleted      - a service account / workload identity (never counted as a "user")
  role_assigned / role_removed             - access was granted to / removed from an existing identity
  permission_changed                       - a role or policy definition itself changed

A role assignment is never counted as a new user. Failed or denied calls are listed separately and never counted.
Only events that were actually collected are counted: providers or scopes without audit collection are reported as gaps.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, date, datetime
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import AuditEvent

IST = ZoneInfo("Asia/Kolkata")

KINDS = {
    "user_created": "User created", "user_deleted": "User deleted",
    "service_identity_created": "Service identity created", "service_identity_deleted": "Service identity deleted",
    "role_assigned": "Access granted", "role_removed": "Access removed", "permission_changed": "Permission definition changed",
}

# provider-native operation names (lower-case) -> kind
_AWS = {
    "createuser": "user_created", "deleteuser": "user_deleted",                     # IAM and IAM Identity Center (identitystore)
    "attachuserpolicy": "role_assigned", "putuserpolicy": "role_assigned", "addusertogroup": "role_assigned",
    "attachgrouppolicy": "role_assigned", "attachrolepolicy": "role_assigned", "createaccountassignment": "role_assigned",
    "creategroupmembership": "role_assigned", "createloginprofile": "role_assigned",
    "detachuserpolicy": "role_removed", "deleteuserpolicy": "role_removed", "removeuserfromgroup": "role_removed",
    "detachgrouppolicy": "role_removed", "detachrolepolicy": "role_removed", "deleteaccountassignment": "role_removed",
    "deletegroupmembership": "role_removed", "deleteloginprofile": "role_removed",
    "createpolicyversion": "permission_changed", "putrolepolicy": "permission_changed", "putgrouppolicy": "permission_changed",
    "updateassumerolepolicy": "permission_changed", "createrole": "permission_changed", "deleterole": "permission_changed",
    "putinlinepolicytopermissionset": "permission_changed", "attachmanagedpolicytopermissionset": "permission_changed",
    "detachmanagedpolicyfrompermissionset": "permission_changed",
}
_ENTRA = {
    "add user": "user_created", "invite external user": "user_created", "delete user": "user_deleted", "hard delete user": "user_deleted",
    "add service principal": "service_identity_created", "remove service principal": "service_identity_deleted",
    "add member to role": "role_assigned", "add eligible member to role": "role_assigned", "add member to group": "role_assigned",
    "add app role assignment to user": "role_assigned", "add app role assignment grant to user": "role_assigned",
    "remove member from role": "role_removed", "remove eligible member from role": "role_removed", "remove member from group": "role_removed",
    "remove app role assignment from user": "role_removed", "update role": "permission_changed",
}
_AZURE_OPS = {
    "microsoft.authorization/roleassignments/write": "role_assigned",
    "microsoft.authorization/roleassignments/delete": "role_removed",
    "microsoft.authorization/roledefinitions/write": "permission_changed",
    "microsoft.authorization/roledefinitions/delete": "permission_changed",
}
_GCP = {
    "google.iam.admin.v1.createserviceaccount": "service_identity_created",
    "google.iam.admin.v1.deleteserviceaccount": "service_identity_deleted",
    "google.iam.admin.v1.createrole": "permission_changed", "google.iam.admin.v1.updaterole": "permission_changed",
    "google.iam.admin.v1.deleterole": "permission_changed",
}
_SET_IAM = ("setiampolicy",)


def _lower(v) -> str:
    return (v or "").strip().lower()


def _gcp_deltas(raw: dict) -> list[dict]:
    sd = raw.get("serviceData") or {}
    return ((sd.get("policyDelta") or {}).get("bindingDeltas") or []) if isinstance(sd, dict) else []


def classify(e: AuditEvent) -> list[dict]:
    """One audit event -> zero or more lifecycle records (a GCP SetIamPolicy can add and remove several bindings)."""
    raw = e.raw or {}
    name = _lower(e.event_name)
    out: list[dict] = []

    def rec(kind: str, target: str | None, role: str | None = None, human: bool | None = None):
        out.append({"kind": kind, "target": target or e.resource_id or "unknown", "role": role, "human": human})

    if e.provider == "aws":
        kind = _AWS.get(name)
        if not kind:
            return []
        rp = raw.get("requestParameters") or {}
        if not isinstance(rp, dict):
            rp = {}
        user = rp.get("user")
        target = (rp.get("userName") or (user.get("userName") if isinstance(user, dict) else user) or rp.get("roleName")
                  or rp.get("principalId") or rp.get("groupName"))
        role = rp.get("policyArn") or rp.get("permissionSetArn") or rp.get("policyName") or rp.get("groupName")
        rec(kind, target, role, human=True if kind in ("user_created", "user_deleted") else None)
    elif e.provider == "azure" and e.event_id.startswith("entra-audit:"):
        kind = _ENTRA.get(name)
        if not kind:
            return []
        targets = raw.get("targetResources") or [{}]
        t = targets[0] if targets else {}
        target = t.get("userPrincipalName") or t.get("displayName") or t.get("id")
        role = None
        for tr in targets[1:] + [t]:
            for mp in tr.get("modifiedProperties") or []:
                if _lower(mp.get("displayName")) in ("role.displayname", "group.displayname"):
                    role = (mp.get("newValue") or mp.get("oldValue") or "").strip('"')
        rec(kind, target, role, human=True if kind in ("user_created", "user_deleted") else None)
    elif e.provider == "azure":
        kind = _AZURE_OPS.get(name)
        if not kind:
            return []
        props = raw.get("properties") or {}
        body = props.get("requestbody") or props.get("requestBody") if isinstance(props, dict) else None
        target = role = None
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except ValueError:
                body = None
        if isinstance(body, dict):
            p = body.get("properties") or body
            target, role = p.get("principalId"), (p.get("roleDefinitionId") or "").rsplit("/", 1)[-1] or None
        rec(kind, target, role)
    elif e.provider == "gcp":
        if any(name.endswith(s) for s in _SET_IAM):
            for d in _gcp_deltas(raw):
                act = _lower(d.get("action"))
                if act in ("add", "remove"):
                    member = d.get("member") or ""
                    rec("role_assigned" if act == "add" else "role_removed", member, d.get("role"))
            return out
        kind = _GCP.get(name)
        if not kind:
            return []
        req = raw.get("request") or {}
        acct = (req.get("serviceAccount") or {}) if isinstance(req, dict) else {}
        target = acct.get("email") or (req.get("accountId") if isinstance(req, dict) else None) or e.resource_id
        rec(kind, target, human=False)
    return out


def month_bounds(month: str | None = None, now: datetime | None = None) -> tuple[datetime, datetime, str, bool]:
    """(start_utc, end_utc, label, complete) for a calendar month in IST. Default: the current month (incomplete)."""
    now = now or datetime.now(UTC)
    local = now.astimezone(IST)
    if month:
        y, m = (int(x) for x in month.split("-"))
    else:
        y, m = local.year, local.month
    start = datetime(y, m, 1, tzinfo=IST)
    end = datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=IST)
    complete = end <= local
    stop = end if complete else now
    return start.astimezone(UTC), stop.astimezone(UTC), start.strftime("%B %Y"), complete


def _candidates(db: Session, start: datetime, end: datetime, provider: str | None, scope: str | None):
    from sqlalchemy import func
    names = [n for n in list(_AWS) + list(_ENTRA) + list(_AZURE_OPS) + list(_GCP)]
    # event_name keeps the provider's case: compare case-insensitively
    stmt = select(AuditEvent).where(AuditEvent.event_timestamp >= start, AuditEvent.event_timestamp < end,
                                    or_(func.lower(AuditEvent.event_name).in_(names), func.lower(AuditEvent.event_name).like("%setiampolicy")))
    if provider:
        stmt = stmt.where(AuditEvent.provider == provider)
    if scope:
        stmt = stmt.where(AuditEvent.scope_external_id == scope)
    return db.scalars(stmt.order_by(AuditEvent.event_timestamp.desc()))


def activity(db: Session, start: datetime, end: datetime, provider: str | None = None, scope: str | None = None,
             names: dict | None = None) -> dict:
    """Counts and event rows. Counts include only successful events; identical (provider, target, kind) on the same day
    reported by two sources (e.g. IAM and Identity Center) are counted once."""
    names = names or {}
    rows, failed = [], 0
    counted: set = set()
    counts: Counter = Counter()
    for e in _candidates(db, start, end, provider, scope):
        raw = e.raw or {}
        outcome = raw.get("outcome") or "success"
        for r in classify(e):
            row = {"id": e.id, "event_id": e.event_id, "time": e.event_timestamp.isoformat(), "provider": e.provider,
                   "account_id": e.scope_external_id, "account_name": names.get((e.provider, e.scope_external_id), e.scope_external_id),
                   "kind": r["kind"], "kind_label": KINDS[r["kind"]], "target": r["target"], "role": r["role"],
                   "initiated_by": e.principal, "source_ip": e.source_ip, "operation": e.event_name, "outcome": outcome}
            rows.append(row)
            if outcome != "success":
                failed += 1
                continue
            key = (e.provider, _lower(r["target"]), r["kind"], e.event_timestamp.date())
            if key in counted:
                continue
            counted.add(key)
            counts[r["kind"]] += 1
    return {"counts": {k: counts.get(k, 0) for k in KINDS}, "failed_attempts": failed, "events": rows}


def coverage(db: Session, start: datetime, end: datetime) -> list[dict]:
    """Which providers actually delivered audit events in the period (a provider with none cannot show zero additions as fact)."""
    from sqlalchemy import func
    got = dict(db.execute(select(AuditEvent.provider, func.count()).where(AuditEvent.event_timestamp >= start,
                                                                           AuditEvent.event_timestamp < end).group_by(AuditEvent.provider)).all())
    entra = db.scalar(select(func.count()).where(AuditEvent.event_id.like("entra-audit:%"), AuditEvent.event_timestamp >= start,
                                                 AuditEvent.event_timestamp < end)) or 0
    return [{"provider": p, "events": int(got.get(p, 0)), "collected": bool(got.get(p)),
             "note": None if got.get(p) else "No audit events collected for this period: additions and deletions cannot be counted.",
             **({"entra_directory_events": int(entra)} if p == "azure" else {})} for p in ("aws", "azure", "gcp")]


def today_ist(now: datetime | None = None) -> date:
    return (now or datetime.now(UTC)).astimezone(IST).date()



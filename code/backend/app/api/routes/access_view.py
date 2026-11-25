"""Read-only Access (IAM) view: who has access to what, at subscription / account / project, resource group / service and
resource level, for Azure, AWS and Google Cloud. Nothing here changes access; there are no write endpoints.

Data comes from the access_inventory collection (Azure RBAC incl. inherited management-group assignments and PIM, AWS IAM,
Identity Center, S3 / KMS resource policies, GCP project / folder / organization / resource-level IAM). Group principals are
expanded to their members where the directory collection could read them. When a scope could not be read, its node says
"Access data unavailable – missing permission: <permission>" instead of showing an empty (falsely clean) list."""
from __future__ import annotations

from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.core.security import require
from app.database.session import get_db
from app.models import SCOPE_MODELS, AutomationExecutionLog, User
from app.models.access import AccessAssignment, CloudIdentity
from app.models.iam import IdentityGroupMember

router = APIRouter(prefix="/api/v1/access", tags=["access view (read-only)"])
READ = require("access:read")

# what each collection source needs, shown when the provider refused the call
PERMISSION = {
    "azure_rbac": "Microsoft.Authorization/roleAssignments/read (Reader on the subscription)",
    "azure_pim_eligible": "Microsoft.Authorization/roleEligibilitySchedules/read",
    "aws_iam": "iam:ListUsers, iam:ListRoles, iam:ListAttachedUserPolicies, iam:ListAttachedRolePolicies",
    "aws_identity_center": "sso:ListPermissionSets, sso:ListAccountAssignments (management account)",
    "aws_resource_policy": "s3:ListAllMyBuckets, s3:GetBucketPolicy, kms:ListKeys, kms:DescribeKey, kms:GetKeyPolicy",
    "aws_resource_policy:s3": "s3:ListAllMyBuckets, s3:GetBucketPolicy",
    "aws_resource_policy:kms": "kms:ListKeys, kms:DescribeKey, kms:GetKeyPolicy",
    "gcp_iam": "resourcemanager.projects.getIamPolicy",
    "gcp_resource_iam": "cloudasset.assets.searchAllIamPolicies (Cloud Asset Viewer, Cloud Asset API enabled)",
}
RESOURCE_SOURCES = ("aws_resource_policy", "gcp_resource_iam")
LEVEL_NAME = {"azure": ("Subscription", "Resource group"), "aws": ("Account", "Service"), "gcp": ("Project", "Service")}


def _coverage(db: Session) -> tuple[dict[str, list[dict]], str | None, bool]:
    run = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == "access_inventory")
                    .order_by(AutomationExecutionLog.id.desc()).limit(1))
    if run is None:
        return {}, None, False
    return (run.summary or {}).get("coverage") or {}, iso(run.finished_at or run.started_at), True


def _unavailable(cov: list[dict], resource_level: bool) -> list[str]:
    out = []
    for c in cov:
        src = c.get("source", "")
        if c.get("state") == "OK" or src.startswith(RESOURCE_SOURCES) != resource_level:
            continue
        if c.get("state") == "ACCESS_DENIED":
            perm = PERMISSION.get(src) or PERMISSION.get(src.split(":", 1)[0]) or src
            out.append(f"Access data unavailable – missing permission: {perm}")
        else:
            out.append(f"Access data unavailable – {src} failed: {c.get('message', 'error')}")
    return out


def _service(a: AccessAssignment) -> str:
    """Second level below an AWS account / GCP project: the service that owns the resource."""
    p = a.scope_path or ""
    if a.provider == "aws":
        parts = p.split(":")
        return {"s3": "S3 buckets", "kms": "KMS keys"}.get(parts[2] if len(parts) > 2 else "", parts[2] if len(parts) > 2 else "other")
    if p.startswith("//"):
        return p[2:].split("/", 1)[0].replace(".googleapis.com", "")
    return "other"


def _child(a: AccessAssignment) -> str | None:
    if a.scope_level not in ("resource_group", "resource"):
        return None
    return a.resource_group if a.provider == "azure" else _service(a)


def _rows(db: Session, provider: str | None = None, scope: str | None = None):
    q = select(AccessAssignment).where(AccessAssignment.removed_at.is_(None), ~AccessAssignment.scope_external_id.contains(":"))
    if provider:
        q = q.where(AccessAssignment.provider == provider)
    if scope:
        q = q.where(AccessAssignment.scope_external_id == scope)
    return list(db.scalars(q))


@router.get("/tree")
def tree(provider: str | None = None, db: Session = Depends(get_db), _: User = Depends(READ)):
    cov, as_of, ran = _coverage(db)
    by_scope: dict[tuple[str, str], list[AccessAssignment]] = defaultdict(list)
    for a in _rows(db, provider):
        by_scope[(a.provider, a.scope_external_id)].append(a)

    def counts(rows: list[AccessAssignment]) -> dict:
        return {"principals": len({a.principal_id for a in rows}), "assignments": len(rows), "privileged": sum(a.privileged for a in rows),
                "inherited": sum(a.access_type == "Inherited" for a in rows)}

    clouds = []
    for p in ("azure", "aws", "gcp"):
        if provider and p != provider:
            continue
        top, sub = LEVEL_NAME[p]
        root = {"id": p, "level": "cloud", "provider": p, "name": {"azure": "Microsoft Azure", "aws": "Amazon Web Services", "gcp": "Google Cloud"}[p],
                "children": [], "principals": 0, "privileged": 0, "unavailable": []}
        groups: dict[str, dict] = {}
        allp: set[str] = set()
        for s in sorted(db.scalars(select(SCOPE_MODELS[p])), key=lambda s: (s.name or s.external_id).lower()):
            rows = by_scope.get((p, s.external_id), [])
            scope_cov = cov.get(f"{p}:{s.external_id}")
            parent = s.parent or ("Tenant root" if p == "azure" else "Organization root")
            g = groups.setdefault(parent, {"id": f"{p}|g|{parent}", "level": "group", "provider": p, "name": parent.split("/")[-1] if "/" in parent else parent,
                                           "children": [], "principals": 0, "privileged": 0, "unavailable": []})
            top_rows = [a for a in rows if _child(a) is None]
            note = None
            if scope_cov is None:
                note = "Access not collected yet for this scope (no access_inventory run has read it)." if not rows else None
            sn = {"id": f"{p}|s|{s.external_id}", "level": "scope", "kind": top, "provider": p, "scope": s.external_id, "name": s.name or s.external_id,
                  "environment": s.environment, **counts(top_rows), "unavailable": _unavailable(scope_cov or [], False), "note": note, "children": []}
            kids: dict[str, list[AccessAssignment]] = defaultdict(list)
            for a in rows:
                c = _child(a)
                if c is not None:
                    kids[c].append(a)
            for c in sorted(kids, key=str.lower):
                krows = kids[c]
                resources = Counter(a.scope_path for a in krows if a.scope_level == "resource")
                sn["children"].append({"id": f"{p}|c|{s.external_id}|{c}", "level": "child", "kind": sub, "provider": p, "scope": s.external_id, "child": c,
                                       "name": c, **counts(krows), "resources": len(resources), "unavailable": [], "children": []})
            res_unavail = _unavailable(scope_cov or [], True)
            if res_unavail:
                sn["children"].append({"id": f"{p}|c|{s.external_id}|__resources", "level": "child", "kind": "Resource-level access", "provider": p,
                                       "scope": s.external_id, "child": None, "name": "Resource-level access", "principals": 0, "assignments": 0,
                                       "privileged": 0, "inherited": 0, "unavailable": res_unavail, "children": []})
            allp |= {a.principal_id for a in rows}
            g["children"].append(sn)
            g["privileged"] += sum(a.privileged for a in rows)
            g["principals"] = len({a.principal_id for ch in g["children"] for a in by_scope.get((p, ch["scope"]), [])})
        root["children"] = list(groups.values())
        root["principals"], root["privileged"] = len(allp), sum(g["privileged"] for g in groups.values())
        root["scopes"] = sum(len(g["children"]) for g in groups.values())
        clouds.append(root)
    return {"clouds": clouds, "last_refreshed": as_of, "collected": ran,
            "notes": ["Read-only. Changes to access are made in the cloud provider's own console under your change process.",
                      "Inherited = assigned at a management group, organization or folder above this scope.",
                      "AWS shows identity-policy attachments and S3 / KMS resource policies; SCPs and permission boundaries are not combined."]}


def _members(db: Session, provider: str, group_ids: set[str]) -> dict[str, list[dict]]:
    if not group_ids:
        return {}
    rows = list(db.scalars(select(IdentityGroupMember).where(IdentityGroupMember.provider == provider, IdentityGroupMember.group_id.in_(group_ids),
                                                             IdentityGroupMember.removed_at.is_(None))))
    idents = {i.principal_id: i for i in db.scalars(select(CloudIdentity).where(CloudIdentity.provider == provider,
                                                                                 CloudIdentity.principal_id.in_({r.member_id for r in rows})))} if rows else {}
    out: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        i = idents.get(r.member_id)
        out[r.group_id].append({"principal_id": r.member_id, "type": r.member_type, "display_name": i.display_name if i else None,
                                "sign_in_name": i.sign_in_name if i else None, "enabled": i.enabled if i else None})
    return out


@router.get("/who")
def who(provider: str, scope: str, child: str | None = None, resource: str | None = None, q: str | None = None,
        page: int = Query(1, ge=1), size: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db), _: User = Depends(READ)):
    """Everyone with access at a node, including what reaches it from above (subscription → resource group → resource)."""
    rows = _rows(db, provider, scope)
    above = {"azure": "subscription", "aws": "account (identity policies; may apply)", "gcp": "project"}[provider]
    out: list[tuple[AccessAssignment, str | None]] = []
    for a in rows:
        c = _child(a)
        inherited = a.inherited_from if a.access_type == "Inherited" else None
        if resource:                      # resource node: on the resource, on its resource group, or from the scope / above
            if a.scope_path == resource:
                out.append((a, inherited))
            elif c is None:
                out.append((a, inherited or above))
            elif c == child and a.scope_level == "resource_group":
                out.append((a, "resource group"))
        elif child is not None:           # resource group / service node
            if c is None:
                out.append((a, inherited or above))
            elif c == child and a.scope_level == "resource_group":
                out.append((a, inherited))
        elif c is None:                   # subscription / account / project node
            out.append((a, inherited))
    idents = {i.principal_id: i for i in db.scalars(select(CloudIdentity).where(CloudIdentity.provider == provider,
                                                                                 CloudIdentity.principal_id.in_({a.principal_id for a, _ in out})))} if out else {}
    if q:
        ql = q.lower()
        out = [(a, v) for a, v in out if ql in a.principal_id.lower() or ql in (a.role_name or "").lower()
               or (idents.get(a.principal_id) and ql in f"{idents[a.principal_id].display_name or ''} {idents[a.principal_id].sign_in_name or ''}".lower())]
    groups = _members(db, provider, {a.principal_id for a, _ in out if a.principal_type == "Group"})
    resources = sorted({(a.scope_path, a.resource_name) for a in rows if a.scope_level == "resource" and _child(a) == child}) if child and not resource else []
    def name(a: AccessAssignment) -> str:
        i = idents.get(a.principal_id)
        return ((i.display_name if i else None) or a.principal_id).lower()
    out.sort(key=lambda x: (x[1] is not None, not x[0].privileged, name(x[0])))
    total = len(out)
    items = []
    for a, via in out[(page - 1) * size: page * size]:
        i = idents.get(a.principal_id)
        items.append({"id": a.id, "principal_id": a.principal_id, "type": a.principal_type, "display_name": (i.display_name if i else None) or a.principal_id,
                      "sign_in_name": i.sign_in_name if i else None, "enabled": i.enabled if i else None, "lifecycle": i.lifecycle_status if i else None,
                      "last_sign_in": iso(i.last_sign_in_at) if i and i.last_sign_in_at else None, "role": a.role_name, "access_type": a.access_type,
                      "privileged": a.privileged, "level": a.scope_level, "assigned_at": a.scope_path, "inherited_via": via,
                      "cross_account": a.inherited_from == "cross-account", "condition": a.condition,
                      "pim_state": a.pim_state, "expires_at": iso(a.expires_at), "resource": a.resource_name, "last_seen_at": iso(a.last_seen_at),
                      "members": groups.get(a.principal_id) if a.principal_type == "Group" else None,
                      "members_note": None if a.principal_type != "Group" or a.principal_id in groups else "Group membership not collected"})
    return {"total": total, "items": items, "resources": [{"resource": r, "name": n or r.rsplit("/", 1)[-1]} for r, n in resources]}


@router.get("/search")
def search(q: str = Query(..., min_length=2), provider: str | None = None, db: Session = Depends(get_db), _: User = Depends(READ)):
    """Find a person, group or service identity by name and list everything they can reach (directly or through a group)."""
    like = f"%{q}%"
    iq = select(CloudIdentity).where(or_(CloudIdentity.display_name.ilike(like), CloudIdentity.sign_in_name.ilike(like), CloudIdentity.principal_id.ilike(like)))
    if provider:
        iq = iq.where(CloudIdentity.provider == provider)
    idents = list(db.scalars(iq.limit(25)))
    names = {(p, s.external_id): s.name or s.external_id for p, m in SCOPE_MODELS.items() for s in db.scalars(select(m))}
    out = []
    for i in idents:
        via_groups = {m.group_id: m.group_name for m in db.scalars(select(IdentityGroupMember).where(
            IdentityGroupMember.provider == i.provider, IdentityGroupMember.member_id == i.principal_id, IdentityGroupMember.removed_at.is_(None)))}
        rows = list(db.scalars(select(AccessAssignment).where(AccessAssignment.provider == i.provider, AccessAssignment.removed_at.is_(None),
                                                              ~AccessAssignment.scope_external_id.contains(":"),
                                                              AccessAssignment.principal_id.in_({i.principal_id, *via_groups}))))
        out.append({"provider": i.provider, "principal_id": i.principal_id, "type": i.principal_type, "display_name": i.display_name or i.principal_id,
                    "sign_in_name": i.sign_in_name, "enabled": i.enabled, "lifecycle": i.lifecycle_status,
                    "last_sign_in": iso(i.last_sign_in_at) if i.last_sign_in_at else None,
                    "access": [{"scope": a.scope_external_id, "scope_name": names.get((a.provider, a.scope_external_id), a.scope_external_id),
                                "level": a.scope_level, "where": a.resource_name or a.resource_group or names.get((a.provider, a.scope_external_id)), "role": a.role_name,
                                "privileged": a.privileged, "access_type": a.access_type,
                                "through_group": (via_groups.get(a.principal_id) or a.principal_id) if a.principal_id != i.principal_id else None,
                                "inherited_via": a.inherited_from}
                               for a in sorted(rows, key=lambda a: (not a.privileged, a.scope_external_id))]})
    return {"items": out}

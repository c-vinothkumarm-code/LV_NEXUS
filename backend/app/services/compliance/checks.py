"""Automated compliance checks over data LV NEXUS has actually collected from the clouds.

Every check returns a list of results, one per scope it can judge:
    {"provider", "scope", "status": PASS | FAIL | NOT_ASSESSED, "failing", "assessed", "detail", "evidence": [...], "basis"}
Rules that keep results honest:
- NOT_ASSESSED whenever the data a check needs was not collected for that scope (never PASS by absence of data);
- provider-finding checks only judge scopes whose findings are being received (the provider service is reporting);
- evidence lists the concrete items (names, not IDs where a name is known) that caused a FAIL."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import SCOPE_MODELS, AuditEvent, AutomationExecutionLog, DetectionRule, InvestigationCase, NotificationLog, VMInventory
from app.models.access import AccessAssignment, CloudIdentity
from app.models.iam import IamCredential
from app.models.inventory import CloudResource
from app.models.vuln import CloudSecurityFinding as F

PASS, FAIL, NA = "PASS", "FAIL", "NOT_ASSESSED"
OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")
ELIGIBLE = ("Fully Onboarded", "Partially Onboarded")
SERVICE_TYPES = ("serviceprincipal", "managedidentity", "serviceaccount", "role", "application")
OWNER_ROLES = ("owner", "roles/owner", "administratoraccess")
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 5985: "WinRM", 5986: "WinRM",
               27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
DATA_STORE = ("storageaccounts", "microsoft.sql", "dbforpostgresql", "dbformysql", "documentdb", "s3", "rds", "dynamodb", "redshift",
              "bucket", "sqladmin", "bigquery", "storage.googleapis.com")
SOURCE = {"aws": "AWS Security Hub", "azure": "Microsoft Defender for Cloud / Azure Advisor", "gcp": "Google Security Command Center"}


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def r(provider, scope, status, detail, evidence=None, failing=0, assessed=0, basis=None) -> dict:
    return {"provider": provider, "scope": scope, "status": status, "detail": detail, "evidence": (evidence or [])[:20],
            "failing": failing, "assessed": assessed, "basis": basis}


class Ctx:
    """Shared, lazily loaded lookups for one evaluation run."""

    def __init__(self, db: Session, settings: Settings):
        self.db, self.settings, self.now = db, settings, _now()
        self.scopes = {p: list(db.scalars(select(m).where(m.onboarding_status != "Inactive"))) for p, m in SCOPE_MODELS.items()}
        self.names = {(p, s.external_id): s.name or s.external_id for p, rows in self.scopes.items() for s in rows}
        self._idents = None

    def name(self, provider, sid) -> str:
        if provider == "platform":
            return "LV NEXUS platform"
        n = self.names.get((provider, sid))
        if n:
            return n
        if provider == "azure" and sid == (self.settings.azure_tenant_id or ""):
            return "Microsoft Entra ID (tenant)"
        return sid

    def enabled(self, provider) -> bool:
        return {"aws": self.settings.aws_enabled, "azure": self.settings.azure_enabled, "gcp": self.settings.gcp_enabled}.get(provider, True)

    def monitored(self, provider) -> list:
        return [s for s in self.scopes.get(provider, []) if s.onboarding_status in ELIGIBLE and s.monitoring_enabled]

    def unmonitored(self, provider) -> list:
        return [s for s in self.scopes.get(provider, []) if not (s.onboarding_status in ELIGIBLE and s.monitoring_enabled)]

    @property
    def idents(self) -> dict:
        if self._idents is None:
            self._idents = {(i.provider, i.principal_id): i for i in self.db.scalars(select(CloudIdentity))}
        return self._idents

    def who(self, provider, pid) -> str:
        i = self.idents.get((provider, pid))
        return (i.sign_in_name or i.display_name) if i and (i.sign_in_name or i.display_name) else pid


def _clouds(ctx: Ctx, policy) -> list[str]:
    return [p for p in policy.clouds if p != "platform" and ctx.enabled(p)]


def _not_monitored(ctx: Ctx, p: str) -> list[dict]:
    return [r(p, s.external_id, NA, f"Not assessed: {s.name} is '{s.onboarding_status}', so its data is not collected yet") for s in ctx.unmonitored(p)]


# ------------------------------------------------------------------ provider-finding checks
KEYWORDS = {
    "finding_mfa": (["mfa", "multi-factor", "multifactor", "multi factor", "two-factor", "2-step"], []),
    "finding_encryption_rest": (["encrypt", "unencrypted", "customer-managed key", "kms key", "disk encryption", "cmk"],
                                ["transit", "tls", "https", "ssl", "secure transfer"]),
    "finding_encryption_transit": (["tls", "https", "ssl", "secure transfer", "in transit", "encryption in transit"], []),
    "finding_keys": (["key rotation", "purge protection", "soft delete", "soft-delete", "rotate", "key expiration"], []),
    "finding_public_storage": (["public access", "publicly accessible", "public read", "anonymous", "allusers", "public blob", "block public"], []),
    "finding_network": (["network security group", "security group", "0.0.0.0/0", "unrestricted", "firewall rule", "inbound", "ingress"], []),
    "finding_db_exposure": (["sql", "database", "postgres", "mysql", "cosmos", "rds", "cloud sql", "redis"], []),
    "finding_logging": (["diagnostic", "flow log", "logging", "audit log", "log analytics", "cloudtrail", "access log"], []),
    "finding_patching": (["system update", "security update", "patch", "missing update", "vulnerabilities in", "os vulnerabilit", "should be remediated"], []),
    "finding_endpoint": (["endpoint protection", "antimalware", "anti-malware", "edr", "defender for endpoint", "malware"], []),
    "finding_backup": (["backup"], []),
}
DB_EXPOSURE_ALSO = ["public", "firewall", "network access", "internet"]


def _text(f) -> str:
    return " ".join(str(x or "") for x in (f.title, f.category, f.control_id, f.finding_type, f.description)).lower()


def finding_check(ctx: Ctx, policy) -> list[dict]:
    inc, exc = KEYWORDS[policy.check]
    out = []
    for p in _clouds(ctx, policy):
        received = {s for (s,) in ctx.db.execute(select(F.scope_external_id).where(F.provider == p).distinct())}
        rows = defaultdict(list)
        q = select(F).where(F.provider == p, F.is_security.is_(True), F.internal_status.in_(OPEN), F.native_state == "ACTIVE")
        for f in ctx.db.scalars(q):
            t = _text(f)
            if any(k in t for k in inc) and not any(k in t for k in exc) and \
                    (policy.check != "finding_db_exposure" or any(k in t for k in DB_EXPOSURE_ALSO)):
                rows[f.scope_external_id].append(f)
        for s in ctx.monitored(p):
            sid = s.external_id
            if sid not in received:
                out.append(r(p, sid, NA, f"Not assessed: no findings received from {SOURCE[p]} for {s.name} (service off or not readable)"))
                continue
            bad = rows.get(sid, [])
            if bad:
                ev = [{"item": f.resource_name or (f.resource_id or "").rsplit("/", 1)[-1] or f.title, "issue": f.title[:200], "severity": f.severity,
                       "source": f.source} for f in sorted(bad, key=lambda x: ("Critical", "High", "Medium", "Low").index(x.severity)
                                                           if x.severity in ("Critical", "High", "Medium", "Low") else 9)]
                out.append(r(p, sid, FAIL, f"{len(bad)} open {SOURCE[p]} finding(s) for this control", ev, len(bad), len(bad), SOURCE[p]))
            else:
                out.append(r(p, sid, PASS, f"No open {SOURCE[p]} finding for this control", basis=SOURCE[p]))
        out += _not_monitored(ctx, p)
    return out


def benchmark_failures(ctx: Ctx, policy) -> list[dict]:
    out = []
    for p in _clouds(ctx, policy):
        received = {s for (s,) in ctx.db.execute(select(F.scope_external_id).where(F.provider == p, F.compliance_standard.is_not(None)).distinct())}
        for s in ctx.monitored(p):
            if s.external_id not in received:
                out.append(r(p, s.external_id, NA, "Not assessed: no benchmark (CIS / provider standard) results received for this scope"))
                continue
            bad = list(ctx.db.scalars(select(F).where(F.provider == p, F.scope_external_id == s.external_id, F.internal_status.in_(OPEN),
                                                       F.native_state == "ACTIVE", F.compliance_standard.is_not(None)).limit(500)))
            ev = [{"item": f.control_id or f.title[:80], "issue": f.title[:200], "severity": f.severity, "standard": (f.compliance_standard or "")[:80]} for f in bad]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} failing benchmark control result(s)" if bad else "No failing benchmark control",
                         ev, len(bad), len(bad), "Provider compliance standards"))
        out += _not_monitored(ctx, p)
    return out


# ------------------------------------------------------------------ identity checks
def _live_assignments(ctx: Ctx, p: str, privileged_only=False):
    q = select(AccessAssignment).where(AccessAssignment.provider == p, AccessAssignment.removed_at.is_(None))
    if privileged_only:
        q = q.where(AccessAssignment.privileged.is_(True))
    by = defaultdict(list)
    for a in ctx.db.scalars(q):
        by[a.scope_external_id].append(a)
    return by


def _iam_scopes(ctx: Ctx, p: str, by_scope_all: dict):
    """Monitored scopes split into (scope, has access data)."""
    return [(s, bool(by_scope_all.get(s.external_id))) for s in ctx.monitored(p)]


def privileged_holders(ctx: Ctx, policy, params) -> list[dict]:
    limit = int(params.get("max_privileged", 5))
    out = []
    for p in _clouds(ctx, policy):
        allv, priv = _live_assignments(ctx, p), _live_assignments(ctx, p, True)
        for s, has in _iam_scopes(ctx, p, allv):
            if not has:
                out.append(r(p, s.external_id, NA, "Not assessed: access inventory not collected for this scope"))
                continue
            holders = sorted({a.principal_id for a in priv.get(s.external_id, [])})
            ev = [{"item": ctx.who(p, h), "issue": ", ".join(sorted({a.role_name for a in priv[s.external_id] if a.principal_id == h}))[:200]} for h in holders]
            ok = len(holders) <= limit
            out.append(r(p, s.external_id, PASS if ok else FAIL, f"{len(holders)} identities hold privileged roles (limit {limit})", ev,
                         0 if ok else len(holders) - limit, len(holders), "Access inventory"))
        out += _not_monitored(ctx, p)
    return out


def guest_privileged(ctx: Ctx, policy, params) -> list[dict]:
    out = []
    for p in _clouds(ctx, policy):
        allv, priv = _live_assignments(ctx, p), _live_assignments(ctx, p, True)
        for s, has in _iam_scopes(ctx, p, allv):
            if not has:
                out.append(r(p, s.external_id, NA, "Not assessed: access inventory not collected for this scope"))
                continue
            bad = [a for a in priv.get(s.external_id, []) if (ctx.idents.get((p, a.principal_id)) and
                                                             (ctx.idents[(p, a.principal_id)].user_type or "").lower() == "guest")]
            ev = [{"item": ctx.who(p, a.principal_id), "issue": f"guest with {a.role_name}"} for a in bad]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} privileged assignment(s) held by guest accounts", ev, len(bad),
                         len(priv.get(s.external_id, [])), "Access inventory + Entra ID"))
        out += _not_monitored(ctx, p)
    return out


def disabled_with_access(ctx: Ctx, policy, params) -> list[dict]:
    out = []
    for p in _clouds(ctx, policy):
        allv = _live_assignments(ctx, p)
        for s, has in _iam_scopes(ctx, p, allv):
            if not has:
                out.append(r(p, s.external_id, NA, "Not assessed: access inventory not collected for this scope"))
                continue
            bad = []
            for a in allv[s.external_id]:
                i = ctx.idents.get((p, a.principal_id))
                if i is not None and (i.enabled is False or (i.lifecycle_status or "").lower() in ("deleted", "disabled", "missing")):
                    bad.append({"item": ctx.who(p, a.principal_id), "issue": f"{(i.lifecycle_status or 'disabled')} identity still has {a.role_name}"})
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} assignment(s) held by disabled or departed identities", bad, len(bad),
                         len(allv[s.external_id]), "Access inventory + directory"))
        out += _not_monitored(ctx, p)
    return out


def dormant_privileged(ctx: Ctx, policy, params) -> list[dict]:
    days = int(params.get("days", 90))
    cutoff = ctx.now - timedelta(days=days)
    out = []
    for p in _clouds(ctx, policy):
        if not ctx.db.scalar(select(func.count()).select_from(CloudIdentity).where(CloudIdentity.provider == p, CloudIdentity.last_sign_in_at.is_not(None))):
            out.append(r(p, "*", NA, "Not assessed: last sign-in dates are not collected (needs AuditLog.Read.All and Entra ID P1/P2)"))
            continue
        allv, priv = _live_assignments(ctx, p), _live_assignments(ctx, p, True)
        for s, has in _iam_scopes(ctx, p, allv):
            if not has:
                out.append(r(p, s.external_id, NA, "Not assessed: access inventory not collected for this scope"))
                continue
            bad = []
            for pid in sorted({a.principal_id for a in priv.get(s.external_id, []) if (a.principal_type or "").lower() == "user"}):
                i = ctx.idents.get((p, pid))
                if i and i.last_sign_in_at and _aware(i.last_sign_in_at) < cutoff:
                    bad.append({"item": ctx.who(p, pid), "issue": f"last sign-in {_aware(i.last_sign_in_at):%d %b %Y}"})
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} privileged user(s) without sign-in for {days} days", bad, len(bad),
                         len(priv.get(s.external_id, [])), "Access inventory + sign-in logs"))
    return out


def root_usage(ctx: Ctx, policy, params) -> list[dict]:
    since = ctx.now - timedelta(days=int(params.get("days", 30)))
    out = []
    for p in _clouds(ctx, policy):
        for s in ctx.monitored(p):
            n = ctx.db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.provider == p, AuditEvent.scope_external_id == s.external_id,
                                                                                 AuditEvent.event_timestamp >= since))
            if not n:
                out.append(r(p, s.external_id, NA, "Not assessed: no activity collected for this scope in the period"))
                continue
            q = select(AuditEvent).where(AuditEvent.provider == p, AuditEvent.scope_external_id == s.external_id, AuditEvent.event_timestamp >= since)
            if p == "aws":  # root identity type is in the stored raw event; filtered here so it works on every database
                q = q.where(AuditEvent.event_name != "ConsoleLogin")
                bad = [e for e in ctx.db.scalars(q.execution_options(yield_per=1000)) if (e.raw or {}).get("userIdentityType") == "Root"][:50]
            elif p == "azure":
                bad = list(ctx.db.scalars(q.where(func.lower(AuditEvent.event_name).like("%elevateaccess%")).limit(50)))
            else:
                bad = []  # Google Cloud has no root user; Owner grants are covered by detection rule AUD-001
            ev = [{"item": e.principal or "unknown", "issue": f"{e.event_name} at {_aware(e.event_timestamp):%d %b %H:%M} UTC"} for e in bad]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} root / elevated-access action(s) in the period", ev, len(bad), n, "Activity logs"))
        out += _not_monitored(ctx, p)
    return out


def app_credentials(ctx: Ctx, policy, params) -> list[dict]:
    max_days = int(params.get("max_days", 365))
    out = []
    for p in _clouds(ctx, policy):
        creds = list(ctx.db.scalars(select(IamCredential).where(IamCredential.provider == p, IamCredential.removed_at.is_(None))))
        if not creds:
            out.append(r(p, "*", NA, "Not assessed: application credential metadata not collected"))
            continue
        by = defaultdict(list)
        for c in creds:
            by[c.scope_external_id or "*"].append(c)
        for sid, rows in by.items():
            bad = []
            for c in rows:
                exp, made = _aware(c.expires_at), _aware(c.created_at_provider)
                if exp is None:
                    bad.append({"item": ctx.who(p, c.principal_id), "issue": f"{c.kind} without expiry"})
                elif exp < ctx.now:
                    bad.append({"item": ctx.who(p, c.principal_id), "issue": f"{c.kind} expired {exp:%d %b %Y} but still present"})
                elif made and (exp - made).days > max_days:
                    bad.append({"item": ctx.who(p, c.principal_id), "issue": f"{c.kind} valid {(exp - made).days} days (limit {max_days})"})
            out.append(r(p, sid, FAIL if bad else PASS, f"{len(bad)} of {len(rows)} app credential(s) out of policy", bad, len(bad), len(rows),
                         "Entra ID application credentials"))
    return out


def workload_owner(ctx: Ctx, policy, params) -> list[dict]:
    out = []
    for p in _clouds(ctx, policy):
        allv = _live_assignments(ctx, p)
        for s, has in _iam_scopes(ctx, p, allv):
            if not has:
                out.append(r(p, s.external_id, NA, "Not assessed: access inventory not collected for this scope"))
                continue
            bad = [a for a in allv[s.external_id] if (a.principal_type or "").lower() in SERVICE_TYPES and (a.role_name or "").lower() in OWNER_ROLES]
            ev = [{"item": ctx.who(p, a.principal_id), "issue": f"{a.role_name} at {a.scope_level or 'scope'}"} for a in bad]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} workload identit(ies) with Owner-level rights", ev, len(bad),
                         len(allv[s.external_id]), "Access inventory"))
        out += _not_monitored(ctx, p)
    return out


# ------------------------------------------------------------------ exposure / logging / incident
def open_admin_ports(ctx: Ctx, policy, params) -> list[dict]:
    out = []
    for p in _clouds(ctx, policy):
        vms = defaultdict(list)
        for v in ctx.db.scalars(select(VMInventory).where(VMInventory.provider == p, VMInventory.deleted_at.is_(None))):
            vms[v.scope_external_id].append(v)
        for s in ctx.monitored(p):
            rows = vms.get(s.external_id)
            if not rows:
                out.append(r(p, s.external_id, NA, "Not assessed: no virtual machines collected for this scope"))
                continue
            bad = [{"item": v.name or v.instance_id, "issue": "open to the internet: " + ", ".join(f"{pt} ({ADMIN_PORTS[pt]})" for pt in sorted(set(v.exposed_ports or []) & set(ADMIN_PORTS)))}
                   for v in rows if v.public_ip and set(v.exposed_ports or []) & set(ADMIN_PORTS)]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} of {len(rows)} VM(s) expose admin or database ports", bad, len(bad), len(rows),
                         "VM inventory (network rules evaluated)"))
        out += _not_monitored(ctx, p)
    return out


def _latest_run(ctx: Ctx, job: str):
    return ctx.db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == job, AutomationExecutionLog.finished_at.is_not(None))
                         .order_by(AutomationExecutionLog.started_at.desc()).limit(1))


def activity_collected(ctx: Ctx, policy, params) -> list[dict]:
    from app.services.scopes import check_passed
    run = _latest_run(ctx, "security_events")
    failed = {(f.get("provider"), f.get("scope")): f.get("reason") for f in (run.failures or [])} if run else {}
    fresh = run is not None and ctx.now - _aware(run.finished_at) < timedelta(hours=2)
    out = []
    for p in _clouds(ctx, policy):
        for s in ctx.scopes.get(p, []):
            sid = s.external_id
            if not (s.onboarding_status in ELIGIBLE and s.monitoring_enabled):
                out.append(r(p, sid, FAIL, f"Activity not collected: {s.name} is '{s.onboarding_status}'", [{"item": s.name, "issue": s.onboarding_status}], 1, 1,
                             "Onboarding status"))
            elif not check_passed(s, "audit_logs"):
                out.append(r(p, sid, FAIL, "Activity log access not validated for this scope", [{"item": s.name, "issue": "audit log permission"}], 1, 1, "Onboarding checks"))
            elif (p, sid) in failed:
                out.append(r(p, sid, FAIL, f"Last collection failed: {str(failed[(p, sid)])[:180]}", [{"item": s.name, "issue": str(failed[(p, sid)])[:200]}], 1, 1,
                             "security_events job"))
            elif not fresh:
                out.append(r(p, sid, FAIL, "Activity collection has not succeeded in the last 2 hours", [{"item": s.name, "issue": "stale"}], 1, 1, "security_events job"))
            else:
                out.append(r(p, sid, PASS, "Activity logs collected in the last run", assessed=1, basis="security_events job"))
    return out


def security_service_on(ctx: Ctx, policy, params) -> list[dict]:
    since = ctx.now - timedelta(days=3)
    out = []
    for p in _clouds(ctx, policy):
        recent = {s for (s,) in ctx.db.execute(select(F.scope_external_id).where(F.provider == p, F.last_synced_at >= since).distinct())}
        for s in ctx.monitored(p):
            ok = s.external_id in recent
            out.append(r(p, s.external_id, PASS if ok else FAIL,
                         f"{SOURCE[p]} findings received in the last 3 days" if ok else f"No {SOURCE[p]} findings received in 3 days: service off, or LV NEXUS cannot read it",
                         [] if ok else [{"item": s.name, "issue": f"enable {SOURCE[p]} and grant Security Reader"}], 0 if ok else 1, 1, "security_findings_sync"))
        out += _not_monitored(ctx, p)
    return out


def sla_overdue(ctx: Ctx, policy, params) -> list[dict]:
    out = []
    for p in _clouds(ctx, policy):
        received = {s for (s,) in ctx.db.execute(select(F.scope_external_id).where(F.provider == p).distinct())}
        for s in ctx.monitored(p):
            if s.external_id not in received:
                out.append(r(p, s.external_id, NA, "Not assessed: no findings received for this scope"))
                continue
            bad = list(ctx.db.scalars(select(F).where(F.provider == p, F.scope_external_id == s.external_id, F.internal_status.in_(OPEN),
                                                       F.severity.in_(("Critical", "High")), F.sla_due_at < ctx.now,
                                                       or_(F.sla_paused.is_(False), F.sla_paused.is_(None))).limit(200)))
            ev = [{"item": f.resource_name or f.title[:60], "issue": f"{f.severity}: {f.title[:150]} (due {_aware(f.sla_due_at):%d %b})", "severity": f.severity} for f in bad]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} critical/high finding(s) past their SLA", ev, len(bad), len(bad), "Vulnerability SLA"))
        out += _not_monitored(ctx, p)
    return out


def _data_stores(ctx: Ctx, p: str):
    by = defaultdict(list)
    for res in ctx.db.scalars(select(CloudResource).where(CloudResource.provider == p, or_(CloudResource.state.is_(None), CloudResource.state != "deleted"))):
        if any(k in (res.resource_type or "").lower() for k in DATA_STORE):
            by[res.scope_external_id].append(res)
    return by


def classification_tags(ctx: Ctx, policy, params) -> list[dict]:
    key = params.get("tag_key", "data-classification").lower()
    out = []
    for p in _clouds(ctx, policy):
        stores = _data_stores(ctx, p)
        for s in ctx.monitored(p):
            rows = stores.get(s.external_id)
            if not rows:
                out.append(r(p, s.external_id, NA, "Not assessed: no storage or database resources collected for this scope"))
                continue
            bad = [{"item": x.name, "issue": f"{x.resource_type} without '{key}' tag"} for x in rows
                   if key not in {k.lower() for k in ((x.attributes or {}).get("tags") or {})}]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} of {len(rows)} data store(s) not classified", bad, len(bad), len(rows), "Resource inventory tags"))
        out += _not_monitored(ctx, p)
    return out


def pii_regions(ctx: Ctx, policy, params) -> list[dict]:
    key = params.get("tag_key", "data-classification").lower()
    personal = {v.lower() for v in params.get("personal_values", [])}
    approved = {v.lower() for v in params.get("approved_regions", [])}
    out = []
    for p in _clouds(ctx, policy):
        stores = _data_stores(ctx, p)
        for s in ctx.monitored(p):
            tagged = [x for x in stores.get(s.external_id, []) if any(k.lower() == key and str(v).lower() in personal
                                                                      for k, v in ((x.attributes or {}).get("tags") or {}).items())]
            if not tagged:
                out.append(r(p, s.external_id, NA, f"Not assessed: no data store tagged {key}=personal in this scope"))
                continue
            bad = [{"item": x.name, "issue": f"personal data in region {x.region}"} for x in tagged if (x.region or "").lower() not in approved]
            out.append(r(p, s.external_id, FAIL if bad else PASS, f"{len(bad)} of {len(tagged)} personal-data store(s) outside approved regions", bad, len(bad),
                         len(tagged), "Resource inventory tags + regions"))
    return out


def detection_rules(ctx: Ctx, policy, params) -> list[dict]:
    keys = params.get("rules", [])
    rules = {d.rule_key: d for d in ctx.db.scalars(select(DetectionRule).where(DetectionRule.rule_key.in_(keys)))}
    bad = [{"item": k, "issue": "missing" if k not in rules else f"disabled: {rules[k].name}"} for k in keys if k not in rules or not rules[k].enabled]
    return [r("platform", "platform", FAIL if bad else PASS, f"{len(keys) - len(bad)} of {len(keys)} core detection rules enabled", bad, len(bad), len(keys),
              "Audit detection rules")]


def triage_6h(ctx: Ctx, policy, params) -> list[dict]:
    hours = int(params.get("hours", 6))
    cases = list(ctx.db.scalars(select(InvestigationCase).where(InvestigationCase.risk.in_(("Critical", "High")),
                                                                InvestigationCase.created_at >= ctx.now - timedelta(days=30))))
    bad = [c for c in cases if c.status == "DETECTED" and _aware(c.created_at) < ctx.now - timedelta(hours=hours)]
    ev = [{"item": c.title[:120], "issue": f"{c.risk}, untriaged since {_aware(c.created_at):%d %b %H:%M} UTC"} for c in bad]
    if not cases:
        return [r("platform", "platform", PASS, "No high-risk detection in the last 30 days", basis="Investigation cases")]
    return [r("platform", "platform", FAIL if bad else PASS, f"{len(bad)} of {len(cases)} high-risk case(s) untriaged after {hours} h", ev, len(bad), len(cases),
              "Investigation cases")]


def alert_channels(ctx: Ctx, policy, params) -> list[dict]:
    from app.services.notifications.channels import GmailChannel
    s = ctx.settings
    configured = [n for n, ok in (("e-mail", GmailChannel(s).configured()), ("Google Chat", bool(s.chat_webhook_url))) if ok]
    if not configured:
        return [r("platform", "platform", FAIL, "No alert channel configured", [{"item": "SMTP_* / CHAT_WEBHOOK_URL", "issue": "not set"}], 1, 1, "Settings")]
    sent = ctx.db.scalar(select(func.count()).select_from(NotificationLog).where(NotificationLog.status == "sent", NotificationLog.sent_at >= ctx.now - timedelta(hours=48)))
    if not sent:
        return [r("platform", "platform", FAIL, f"{', '.join(configured)} configured but nothing delivered in 48 h", [{"item": ", ".join(configured), "issue": "no delivery"}],
                  1, 1, "Notification log")]
    return [r("platform", "platform", PASS, f"{sent} message(s) delivered in 48 h via {', '.join(configured)}", assessed=1, basis="Notification log")]


def log_retention(ctx: Ctx, policy, params) -> list[dict]:
    days = ctx.settings.audit_retention_days
    oldest = ctx.db.scalar(select(func.min(AuditEvent.event_timestamp)))
    history = f"; history held since {_aware(oldest):%d %b %Y}" if oldest else "; no events stored yet"
    host = (ctx.settings.database_url.split("@", 1)[-1].split("/", 1)[0].split(":", 1)[0] if "@" in ctx.settings.database_url else "local file")
    ev = [{"item": "AUDIT_RETENTION_DAYS", "issue": str(days)}, {"item": "database host", "issue": f"{host} (must be in India for CERT-In)"}]
    if days >= 365:
        return [r("platform", "platform", PASS, f"Retention {days} days: meets CERT-In (180) and DPDP (365){history}", ev, 0, 1, "Platform settings")]
    if days >= 180:
        return [r("platform", "platform", FAIL, f"Retention {days} days: meets CERT-In 180 days but not DPDP one year (from 13 May 2027){history}", ev, 1, 1, "Platform settings")]
    return [r("platform", "platform", FAIL, f"Retention {days} days is below the CERT-In 180-day minimum{history}", ev, 1, 1, "Platform settings")]


def app_sso(ctx: Ctx, policy, params) -> list[dict]:
    m = ctx.settings.auth_mode
    return [r("platform", "platform", FAIL if m == "dev" else PASS, f"AUTH_MODE={m}" + (" (development sign-in, no MFA)" if m == "dev" else " (corporate identity provider)"),
              [{"item": "AUTH_MODE", "issue": m}] if m == "dev" else [], 1 if m == "dev" else 0, 1, "Platform settings")]


def app_secrets(ctx: Ctx, policy, params) -> list[dict]:
    from app.core import secrets
    s = ctx.settings
    if s.app_env != "production":
        return [r("platform", "platform", NA, f"Not assessed in APP_ENV={s.app_env}: secrets may come from .env on a workstation", basis="Platform settings")]
    loose = [k for k, v in secrets.SOURCES.items() if v in ("dotenv", "environment")]
    ok = bool(s.azure_key_vault_url) and secrets.STATUS.get("state") == "ok" and not loose
    return [r("platform", "platform", PASS if ok else FAIL, "Secrets read from Key Vault" if ok else "Production secrets not (all) in Key Vault",
              [{"item": k, "issue": "read from .env / environment"} for k in loose], len(loose) or (0 if ok else 1), 1, "Secret sources")]


def app_hardening(ctx: Ctx, policy, params) -> list[dict]:
    s = ctx.settings
    bad = []
    if not s.rate_limit_per_minute:
        bad.append({"item": "RATE_LIMIT_PER_MINUTE", "issue": "0 (off)"})
    if not s.auth_rate_limit_per_minute:
        bad.append({"item": "AUTH_RATE_LIMIT_PER_MINUTE", "issue": "0 (off)"})
    if s.session_idle_minutes > 60:
        bad.append({"item": "SESSION_IDLE_MINUTES", "issue": str(s.session_idle_minutes)})
    return [r("platform", "platform", FAIL if bad else PASS, "API rate limits and session timeouts configured" if not bad else f"{len(bad)} setting(s) weaker than policy",
              bad, len(bad), 3, "Platform settings")]


def attestation(ctx: Ctx, policy, params, setting=None) -> list[dict]:
    if setting is None or not setting.attested_status:
        return [r("platform", "platform", NA, "Not assessed: needs an attestation with evidence (cannot be read from a cloud API)", basis="Attestation")]
    valid = setting.attestation_valid_until
    if valid and valid < date.today():
        return [r("platform", "platform", NA, f"Attestation expired on {valid:%d %b %Y}; attest again with current evidence", basis="Attestation")]
    ev = [{"item": setting.attested_by or "unknown", "issue": f"attested {setting.attested_status} on {_aware(setting.attested_at):%d %b %Y}",
           "evidence": setting.attestation_evidence or ""}]
    return [r("platform", "platform", setting.attested_status, f"Attested by {setting.attested_by}" + (f", valid until {valid:%d %b %Y}" if valid else ""),
              ev, 1 if setting.attested_status == FAIL else 0, 1, "Attestation")]


CHECKS = {name: (lambda n: (lambda ctx, pol, params: finding_check(ctx, pol)))(name) for name in KEYWORDS}
CHECKS.update({"benchmark_failures": lambda ctx, pol, params: benchmark_failures(ctx, pol), "privileged_holders": privileged_holders,
               "guest_privileged": guest_privileged, "disabled_with_access": disabled_with_access, "dormant_privileged": dormant_privileged,
               "root_usage": root_usage, "app_credentials": app_credentials, "workload_owner": workload_owner, "open_admin_ports": open_admin_ports,
               "activity_collected": activity_collected, "security_service_on": security_service_on, "sla_overdue": sla_overdue,
               "classification_tags": classification_tags, "pii_regions": pii_regions, "detection_rules": detection_rules, "triage_6h": triage_6h,
               "alert_channels": alert_channels, "log_retention": log_retention, "app_sso": app_sso, "app_secrets": app_secrets,
               "app_hardening": app_hardening})

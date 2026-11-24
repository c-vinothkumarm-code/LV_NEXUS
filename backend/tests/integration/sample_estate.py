"""A small, clearly fictional sample estate (Azure, AWS, GCP) used by the API sweep and UI tests. Test-only data."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select

from app.models import (
    AutomationExecutionLog,
    AutomationJob,
    BillingRecord,
    CloudAccount,
    CloudProject,
    CloudResource,
    CloudSecurityFinding,
    CloudSubscription,
    SyncCheckpoint,
    VMInventory,
)
from app.models.access import AccessAssignment, CloudIdentity
from app.models.iam import IdentityGroupMember
from app.models.platform import AuditAnomaly, CostDetailRecord
from app.services.access.collectors import h


def seed(db) -> None:
    now = datetime.now(UTC)
    today = date.today()
    db.add_all([CloudSubscription(external_id="sub-prod", name="contoso-prod", onboarding_status="Fully Onboarded", tenant_id="tenant-demo", parent="mg-platform", environment="Production"),
                CloudSubscription(external_id="sub-dev", name="contoso-dev", onboarding_status="Fully Onboarded", tenant_id="tenant-demo", parent="mg-platform", environment="Development"),
                CloudAccount(external_id="100000000001", name="demo-payments", onboarding_status="Fully Onboarded", parent="ou-workloads", environment="Production"),
                CloudAccount(external_id="100000000002", name="demo-sandbox", onboarding_status="Discovered", parent="ou-sandbox", environment="Sandbox"),
                CloudProject(external_id="demo-analytics", name="demo-analytics", onboarding_status="Fully Onboarded", parent="folders/1001", environment="Production")])
    rgs = ["rg-web", "rg-data", "rg-network"]
    for sub in ("sub-prod", "sub-dev"):
        for i, rg in enumerate(rgs):
            for k in range(3 + i):
                rid = f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/st{rg[3:]}{k}"
                db.add(CloudResource(provider="azure", scope_external_id=sub, resource_id=rid, resource_type="microsoft.storage/storageaccounts", name=f"st{rg[3:]}{k}", region="centralindia", attributes={}, last_seen_at=now))
                db.add(CostDetailRecord(row_hash=h(rid), provider="azure", breakdown="resource", scope_external_id=sub, usage_date=today, currency="USD", amount=Decimal(40 + 13 * k), amount_usd=Decimal(40 + 13 * k), resource_group=rg, resource_id=rid))
            db.add(VMInventory(provider="azure", scope_external_id=sub, instance_id=f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/vm-{rg[3:]}", name=f"vm-{rg[3:]}", region="centralindia", health_status="critical" if rg == "rg-web" else "healthy", power_state="running", exposed_ports=[22] if rg == "rg-web" else []))
    for reg in ("ap-south-1", "us-east-1"):
        for k in range(4):
            db.add(CloudResource(provider="aws", scope_external_id="100000000001", resource_id=f"arn:aws:s3:::demo-{reg}-{k}", resource_type="s3", name=f"demo-{reg}-{k}", region=reg, attributes={}, last_seen_at=now))
    db.add(CloudResource(provider="gcp", scope_external_id="demo-analytics", resource_id="//storage/raw-zone", resource_type="bucket", name="raw-zone", region="asia-south1", attributes={}, last_seen_at=now))
    for d in range(18):
        for p, sc, v in (("azure", "sub-prod", 420), ("azure", "sub-dev", 90), ("aws", "100000000001", 310), ("gcp", "demo-analytics", 140)):
            db.add(BillingRecord(provider=p, scope_external_id=sc, service={"azure": "Virtual Machines", "aws": "Amazon EC2", "gcp": "BigQuery"}[p], usage_date=today.replace(day=1) + timedelta(days=d) if (today.replace(day=1) + timedelta(days=d)) <= today else today, cost_original=Decimal(v + d * 3), currency_original="USD", cost_usd=Decimal(v + d * 3)))
    for n, (p, sc, sev, rg) in enumerate([("azure", "sub-prod", "Critical", "rg-web"), ("azure", "sub-prod", "High", "rg-data"), ("aws", "100000000001", "High", None), ("gcp", "demo-analytics", "Medium", None), ("aws", "100000000001", "Critical", None)]):
        db.add(CloudSecurityFinding(provider=p, source={"azure": "azure_advisor", "aws": "security_hub", "gcp": "scc"}[p], native_id=f"n{n}", native_id_hash=f"n{n}", scope_external_id=sc, resource_group=rg, region="ap-south-1" if p == "aws" else None, title=["Storage account allows public blob access", "Key Vault soft delete disabled", "S3 bucket without encryption", "Bucket uniform access disabled", "Root account without MFA"][n], severity=sev, resource_id=f"/subscriptions/{sc}/resourceGroups/{rg}/x" if rg else None, first_observed_at=now - timedelta(days=n + 1), first_synced_at=now - timedelta(days=n + 1), last_synced_at=now, raw={}))
        db.add(SyncCheckpoint(provider=p, source={"azure": "azure_advisor", "aws": "security_hub", "gcp": "scc"}[p], scope_external_id=sc, region=f"r{n}", state="OK" if p != "gcp" else "ACCESS_DENIED", last_success_at=now if p != "gcp" else None, last_error=None if p != "gcp" else "403 securitycenter.findings.list denied on organizations/0000"))
    def A(p, sc, sid, lvl, path, pid, pt, role, **kw):
        return AccessAssignment(provider=p, source=kw.pop("source", "t"), source_id=sid, source_id_hash=h("t", sid), scope_external_id=sc, scope_level=lvl, scope_path=path, principal_id=pid, principal_type=pt, role_name=role, access_type=kw.pop("access", "Direct"), privileged=kw.pop("priv", False), **kw)
    db.add_all([A("azure", "sub-prod", "1", "subscription", "/subscriptions/sub-prod", "u1", "User", "Owner", priv=True),
                A("azure", "sub-prod", "2", "management_group", "/providers/Microsoft.Management/managementGroups/mg-platform", "u2", "User", "Reader", access="Inherited", inherited_from="/providers/Microsoft.Management/managementGroups/mg-platform"),
                A("azure", "sub-prod", "3", "resource_group", "/subscriptions/sub-prod/resourceGroups/rg-web", "g1", "Group", "Contributor", access="Group", resource_group="rg-web", priv=True),
                A("azure", "sub-prod", "4", "resource", "/subscriptions/sub-prod/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm-web", "sp1", "ServicePrincipal", "Virtual Machine Contributor", resource_group="rg-web", resource_name="vm-web"),
                A("aws", "100000000001", "5", "account", "arn:aws:iam::100000000001", "arn:aws:iam::100000000001:role/DemoAdmin", "Role", "AdministratorAccess", priv=True),
                A("aws", "100000000001", "6", "resource", "arn:aws:s3:::demo-ap-south-1-0", "arn:aws:iam::200000000002:role/partner-reader", "Role", "s3:GetObject", resource_name="demo-ap-south-1-0", inherited_from="cross-account", source="aws_resource_policy"),
                A("gcp", "demo-analytics", "7", "project", "projects/demo-analytics", "user:priya@example.com", "User", "roles/editor", priv=True),
                A("gcp", "demo-analytics", "8", "resource", "//storage.googleapis.com/projects/_/buckets/raw-zone", "group:data-eng@example.com", "Group", "roles/storage.objectViewer", access="Group", resource_name="raw-zone", source="gcp_resource_iam")])
    db.add_all([CloudIdentity(provider="azure", principal_id="u1", principal_type="User", display_name="Asha Rao (sample)", sign_in_name="asha@example.com", last_sign_in_at=now - timedelta(hours=3)),
                CloudIdentity(provider="azure", principal_id="u2", principal_type="User", display_name="Ravi Kumar (sample)", sign_in_name="ravi@example.com"),
                CloudIdentity(provider="azure", principal_id="g1", principal_type="Group", display_name="web-operators"),
                CloudIdentity(provider="azure", principal_id="u3", principal_type="User", display_name="Meena Iyer (sample)", sign_in_name="meena@example.com"),
                CloudIdentity(provider="azure", principal_id="sp1", principal_type="ServicePrincipal", display_name="deploy-pipeline"),
                IdentityGroupMember(provider="azure", group_id="g1", group_name="web-operators", member_id="u3", member_type="User")])
    def job(n):
        return db.scalar(select(AutomationJob).where(AutomationJob.name == n))
    db.add(AutomationExecutionLog(job_id=job("access_inventory").id, job_name="access_inventory", status="partial", finished_at=now - timedelta(minutes=9), summary={"coverage": {
        "azure:sub-prod": [{"source": "azure_rbac", "state": "OK", "message": "ok"}], "azure:sub-dev": [{"source": "azure_rbac", "state": "ACCESS_DENIED", "message": "AuthorizationFailed"}],
        "aws:100000000001": [{"source": "aws_iam", "state": "OK", "message": "ok"}, {"source": "aws_resource_policy:kms", "state": "ACCESS_DENIED", "message": "AccessDenied"}],
        "gcp:demo-analytics": [{"source": "gcp_iam", "state": "OK", "message": "ok"}]}}, failures=[{"provider": "azure", "scope": "sub-dev", "reason": "azure_rbac: AuthorizationFailed (403)"}]))
    db.add(AutomationExecutionLog(job_id=job("billing_refresh").id, job_name="billing_refresh", status="success", finished_at=now - timedelta(minutes=20)))
    db.add(AutomationExecutionLog(job_id=job("cost_detail_refresh").id, job_name="cost_detail_refresh", status="failed", finished_at=now - timedelta(minutes=40), error="[throttle] 429 Too many requests from Cost Management"))
    db.add(AutomationExecutionLog(job_id=job("preflight").id, job_name="preflight", status="partial", finished_at=now - timedelta(hours=2), summary={"preflight": {"verdict": "FAIL", "counts": {"PASS": 14, "WARN": 2, "FAIL": 2}, "generated_at": (now - timedelta(hours=2)).isoformat(), "checks": [
        {"area": "cloud", "cloud": "azure", "scope": None, "check": "Credentials and discovery", "status": "PASS", "message": "Credentials work; 2 subscriptions visible", "fix": None},
        {"area": "scope", "cloud": "azure", "scope": "contoso-dev", "check": "Azure RBAC, Microsoft Graph, PIM", "status": "FAIL", "message": "azure_rbac: AuthorizationFailed (403)", "fix": "Grant the read permission named in the message to the CloudNexus identity on this scope (see System Health)."},
        {"area": "scope", "cloud": "gcp", "scope": "demo-analytics", "check": "Security Command Center", "status": "FAIL", "message": "403 securitycenter.findings.list denied", "fix": "Grant the read permission named in the message to the CloudNexus identity on this scope (see System Health)."},
        {"area": "platform", "cloud": None, "scope": None, "check": "Secrets from Azure Key Vault", "status": "WARN", "message": "AZURE_KEY_VAULT_URL is not set (fine for local use)", "fix": "Create the secrets listed in the README in Key Vault and set AZURE_KEY_VAULT_URL."}]}}))
    for i, (rule, sev, title, pr, det) in enumerate([("mass_deletion", "Critical", "Mass deletion", "arn:aws:iam::100000000001:user/ci-bot", {"max_in_window": 27, "window_minutes": 10, "operations": ["DeleteObject", "DeleteBucket"]}),
        ("new_country", "High", "Sign-in from a new country", "asha@example.com", {"countries": ["RO"], "known_countries": ["IN"], "baseline_signins": 41}),
        ("privilege_change", "High", "Privilege or access change", "ravi@example.com", {"operations": ["Microsoft.Authorization/roleAssignments/write"]}),
        ("unusual_hours", "Medium", "Activity at unusual hours", "deploy-pipeline", {"local_hours": [3], "timezone": "Asia/Kolkata", "share_of_history_pct": 0.4, "operations": ["Microsoft.Compute/virtualMachines/write"]})]):
        db.add(AuditAnomaly(dedupe_key=f"k{i}", rule=rule, severity=sev, title=title, provider="aws" if i == 0 else "azure", scope_external_id="100000000001" if i == 0 else "sub-prod", principal=pr, detail=det, event_ids=[], event_count=3 + i, first_event_at=now - timedelta(hours=i + 1), last_event_at=now - timedelta(minutes=10 * (i + 1))))
    db.commit()

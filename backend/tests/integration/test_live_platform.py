"""Live activity (feed, investigation, export, Entra logs), cost detail and cost analysis (periods, grouping, forecast kept
separate), Defender / Azure Policy collectors with Advisor de-duplication, structured AI validation, connection registry,
resource collectors that never mark resources deleted from a partial listing, and executive decisions."""
from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace as NS

from sqlalchemy import select

from app.models import AutomationJob, BillingForecast, BillingRecord, CloudResource, CloudSubscription
from app.models.platform import AIAnalysisResult, CostDetailRecord
from app.scheduler.engine import JobContext
from app.services.finops.detail import AzureCostDetail, run_cost_detail
from app.services.intelligence import structured
from app.services.inventory import AwsResourceCollector, store
from app.services.soc.engine import _store
from app.services.soc.entra import EntraActivityCollector, normalize_directory_audit, run_entra_activity
from app.services.soc.normalize import normalize_cloudtrail
from app.services.vuln.azure_extra import AzurePolicyCollector, DefenderAssessmentCollector
from app.services.vuln.common import HttpError
from tests.integration.test_identity_governance import FakeRest, login

H = {"X-Requested-With": "mcp-dashboard"}
SUB = "33333333-aaaa-bbbb-cccc-000000000001"


def ct(i, name="DeleteBucket", who="arn:aws:iam::111111111111:user/eve", error=None, ip="198.51.100.7", when=None):
    detail = {"eventID": f"ev{i}", "eventName": name, "awsRegion": "ap-south-1", "sourceIPAddress": ip, "userIdentity": {"arn": who, "type": "IAMUser"},
              "eventSource": "s3.amazonaws.com", "eventTime": (when or datetime.now(UTC)).isoformat()}
    if error:
        detail["errorCode"] = error
    return normalize_cloudtrail({"EventId": f"ev{i}", "EventName": name, "EventTime": when or datetime.now(UTC), "CloudTrailEvent": json.dumps(detail),
                                 "Resources": [{"ResourceName": f"bucket-{i}", "ResourceType": "AWS::S3::Bucket"}]}, "111111111111")


def test_activity_feed_investigation_and_export(client, db):
    _store(db, [ct(1), ct(2, "PutBucketPolicy", error="AccessDenied"), ct(3, "ListBuckets", ip="=cmd|calc")])
    db.commit()
    login(client, db, "sec@latentview.com", "security_analyst")
    feed = client.get("/api/v1/activity/events").json()
    assert feed["total"] == 3 and feed["latest_id"] and all(i["provider_delay_seconds"] is not None for i in feed["items"])
    denied = client.get("/api/v1/activity/events", params={"result": "failure"}).json()
    assert [i["operation"] for i in denied["items"]] == ["PutBucketPolicy"]
    after = client.get("/api/v1/activity/events", params={"after_id": feed["latest_id"]}).json()
    assert after["total"] == 0
    eid = next(i["id"] for i in feed["items"] if i["operation"] == "PutBucketPolicy")
    inv = client.get(f"/api/v1/activity/events/{eid}/investigation").json()
    answers = {a["q"]: a["a"] for a in inv["answers"]}
    assert answers["Was the operation successful?"] == "No (access denied)" and "eve" in answers["Who performed the action?"]
    assert answers["Was it associated with an approved request?"].startswith("No approved request")
    assert len(inv["related"]) == 2  # same principal within 24 hours
    csv_text = client.get("/api/v1/activity/export", params={"format": "csv"}).text
    assert "'=cmd|calc" in csv_text  # spreadsheet formula injection neutralised
    assert len(client.get("/api/v1/activity/export", params={"format": "json"}).json()["items"]) == 3
    fresh = client.get("/api/v1/activity/freshness").json()
    assert fresh["delay"]["aws"]["sample"] == 3 and fresh["limitations"]
    login(client, db, "fin@latentview.com", "finops_analyst")
    assert client.get("/api/v1/activity/events").status_code == 403


def test_entra_activity_job_and_permission_gap(db, settings):
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "entra_activity"))
    audit = {"id": "a1", "activityDateTime": datetime.now(UTC).isoformat(), "activityDisplayName": "Add member to role", "category": "RoleManagement",
             "result": "success", "initiatedBy": {"user": {"userPrincipalName": "admin@latentview.com", "ipAddress": "203.0.113.4"}},
             "targetResources": [{"id": "u9", "type": "User", "userPrincipalName": "new@latentview.com"}]}
    assert normalize_directory_audit(audit, "t")["event_category"] == "EntraAudit:RoleManagement"
    s = settings.model_copy(update={"azure_tenant_id": "t"})
    rest = FakeRest({"directoryAudits": [audit], "signIns": HttpError(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant")})
    res = run_entra_activity(JobContext(db=db, job=job, execution_id=1), s, EntraActivityCollector(s, rest))
    # no Entra ID P1/P2 licence: sign-in logs do not exist in this tenant -> reported with a note, not as a failure
    assert res.status.value == "success" and res.summary["sources"]["sign_ins"]["unavailable"] == "licence"
    assert "P1 or P2" in res.summary["sources"]["sign_ins"]["note"]
    assert res.summary["sources"]["directory_audits"]["stored"] == 1
    denied = FakeRest({"directoryAudits": HttpError(403, "Authorization_RequestDenied"), "signIns": []})
    res = run_entra_activity(JobContext(db=db, job=job, execution_id=2), s, EntraActivityCollector(s, denied))
    assert res.status.value == "partial" and "missing permission" in res.failures[0]["reason"] and "Global Reader" in res.failures[0]["reason"]


def _azure_cost_rest():
    cols = lambda *n: [{"name": x} for x in n]  # noqa: E731
    d = int(date.today().strftime("%Y%m%d"))
    rid = f"/subscriptions/{SUB}/resourceGroups/rg-data/providers/Microsoft.Compute/disks/disk1"
    return FakeRest({"/query?": {"properties": {"columns": cols("Cost", "UsageDate", "ResourceId", "ServiceName", "ResourceLocation", "Currency"),
                                                "rows": [[12.5, d, rid, "Storage", "centralindia", "USD"]]}},
                     "/forecast?": {"properties": {"columns": cols("Cost", "UsageDate", "Currency"), "rows": [[100, d, "USD"], [50, d, "USD"]]}},
                     "Consumption/budgets": [{"id": "b1", "name": "monthly", "properties": {"amount": 1000, "timeGrain": "Monthly",
                                                                                            "currentSpend": {"amount": 12.5, "unit": "USD"},
                                                                                            "notifications": {"n": {"threshold": 80}}}}]})


def test_cost_detail_job_and_analysis(client, db, settings):
    db.add(CloudSubscription(external_id=SUB, name="data-prod", onboarding_status="Fully Onboarded",
                             checks={"billing": {"status": "pass"}, "permissions": {"status": "pass"}}))
    today = date.today()
    for i in range(3):
        d = today - timedelta(days=i)
        db.add(BillingRecord(provider="azure", scope_external_id=SUB, service="Storage", usage_date=d, cost_original=Decimal(10), currency_original="USD",
                             cost_usd=Decimal(10), is_final=False))
    db.commit()
    s = settings.model_copy(update={"cost_tag_keys": ["environment"], "cost_include_amortized": False})
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "cost_detail_refresh"))
    res = run_cost_detail(JobContext(db=db, job=job, execution_id=1), s, {"azure": object()}, {"azure": AzureCostDetail(s, _azure_cost_rest())})
    assert res.status.value == "success", res.failures
    rows = list(db.scalars(select(CostDetailRecord).where(CostDetailRecord.breakdown == "resource")))
    assert rows[0].resource_group == "rg-data" and rows[0].resource_type == "Microsoft.Compute/disks" and float(rows[0].amount) == 12.5
    fc = db.scalar(select(BillingForecast).where(BillingForecast.method.like("provider:%")))
    assert float(fc.forecast_amount) == 150 and res.summary["budgets"]["azure"] == 1
    # re-running replaces (never duplicates) the window
    run_cost_detail(JobContext(db=db, job=job, execution_id=2), s, {"azure": object()}, {"azure": AzureCostDetail(s, _azure_cost_rest())})
    assert len(list(db.scalars(select(CostDetailRecord).where(CostDetailRecord.breakdown == "resource")))) == 1
    login(client, db, "fin@latentview.com", "finops_analyst")
    a = client.get("/api/v1/cost/analysis", params={"period": "last_7_days", "group_by": "resource_group"}).json()
    assert a["summary"]["actual_usd"] == 30 and a["groups"][0]["key"] == "rg-data" and a["group_coverage"]["azure"] == "collected"
    assert a["group_coverage"]["aws"] in ("not collected (enable resource-level cost)", "collected")
    assert a["summary"]["forecast_month_usd"] is not None and "provider forecast" in a["summary"]["forecast_method"]
    assert all(p["actual"] is None or p["forecast"] is None for p in a["actual_vs_forecast"])  # never both on one day
    assert a["top_resources"][0]["name"] == "disk1" and a["provider_budgets"][0]["amount"] == 1000
    sku = client.get("/api/v1/cost/analysis", params={"period": "this_month", "group_by": "sku"}).json()
    assert sku["group_coverage"]["azure"] == "not available from this provider"
    prev = client.get("/api/v1/cost/analysis", params={"period": "previous_month"}).json()
    assert prev["period"]["end"] < today.replace(day=1).isoformat()
    fy = client.get("/api/v1/cost/analysis", params={"period": "financial_year", "fy": 2025}).json()
    assert fy["period"]["start"] == "2025-04-01"
    assert client.get("/api/v1/cost/analysis", params={"period": "nope"}).status_code == 422


def test_defender_and_policy_collectors_dedupe_with_advisor():
    rid = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1"
    rest = FakeRest({"Microsoft.Security/assessments": [
        {"id": f"{rid}/providers/Microsoft.Security/assessments/aaa", "name": "aaa", "properties": {
            "status": {"code": "Unhealthy"}, "resourceDetails": {"Id": rid}, "displayName": "Secure transfer", "metadata": {"severity": "High"}}},
        {"id": f"{rid}/providers/Microsoft.Security/assessments/bbb", "name": "bbb", "properties": {
            "status": {"code": "Unhealthy"}, "resourceDetails": {"Id": rid}, "displayName": "Dup", "metadata": {"severity": "Low"}}},
        {"id": "x", "name": "ccc", "properties": {"status": {"code": "Healthy"}, "resourceDetails": {"Id": rid}}}],
        "policyStates": [{"resourceId": rid, "policyAssignmentId": "pa", "policyDefinitionName": "pd1", "resourceType": "Microsoft.Storage/storageAccounts",
                          "resourceGroup": "rg", "policySetDefinitionName": "asb"}]})
    s = NS(azure_tenant_id="t")
    scope = NS(external_id=SUB)
    found = list(DefenderAssessmentCollector(s, rest, {(rid.lower(), "bbb")})._list(scope))
    assert [f.control_id for f in found] == ["aaa"] and found[0].severity == "High" and found[0].resource_group == "rg"
    pol = list(AzurePolicyCollector(s, rest)._list(scope))
    assert pol[0].severity == "Medium" and pol[0].compliance_standard == "asb" and pol[0].source == "azure_policy"


def test_structured_ai_rejects_invented_evidence(db, settings):
    _store(db, [ct(10), ct(11, "PutBucketAcl")])
    db.commit()
    from app.models import AuditEvent
    e = db.scalar(select(AuditEvent).where(AuditEvent.event_name == "DeleteBucket"))

    class Model:
        model = "fake-model"

        def __init__(self, reply):
            self.reply = reply

        def generate(self, system, prompt):
            assert "<untrusted_data>" in prompt
            return json.dumps(self.reply)
    invented = {"summary": "x", "risk": "High", "confidence": "high", "supporting_event_ids": [99999], "affected_resources": []}
    r = structured.analyze(db, settings, "a@latentview.com", "activity_event", str(e.id), provider=Model(invented))
    assert r.generated_by.startswith("rule template") and r.supporting_event_ids[0] == e.id
    good = {"summary": "Bucket deleted", "risk": "Medium", "confidence": "medium", "supporting_event_ids": [e.id], "affected_resources": ["bucket-10"],
            "evidence": ["DeleteBucket by eve"], "business_impact": "data loss", "recommended_action": "confirm with owner"}
    r2 = structured.analyze(db, settings, "a@latentview.com", "activity_event", str(e.id), provider=Model(good))
    assert r2.generated_by == "fake-model" and r2.human_approval_required
    db.commit()
    assert db.scalar(select(AIAnalysisResult).where(AIAnalysisResult.id == r2.id)).risk == "Medium"


def test_aws_resources_partial_listing_marks_nothing_deleted(db):
    class Client:
        def __init__(self, svc):
            self.svc = svc

        def list_buckets(self):
            return {"Buckets": [{"Name": "logs"}]}

        def can_paginate(self, op):
            return True

        def get_paginator(self, op):
            if self.svc == "rds":
                raise HttpError(403, "AccessDenied")
            data = {"describe_vpcs": {"Vpcs": [{"VpcId": "vpc-1", "Tags": [{"Key": "Name", "Value": "main"}]}]}}.get(op, {})
            return NS(paginate=lambda **kw: [data])
    conn = NS(session_for=lambda a, m: "s", regions=lambda s: ["ap-south-1"], client=lambda s, svc, region=None: Client(svc))
    db.add(CloudResource(provider="aws", scope_external_id="111111111111", resource_id="arn:old", resource_type="vpc", state="present"))
    db.commit()
    got = AwsResourceCollector(None, conn).collect(NS(external_id="111111111111", is_management=False))
    assert not got["complete"] and any("rds" in e for e in got["errors"])
    store(db, "aws", "111111111111", got["items"], mark_deleted=got["complete"])
    db.commit()
    rows = {r.resource_id: r for r in db.scalars(select(CloudResource))}
    assert rows["arn:old"].state == "present" and rows["arn:aws:s3:::logs"].resource_type == "s3_bucket"
    assert next(r for r in rows.values() if r.resource_type == "vpc" and r.name == "main")


def test_connection_registry_decisions_and_operations_health(client, db):
    db.add(CloudSubscription(external_id=SUB, name="data-prod", checks={"authentication": {"status": "pass"}, "permissions": {"status": "pass"},
                                                                        "billing": {"status": "fail"}}))
    db.commit()
    login(client, db, "admin@latentview.com", "admin")
    reg = client.get("/api/v1/connections/registry").json()
    item = reg["items"][0]
    assert item["sources"]["cost"]["state"] == "NOT_PERMITTED" and item["sources"]["activity"]["state"] == "NEVER_SYNCHRONIZED"
    assert item["health"] == "Not connected" and reg["totals"]["azure"]["scopes"] == 1
    d = client.post("/api/v1/executive/decisions", headers=H, json={"title": "Approve WAF for public apps", "source": "finding:1",
                                                                    "risk_summary": "Public endpoints without WAF", "business_impact": "Customer data exposure",
                                                                    "recommended_action": "Fund WAF rollout", "priority": "High", "owner": "ciso@latentview.com",
                                                                    "due_date": (date.today() - timedelta(days=1)).isoformat()}).json()
    assert d["key"].startswith("DEC-") and d["overdue"]
    assert client.patch(f"/api/v1/executive/decisions/{d['id']}", headers=H, json={"status": "DECIDED"}).status_code == 422
    assert client.patch(f"/api/v1/executive/decisions/{d['id']}", headers=H, json={"status": "DECIDED", "decision": "Approved Q1"}).json()["status"] == "DECIDED"
    oh = client.get("/api/v1/executive/operations-health").json()
    k = {x["key"]: x for x in oh["kpis"]}
    assert k["new_identities"]["value"] is None and k["new_identities"]["reason"]  # unknown, not zero
    assert k["failed_operations"]["value"] is None and oh["clouds"]["azure"]["scopes"] == 1
    trail = client.get("/api/v1/audit-trail", params={"category": "governance"}).json()
    assert trail["total"] >= 2 and client.get("/api/v1/audit-trail/verify").json()["valid"]

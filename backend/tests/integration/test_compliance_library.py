"""Compliance policy library: checks judge only collected data (NOT_ASSESSED otherwise), FAIL with named evidence,
legal vs voluntary frameworks kept apart, settings and attestations audited, scores exclude unassessed results,
audit report renders, read-only roles cannot change policies."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from app.core.config import Settings
from app.models import AuditEvent, CloudSubscription, InvestigationCase, VMInventory
from app.models.access import AccessAssignment, CloudIdentity
from app.models.vuln import CloudSecurityFinding
from app.services.compliance import engine
from app.services.compliance.library import FRAMEWORKS, POLICIES
from tests.integration.test_identity_governance import login
from tests.integration.test_vuln_api import H

S = Settings(_env_file=None, azure_enabled=True, aws_enabled=False, gcp_enabled=False, auth_mode="dev", audit_retention_days=200)


def _sub(db, sid="sub-1", name="Pay-As-You-Go-IT", status="Fully Onboarded"):
    db.add(CloudSubscription(external_id=sid, name=name, onboarding_status=status, tenant_id="t", monitoring_enabled=True,
                             checks={"audit_logs": {"status": "pass"}, "billing": {"status": "pass"}}))


def _results(db, run, key):
    from sqlalchemy import select

    from app.models.compliance import ComplianceResult
    return list(db.scalars(select(ComplianceResult).where(ComplianceResult.run_id == run.id, ComplianceResult.policy_key == key)))


def test_library_is_complete_and_classified():
    assert len(POLICIES) >= 35 and len({p.key for p in POLICIES}) == len(POLICIES)
    assert FRAMEWORKS["certin"]["obligation"] == "legal" and FRAMEWORKS["dpdp"]["obligation"] == "legal_upcoming"
    assert {FRAMEWORKS[k]["obligation"] for k in ("iso27001", "iso27017", "iso27018", "nist_csf", "cis", "soc2", "csa_ccm", "owasp")} == {"voluntary"}
    for p in POLICIES:
        assert p.refs and all(f in FRAMEWORKS for f in p.refs), p.key
    domains = {p.domain for p in POLICIES}
    assert {"iam", "mfa", "least_privilege", "encryption", "exposure", "logging", "vuln", "backup", "privacy", "incident", "platform"} <= domains


def test_checks_use_collected_data_and_name_the_evidence(db):
    _sub(db)
    _sub(db, "sub-2", "Sandbox", status="Pending Access")
    db.add(VMInventory(provider="azure", scope_external_id="sub-1", instance_id="/vm/web01", name="web01", public_ip="20.1.1.1", exposed_ports=[443, 3389],
                       health_status="healthy"))
    db.add(CloudIdentity(provider="azure", principal_id="u-left", principal_type="User", display_name="Ravi K", sign_in_name="ravi@example.com", enabled=False))
    db.add(AccessAssignment(provider="azure", source="rbac", source_id="a1", source_id_hash="h1", scope_external_id="sub-1", scope_level="subscription", scope_path="/subscriptions/sub-1",
                            principal_id="u-left", principal_type="User", role_name="Contributor", access_type="role", privileged=False))
    db.add(AccessAssignment(provider="azure", source="rbac", source_id="a2", source_id_hash="h2", scope_external_id="sub-1", scope_level="subscription", scope_path="/subscriptions/sub-1",
                            principal_id="sp-1", principal_type="ServicePrincipal", role_name="Owner", access_type="role", privileged=True))
    db.add(CloudSecurityFinding(provider="azure", source="defender", native_id="n1", native_id_hash="nh1", scope_external_id="sub-1", title="MFA should be enabled on accounts with owner permissions",
                                severity="High", is_security=True, internal_status="OPEN", native_state="ACTIVE"))
    db.add(InvestigationCase(title="AUD-012 Privileged Entra role granted", status="DETECTED", origin="detection_rule", risk="Critical",
                             created_at=datetime.now(UTC) - timedelta(hours=8)))
    db.commit()
    run = engine.evaluate(db, S)
    db.commit()
    net = {r.scope_external_id: r for r in _results(db, run, "NET-01")}
    assert net["sub-1"].status == "FAIL" and "3389 (RDP)" in net["sub-1"].evidence[0]["issue"] and net["sub-1"].scope_name == "Pay-As-You-Go-IT"
    assert net["sub-2"].status == "NOT_ASSESSED" and "Pending Access" in net["sub-2"].detail
    assert _results(db, run, "IAM-03")[0].evidence[0]["item"] == "ravi@example.com"
    assert {r.status for r in _results(db, run, "IAM-08") if r.scope_external_id == "sub-1"} == {"FAIL"}
    assert {r.status for r in _results(db, run, "IAM-05") if r.scope_external_id == "sub-1"} == {"FAIL"}
    assert _results(db, run, "IR-02")[0].status == "FAIL"
    assert "meets CERT-In 180 days but not DPDP" in _results(db, run, "LOG-02")[0].detail
    assert _results(db, run, "APP-01")[0].status == "FAIL"
    assert _results(db, run, "BCK-02")[0].status == "NOT_ASSESSED"  # attestation needed
    log01 = {r.scope_external_id: r for r in _results(db, run, "LOG-01")}
    assert log01["sub-2"].status == "FAIL"  # CERT-In: every ICT system must be logged; an unmonitored subscription is a gap
    sc = run.scores
    assert sc["certin"]["score"] is not None and sc["certin"]["coverage"] <= 100
    assert all(v["results_not_assessed"] >= 0 for v in sc.values())


def test_finding_checks_do_not_pass_without_provider_data(db):
    _sub(db)
    db.commit()
    run = engine.evaluate(db, S)
    assert {r.status for r in _results(db, run, "ENC-01")} == {"NOT_ASSESSED"}
    assert {r.status for r in _results(db, run, "NET-02")} == {"NOT_ASSESSED"}


def test_api_settings_attestation_report_and_rbac(client, db):
    _sub(db)
    db.add(AuditEvent(event_id="e1", provider="azure", scope_external_id="sub-1", event_timestamp=datetime.now(UTC), event_name="x", raw={"outcome": "success"}))
    db.commit()
    login(client, db, "viewer@latentview.com", "viewer")
    assert client.put("/api/v1/compliance/policies/IAM-01", headers=H, json={"severity": "Critical"}).status_code == 403
    login(client, db, "gov@latentview.com", "admin")
    assert client.post("/api/v1/compliance/evaluate", headers=H).status_code == 200
    ov = client.get("/api/v1/compliance/overview").json()
    assert ov["totals"]["policies"] == len(POLICIES) and {f["obligation"] for f in ov["frameworks"]} >= {"legal", "legal_upcoming", "voluntary"}
    r = client.put("/api/v1/compliance/policies/IAM-01", headers=H, json={"severity": "Critical", "params": {"max_privileged": 3}, "owner": "secops@latentview.com"})
    assert r.status_code == 200 and r.json()["severity"] == "Critical" and r.json()["params"]["max_privileged"] == 3
    assert client.put("/api/v1/compliance/policies/IAM-01", headers=H, json={"params": {"nope": 1}}).status_code == 422
    assert client.post("/api/v1/compliance/policies/IAM-01/attest", headers=H, json={"status": "PASS", "evidence": "x" * 10,
                                                                          "valid_until": str(date.today() + timedelta(days=30))}).status_code == 422
    a = client.post("/api/v1/compliance/policies/IR-04/attest", headers=H, json={"status": "PASS", "evidence": "CERT-In acknowledgement ref 2026/123",
                                                                      "valid_until": str(date.today() + timedelta(days=365))})
    assert a.status_code == 200 and a.json()["attestation"]["by"] == "gov@latentview.com"
    client.post("/api/v1/compliance/evaluate", headers=H)
    d = client.get("/api/v1/compliance/policies/IR-04").json()
    assert d["status"] == "PASS" and d["results"][0]["basis"] == "Attestation"
    html = client.get("/api/v1/compliance/report", params={"framework": "certin"})
    assert html.status_code == 200 and "CERT-In Directions 2022" in html.text and "Legal requirement (in force)" in html.text
    csv_ = client.get("/api/v1/compliance/report", params={"framework": "dpdp", "format": "csv"})
    assert csv_.status_code == 200 and "Rule 8(3)" in csv_.text


def test_assistant_answers_compliance_from_the_latest_evaluation(client, db):
    from tests.integration.test_assistant import ask
    _sub(db)
    db.add(VMInventory(provider="azure", scope_external_id="sub-1", instance_id="/vm/db01", name="db01", public_ip="20.1.1.2", exposed_ports=[22],
                       health_status="healthy"))
    db.commit()
    login(client, db, "ciso@latentview.com", "admin")
    from tests.conftest import use_settings
    use_settings(client, auth_mode="google", google_oauth_client_id="c", google_oauth_client_secret="x", google_allowed_domain="latentview.com",
                 secret_key="k" * 40, azure_enabled=True)
    before = ask(client, "What is our CERT-In compliance score?")
    assert any(r["tool"] == "compliance_posture" and r.get("gap") for r in before["results"])  # no evaluation yet: says so, invents nothing
    client.post("/api/v1/compliance/evaluate", headers=H)
    out = ask(client, "What is our CERT-In compliance score?")
    post = next(r for r in out["results"] if r["tool"] == "compliance_posture")
    assert post["as_of"] and "CERT-In Directions 2022 (legal requirement)" in post["facts"][0]["fact"]
    gaps = ask(client, "Which compliance gaps do we need to fix?")
    g = next(r for r in gaps["results"] if r["tool"] == "compliance_gaps")
    assert any("Pay-As-You-Go-IT" in x["fact"] and "Fix:" in x["fact"] for x in g["facts"])
    login(client, db, "nobody@latentview.com", "finops_analyst")  # no governance read: tool is denied, not answered
    denied = ask(client, "What is our CERT-In compliance score?")
    assert all(r["tool"] != "compliance_posture" for r in denied["results"])

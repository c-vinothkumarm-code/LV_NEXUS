"""Onboard a cloud: kits are generated from the organisation's own identifiers, the external ID is random and shown to
managers only, files never contain credentials, verification is read-only and honest, and a cloud is switched on only
after a verification without failures."""
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import select

import app.services.registry as registry
from app.core.config import Settings
from app.models import AdminAuditLog, CloudAccount, CloudConnection
from app.services.connector import CheckResult
from app.services.onboarding import wizard
from tests.fakes import FakeConnector
from tests.integration.test_identity_governance import login

H = {"X-Requested-With": "mcp-dashboard"}
BASE = "/api/v1/onboarding/wizard"
ROOT = Path(__file__).resolve().parents[3]


def test_packaged_aws_templates_match_the_deploy_folder():
    for name in ("cloudnexus-member-role.yaml", "cloudnexus-management-role.yaml"):
        assert (wizard.TEMPLATES / "aws" / name).read_text(encoding="utf-8") == (ROOT / "deploy" / "aws" / name).read_text(encoding="utf-8"), name
        text = (wizard.TEMPLATES / "aws" / name).read_text(encoding="utf-8")
        assert "NoDataContentOrSecretReads" in text and "secretsmanager:GetSecretValue" in text and "AllowedSourceIps" in text


def test_aws_kit_external_id_and_files(client, db):
    r = client.post(f"{BASE}/aws/external-id", headers=H, json={})
    assert r.status_code == 200 and r.json()["created"] is True
    ext = db.scalar(select(CloudConnection).where(CloudConnection.provider == "aws")).config["aws_external_id"]
    assert len(ext) >= 40
    # an external ID in use is kept (working member roles are not broken); only an explicit rotation replaces it
    assert client.post(f"{BASE}/aws/external-id", headers=H, json={}).json()["created"] is False
    assert db.scalar(select(AdminAuditLog).where(AdminAuditLog.action == "onboarding.external_id")) is not None
    assert ext not in str([a.detail for a in db.scalars(select(AdminAuditLog))])  # never logged

    r = client.put(f"{BASE}/aws/inputs", headers=H, json={
        "config": {"aws_member_role_name": "CloudNexusReadOnly", "aws_default_region": "ap-south-1"},
        "inputs": {"management_account_id": "123456789012", "root_ou_id": "r-ab12", "certificate_cn": "lvnexus-prod",
                   "allowed_source_ips": "203.0.113.10/32, 198.51.100.0/28"}})
    assert r.status_code == 200, r.text
    kit = r.json()
    assert kit["external_id"]["value"] == ext and [s["id"] for s in kit["steps"]] == ["certificate", "management", "members", "server"]
    assert kit["steps"][3]["ready"] is False  # stack outputs not entered yet

    script = client.get(f"{BASE}/aws/files/aws-onboarding.sh").text
    assert "123456789012" in script and "r-ab12" in script and ext in script and "--auto-deployment Enabled=true" in script
    assert "AllowedSourceIps" in script and "203.0.113.10/32" in script
    assert "aws_secret_access_key" not in script.lower() and "create-access-key" not in script
    cfg = client.get(f"{BASE}/aws/files/aws-config").text
    assert "credential_process = /run/secrets/cloud/aws/aws_signing_helper" in cfg and "<TrustAnchorArn>" in cfg
    yaml_ = client.get(f"{BASE}/aws/files/cloudnexus-member-role.yaml")
    assert yaml_.status_code == 200 and 'filename="cloudnexus-member-role.yaml"' in yaml_.headers["content-disposition"]
    assert client.get(f"{BASE}/aws/files/../../etc/passwd").status_code == 404
    assert client.get(f"{BASE}/aws/files/azure-onboarding.sh").status_code == 404

    # outputs entered -> the server config is complete
    arn = "arn:aws:rolesanywhere:ap-south-1:123456789012:{}/0f0f0f0f-1111-2222-3333-444444444444"
    client.put(f"{BASE}/aws/inputs", headers=H, json={"config": {"aws_member_role_name": "CloudNexusReadOnly"}, "inputs": {
        "management_account_id": "123456789012", "root_ou_id": "r-ab12", "certificate_cn": "lvnexus-prod",
        "trust_anchor_arn": arn.format("trust-anchor"), "profile_arn": arn.format("profile"),
        "role_arn": "arn:aws:iam::123456789012:role/CloudNexusManagementReader"}})
    cfg = client.get(f"{BASE}/aws/files/aws-config").text
    assert "<" not in cfg and "CloudNexusManagementReader" in cfg
    # the generic Cloud connections form keeps the wizard state
    client.put("/api/v1/connections/aws", headers=H, json={"enabled": False, "config": {"aws_member_role_name": "CloudNexusReadOnly"}})
    assert client.get(f"{BASE}/aws").json()["inputs"][0]["value"] == "123456789012"


def test_invalid_inputs_are_rejected(client):
    put = lambda p, inputs, config=None: client.put(f"{BASE}/{p}/inputs", headers=H, json={"config": config or {}, "inputs": inputs})  # noqa: E731
    assert put("aws", {"management_account_id": "12345"}).status_code == 422
    assert put("aws", {"root_ou_id": "ou-root; rm -rf /"}).status_code == 422
    assert put("aws", {"allowed_source_ips": "0.0.0.0/0; curl x"}).status_code == 422
    assert put("aws", {"secret_access_key": "x"}).status_code == 422  # unknown fields (credentials) are refused
    assert put("gcp", {"host_project_id": "Bad_Project"}).status_code == 422
    assert put("azure", {}, {"azure_tenant_id": "not-a-guid"}).status_code == 422
    assert client.get(f"{BASE}/oracle").status_code == 404
    assert client.put(f"{BASE}/aws/inputs", json={"config": {}, "inputs": {}}).status_code == 403  # CSRF header required


def test_azure_and_gcp_scripts(client):
    tenant = "11111111-2222-3333-4444-555555555555"
    r = client.put(f"{BASE}/azure/inputs", headers=H, json={"config": {"azure_tenant_id": tenant}, "inputs": {"app_name": "LV NEXUS Reader"}})
    assert r.status_code == 200, r.text
    az = client.get(f"{BASE}/azure/files/azure-onboarding.sh").text
    assert tenant in az and "managementGroups/$TENANT_ID" in az and "--cert" in az and "--append" in az
    assert "Monitoring Reader" in az and "AuditLog.Read.All" in az and "credential reset --id \"$APP_ID\" --cert" in az
    assert "--password" not in az and "client_secret" not in az.lower()  # no client secret is ever created
    cert = client.get(f"{BASE}/azure/files/azure-server-certificate.sh").text
    assert "chmod 600" in cert and "PUBLIC certificate only" in cert

    client.put(f"{BASE}/gcp/inputs", headers=H, json={"config": {"gcp_organization_id": "123456789012"}, "inputs": {
        "host_project_id": "lv-security-tools", "host_project_number": "998877665544", "certificate_cn": "lvnexus-prod"}})
    g = client.get(f"{BASE}/gcp/files/gcp-onboarding.sh").text
    assert "123456789012" in g and "create-x509" in g and "roles/iam.workloadIdentityUser" in g and "create-cred-config" in g
    assert "assertion.subject.dn.cn == '$CERT_CN'" in g and "CERT_CN=lvnexus-prod" in g and "keys create" not in g


def test_viewer_sees_steps_but_not_the_external_id_or_files(client, db):
    client.post(f"{BASE}/aws/external-id", headers=H, json={})
    login(client, db, "viewer@latentview.com", "viewer")
    kit = client.get(f"{BASE}/aws")
    assert kit.status_code == 200 and kit.json()["external_id"] == {"value": None, "is_set": True} and kit.json()["can_manage"] is False
    assert client.get(f"{BASE}/aws/files/aws-onboarding.sh").status_code == 403
    assert client.post(f"{BASE}/aws/verify", headers=H).status_code == 403
    assert client.post(f"{BASE}/aws/activate", headers=H).status_code == 403


def test_verify_then_activate(client, db, monkeypatch):
    checks_ok = {"authentication": CheckResult("pass"), "permissions": CheckResult("pass"),
                 "audit_logs": CheckResult("fail", "CloudTrail not readable", "Add cloudtrail:LookupEvents")}
    fake = FakeConnector("aws", {"111111111111": {"name": "prod", "checks": checks_ok}, "222222222222": {"name": "dev", "checks": checks_ok}})
    monkeypatch.setattr(registry, "build_connector", lambda provider, settings: fake)

    assert client.post(f"{BASE}/aws/activate", headers=H).status_code == 409  # never without a verification
    client.put(f"{BASE}/aws/inputs", headers=H, json={"config": {"aws_member_role_name": "CloudNexusReadOnly"}, "inputs": {}})
    res = client.post(f"{BASE}/aws/verify", headers=H).json()
    by = {s["key"]: s for s in res["steps"]}
    assert by["settings"]["status"] == "PASS" and by["signin"]["status"] == "PASS" and "2 accounts visible" in by["signin"]["detail"]
    assert by["credential"]["status"] == "WARN"  # no Roles Anywhere config in development: told, not hidden
    assert by["check:audit_logs"]["status"] == "WARN" and by["check:audit_logs"]["fix"] == "Add cloudtrail:LookupEvents"
    assert res["status"] == "WARN" and sorted(res["sampled"]) == ["111111111111", "222222222222"]
    assert db.scalar(select(CloudAccount)) is None  # verification stores no inventory

    r = client.post(f"{BASE}/aws/activate", headers=H)
    assert r.status_code == 200 and r.json()["enabled"] is True
    db.expire_all()
    assert db.scalar(select(CloudConnection).where(CloudConnection.provider == "aws")).enabled is True
    assert {a.name for a in db.scalars(select(CloudAccount))} == {"prod", "dev"}  # first discovery ran
    ov = client.get(BASE).json()["providers"]
    assert next(p for p in ov if p["provider"] == "aws")["enabled"] is True


def test_failed_verification_blocks_activation(client, monkeypatch):
    monkeypatch.setattr(registry, "build_connector", lambda provider, settings: FakeConnector(
        "azure", discover_error=RuntimeError("AADSTS7000215: Invalid client secret provided. client_secret=abc123")))
    client.put(f"{BASE}/azure/inputs", headers=H, json={"config": {"azure_tenant_id": "11111111-2222-3333-4444-555555555555"}, "inputs": {}})
    res = client.post(f"{BASE}/azure/verify", headers=H).json()
    sign = next(s for s in res["steps"] if s["key"] == "signin")
    assert res["status"] == "FAIL" and sign["status"] == "FAIL" and "AADSTS7000215" in sign["detail"] and "abc123" not in sign["detail"]
    r = client.post(f"{BASE}/azure/activate", headers=H)
    assert r.status_code == 409 and "failed" in r.json()["detail"]


def test_credential_file_checks(tmp_path):
    key = tmp_path / "server.key"
    key.write_text("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
    if os.name == "nt":  # Windows has no POSIX mode bits; access is controlled by NTFS permissions
        status, detail, _ = wizard._file_check(str(key), "key", secret=True)
        assert status == "PASS" and "NTFS" in detail
    else:
        os.chmod(key, 0o644)
        assert wizard._file_check(str(key), "key", secret=True)[0] == "WARN"
        os.chmod(key, 0o600)
        assert wizard._file_check(str(key), "key", secret=True)[0] == "PASS"
    assert wizard._file_check(str(tmp_path / "missing.pem"), "cert")[0] == "FAIL"
    cred = tmp_path / "gcp.json"
    cred.write_text('{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----"}')
    s = Settings(_env_file=None).model_copy(update={"gcp_credentials_file": str(cred), "app_env": "production"})
    step = wizard._credential_checks("gcp", s)[0]
    assert step["status"] == "WARN" and "KEY file" in step["detail"] and "BEGIN" not in step["detail"]
    cred.write_text('{"type": "external_account", "audience": "//iam.googleapis.com/x"}')
    assert wizard._credential_checks("gcp", s)[0]["status"] == "PASS"
    assert wizard._credential_checks("azure", Settings(_env_file=None).model_copy(update={"app_env": "production"}))[0]["status"] == "FAIL"

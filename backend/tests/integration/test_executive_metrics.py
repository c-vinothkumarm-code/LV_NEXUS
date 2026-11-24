"""Executive Overview metrics: real values with metadata; missing sources are 'not_collected' (None), never zero; RBAC limits sections."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from app.models import AuditEvent, BillingRecord, CloudSecurityFinding
from tests.integration.test_identity_governance import login

NOW = datetime.now(UTC)


def _by_key(body):
    return {m["key"]: m for m in body["metrics"]}


def test_empty_platform_reports_not_collected_not_zero(client):
    body = client.get("/api/v1/home/metrics").json()
    m = _by_key(body)
    assert {s["key"] for s in body["sections"]} >= {"connectivity", "security", "infrastructure", "finops", "governance", "operations"}
    for key in ("spend_mtd", "findings_open", "forecast_month", "compliance_percent", "events_24h", "monitoring_coverage", "account_coverage"):
        assert m[key]["value"] is None and m[key]["availability"] == "not_collected", key
    for meta in ("definition", "source", "calculation", "scope", "as_of", "availability", "link"):
        assert meta in m["spend_mtd"]


def test_values_come_from_collected_data(client, db):
    db.add(BillingRecord(provider="aws", scope_external_id="a1", usage_date=date.today(), service="EC2", cost_usd=Decimal("120.50"), cost_original=Decimal("120.50"), currency_original="USD",
                         collected_at=NOW))
    db.add(BillingRecord(provider="azure", scope_external_id="s1", usage_date=date.today(), service="VM", cost_usd=Decimal("79.50"), cost_original=Decimal("79.50"), currency_original="USD",
                         collected_at=NOW))
    for i, sev in enumerate(["Critical", "High", "High", "Low"]):
        db.add(CloudSecurityFinding(provider="aws", source="securityhub", is_security=True, native_id=f"f{i}", native_id_hash=f"h{i}", scope_external_id="a1",
                                    title=f"finding {i}", severity=sev, native_state="ACTIVE", internal_status="OPEN", first_observed_at=NOW - timedelta(days=1),
                                    last_synced_at=NOW))
    db.add(AuditEvent(event_id="e1", provider="aws", scope_external_id="a1", event_timestamp=NOW - timedelta(minutes=20), event_name="RunInstances",
                      collected_at=NOW - timedelta(minutes=5), raw={}))
    db.commit()
    m = _by_key(client.get("/api/v1/home/metrics").json())
    assert m["spend_mtd"]["value"] == 200.0 and m["spend_mtd"]["breakdown"] == {"aws": 120.5, "azure": 79.5}
    assert m["spend_mtd_gcp"]["value"] is None  # no GCP billing: unknown, not $0
    assert m["findings_open"]["value"] == 4 and m["findings_critical"]["value"] == 1 and m["findings_high"]["value"] == 2
    assert m["findings_new_7d"]["value"] == 4 and m["findings_critical"]["tone"] == "critical"
    assert m["events_24h"]["value"] == 1 and m["ingestion_latency"]["value"] == 15.0
    assert m["spend_mtd"]["availability"] == "available"


def test_sections_follow_permissions(client, db):
    login(client, db, "viewer@latentview.com", "viewer")
    r = client.get("/api/v1/home/metrics")
    if r.status_code == 403:  # viewer without inventory:read never reaches the endpoint
        return
    perms = set(client.get("/api/v1/auth/me").json()["permissions"])
    keys = {s["key"] for s in r.json()["sections"]}
    assert ("finops" in keys) == ("finops:read" in perms)
    assert ("security" in keys) == ("vuln:read" in perms)
    assert ("operations" in keys) == ("audit:read" in perms)

"""Overview endpoint: every section carries its own freshness; data without a recorded job run still shows its time;
a failed latest run marks the section degraded but keeps the last data; viewers without inventory access are refused."""
from __future__ import annotations

from datetime import date
from decimal import Decimal

from sqlalchemy import select

from app.models import AutomationExecutionLog, AutomationJob, BillingRecord, CloudSubscription
from tests.integration.test_identity_governance import login


def test_overview_sections_and_freshness(client, db):
    login(client, db, "exec@latentview.com", "executive")
    empty = client.get("/api/v1/home").json()
    assert empty["cost"]["status"] == "never" and empty["cost"]["month_to_date"] is None  # unknown, not zero
    db.add(CloudSubscription(external_id="sub-1", name="prod", onboarding_status="Fully Onboarded"))
    db.add(BillingRecord(provider="azure", scope_external_id="sub-1", service="VM", usage_date=date.today(), cost_original=Decimal(12),
                         currency_original="USD", cost_usd=Decimal(12)))
    db.commit()
    h = client.get("/api/v1/home").json()
    assert h["clouds"]["azure"]["scopes"] == 1 and h["clouds"]["azure"]["cost_mtd"] == 12 and h["cost"]["status"] == "fresh" and h["cost"]["updated_at"]
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "billing_refresh"))
    db.add(AutomationExecutionLog(job_id=job.id, job_name="billing_refresh", status="failed", error="Timeout talking to Cost Management"))
    db.commit()
    h = client.get("/api/v1/home").json()
    assert h["cost"]["status"] == "degraded" and "Timeout" in h["cost"]["reason"] and h["cost"]["month_to_date"] == 12  # last good data kept
    assert h["health"]["jobs"]["billing_refresh"]["status"] == "failed"
    login(client, db, "owner@latentview.com", "project_owner")  # assigned-scope users have no organisation-wide overview
    assert client.get("/api/v1/home").status_code == 403

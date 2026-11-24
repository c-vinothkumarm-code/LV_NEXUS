"""Billing periods per subscription: real (anniversary) dates from Azure, closed-period totals queried once and cached,
the current period summed from daily records, calendar fallback labelled, permission errors reported (never zero)."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

from app.core.config import Settings
from app.models import BillingPeriod, BillingRecord, CloudSubscription
from app.services.finops import periods
from app.services.vuln.common import HttpError
from tests.integration.test_identity_governance import login

TODAY = date(2026, 11, 23)


class FakeClient:
    def __init__(self, listed=None, error=None, totals=None):
        self.listed, self.error, self.totals, self.calls = listed or [], error, totals or {}, []

    def list(self, sub):
        if self.error:
            raise self.error
        return self.listed

    def total(self, sub, start, end):
        self.calls.append((start, end))
        return self.totals.get(start, Decimal("0")), "USD"


def _anniversary(n=3):
    """Periods running from the 5th to the 4th, newest first; the current one contains TODAY."""
    out, s = [], date(2026, 11, 5)
    for i in range(n):
        e = (s.replace(day=28) + timedelta(days=10)).replace(day=4)
        out.append({"name": f"2026{s.month:02d}-1", "start": s, "end": e, "invoice_ids": [f"G{i}"]})
        s = (s.replace(day=1) - timedelta(days=1)).replace(day=5)
    return out


def _settings(**kw):
    return Settings(_env_file=None, **{"billing_periods_history": 2, **kw})


def _daily(db, sub, d, amount, usd=True):
    db.add(BillingRecord(provider="azure", scope_external_id=sub, service="VM", usage_date=d, cost_original=Decimal(amount),
                         currency_original="USD", cost_usd=Decimal(amount) if usd else None))


def test_periods_follow_the_subscription_cycle_and_closed_totals_are_cached(db):
    _daily(db, "sub-1", date(2026, 11, 4), 99)  # belongs to the previous period
    _daily(db, "sub-1", date(2026, 11, 5), 10)
    _daily(db, "sub-1", date(2026, 11, 20), 15)
    db.commit()
    fake = FakeClient(_anniversary(), totals={date(2026, 10, 5): Decimal("321.5"), date(2026, 9, 5): Decimal("200")})
    res = periods.refresh_scope(db, _settings(), "sub-1", client=fake, today=TODAY)
    db.commit()
    assert res["source"] == "provider" and res["periods"] == 3 and res["queried"] == 2 and not res["gaps"]
    rows = {p.name: p for p in db.query(BillingPeriod).all()}
    cur = rows["202611-1"]
    assert (cur.period_start, cur.period_end) == (date(2026, 11, 5), date(2026, 12, 4))
    assert cur.total_original == Decimal(25) and cur.total_source == "daily_records" and not cur.is_final
    prev = rows["202610-1"]
    assert prev.total_original == Decimal("321.5") and prev.total_source == "provider_query" and prev.is_final
    # the daily record of 4 Nov is stamped with the previous period, not the calendar month
    rec = db.query(BillingRecord).filter_by(usage_date=date(2026, 11, 4)).one()
    assert rec.billing_period_start == date(2026, 10, 5)
    # second run: final closed periods are not queried again
    fake.calls.clear()
    periods.refresh_scope(db, _settings(), "sub-1", client=fake, today=TODAY)
    assert fake.calls == []


def test_calendar_fallback_when_azure_publishes_no_periods(db):
    fake = FakeClient(error=HttpError(400, "Billing periods are not supported for this agreement"))
    res = periods.refresh_scope(db, _settings(), "sub-2", client=fake, today=TODAY)
    assert res["source"] == "calendar_month"
    cur = periods.current_period(db, "sub-2", TODAY)
    assert (cur.period_start, cur.period_end, cur.source) == (date(2026, 11, 1), date(2026, 11, 30), "calendar_month")
    assert cur.total_original is None  # no daily data: unknown, not zero


def test_permission_error_is_reported_not_hidden(db):
    with pytest.raises(PermissionError, match="missing permission"):
        periods.refresh_scope(db, _settings(), "sub-3", client=FakeClient(error=HttpError(403, "AuthorizationFailed")), today=TODAY)
    assert db.query(BillingPeriod).count() == 0


def test_query_budget_queues_the_rest(db):
    fake = FakeClient(_anniversary(3))
    res = periods.refresh_scope(db, _settings(), "sub-4", client=fake, today=TODAY, max_queries=1)
    assert res["queried"] == 1 and any("queued for the next run" in g for g in res["gaps"])


def test_partial_currency_conversion_is_not_summed(db):
    _daily(db, "sub-5", date(2026, 11, 6), 10)
    _daily(db, "sub-5", date(2026, 11, 7), 5, usd=False)
    db.commit()
    periods.refresh_scope(db, _settings(), "sub-5", client=FakeClient(_anniversary(1)), today=TODAY)
    cur = db.query(BillingPeriod).filter_by(scope_external_id="sub-5").one()
    assert cur.total_original == Decimal(15) and cur.total_usd is None


def test_api_lists_every_subscription_with_name_and_reason(client, db):
    db.add_all([CloudSubscription(external_id="sub-1", name="Pay-As-You-Go-IT", onboarding_status="Fully Onboarded", tenant_id="t",
                                  checks={"billing": {"status": "pass"}}),
                 CloudSubscription(external_id="sub-9", name="Sandbox", onboarding_status="Pending Access", tenant_id="t",
                                   checks={"permissions": {"status": "fail", "detail": "Missing role assignments: Cost Management Reader"}})])
    db.add(BillingPeriod(provider="azure", scope_external_id="sub-1", name="202611-1", period_start=date.today() - timedelta(days=3),
                         period_end=date.today() + timedelta(days=26), source="provider", total_original=Decimal(12), currency="USD",
                         total_usd=Decimal(12), total_source="daily_records", is_final=False))
    db.commit()
    login(client, db, "fin@latentview.com", "finops_analyst")
    r = client.get("/api/v1/cost/billing-periods").json()
    subs = {s["name"]: s for s in r["subscriptions"]}
    assert subs["Pay-As-You-Go-IT"]["periods"][0]["status"] == "current" and subs["Pay-As-You-Go-IT"]["periods"][0]["cost_usd"] == 12
    assert subs["Sandbox"]["periods"] == [] and "Cost Management Reader" in subs["Sandbox"]["gap"]
    # the cost analysis "current billing period" uses the subscription's own dates
    a = client.get("/api/v1/cost/analysis", params={"period": "current_billing_period", "scope": "sub-1"}).json()
    assert a["period"]["label"].startswith("Current billing period")


def test_scope_names_endpoint_respects_visibility(client, db):
    db.add_all([CloudSubscription(external_id="sub-a", name="Retail entity", onboarding_status="Fully Onboarded", tenant_id="t"),
                CloudSubscription(external_id="sub-b", name="Finance", onboarding_status="Fully Onboarded", tenant_id="t")])
    db.commit()
    login(client, db, "v@latentview.com", "viewer")
    names = client.get("/api/v1/accounts/names").json()
    assert names["azure"] == {"sub-a": "Retail entity", "sub-b": "Finance"}


def test_daily_review_ignores_a_run_still_in_progress(db):
    from sqlalchemy import select

    from app.models import AutomationExecutionLog, AutomationJob
    from app.services.notifications.reports import collection_health
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "billing_refresh"))
    if job is None:
        job = AutomationJob(name="billing_refresh", description="x", schedule="0 * * * *")
        db.add(job)
        db.flush()
    db.add(AutomationExecutionLog(job_id=job.id, job_name="billing_refresh", trigger="schedule", status="success",
                                  started_at=datetime.now(UTC) - timedelta(minutes=30)))
    db.add(AutomationExecutionLog(job_id=job.id, job_name="billing_refresh", trigger="schedule", status="running",
                                  started_at=datetime.now(UTC)))
    db.commit()
    assert collection_health(db)["jobs"]["billing_refresh"] == "success"


def test_role_check_uses_the_service_principal_not_a_stale_object_id(monkeypatch):
    from app.services.azure import connector as az
    s = Settings(_env_file=None, azure_client_id="app-1", azure_client_secret="x", azure_tenant_id="t", azure_principal_object_id="USER-OID")

    class FakeRest:
        def __init__(self, *a, **k):
            pass

        def get(self, url, params=None):
            assert "servicePrincipals(appId='app-1')" in url
            return {"id": "sp-oid"}
    monkeypatch.setattr("app.services.azure.rest.AzureRest", FakeRest)
    c = az.AzureConnector(s)
    monkeypatch.setattr(c.clients, "credential", lambda: object())
    oid, mismatch = c._principal_oid()
    assert oid == "sp-oid" and "user-oid" in mismatch and "sp-oid" in mismatch

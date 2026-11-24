from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace as NS

import boto3
from botocore.stub import Stubber
from sqlalchemy import func, select

from app.core.config import Settings
from app.models import BillingBudget, BillingForecast, BillingRecord
from app.services.finops import analysis
from app.services.finops.collectors import AwsBillingCollector, AzureBillingCollector, GcpBillingCollector, month_is_final
from app.services.finops.engine import convert, refresh_forecasts, run_billing_refresh, upsert_records
from tests.helpers import onboard, run

S = Settings(_env_file=None, fx_usd_inr_rate=84.0)
TODAY = datetime.now(UTC).date()


def row(provider="aws", scope="1" * 12, service="Amazon EC2", day=None, cost="10", currency="USD", final=False, period=None):
    d = day or TODAY - timedelta(days=1)
    return {"provider": provider, "scope_external_id": scope, "service": service, "usage_date": d, "cost": Decimal(cost), "currency": currency,
            "is_final": final, "billing_period_start": (period or d.replace(day=1)), "billing_period_end": None}


def test_currency_conversion_stores_rate_and_never_guesses():
    assert convert(Decimal("10"), "USD", 84.0) == (Decimal("10"), Decimal("840.0"), Decimal("84.0"))
    usd, inr, rate = convert(Decimal("840"), "INR", 84.0)
    assert usd == Decimal("10") and inr == Decimal("840")
    assert convert(Decimal("10"), "USD", None) == (Decimal("10"), None, None)
    assert convert(Decimal("10"), "EUR", 84.0) == (None, None, None)


def test_aws_cost_explorer_pagination_and_provisional_flag():
    ce = boto3.client("ce", region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t")
    stub = Stubber(ce)
    grp = lambda acct, svc, amt: {"Keys": [acct, svc], "Metrics": {"UnblendedCost": {"Amount": amt, "Unit": "USD"}}}  # noqa: E731
    base = {"TimePeriod": {"Start": "2026-11-01", "End": "2026-11-03"}, "Granularity": "DAILY", "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}, {"Type": "DIMENSION", "Key": "SERVICE"}]}
    stub.add_response("get_cost_and_usage", {"NextPageToken": "p2", "ResultsByTime": [
        {"TimePeriod": {"Start": "2026-11-01", "End": "2026-11-02"}, "Estimated": False, "Groups": [grp("111111111111", "Amazon EC2", "12.5"), grp("222222222222", "Amazon S3", "0")]}]}, base)
    stub.add_response("get_cost_and_usage", {"ResultsByTime": [
        {"TimePeriod": {"Start": "2026-11-02", "End": "2026-11-03"}, "Estimated": True, "Groups": [grp("222222222222", "Amazon S3", "3.25")]}]}, {**base, "NextPageToken": "p2"})
    stub.activate()
    conn = NS(base_session=lambda: None, client=lambda session, service, region=None: ce)
    rows = list(AwsBillingCollector(S, conn).collect(date(2026, 11, 1), date(2026, 11, 2)))
    assert [(r["scope_external_id"], r["service"], r["cost"], r["is_final"]) for r in rows] == [
        ("111111111111", "Amazon EC2", Decimal("12.5"), True), ("222222222222", "Amazon S3", Decimal("3.25"), False)]
    assert rows[0]["billing_period_start"] == date(2026, 11, 1) and rows[0]["billing_period_end"] == date(2026, 11, 30)  # calendar month
    stub.assert_no_pending_responses()


def test_gcp_collector_requires_valid_export_table():
    assert GcpBillingCollector(Settings(_env_file=None), None).missing_configuration()
    assert GcpBillingCollector(Settings(_env_file=None, gcp_billing_export_table="x; DROP TABLE y"), None).missing_configuration()
    assert not GcpBillingCollector(Settings(_env_file=None, gcp_billing_export_table="proj.ds.gcp_billing_export_v1_ABC"), None).missing_configuration()


def test_azure_uses_each_subscriptions_own_billing_period():
    starts = {"sub-a": 20261105, "sub-b": 20261112}  # two subscriptions, two different billing periods

    def usage(scope, definition):
        sub = scope.rsplit("/", 1)[-1]
        cols = [NS(name="Cost"), NS(name="UsageDate"), NS(name="ServiceName"), NS(name="Currency")]
        if definition.timeframe == "BillingMonthToDate":
            return NS(columns=cols[:2] + cols[3:], rows=[[5.0, starts[sub], "USD"], [6.0, starts[sub] + 1, "USD"]])
        return NS(columns=cols, rows=[[4.0, 20261103, "Virtual Machines", "USD"], [7.0, starts[sub] + 1, "Storage", "USD"]])

    conn = NS(clients=NS(cost=lambda: NS(query=NS(usage=usage))))
    c = AzureBillingCollector(S, conn)
    a = list(c.collect(NS(external_id="sub-a"), date(2026, 11, 1), date(2026, 11, 14)))
    b = list(c.collect(NS(external_id="sub-b"), date(2026, 11, 1), date(2026, 11, 14)))
    assert [r["billing_period_start"] for r in a] == [None, date(2026, 11, 5)]  # day before the period keeps NULL, not a guess
    assert [r["billing_period_start"] for r in b] == [None, date(2026, 11, 12)]


def test_upsert_is_idempotent_and_final_is_not_overwritten(db):
    assert upsert_records(db, S, [row(cost="10")]) == (1, 0)
    assert upsert_records(db, S, [row(cost="12")]) == (0, 1)
    db.commit()
    rec = db.scalar(select(BillingRecord))
    assert db.scalar(select(func.count()).select_from(BillingRecord)) == 1 and rec.cost_usd == Decimal("12") and rec.cost_inr == Decimal("1008")
    assert rec.currency_original == "USD" and rec.conversion_rate == Decimal("84") and rec.conversion_timestamp is not None and not rec.is_final
    upsert_records(db, S, [row(cost="13", final=True)])
    upsert_records(db, S, [row(cost="99", final=False)])  # provisional data must not replace final
    db.commit()
    db.expire_all()
    rec = db.scalar(select(BillingRecord))
    assert rec.is_final and rec.cost_usd == Decimal("13")


def test_month_finality():
    s = Settings(_env_file=None, finops_final_after_days=5)
    assert not month_is_final(date(2026, 10, 31), s, today=date(2026, 11, 5)) and month_is_final(date(2026, 10, 31), s, today=date(2026, 11, 6))
    assert not month_is_final(date(2026, 11, 3), s, today=date(2026, 11, 17))


def test_budget_levels_forecast_and_anomaly(db):
    start = TODAY.replace(day=1)
    days = [TODAY - timedelta(days=i) for i in range(1, 12)]
    rows = [row(day=d, cost="100") for d in days[1:]] + [row(day=days[0], cost="900")]
    rows += [row(scope="2" * 12, day=d, cost="50") for d in days]
    upsert_records(db, S, rows)
    mtd_a = sum(Decimal("900") if d == days[0] else Decimal("100") for d in days if d >= start)
    db.add_all([BillingBudget(provider="aws", scope_external_id="1" * 12, service="*", period_start=start, period_end=start + timedelta(days=27),
                              amount=mtd_a / Decimal("0.92") if mtd_a else Decimal("1")),
                BillingBudget(provider="aws", scope_external_id="2" * 12, service="*", period_start=start, period_end=start + timedelta(days=27), amount=Decimal("1000000"))])
    db.commit()
    status = {b["scope"]: b for b in analysis.budget_status(db)}
    if mtd_a:
        assert status["1" * 12]["level"] == "high" and status["1" * 12]["level_label"] == "High Warning" and 91 < status["1" * 12]["utilisation_percent"] < 93
    assert status["2" * 12]["level"] is None and status["2" * 12]["remaining"] > 0
    found = analysis.anomalies(db, S)
    assert [a["scope"] for a in found] == ["1" * 12] and found[0]["cost_usd"] == 900.0 and found[0]["baseline_mean_usd"] == 100.0
    n = refresh_forecasts(db)
    db.commit()
    if (TODAY - start).days >= 1:
        assert n == 2 and db.scalar(select(func.count()).select_from(BillingForecast)) == 2
        assert all(f.method == "run_rate" and f.forecast_amount > 0 for f in db.scalars(select(BillingForecast)))


def test_weekly_and_daily_summaries(db):
    upsert_records(db, S, [row(day=TODAY - timedelta(days=i), cost="20") for i in range(1, 8)] + [row(day=TODAY - timedelta(days=i), cost="10") for i in range(8, 15)]
                   + [row(service="Amazon S3", day=TODAY - timedelta(days=1), cost="5")])
    db.commit()
    w = analysis.weekly_summary(db)
    assert w["current_week"] == 145.0 and w["previous_week"] == 70.0 and w["variation_percent"] == 107.1
    assert w["top_increasing_services"][0] == {"service": "Amazon EC2", "increase_usd": 70.0, "new": False} and w["top_increasing_services"][1]["new"]
    d = analysis.daily_summary(db)
    assert d["previous_day"] == {"aws": 25.0} and d["change"] == {"aws": 5.0}


class FakeBilling:
    provider, per_scope = "aws", False

    def __init__(self, rows=None, error=None):
        self.rows, self.error = rows or [], error

    def collect(self, start, end):
        if self.error:
            raise self.error
        return iter(self.rows)


def test_billing_job_reports_unconfigured_and_failed_collectors(session_factory, db):
    onboard(session_factory, aws=["1" * 12])
    gcp = GcpBillingCollector(Settings(_env_file=None), None)
    entry = run(session_factory, "billing_refresh", lambda ctx: run_billing_refresh(ctx, S, [FakeBilling([row()]), gcp]))
    assert entry.status == "partial" and entry.summary["inserted"] == 1 and "GCP_BILLING_EXPORT_TABLE" in entry.failures[0]["reason"]
    bad = run(session_factory, "billing_refresh", lambda ctx: run_billing_refresh(ctx, S, [FakeBilling(error=RuntimeError("AccessDenied"))]))
    assert bad.status == "failed" and "AccessDenied" in bad.failures[0]["reason"]
    assert run(session_factory, "billing_refresh", lambda ctx: run_billing_refresh(ctx, S, [])).status == "failed"

"""Billing collectors. Each yields rows: provider, scope_external_id, service, usage_date, cost, currency,
is_final, billing_period_start, billing_period_end. Read-only APIs only."""
from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from app.core.config import Settings
from app.services.reliability import BQ_TIMEOUT

_TABLE_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")


def month_bounds(d: date) -> tuple[date, date]:
    start = d.replace(day=1)
    nxt = (start + timedelta(days=32)).replace(day=1)
    return start, nxt - timedelta(days=1)


def month_is_final(d: date, settings: Settings, today: date | None = None) -> bool:
    """Provider data for a month is treated as final only some days after the month closes."""
    return (today or datetime.now(UTC).date()) > month_bounds(d)[1] + timedelta(days=settings.finops_final_after_days)


def _row(provider, scope, service, usage_date, cost, currency, is_final, period=None) -> dict:
    start, end = period or month_bounds(usage_date)
    return {"provider": provider, "scope_external_id": str(scope), "service": (service or "Unknown")[:255], "usage_date": usage_date,
            "cost": Decimal(str(cost)), "currency": (currency or "USD").upper()[:3], "is_final": bool(is_final),
            "billing_period_start": start, "billing_period_end": end}


class AwsBillingCollector:
    """Cost Explorer from the payer account, grouped by linked account and service (calendar month billing)."""

    provider = "aws"
    per_scope = False

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def collect(self, start: date, end: date) -> Iterator[dict]:
        ce = self.connector.client(self.connector.base_session(), "ce", "us-east-1")
        params = {"TimePeriod": {"Start": start.isoformat(), "End": (end + timedelta(days=1)).isoformat()}, "Granularity": "DAILY",
                  "Metrics": ["UnblendedCost"], "GroupBy": [{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}, {"Type": "DIMENSION", "Key": "SERVICE"}]}
        while True:
            resp = ce.get_cost_and_usage(**params)
            for day in resp.get("ResultsByTime", []):
                usage_date = date.fromisoformat(day["TimePeriod"]["Start"])
                for g in day.get("Groups", []):
                    m = g["Metrics"]["UnblendedCost"]
                    if Decimal(m["Amount"]) != 0:
                        yield _row("aws", g["Keys"][0], g["Keys"][1], usage_date, m["Amount"], m.get("Unit"), not day.get("Estimated", True))
            if not resp.get("NextPageToken"):
                return
            params["NextPageToken"] = resp["NextPageToken"]


class GcpBillingCollector:
    """Cloud Billing export in BigQuery (cost net of credits), grouped by project, service and day."""

    provider = "gcp"
    per_scope = False

    def __init__(self, settings: Settings, connector, client=None):
        self.settings, self.connector, self._client = settings, connector, client

    def missing_configuration(self) -> list[str]:
        t = self.settings.gcp_billing_export_table
        return [] if t and _TABLE_RE.match(t) else ["GCP_BILLING_EXPORT_TABLE (project.dataset.table)"]

    def _bq(self):
        if self._client is None:
            from google.cloud import bigquery
            self._client = bigquery.Client(project=self.settings.gcp_billing_query_project or self.settings.gcp_billing_export_table.split(".")[0],
                                           credentials=self.connector.clients.credentials())
        return self._client

    def collect(self, start: date, end: date) -> Iterator[dict]:
        from google.cloud import bigquery

        sql = f"""
            SELECT project.id AS project_id, service.description AS service, DATE(usage_start_time) AS usage_date, currency,
                   SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS cost
            FROM `{self.settings.gcp_billing_export_table}`
            WHERE DATE(usage_start_time) BETWEEN @start AND @end AND project.id IS NOT NULL
            GROUP BY project_id, service, usage_date, currency"""  # noqa: S608 - table name is validated against _TABLE_RE
        cfg = bigquery.QueryJobConfig(query_parameters=[bigquery.ScalarQueryParameter("start", "DATE", start),
                                                         bigquery.ScalarQueryParameter("end", "DATE", end)])
        for r in self._bq().query(sql, job_config=cfg).result(timeout=BQ_TIMEOUT):
            if r["cost"]:
                yield _row("gcp", r["project_id"], r["service"], r["usage_date"], r["cost"], r["currency"],
                           month_is_final(r["usage_date"], self.settings))


class AzureBillingCollector:
    """Cost Management per subscription. The current billing period comes from the subscription's own
    billing month (BillingMonthToDate); it is never assumed to be the calendar month."""

    provider = "azure"
    per_scope = True

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    @staticmethod
    def _rows(result) -> list[dict]:
        cols = [c.name for c in (result.columns or [])] if result is not None else []
        return [dict(zip(cols, r, strict=False)) for r in (result.rows or [])] if result is not None else []

    @staticmethod
    def _date(value) -> date:
        s = str(value)
        return date(int(s[:4]), int(s[4:6]), int(s[6:8])) if s.isdigit() else date.fromisoformat(s[:10])

    def _query(self, scope_id: str, timeframe: str, grouping: bool, start: date | None = None, end: date | None = None):
        from azure.mgmt.costmanagement.models import QueryAggregation, QueryDataset, QueryDefinition, QueryGrouping, QueryTimePeriod

        dataset = QueryDataset(granularity="Daily", aggregation={"totalCost": QueryAggregation(name="Cost", function="Sum")},
                               grouping=[QueryGrouping(type="Dimension", name="ServiceName")] if grouping else None)
        period = QueryTimePeriod(from_property=datetime(start.year, start.month, start.day, tzinfo=UTC),
                                 to=datetime(end.year, end.month, end.day, 23, 59, 59, tzinfo=UTC)) if start else None
        definition = QueryDefinition(type="ActualCost", timeframe=timeframe, time_period=period, dataset=dataset)
        from app.services import reliability as rel
        # Cost Management allows only a few queries per minute per scope: wait as Azure asks (Retry-After) and retry.
        return self._rows(rel.call("azure", "cost_query", lambda: self.connector.clients.cost().query.usage(f"/subscriptions/{scope_id}", definition),
                                   scope=scope_id, rate_key="azure_cost", attempts=7, base_delay=10.0, max_delay=120.0))

    def current_period_start(self, scope_id: str) -> tuple[date | None, str]:
        """First usage day of the subscription's current billing month, and how it was determined."""
        try:
            rows = self._query(scope_id, "BillingMonthToDate", grouping=False)
        except Exception:  # noqa: BLE001 - not every agreement type supports billing-month timeframes
            return None, "unavailable"
        days = [self._date(r["UsageDate"]) for r in rows if "UsageDate" in r]
        return (min(days), "billing_month") if days else (None, "no_usage")

    def collect(self, scope, start: date, end: date) -> Iterator[dict]:
        period_start, _ = self.current_period_start(scope.external_id)
        for r in self._query(scope.external_id, "Custom", grouping=True, start=start, end=end):
            usage_date = self._date(r["UsageDate"])
            cost = r.get("Cost", r.get("PreTaxCost", 0))
            if not cost:
                continue
            # Period boundaries are stored only when known from the provider; earlier days keep NULL rather than a guess.
            period = (period_start, None) if period_start and usage_date >= period_start else (None, None)
            row = _row("azure", scope.external_id, r.get("ServiceName"), usage_date, cost, r.get("Currency"),
                       month_is_final(usage_date, self.settings), period=(usage_date, usage_date))
            row["billing_period_start"], row["billing_period_end"] = period
            yield row

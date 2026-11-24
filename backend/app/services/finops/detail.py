# ruff: noqa: B023 - breakdown lambdas are evaluated immediately by _safe(), never deferred
"""Detailed cost (resource, region, SKU, usage type, allocation tags), provider forecasts and provider budgets.

Read-only APIs:
- Azure: Cost Management Query (ActualCost and AmortizedCost; grouped by resource + service, service + region, and tag),
  Cost Management Forecast, Consumption Budgets.
- AWS: Cost Explorer GetCostAndUsage per linked account (service + region, service + usage type, tag), GetCostForecast,
  optional GetCostAndUsageWithResources (needs opt-in; 14 days), AWS Budgets.
- GCP: Cloud Billing export in BigQuery (project, service, SKU, location, labels, credits); resource level only from the
  detailed export table when configured. GCP has no forecast API: the run-rate estimate is used and labelled as such.

Providers limit grouping dimensions per query, so each row records the `breakdown` it came from; rows from different
breakdowns are never added together. A failed query leaves the previous rows untouched and is reported."""
from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import BillingForecast, JobStatus
from app.models.platform import CostDetailRecord, ProviderBudget
from app.scheduler.engine import JobContext, JobResult
from app.services import reliability as rel
from app.services.access.collectors import h
from app.services.azure.rest import ARM, AzureRest
from app.services.finops.collectors import _TABLE_RE, month_bounds, month_is_final
from app.services.finops.engine import convert
from app.services.reliability import BQ_TIMEOUT
from app.services.scopes import check_passed, eligible_scopes
from app.services.vuln.common import with_retry

log = logging.getLogger(__name__)
COST_API = "2023-03-01"
_RG = re.compile(r"/resourcegroups/([^/]+)", re.I)


def _d(v) -> date:
    s = str(v)
    return date(int(s[:4]), int(s[4:6]), int(s[6:8])) if s.isdigit() else date.fromisoformat(s[:10])


class BreakdownError(Exception):
    """One breakdown query failed; the others still run and the previous rows of this breakdown are kept."""


def _safe(fn):
    """Evaluate one breakdown query; a failure becomes a BreakdownError value instead of aborting the scope."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - isolated per breakdown, reported by run_cost_detail
        return BreakdownError(exc)


def row(provider: str, breakdown: str, cost_type: str, scope: str, usage_date: date, amount, currency: str, settings: Settings, **kw) -> dict:
    return {"provider": provider, "breakdown": breakdown, "cost_type": cost_type, "scope_external_id": str(scope)[:128], "usage_date": usage_date,
            "amount": Decimal(str(amount or 0)), "currency": (currency or "USD").upper()[:3], "billing_period": usage_date.strftime("%Y-%m"),
            "is_final": month_is_final(usage_date, settings), **kw}


# ------------------------------------------------------------------------------------------------ Azure
class AzureCostDetail:
    provider = "azure"

    def __init__(self, settings: Settings, rest: AzureRest | None = None):
        self.settings = settings
        self.rest = rest or AzureRest(settings)

    def _query(self, sub: str, cost_type: str, start: date, end: date, grouping: list[dict]) -> Iterator[dict]:
        body = {"type": cost_type, "timeframe": "Custom",
                "timePeriod": {"from": f"{start}T00:00:00Z", "to": f"{end}T23:59:59Z"},
                "dataset": {"granularity": "Daily", "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}}, "grouping": grouping}}
        url = f"{ARM}/subscriptions/{sub}/providers/Microsoft.CostManagement/query?api-version={COST_API}"
        while url:
            data = self.rest.request("POST", url, json=body)
            props = data.get("properties") or {}
            cols = [c["name"] for c in props.get("columns", [])]
            for r in props.get("rows", []):
                yield dict(zip(cols, r, strict=False))
            url = props.get("nextLink")

    def breakdowns(self, sub: str, start: date, end: date) -> Iterator[tuple[str, str, list[dict]]]:
        types = ["ActualCost"] + (["AmortizedCost"] if self.settings.cost_include_amortized else [])
        for t in types:
            ct = "actual" if t == "ActualCost" else "amortized"
            yield "resource", ct, _safe(lambda: [self._resource_row(sub, ct, r) for r in self._query(sub, t, start, end, [
                {"type": "Dimension", "name": "ResourceId"}, {"type": "Dimension", "name": "ServiceName"}]) if r.get("Cost")])
            if ct == "actual":
                yield "service_region", ct, _safe(lambda: [row("azure", "service_region", ct, sub, _d(r["UsageDate"]), r.get("Cost"), r.get("Currency"), self.settings,
                                                 service=r.get("ServiceName"), region=r.get("ResourceLocation"))
                                             for r in self._query(sub, t, start, end, [{"type": "Dimension", "name": "ServiceName"},
                                                                                       {"type": "Dimension", "name": "ResourceLocation"}]) if r.get("Cost")])
                yield "usage_type", ct, _safe(lambda: [row("azure", "usage_type", ct, sub, _d(r["UsageDate"]), r.get("Cost"), r.get("Currency"), self.settings,
                                             service=r.get("MeterCategory"), usage_type=r.get("MeterSubCategory"))
                                         for r in self._query(sub, t, start, end, [{"type": "Dimension", "name": "MeterCategory"},
                                                                                   {"type": "Dimension", "name": "MeterSubCategory"}]) if r.get("Cost")])
                for key in self.settings.cost_tag_keys:
                    yield f"tag:{key}"[:24], ct, _safe(lambda: [row("azure", f"tag:{key}"[:24], ct, sub, _d(r["UsageDate"]), r.get("Cost"), r.get("Currency"),
                                                      self.settings, tags={key: r.get("TagValue") or "(untagged)"})
                                                  for r in self._query(sub, t, start, end, [{"type": "TagKey", "name": key}]) if r.get("Cost")])

    def _resource_row(self, sub, ct, r) -> dict:
        rid = r.get("ResourceId") or ""
        m = _RG.search(rid)
        parts = rid.split("/providers/", 1)[-1].split("/") if "/providers/" in rid else []
        return row("azure", "resource", ct, sub, _d(r["UsageDate"]), r.get("Cost"), r.get("Currency"), self.settings, service=r.get("ServiceName"),
                   resource_id=rid or None, resource_group=m.group(1) if m else None, resource_name=rid.rsplit("/", 1)[-1] if rid else None,
                   resource_type="/".join(parts[:2]) if len(parts) >= 2 else None)

    def forecast(self, sub: str, today: date) -> tuple[Decimal | None, str | None]:
        start, end = month_bounds(today)
        # remaining days of the month only (same meaning as the AWS forecast); month-to-date actual is added separately
        body = {"type": "ActualCost", "timeframe": "Custom", "timePeriod": {"from": f"{today}T00:00:00Z", "to": f"{end}T23:59:59Z"},
                "dataset": {"granularity": "Daily", "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}}},
                "includeActualCost": False, "includeFreshPartialCost": False}
        data = self.rest.request("POST", f"{ARM}/subscriptions/{sub}/providers/Microsoft.CostManagement/forecast?api-version={COST_API}", json=body)
        props = data.get("properties") or {}
        cols = [c["name"] for c in props.get("columns", [])]
        rows = [dict(zip(cols, r, strict=False)) for r in props.get("rows", [])]
        if not rows:
            return None, None
        return Decimal(str(sum(Decimal(str(r.get("Cost") or 0)) for r in rows))), rows[0].get("Currency")

    def budgets(self, sub: str) -> list[dict]:
        out = []
        for b in self.rest.pages(f"{ARM}/subscriptions/{sub}/providers/Microsoft.Consumption/budgets", {"api-version": "2023-05-01"}):
            p = b.get("properties") or {}
            tp = p.get("timePeriod") or {}
            out.append({"native_id": b["id"], "scope_external_id": sub, "name": b.get("name"), "time_grain": p.get("timeGrain"),
                        "amount": p.get("amount"), "currency": ((p.get("currentSpend") or {}).get("unit") or "USD"),
                        "current_spend": (p.get("currentSpend") or {}).get("amount"), "forecast_spend": (p.get("forecastSpend") or {}).get("amount"),
                        "period_start": tp.get("startDate"), "period_end": tp.get("endDate"),
                        "thresholds": sorted({n.get("threshold") for n in (p.get("notifications") or {}).values() if n.get("threshold") is not None})})
        return out


# ------------------------------------------------------------------------------------------------ AWS
class AwsCostDetail:
    provider = "aws"

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def _ce(self):
        return self.connector.client(self.connector.base_session(), "ce", "us-east-1")

    def _get(self, account: str, start: date, end: date, group_by: list[dict], metrics: list[str]) -> Iterator[tuple[date, list[str], dict, bool]]:
        ce = self._ce()
        params = {"TimePeriod": {"Start": start.isoformat(), "End": (end + timedelta(days=1)).isoformat()}, "Granularity": "DAILY", "Metrics": metrics,
                  "GroupBy": group_by, "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account]}}}
        while True:
            resp = with_retry(lambda p=dict(params): ce.get_cost_and_usage(**p))
            for day in resp.get("ResultsByTime", []):
                for g in day.get("Groups", []):
                    yield date.fromisoformat(day["TimePeriod"]["Start"]), g["Keys"], g["Metrics"], not day.get("Estimated", True)
            if not resp.get("NextPageToken"):
                return
            params["NextPageToken"] = resp["NextPageToken"]

    def breakdowns(self, account: str, start: date, end: date) -> Iterator[tuple[str, str, list[dict]]]:
        metrics = ["UnblendedCost"] + (["AmortizedCost"] if self.settings.cost_include_amortized else [])
        sr = _safe(lambda: list(self._get(account, start, end, [{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "REGION"}], metrics)))
        for m, ct in (("UnblendedCost", "actual"), ("AmortizedCost", "amortized")):
            if m in metrics:
                yield "service_region", ct, sr if isinstance(sr, BreakdownError) else _safe(lambda m=m, ct=ct: [row("aws", "service_region", ct, account, d, mt[m]["Amount"], mt[m].get("Unit"), self.settings,
                                                 service=k[0], region=k[1]) for d, k, mt, _ in sr if Decimal(mt[m]["Amount"]) != 0])
        yield "usage_type", "actual", _safe(lambda: [row("aws", "usage_type", "actual", account, d, mt["UnblendedCost"]["Amount"], mt["UnblendedCost"].get("Unit"),
                                           self.settings, service=k[0], usage_type=k[1])
                                       for d, k, mt, _ in self._get(account, start, end, [{"Type": "DIMENSION", "Key": "SERVICE"},
                                                                                          {"Type": "DIMENSION", "Key": "USAGE_TYPE"}], ["UnblendedCost"])
                                       if Decimal(mt["UnblendedCost"]["Amount"]) != 0])
        for key in self.settings.cost_tag_keys:
            yield f"tag:{key}"[:24], "actual", _safe(lambda: [row("aws", f"tag:{key}"[:24], "actual", account, d, mt["UnblendedCost"]["Amount"],
                                                    mt["UnblendedCost"].get("Unit"), self.settings, tags={key: (k[0].split("$", 1)[-1] or "(untagged)")})
                                                for d, k, mt, _ in self._get(account, start, end, [{"Type": "TAG", "Key": key}], ["UnblendedCost"])
                                                if Decimal(mt["UnblendedCost"]["Amount"]) != 0])
        if self.settings.aws_resource_cost_enabled:
            yield "resource", "actual", _safe(lambda: list(self._resources(account, max(start, date.today() - timedelta(days=13)), end)))

    def _resources(self, account: str, start: date, end: date) -> Iterator[dict]:
        ce = self._ce()
        params = {"TimePeriod": {"Start": start.isoformat(), "End": (end + timedelta(days=1)).isoformat()}, "Granularity": "DAILY",
                  "Metrics": ["UnblendedCost"], "GroupBy": [{"Type": "DIMENSION", "Key": "RESOURCE_ID"}],
                  "Filter": {"And": [{"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account]}},
                                     {"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Elastic Compute Cloud - Compute"]}}]}}
        while True:
            resp = with_retry(lambda p=dict(params): ce.get_cost_and_usage_with_resources(**p))
            for day in resp.get("ResultsByTime", []):
                for g in day.get("Groups", []):
                    m = g["Metrics"]["UnblendedCost"]
                    if Decimal(m["Amount"]) != 0:
                        yield row("aws", "resource", "actual", account, date.fromisoformat(day["TimePeriod"]["Start"]), m["Amount"], m.get("Unit"),
                                  self.settings, service="Amazon Elastic Compute Cloud - Compute", resource_id=g["Keys"][0],
                                  resource_name=g["Keys"][0].rsplit("/", 1)[-1])
            if not resp.get("NextPageToken"):
                return
            params["NextPageToken"] = resp["NextPageToken"]

    def forecast(self, account: str, today: date) -> tuple[Decimal | None, str | None]:
        _, end = month_bounds(today)
        if today >= end:
            return None, None
        resp = with_retry(lambda: self._ce().get_cost_forecast(TimePeriod={"Start": today.isoformat(), "End": (end + timedelta(days=1)).isoformat()},
                                                               Metric="UNBLENDED_COST", Granularity="MONTHLY",
                                                               Filter={"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account]}}))
        total = resp.get("Total") or {}
        return (Decimal(total["Amount"]) if total.get("Amount") else None), total.get("Unit")

    def budgets(self) -> list[dict]:
        session = self.connector.base_session()
        acct = self.connector.client(session, "sts").get_caller_identity()["Account"]
        client = self.connector.client(session, "budgets", "us-east-1")
        out = []
        for page in client.get_paginator("describe_budgets").paginate(AccountId=acct):
            for b in page.get("Budgets", []):
                lim = b.get("BudgetLimit") or {}
                spend = (b.get("CalculatedSpend") or {})
                linked = ((b.get("CostFilters") or {}).get("LinkedAccount") or [acct])
                out.append({"native_id": f"{acct}:{b['BudgetName']}", "scope_external_id": linked[0] if len(linked) == 1 else acct,
                            "name": b["BudgetName"], "time_grain": b.get("TimeUnit"), "amount": lim.get("Amount"), "currency": lim.get("Unit") or "USD",
                            "current_spend": (spend.get("ActualSpend") or {}).get("Amount"),
                            "forecast_spend": (spend.get("ForecastedSpend") or {}).get("Amount"),
                            "period_start": (b.get("TimePeriod") or {}).get("Start"), "period_end": (b.get("TimePeriod") or {}).get("End"), "thresholds": []})
        return out


# ------------------------------------------------------------------------------------------------ GCP
class GcpCostDetail:
    provider = "gcp"

    def __init__(self, settings: Settings, connector, client=None):
        self.settings, self.connector, self._client = settings, connector, client

    def _bq(self):
        if self._client is None:
            from google.cloud import bigquery
            table = self.settings.gcp_billing_export_table
            self._client = bigquery.Client(project=self.settings.gcp_billing_query_project or table.split(".")[0],
                                           credentials=self.connector.clients.credentials())
        return self._client

    def breakdowns(self, start: date, end: date) -> Iterator[tuple[str, str, list[dict]]]:
        from google.cloud import bigquery
        table = self.settings.gcp_billing_export_table
        if not table or not _TABLE_RE.match(table):
            raise ValueError("GCP_BILLING_EXPORT_TABLE is not configured (project.dataset.table)")
        keys = [k for k in self.settings.cost_tag_keys if re.fullmatch(r"[a-z0-9_-]+", k)]
        label_cols = ", ".join(f"(SELECT l.value FROM UNNEST(labels) l WHERE l.key = '{k}') AS `lbl_{k.replace('-', '_')}`" for k in keys)
        sql = f"""
            SELECT project.id AS project_id, billing_account_id, service.description AS service, sku.description AS sku,
                   location.region AS region, DATE(usage_start_time) AS usage_date, currency{', ' + label_cols if label_cols else ''},
                   SUM(cost) AS gross, SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS credits
            FROM `{table}`
            WHERE DATE(usage_start_time) BETWEEN @start AND @end AND project.id IS NOT NULL
            GROUP BY project_id, billing_account_id, service, sku, region, usage_date, currency{''.join(f', lbl_{k.replace("-", "_")}' for k in keys)}"""  # noqa: S608
        cfg = bigquery.QueryJobConfig(query_parameters=[bigquery.ScalarQueryParameter("start", "DATE", start),
                                                         bigquery.ScalarQueryParameter("end", "DATE", end)])
        rows = []
        for r in self._bq().query(sql, job_config=cfg).result(timeout=BQ_TIMEOUT):
            net = Decimal(str(r["gross"] or 0)) + Decimal(str(r["credits"] or 0))
            if net == 0 and not r["gross"]:
                continue
            tags = {k: r.get(f"lbl_{k.replace('-', '_')}") for k in keys if r.get(f"lbl_{k.replace('-', '_')}")}
            rows.append(row("gcp", "sku", "actual", r["project_id"], r["usage_date"], net, r["currency"], self.settings,
                            billing_account=r["billing_account_id"], service=r["service"], sku=r["sku"], region=r["region"],
                            credits=Decimal(str(r["credits"] or 0)), tags=tags))
        yield "sku", "actual", rows
        detailed = self.settings.gcp_billing_detailed_export_table
        if detailed and _TABLE_RE.match(detailed):
            sql = f"""
                SELECT project.id AS project_id, service.description AS service, resource.name AS resource_name,
                       resource.global_name AS resource_id, location.region AS region, DATE(usage_start_time) AS usage_date, currency,
                       SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net
                FROM `{detailed}`
                WHERE DATE(usage_start_time) BETWEEN @start AND @end AND project.id IS NOT NULL
                GROUP BY project_id, service, resource_name, resource_id, region, usage_date, currency"""  # noqa: S608
            yield "resource", "actual", [row("gcp", "resource", "actual", r["project_id"], r["usage_date"], r["net"], r["currency"], self.settings,
                                             service=r["service"], resource_id=r["resource_id"], resource_name=r["resource_name"], region=r["region"])
                                         for r in self._bq().query(sql, job_config=cfg).result(timeout=BQ_TIMEOUT) if r["net"]]


# ------------------------------------------------------------------------------------------------ job
def _replace(db: Session, settings: Settings, provider: str, scope: str | None, breakdown: str, cost_type: str, start: date, end: date,
             rows: list[dict], refreshed: datetime) -> int:
    q = delete(CostDetailRecord).where(CostDetailRecord.provider == provider, CostDetailRecord.breakdown == breakdown,
                                       CostDetailRecord.cost_type == cost_type, CostDetailRecord.usage_date.between(start, end))
    if scope is not None:
        q = q.where(CostDetailRecord.scope_external_id == scope)
    db.execute(q)
    merged: dict[str, dict] = {}
    for r in rows:
        key = h(r["provider"], r["breakdown"], r["cost_type"], r["scope_external_id"], str(r["usage_date"]), str(r.get("service")), str(r.get("region")),
                str(r.get("resource_id")), str(r.get("sku")), str(r.get("usage_type")), str(sorted((r.get("tags") or {}).items())), r["currency"])
        if key in merged:
            merged[key]["amount"] += r["amount"]
            if r.get("credits") is not None:
                merged[key]["credits"] = (merged[key].get("credits") or 0) + r["credits"]
        else:
            merged[key] = dict(r)
    for key, r in merged.items():
        usd, _, _ = convert(r["amount"], r["currency"], settings.fx_usd_inr_rate)
        db.add(CostDetailRecord(row_hash=key, amount_usd=usd, provider_refreshed_at=refreshed, **{k: v for k, v in r.items()}))
    return len(merged)


def _forecast(db: Session, provider: str, scope: str, amount: Decimal | None, currency: str | None, today: date) -> None:
    if amount is None:
        return
    start, end = month_bounds(today)
    db.execute(delete(BillingForecast).where(BillingForecast.provider == provider, BillingForecast.scope_external_id == scope,
                                             BillingForecast.period_start == start, BillingForecast.method.like("provider:%")))
    db.add(BillingForecast(provider=provider, scope_external_id=scope, period_start=start, period_end=end, forecast_amount=amount,
                           currency=(currency or "USD")[:3], method=f"provider:{provider}_remaining_month"))


def _budgets(db: Session, provider: str, items: list[dict]) -> int:
    t = datetime.now(UTC)
    known = {b.native_id: b for b in db.scalars(select(ProviderBudget).where(ProviderBudget.provider == provider))}
    seen = set()
    for it in items:
        if it.get("amount") is None:
            continue
        seen.add(it["native_id"])
        b = known.get(it["native_id"]) or ProviderBudget(provider=provider, native_id=it["native_id"][:512])
        if b.id is None:
            db.add(b)
        b.scope_external_id, b.name, b.time_grain = it["scope_external_id"], (it.get("name") or "")[:255], it.get("time_grain")
        b.amount, b.currency = Decimal(str(it["amount"])), (it.get("currency") or "USD")[:3]
        b.current_spend = Decimal(str(it["current_spend"])) if it.get("current_spend") is not None else None
        b.forecast_spend = Decimal(str(it["forecast_spend"])) if it.get("forecast_spend") is not None else None
        b.period_start = _d(it["period_start"]) if it.get("period_start") else None
        b.period_end = _d(it["period_end"]) if it.get("period_end") else None
        b.thresholds, b.last_seen_at, b.removed_at = it.get("thresholds") or [], t, None
    for nid, b in known.items():
        if nid not in seen and b.removed_at is None:
            b.removed_at = t
    return len(seen)


def run_cost_detail(ctx: JobContext, settings: Settings, connectors: dict, sources: dict | None = None) -> JobResult:
    db = ctx.db
    today = datetime.now(UTC).date()
    start, end = today - timedelta(days=settings.cost_detail_days), today
    refreshed = datetime.now(UTC)
    summary: dict = {"window": [str(start), str(end)], "rows": {}, "forecasts": 0, "budgets": {}}
    failures: list[dict] = []
    total = failed = 0
    srcs = sources or {}

    def run(provider, scope, gen_factory):
        nonlocal total, failed
        total += 1
        skip = rel.scope_gate(provider)
        if skip:
            failed += 1
            failures.append({"provider": provider, "scope": scope or "*", "reason": skip})
            return
        try:
            broken = []
            for breakdown, ct, rows in gen_factory():
                if isinstance(rows, BreakdownError):  # keep the previous data of this breakdown; report it
                    broken.append(f"{breakdown}/{ct}: {rel.scope_failed(provider, rows.args[0])}")
                    continue
                n = _replace(db, settings, provider, scope, breakdown, ct, start, end, rows, refreshed)
                summary["rows"][f"{provider}:{breakdown}:{ct}"] = summary["rows"].get(f"{provider}:{breakdown}:{ct}", 0) + n
                db.commit()
            if broken:
                failures.append({"provider": provider, "scope": scope or "*", "reason": "Some breakdowns not refreshed (previous data kept): " + " | ".join(broken)[:900]})
            else:
                rel.scope_ok(provider)
        except Exception as exc:  # noqa: BLE001 - previous rows stay; failure is reported
            db.rollback()
            failed += 1
            failures.append({"provider": provider, "scope": scope or "*", "reason": rel.scope_failed(provider, exc)})

    if "azure" in connectors:
        az = srcs.get("azure") or AzureCostDetail(settings)
        for s in eligible_scopes(db, "azure"):
            if not check_passed(s, "billing"):
                continue
            run("azure", s.external_id, lambda sid=s.external_id: az.breakdowns(sid, start, end))
            try:
                amt, cur = az.forecast(s.external_id, today)
                _forecast(db, "azure", s.external_id, amt, cur, today)
                summary["forecasts"] += amt is not None
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                failures.append({"provider": "azure", "scope": s.external_id, "reason": f"forecast: {safe_error(exc)}"})
        try:
            items = [b for s in eligible_scopes(db, "azure") if check_passed(s, "billing") for b in az.budgets(s.external_id)]
            summary["budgets"]["azure"] = _budgets(db, "azure", items)
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            failures.append({"provider": "azure", "scope": "*", "reason": f"budgets: {safe_error(exc)}"})
    if "aws" in connectors:
        aw = srcs.get("aws") or AwsCostDetail(settings, connectors["aws"])
        for s in eligible_scopes(db, "aws"):
            run("aws", s.external_id, lambda sid=s.external_id: aw.breakdowns(sid, start, end))
            try:
                amt, cur = aw.forecast(s.external_id, today)
                _forecast(db, "aws", s.external_id, amt, cur, today)
                summary["forecasts"] += amt is not None
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                failures.append({"provider": "aws", "scope": s.external_id, "reason": f"forecast: {safe_error(exc)}"})
        try:
            summary["budgets"]["aws"] = _budgets(db, "aws", aw.budgets())
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            failures.append({"provider": "aws", "scope": "*", "reason": f"budgets: {safe_error(exc)}"})
    if "gcp" in connectors:
        gc = srcs.get("gcp") or GcpCostDetail(settings, connectors["gcp"])
        run("gcp", None, lambda: gc.breakdowns(start, end))
        summary["gcp_note"] = "GCP has no forecast API; the run-rate estimate is used. Billing budgets are not read."
    if total == 0:
        if not connectors:
            why = "No cloud connection is enabled for this run (AZURE_ENABLED / AWS_ENABLED / GCP_ENABLED)."
        else:
            unchecked = [f"{p}:{s.external_id}" for p in connectors if p in ("azure",) for s in eligible_scopes(db, p) if not check_passed(s, "billing")]
            why = ("Billing access is not validated for " + ", ".join(unchecked[:5]) +
                   ". Fix: grant Cost Management Reader on the subscription, run account_discovery, then cost_detail_refresh."
                   if unchecked else "No onboarded scope with billing access was found. Fix: run account_discovery, then cost_detail_refresh.")
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures or [{"provider": "*", "scope": "*", "reason": why}])
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if failed == total else JobStatus.PARTIAL
    return JobResult(status, total, failed, summary, failures)

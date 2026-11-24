"""Source-to-application reconciliation for Azure.

Asks Azure directly (a separate code path from the collectors) and compares the answers with what the
application stored and shows. Read-only: list and query calls only, nothing is written to Azure, and the
only database writes are none (it reads the application's tables)."""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import AuditEvent, AutomationExecutionLog, BillingRecord, CloudSubscription, JobStatus, OnboardingStatus, VMInventory

from .report import FAIL, PASS, SKIP, WARN, Report

READ_ONLY_ROLES = {"Reader", "Monitoring Reader", "Cost Management Reader", "Billing Reader", "Log Analytics Reader", "Security Reader"}
IN_FLIGHT = {"Started", "Accepted", "Running"}


def _claims(token: str) -> dict:
    """Unverified decode of the access token body, only to learn who we are (app or user). Never printed."""
    try:
        body = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception:  # noqa: BLE001
        return {}


def _val(x):
    return getattr(x, "value", x)


class AzureReconciler:
    def __init__(self, db: Session, settings: Settings, clients, compute_factory=None):
        self.db, self.s, self.clients = db, settings, clients
        self._compute_factory = compute_factory
        self.report = Report("Azure source-to-application reconciliation")
        self.principal_oid: str | None = None

    def _compute(self, sub: str):
        if self._compute_factory:
            return self._compute_factory(sub)
        from azure.mgmt.compute import ComputeManagementClient
        return ComputeManagementClient(self.clients.credential(), sub)

    # ---------------------------------------------------------------- identity
    def check_identity(self) -> None:
        try:
            tok = self.clients.credential().get_token("https://management.azure.com/.default")
        except Exception as exc:  # noqa: BLE001
            self.report.add("R1", "Azure authentication", FAIL, f"Could not obtain a token: {safe_error(exc, 200)}")
            raise SystemExit(self.finish()) from None
        c = _claims(tok.token)
        self.principal_oid = c.get("oid")
        kind = "service principal" if c.get("idtyp") == "app" or ("appid" in c and "upn" not in c and "unique_name" not in c) else "user"
        expires = datetime.fromtimestamp(tok.expires_on, UTC).isoformat()
        if c.get("tid") and self.s.azure_tenant_id and c["tid"].lower() != self.s.azure_tenant_id.lower():
            self.report.add("R1", "Azure authentication", FAIL, f"Token is for tenant {c['tid']}, configured tenant is {self.s.azure_tenant_id}")
        elif kind == "user":
            self.report.add("R1", "Azure authentication", WARN, "Authenticated as a user (az login). Unattended operation needs a service principal (blocker B1).",
                            identity_type=kind, token_expires=expires)
        else:
            self.report.add("R1", "Azure authentication", PASS, f"Authenticated as a service principal; token valid until {expires}",
                            identity_type=kind, app_id=c.get("appid"), object_id=self.principal_oid, token_expires=expires)

    # ---------------------------------------------------------------- subscriptions
    def check_subscriptions(self) -> list[str]:
        tenant = (self.s.azure_tenant_id or "").lower()
        live = {}
        for sub in self.clients.subscriptions().subscriptions.list():
            if (sub.tenant_id or "").lower() == tenant:
                live[sub.subscription_id] = {"name": sub.display_name, "state": str(_val(sub.state))}
        stored = {r.external_id: r for r in self.db.scalars(select(CloudSubscription))}
        active_stored = {k for k, r in stored.items() if r.onboarding_status != OnboardingStatus.INACTIVE.value}
        active_live = {k for k, v in live.items() if v["state"] in ("Enabled", "Warned", "PastDue")}
        missing, extra = sorted(active_live - set(stored)), sorted(active_stored - set(live))
        names_wrong = sorted(k for k in set(live) & set(stored) if live[k]["name"] != stored[k].name)
        status = FAIL if missing or extra else WARN if names_wrong else PASS
        self.report.add("R2", "Subscriptions discovered", status,
                        f"Azure: {len(live)} in tenant ({len(active_live)} active); application: {len(stored)} stored ({len(active_stored)} active). "
                        f"Missing in app: {len(missing)}, in app but not in Azure: {len(extra)}, name differences: {len(names_wrong)}",
                        missing_in_app=missing, not_in_azure=extra, name_differences=names_wrong)
        return sorted(active_live & set(stored))

    # ---------------------------------------------------------------- RBAC
    def check_roles(self, subs: list[str]) -> None:
        if not self.principal_oid:
            self.report.add("R3", "Read-only access (RBAC)", SKIP, "Principal object ID not available from the token")
            return
        findings, cache = {}, {}
        for sub in subs:
            authz = self.clients.authorization(sub)
            names = []
            for a in authz.role_assignments.list_for_subscription(filter=f"assignedTo('{self.principal_oid}')"):
                rid = a.role_definition_id
                if rid not in cache:
                    cache[rid] = authz.role_definitions.get_by_id(rid).role_name
                names.append(cache[rid])
            findings[sub] = sorted(set(names))
        excess = {s: [n for n in r if n not in READ_ONLY_ROLES] for s, r in findings.items()}
        excess = {s: r for s, r in excess.items() if r}
        missing = {s: sorted({"Reader", "Monitoring Reader", "Cost Management Reader"} - set(r)) for s, r in findings.items()}
        missing = {s: r for s, r in missing.items() if r}
        status = FAIL if excess else WARN if missing else PASS
        self.report.add("R3", "Read-only access (RBAC)", status,
                        f"{len(excess)} subscription(s) grant more than read access; {len(missing)} lack an expected read role",
                        roles_by_subscription=findings, write_capable_roles=excess, missing_read_roles=missing)

    # ---------------------------------------------------------------- VMs
    def check_vms(self, subs: list[str]) -> None:
        rows, total_live, total_app = {}, 0, 0
        status = PASS
        for sub in subs:
            compute = self._compute(sub)
            live = {v.id.lower(): v.name for v in compute.virtual_machines.list_all()}
            power = {}
            for v in compute.virtual_machines.list_all(status_only="true"):
                codes = [s.code for s in (getattr(v.instance_view, "statuses", None) or []) if (s.code or "").startswith("PowerState/")]
                power[v.id.lower()] = codes[0].split("/", 1)[1] if codes else "unknown"
            app = {v.instance_id.lower(): v for v in self.db.scalars(select(VMInventory).where(
                VMInventory.provider == "azure", VMInventory.scope_external_id == sub, VMInventory.deleted_at.is_(None)))}
            missing, extra = sorted(set(live) - set(app)), sorted(set(app) - set(live))
            state_diff = sorted(i for i in set(live) & set(app) if _norm_power(power.get(i)) != _norm_power(app[i].power_state))
            total_live, total_app = total_live + len(live), total_app + len(app)
            rows[sub] = {"azure": len(live), "application": len(app), "missing_in_app": [live[i] for i in missing],
                         "not_in_azure": [app[i].name for i in extra], "power_state_differs": [live[i] for i in state_diff]}
            if missing or extra:
                status = FAIL
            elif state_diff and status == PASS:
                status = WARN
        last = _last_ok(self.db, "vm_metrics")
        self.report.add("R4", "VM inventory", status, f"Azure: {total_live} VMs; application: {total_app}. Last VM collection: {last or 'never'}. "
                        "Power-state differences can be genuine changes since that collection.", by_subscription=rows)

    # ---------------------------------------------------------------- activity log
    def check_activity(self, subs: list[str], hours: int) -> None:
        last = _last_ok(self.db, "security_events")
        first = self.db.scalar(select(func.min(AutomationExecutionLog.started_at)).where(
            AutomationExecutionLog.job_name == "security_events", AutomationExecutionLog.status.in_([JobStatus.SUCCESS.value, JobStatus.PARTIAL.value])))
        if not last:
            self.report.add("R5", "Activity log events", FAIL, "security_events has never completed successfully")
            return
        end = datetime.fromisoformat(last) - timedelta(minutes=30)  # leave room for Azure's ingestion delay
        start = end - timedelta(hours=hours)
        covered_from = first - timedelta(hours=self.s.soc_initial_lookback_hours) if first else None
        if covered_from and covered_from > start:  # the window starts before anything was ever collected
            start = covered_from
            note = f" (window shortened to the start of collection, {covered_from:%Y-%m-%d %H:%M} UTC)"
        else:
            note = ""
        rows, status = {}, PASS
        for sub in subs:
            flt = f"eventTimestamp ge '{start:%Y-%m-%dT%H:%M:%SZ}' and eventTimestamp le '{end:%Y-%m-%dT%H:%M:%SZ}'"
            ids = set()
            for ev in self.clients.monitor(sub).activity_logs.list(filter=flt, select="eventDataId,status,eventTimestamp"):
                if str(_val(getattr(ev, "status", None)) or "") not in IN_FLIGHT:
                    ids.add(getattr(ev, "event_data_id", None) or getattr(ev, "id", None))
            app_ids = set(self.db.scalars(select(AuditEvent.event_id).where(
                AuditEvent.provider == "azure", AuditEvent.scope_external_id == sub,
                AuditEvent.event_timestamp >= start, AuditEvent.event_timestamp <= end)))
            missing, extra = ids - app_ids, app_ids - ids
            coverage = 100.0 if not ids else round(100 * len(ids & app_ids) / len(ids), 2)
            rows[sub] = {"azure": len(ids), "application": len(app_ids), "matched": len(ids & app_ids), "coverage_percent": coverage,
                         "missing_sample": sorted(missing)[:10], "not_in_azure_sample": sorted(extra)[:10]}
            if coverage < 98 or extra:
                status = FAIL
            elif coverage < 100 and status == PASS:
                status = WARN
        self.report.add("R5", "Activity log events", status,
                        f"Window {start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC, compared by event ID{note}", window={"from": start, "to": end},
                        by_subscription=rows)

    # ---------------------------------------------------------------- cost
    def check_cost(self, subs: list[str], days: int) -> None:
        from azure.mgmt.costmanagement.models import QueryAggregation, QueryDataset, QueryDefinition, QueryTimePeriod

        end = datetime.now(UTC).date() - timedelta(days=2)  # the last two days are still being processed by Azure
        start = end - timedelta(days=days - 1)
        rows, status = {}, PASS
        for sub in subs:
            q = QueryDefinition(type="ActualCost", timeframe="Custom",
                                time_period=QueryTimePeriod(from_property=datetime(start.year, start.month, start.day, tzinfo=UTC),
                                                            to=datetime(end.year, end.month, end.day, 23, 59, 59, tzinfo=UTC)),
                                dataset=QueryDataset(aggregation={"totalCost": QueryAggregation(name="Cost", function="Sum")}))
            try:
                res = self.clients.cost().query.usage(f"/subscriptions/{sub}", q)
            except Exception as exc:  # noqa: BLE001
                rows[sub] = {"error": safe_error(exc, 200)}
                status = FAIL
                continue
            cols = [c.name for c in (res.columns or [])]
            live = {}
            for r in res.rows or []:
                d = dict(zip(cols, r, strict=False))
                cur = d.get("Currency", "USD")
                live[cur] = live.get(cur, Decimal(0)) + Decimal(str(d.get("Cost", d.get("PreTaxCost", 0)) or 0))
            app = dict(self.db.execute(select(BillingRecord.currency_original, func.sum(BillingRecord.cost_original)).where(
                BillingRecord.provider == "azure", BillingRecord.scope_external_id == sub, BillingRecord.usage_date >= start,
                BillingRecord.usage_date <= end).group_by(BillingRecord.currency_original)).all())
            sub_rows = {}
            for cur in set(live) | set(app):
                a, b = live.get(cur, Decimal(0)), Decimal(app.get(cur) or 0)
                diff = abs(a - b)
                pct = float(100 * diff / a) if a else (0.0 if not b else 100.0)
                verdict = PASS if diff <= max(Decimal("1"), a * Decimal("0.01")) else WARN if pct <= 5 else FAIL
                sub_rows[cur] = {"azure": round(float(a), 2), "application": round(float(b), 2), "difference": round(float(diff), 2),
                                 "difference_percent": round(pct, 2), "result": verdict}
                status = FAIL if verdict == FAIL else WARN if verdict == WARN and status == PASS else status
            rows[sub] = sub_rows
        self.report.add("R6", "Cost totals", status, f"{start} to {end}, original currency, tolerance 1% (or 1 unit); run billing_refresh first",
                        period={"from": start, "to": end}, by_subscription=rows)

    # ---------------------------------------------------------------- app consistency
    def check_app_consistency(self) -> None:
        """The dashboard endpoints must report the same numbers as the tables they read."""
        from app.api.routes import dashboard

        o = dashboard.overview(provider="azure", scope=None, date_from=None, date_to=None, db=self.db, settings=self.s, _=None)
        from types import SimpleNamespace

        system = SimpleNamespace(permission_names={"infra:read", "inventory:read"}, email="system:validation")  # unrestricted view
        infra = dashboard.infrastructure(provider="azure", scope=None, region=None, environment=None, db=self.db, user=system)
        db_subs = self.db.scalar(select(func.count()).select_from(CloudSubscription).where(
            CloudSubscription.onboarding_status != OnboardingStatus.INACTIVE.value))
        db_vms = self.db.scalar(select(func.count()).select_from(VMInventory).where(VMInventory.provider == "azure", VMInventory.deleted_at.is_(None)))
        pairs = {"overview subscriptions": (o["scopes"]["azure"]["total"], db_subs),
                 "infrastructure VMs": (sum(infra["by_health"].values()), db_vms),
                 "overview VMs": (o["vms"]["total"], db_vms)}
        bad = {k: v for k, v in pairs.items() if v[0] != v[1]}
        self.report.add("R7", "Dashboard matches database", FAIL if bad else PASS,
                        "; ".join(f"{k}: dashboard {a} / database {b}" for k, (a, b) in pairs.items()), mismatches=bad)

    def finish(self) -> int:
        return 1 if self.report.overall == FAIL else 0

    def run(self, hours: int, days: int) -> Report:
        self.check_identity()
        subs = self.check_subscriptions()
        for fn in (lambda: self.check_roles(subs), lambda: self.check_vms(subs), lambda: self.check_activity(subs, hours),
                   lambda: self.check_cost(subs, days), self.check_app_consistency):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - one failing check must not hide the others
                self.report.add("R?", "Check error", FAIL, safe_error(exc, 300))
        return self.report


def _norm_power(state: str | None) -> str:
    return {"deallocated": "stopped", "deallocating": "stopped", "stopping": "stopped"}.get((state or "unknown").lower(), (state or "unknown").lower())


def _last_ok(db: Session, job: str) -> str | None:
    t = db.scalar(select(func.max(AutomationExecutionLog.finished_at)).where(
        AutomationExecutionLog.job_name == job, AutomationExecutionLog.status.in_([JobStatus.SUCCESS.value, JobStatus.PARTIAL.value])))
    return t.isoformat() if t else None

"""Shared helpers for tests of the collection pipelines."""
from __future__ import annotations

from datetime import UTC, datetime

from app.scheduler.engine import run_job
from app.services.onboarding.engine import run_discovery
from tests.fakes import FakeConnector


def onboard(factory, **scopes: list[str]):
    """Register fully onboarded scopes, e.g. onboard(factory, aws=["111111111111"], gcp=["proj-a"])."""
    conns = [FakeConnector(p, {i: {"name": f"{p}-{i}"} for i in ids}) for p, ids in scopes.items()]
    return run_job(factory, "account_discovery", lambda ctx: run_discovery(ctx, conns))


def run(factory, job: str, fn):
    return run_job(factory, job, fn, trigger="manual")


def ev(provider="aws", scope="111111111111", name="AuthorizeSecurityGroupIngress", event_id="e1", principal="arn:aws:iam::111111111111:user/alice",
       outcome="success", ts=None, **kw) -> dict:
    return {"provider": provider, "scope_external_id": scope, "event_id": event_id, "event_timestamp": ts or datetime.now(UTC),
            "event_name": name, "region": kw.get("region", "ap-south-1"), "principal": principal, "source_ip": kw.get("source_ip", "203.0.113.9"),
            "resource_id": kw.get("resource_id", "sg-1"), "resource_type": kw.get("resource_type"), "event_category": kw.get("category", "Management"),
            "outcome": outcome, "error_code": kw.get("error_code"), "read_only": kw.get("read_only", False), "service": kw.get("service", "ec2.amazonaws.com"),
            "raw": kw.get("raw", {})}


class ListCollector:
    """Audit collector returning prepared events per scope; records the windows it was asked for."""

    def __init__(self, provider: str, events: dict[str, list[dict]] | None = None, error: Exception | None = None):
        self.provider, self.events, self.error, self.calls = provider, events or {}, error, []

    def collect(self, scope, since, until):
        self.calls.append((scope.external_id, since, until))
        if self.error:
            raise self.error
        yield from self.events.get(scope.external_id, [])

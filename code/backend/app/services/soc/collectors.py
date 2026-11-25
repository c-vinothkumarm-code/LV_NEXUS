"""Incremental audit-log collectors. Read-only API calls; each yields normalised events for one scope."""
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

from app.core.config import Settings

from .normalize import normalize_azure, normalize_cloudtrail, normalize_gcp


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class AwsAuditCollector:
    """CloudTrail LookupEvents (management events, 90-day history) in every enabled region."""

    provider = "aws"

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def collect(self, scope, since: datetime, until: datetime) -> Iterator[dict]:
        session = self.connector.session_for(scope.external_id, getattr(scope, "is_management", False))
        params: dict = {"StartTime": since, "EndTime": until}
        if not self.settings.soc_aws_include_read_events:
            params["LookupAttributes"] = [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]
        seen: set[str] = set()  # global-service events are returned by more than one region
        for region in self.connector.regions(session):
            pages = self.connector.client(session, "cloudtrail", region).get_paginator("lookup_events").paginate(**params)
            for page in pages:
                for record in page.get("Events", []):
                    if record.get("EventId") not in seen:
                        seen.add(record.get("EventId"))
                        yield normalize_cloudtrail(record, scope.external_id)


class GcpAuditCollector:
    """Cloud Audit Logs per project: Admin Activity, System Event, Policy Denied (+ Data Access when enabled)."""

    provider = "gcp"

    def __init__(self, settings: Settings, connector, client_factory=None):
        self.settings, self.connector = settings, connector
        self._factory = client_factory or self._default_client

    def _default_client(self, project_id: str):
        from google.cloud import logging as gcl
        return gcl.Client(project=project_id, credentials=self.connector.clients.credentials())

    def collect(self, scope, since: datetime, until: datetime) -> Iterator[dict]:
        pid = scope.external_id
        logs = ["activity", "system_event", "policy"] + (["data_access"] if self.settings.soc_gcp_include_data_access else [])
        names = " OR ".join(f'"projects/{pid}/logs/cloudaudit.googleapis.com%2F{n}"' for n in logs)
        flt = f'logName=({names}) AND timestamp>"{_iso(since)}" AND timestamp<="{_iso(until)}"'
        for entry in self._factory(pid).list_entries(resource_names=[f"projects/{pid}"], filter_=flt, page_size=1000):
            yield normalize_gcp(entry.to_api_repr() if hasattr(entry, "to_api_repr") else entry, pid)


class AzureAuditCollector:
    """Subscription Activity Log."""

    provider = "azure"

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def collect(self, scope, since: datetime, until: datetime) -> Iterator[dict]:
        flt = f"eventTimestamp ge '{_iso(since)}' and eventTimestamp le '{_iso(until)}'"
        for ev in self.connector.clients.monitor(scope.external_id).activity_logs.list(filter=flt):
            event = normalize_azure(ev, scope.external_id)
            if event is not None:
                yield event

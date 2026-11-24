"""Read-only native security collectors: AWS Security Hub, Azure Advisor, Google Security Command Center.

Each collector turns the eligible scopes into Partitions (one checkpoint each) plus Coverage facts. A partition's
fetch(since) yields NormalizedFinding objects; since=None means a full listing. Errors raised by fetch are classified
by the sync engine (permission / throttle / not_enabled / error) and never read as "zero findings".
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime

from app.core.config import Settings

from .common import Coverage, HttpError, NormalizedFinding, Partition, parse_ts, sev, with_retry

# ------------------------------------------------------------------------------------------------ AWS Security Hub


def _sh_state(f: dict) -> str:
    record = f.get("RecordState")
    workflow = (f.get("Workflow") or {}).get("Status") or f.get("WorkflowState")
    compliance = (f.get("Compliance") or {}).get("Status")
    if record == "ARCHIVED" or workflow == "RESOLVED" or compliance == "PASSED":
        return "RESOLVED"
    if workflow == "SUPPRESSED":
        return "SUPPRESSED"
    if compliance == "NOT_AVAILABLE" and record == "ARCHIVED":
        return "NOT_APPLICABLE"
    return "ACTIVE"


def normalize_security_hub(f: dict) -> NormalizedFinding:
    res = (f.get("Resources") or [{}])[0]
    comp = f.get("Compliance") or {}
    pf = f.get("ProductFields") or {}
    standards = [s.get("StandardsId") for s in comp.get("AssociatedStandards") or [] if s.get("StandardsId")]
    std = ", ".join(standards) or pf.get("StandardsArn") or pf.get("StandardsGuideArn")
    types = f.get("Types") or []
    category = "Vulnerability" if f.get("Vulnerabilities") else (types[0].split("/")[0] if types else None)
    rem = (f.get("Remediation") or {}).get("Recommendation") or {}
    return NormalizedFinding(
        provider="aws", source="security_hub", native_id=f["Id"], scope_external_id=str(f.get("AwsAccountId") or ""),
        title=f.get("Title") or f.get("Id"), severity=sev((f.get("Severity") or {}).get("Label")), native_state=_sh_state(f),
        region=f.get("Region"), resource_id=res.get("Id"), resource_name=(res.get("Id") or "").split(":")[-1].split("/")[-1] or None,
        resource_type=res.get("Type"), description=f.get("Description"), category=category, finding_type=", ".join(types)[:512] or None,
        compliance_standard=(std or "")[:512] or None, control_id=comp.get("SecurityControlId") or pf.get("ControlId"),
        remediation=rem.get("Text"), remediation_url=rem.get("Url"), native_workflow_status=(f.get("Workflow") or {}).get("Status"),
        native_record_state=f.get("RecordState"), first_observed_at=parse_ts(f.get("FirstObservedAt") or f.get("CreatedAt")),
        last_observed_at=parse_ts(f.get("LastObservedAt") or f.get("UpdatedAt")), native_updated_at=parse_ts(f.get("UpdatedAt")),
        organization_id=None, raw=f)


class SecurityHubCollector:
    """Uses the cross-region aggregation region of the Security Hub administrator when configured (one read covers
    linked regions and member accounts); otherwise reads every eligible account in every enabled region.
    Membership and aggregation are verified, never assumed."""
    provider, source = "aws", "security_hub"

    def __init__(self, settings: Settings, connector, sleep=None):
        self.settings, self.connector = settings, connector
        self._retry = {"sleep": sleep} if sleep else {}

    def _findings(self, client, since: datetime | None) -> Iterator[dict]:
        filters: dict = {}
        if since:
            filters["UpdatedAt"] = [{"Start": since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                     "End": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}]
        token = None
        while True:
            kw = {"Filters": filters, "MaxResults": 100, **({"NextToken": token} if token else {})}
            page = with_retry(lambda kw=kw: client.get_findings(**kw), **self._retry)
            yield from page.get("Findings", [])
            token = page.get("NextToken")
            if not token:
                return

    def plan(self, scopes: list) -> tuple[list[Partition], list[Coverage]]:
        agg = self.settings.aws_securityhub_aggregation_region
        parts: list[Partition] = []
        cover: list[Coverage] = []
        if agg:
            admin = next((s for s in scopes if getattr(s, "is_management", False)), None)
            admin_id = self.settings.aws_securityhub_admin_account_id or (admin.external_id if admin else None)
            if not admin_id:
                return [], [Coverage("organization", agg, "PARTIALLY_CONFIGURED",
                                     "Aggregation region set but no Security Hub administrator / management account is known")]
            session = self.connector.session_for(admin_id, admin_id == (admin.external_id if admin else None))
            client = self.connector.client(session, "securityhub", agg)
            try:
                linked = with_retry(lambda: client.get_finding_aggregator(
                    FindingAggregatorArn=client.list_finding_aggregators()["FindingAggregators"][0]["FindingAggregatorArn"]), **self._retry)
                cover.append(Coverage(admin_id, agg, "OK", f"Aggregation region; linking mode {linked.get('RegionLinkingMode')}, "
                                                           f"regions {', '.join(linked.get('Regions') or []) or 'all'}"))
            except (IndexError, KeyError):
                cover.append(Coverage(admin_id, agg, "PARTIALLY_CONFIGURED", "No finding aggregator in this region: only its own findings are visible"))
            members = set()
            for page in client.get_paginator("list_members").paginate(OnlyAssociated=True):
                members |= {m["AccountId"] for m in page.get("Members", []) if m.get("MemberStatus") in ("Enabled", "Associated")}
            for s in scopes:
                if s.external_id != admin_id and s.external_id not in members:
                    cover.append(Coverage(s.external_id, "aggregated", "PARTIALLY_CONFIGURED",
                                          "Account is not an enabled Security Hub member of the administrator: its findings are not collected"))
                else:
                    cover.append(Coverage(s.external_id, "aggregated", "OK", "Security Hub member; findings arrive through the aggregation region"))
            parts.append(Partition(admin_id, agg, lambda since, c=client: (normalize_security_hub(f) for f in self._findings(c, since))))
            return parts, cover
        for s in scopes:
            parts.append(Partition(s.external_id, "*", None))  # expanded per enabled region by the engine (see expand)
        return parts, cover

    def regions_for(self, scope) -> list[tuple[str, object]]:
        session = self.connector.session_for(scope.external_id, getattr(scope, "is_management", False))
        return [(r, self.connector.client(session, "securityhub", r)) for r in self.connector.regions(session)]

    def expand(self, partition: Partition, scope) -> list[Partition]:
        """Per-account mode: one partition per enabled region (called by the engine so each region has a checkpoint)."""
        out = []
        for region, client in self.regions_for(scope):
            def fetch(since, c=client):
                with_retry(c.describe_hub, **self._retry)  # raises InvalidAccessException when Security Hub is not enabled here
                return (normalize_security_hub(f) for f in self._findings(c, since))
            out.append(Partition(scope.external_id, region, fetch))
        return out


# ------------------------------------------------------------------------------------------------ Azure Advisor

ARM = "https://management.azure.com"
ADVISOR_API = "2023-01-01"
ARG_API = "2022-10-01"
SECURITY_CATEGORY = "security"
_RG = re.compile(r"/resourceGroups/([^/]+)", re.I)
_TYPE = re.compile(r"/providers/([^/]+/[^/]+)/[^/]+(?:/providers/Microsoft\.Advisor|$)", re.I)


def normalize_advisor(rec: dict, subscription_id: str, tenant_id: str | None, mgmt_group: str | None) -> NormalizedFinding:
    p = rec.get("properties") or {}
    meta = p.get("resourceMetadata") or {}
    resource_id = meta.get("resourceId") or rec.get("id", "").split("/providers/Microsoft.Advisor")[0]
    ext = p.get("extendedProperties") or {}
    desc = p.get("shortDescription") or {}
    category = p.get("category") or "Unknown"
    rtype = p.get("impactedField")
    if not rtype:
        m = _TYPE.search(resource_id or "")
        rtype = m.group(1) if m else None
    state = "SUPPRESSED" if p.get("suppressionIds") else "ACTIVE"
    return NormalizedFinding(
        provider="azure", source="azure_advisor", native_id=rec["id"], scope_external_id=subscription_id,
        title=desc.get("problem") or p.get("recommendationTypeId") or rec.get("name"), severity=sev(p.get("impact")),
        native_state=state, is_security=category.lower() == SECURITY_CATEGORY, organization_id=tenant_id, parent_id=mgmt_group,
        region=ext.get("region") or ext.get("location") or ext.get("Location"), resource_id=resource_id,
        resource_name=p.get("impactedValue"), resource_type=rtype, resource_group=(_RG.search(resource_id or "") or [None, None])[1],
        description=p.get("description") or desc.get("problem"), category=category, finding_type=p.get("recommendationTypeId"),
        control_id=p.get("recommendationTypeId"), remediation=desc.get("solution"),
        remediation_url=p.get("learnMoreLink"), native_workflow_status="Suppressed" if p.get("suppressionIds") else "Active",
        native_record_state=p.get("lastUpdated"), first_observed_at=None, last_observed_at=parse_ts(p.get("lastUpdated")),
        native_updated_at=parse_ts(p.get("lastUpdated")), raw=rec)


class AzureAdvisorCollector:
    """Azure Advisor recommendations per subscription. Security-category recommendations are findings; cost, reliability,
    performance and operational-excellence recommendations are stored as non-security and never counted as vulnerabilities.
    Advisor removes a recommendation once it is fixed, so a complete, successful listing of a subscription is
    authoritative: a previously active recommendation that is absent is marked natively resolved (never deleted).
    Management-group ancestry comes from Azure Resource Graph."""
    provider, source = "azure", "azure_advisor"

    def __init__(self, settings: Settings, credential=None, http=None, sleep=None):
        self.settings = settings
        self._credential = credential
        self._http = http
        self._retry = {"sleep": sleep} if sleep else {}
        self._token: str | None = None

    def _client(self):
        if self._http is None:
            import httpx
            self._http = httpx.Client(timeout=60)
        return self._http

    def _auth(self) -> dict:
        if self._token is None:
            cred = self._credential
            if cred is None:
                from app.services.azure.connector import AzureClients
                cred = AzureClients(self.settings).credential()
            self._token = cred.get_token(f"{ARM}/.default").token
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, url: str, **kw) -> dict:
        def call():
            r = self._client().request(method, url, headers=self._auth(), **kw)
            if r.status_code >= 400:
                ra = r.headers.get("Retry-After")
                raise HttpError(r.status_code, r.text, float(ra) if ra and ra.isdigit() else None)
            return r.json()
        return with_retry(call, **self._retry)

    def management_groups(self, subscription_ids: list[str]) -> dict[str, str]:
        if not subscription_ids:
            return {}
        q = ("resourcecontainers | where type == 'microsoft.resources/subscriptions' "
             "| project subscriptionId, mg = tostring(properties.managementGroupAncestorsChain[0].name)")
        out: dict[str, str] = {}
        body = {"subscriptions": subscription_ids, "query": q, "options": {"resultFormat": "objectArray", "$top": 1000}}
        while True:
            data = self._request("POST", f"{ARM}/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}", json=body)
            out |= {row["subscriptionId"]: row.get("mg") for row in data.get("data", []) if row.get("mg")}
            token = data.get("$skipToken")
            if not token:
                return out
            body["options"]["$skipToken"] = token

    def plan(self, scopes: list) -> tuple[list[Partition], list[Coverage]]:
        cover: list[Coverage] = []
        try:
            groups = self.management_groups([s.external_id for s in scopes])
        except Exception as exc:  # noqa: BLE001 - enrichment only
            groups = {}
            cover.append(Coverage("tenant", "global", "PARTIALLY_CONFIGURED", f"Resource Graph unavailable, management groups not mapped: {str(exc)[:200]}"))
        parts = [Partition(s.external_id, "global", lambda since, scope=s: self._list(scope, groups.get(scope.external_id)), absence_resolves=True)
                 for s in scopes]
        return parts, cover

    def _list(self, scope, mgmt_group) -> Iterator[NormalizedFinding]:
        url = f"{ARM}/subscriptions/{scope.external_id}/providers/Microsoft.Advisor/recommendations?api-version={ADVISOR_API}"
        tenant = getattr(scope, "tenant_id", None) or self.settings.azure_tenant_id
        while url:
            data = self._request("GET", url)
            for rec in data.get("value", []):
                yield normalize_advisor(rec, scope.external_id, tenant, mgmt_group)
            url = data.get("nextLink")


# ------------------------------------------------------------------------------------------------ Google SCC

SCC = "https://securitycenter.googleapis.com/v1"
_LOC = re.compile(r"/(?:zones|regions|locations)/([a-z0-9-]+)")


def normalize_scc(item: dict, project_by_number: dict[str, str], org_id: str | None) -> NormalizedFinding:
    f = item.get("finding") or {}
    r = item.get("resource") or {}
    project = r.get("projectName") or r.get("project") or ""
    number = project.rsplit("/", 1)[-1] if project else ""
    project_id = project_by_number.get(number) or r.get("projectDisplayName") or number or "organization"
    folders = r.get("folders") or []
    resource = f.get("resourceName") or r.get("name")
    loc = _LOC.search(resource or "")
    mute = f.get("mute")
    state = "RESOLVED" if f.get("state") == "INACTIVE" else ("SUPPRESSED" if mute == "MUTED" else "ACTIVE")
    compl = ", ".join(f"{c.get('standard')} {c.get('version') or ''} {','.join(c.get('ids') or [])}".strip() for c in f.get("compliances") or [])
    return NormalizedFinding(
        provider="gcp", source="scc", native_id=f.get("name") or f.get("canonicalName"), scope_external_id=project_id,
        title=(f.get("category") or "").replace("_", " ").title() or f.get("name"), severity=sev(f.get("severity")),
        native_state=state, organization_id=org_id, parent_id=(folders[-1].get("resourceFolder") if folders else None),
        region=loc.group(1) if loc else r.get("location"), resource_id=resource, resource_name=r.get("displayName") or (resource or "").rsplit("/", 1)[-1],
        resource_type=r.get("type"), description=f.get("description"), category=f.get("findingClass") or f.get("category"),
        finding_type=f.get("category"), compliance_standard=compl[:512] or None, control_id=f.get("category"),
        remediation=f.get("nextSteps"), remediation_url=f.get("externalUri"), native_workflow_status=f.get("state"),
        native_record_state=f.get("state"), mute_state=mute, first_observed_at=parse_ts(f.get("createTime") or f.get("eventTime")),
        last_observed_at=parse_ts(f.get("eventTime")), native_updated_at=parse_ts(f.get("eventTime")), raw=item)


class SccCollector:
    """Security Command Center findings. Organization level (one read covering folders and projects) when an
    organization is configured and readable; otherwise each accessible project. Tier differences (Standard/Premium)
    show up as which sources return findings, not as errors."""
    provider, source = "gcp", "scc"

    def __init__(self, settings: Settings, session=None, project_numbers: dict | None = None, sleep=None):
        self.settings = settings
        self._session = session
        self.project_by_number = project_numbers or {}
        self._retry = {"sleep": sleep} if sleep else {}

    def _s(self):
        if self._session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            self._session = AuthorizedSession(creds)
        return self._session

    def _get(self, url: str, params: dict) -> dict:
        def call():
            r = self._s().get(url, params=params, timeout=60)
            if r.status_code >= 400:
                raise HttpError(r.status_code, r.text)
            return r.json()
        return with_retry(call, **self._retry)

    def _list(self, parent: str, since: datetime | None, org_id: str | None) -> Iterator[NormalizedFinding]:
        params: dict = {"pageSize": 1000}
        if since:
            params["filter"] = f'event_time >= "{since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}"'
        while True:
            data = self._get(f"{SCC}/{parent}/sources/-/findings", params)
            for item in data.get("listFindingsResults", []):
                yield normalize_scc(item, self.project_by_number, org_id)
            token = data.get("nextPageToken")
            if not token:
                return
            params["pageToken"] = token

    def plan(self, scopes: list) -> tuple[list[Partition], list[Coverage]]:
        org = self.settings.gcp_organization_id
        cover: list[Coverage] = []
        if org:
            org_id = org.split("/")[-1]
            try:  # probe organization-level read before relying on it
                self._get(f"{SCC}/organizations/{org_id}/sources/-/findings", {"pageSize": 1})
                return [Partition(f"organizations/{org_id}", "global", lambda since: self._list(f"organizations/{org_id}", since, org_id))], []
            except HttpError as exc:
                if exc.status not in (401, 403):
                    raise
                cover.append(Coverage(f"organizations/{org_id}", "global", "ACCESS_DENIED",
                                      "No organization-level SCC access (securitycenter.findings.list): falling back to project-level reads"))
        if not org:
            cover.append(Coverage("organization", "global", "PARTIALLY_CONFIGURED",
                                  "GCP_ORGANIZATION_ID not set: organization and folder-level findings are not collected"))
        return [Partition(s.external_id, "global", lambda since, pid=s.external_id: self._list(f"projects/{pid}", since, None)) for s in scopes], cover

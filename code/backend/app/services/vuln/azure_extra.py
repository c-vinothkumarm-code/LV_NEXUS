"""Microsoft Defender for Cloud and Azure Policy collectors (read-only, per subscription).

- Defender assessments: only Unhealthy assessments are findings. Assessments that Azure Advisor already reports for the
  same resource and control are skipped (Advisor security recommendations are Defender assessments), so one issue is
  stored once.
- Defender security alerts: threat detections (status Active / InProgress are active; Resolved / Dismissed resolved).
- Azure Policy: non-compliant resources from the latest policy states. Policy has no severity: Medium is used and the
  policy definition is kept as the control.

A complete successful listing is authoritative for assessments and policy states (absent = resolved). Errors are
classified by the sync engine and never read as "no findings"."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import CloudSecurityFinding
from app.services.azure.rest import ARM, AzureRest

from .common import NormalizedFinding, Partition, parse_ts, sev

_RG = "/resourcegroups/"


def _rg(rid: str | None) -> str | None:
    low = (rid or "").lower()
    return rid[low.index(_RG) + len(_RG):].split("/")[0] if _RG in low else None


def advisor_pairs(db: Session) -> set[tuple[str, str]]:
    rows = db.execute(select(func.lower(CloudSecurityFinding.resource_id), func.lower(CloudSecurityFinding.control_id)).where(
        CloudSecurityFinding.source == "azure_advisor", CloudSecurityFinding.is_security.is_(True))).all()
    return {(r or "", c or "") for r, c in rows}


class DefenderAssessmentCollector:
    provider, source = "azure", "defender_assessment"

    def __init__(self, settings: Settings, rest: AzureRest | None = None, advisor: set | None = None):
        self.settings, self.rest, self.advisor = settings, rest or AzureRest(settings), advisor or set()

    def plan(self, scopes: list):
        return [Partition(s.external_id, "global", lambda since, scope=s: self._list(scope), absence_resolves=True) for s in scopes], []

    def _list(self, scope) -> Iterator[NormalizedFinding]:
        for a in self.rest.pages(f"{ARM}/subscriptions/{scope.external_id}/providers/Microsoft.Security/assessments",
                                 {"api-version": "2021-06-01", "$expand": "metadata"}):
            p = a.get("properties") or {}
            code = ((p.get("status") or {}).get("code") or "").lower()
            if code != "unhealthy":
                continue
            md = p.get("metadata") or {}
            rid = (p.get("resourceDetails") or {}).get("Id") or (p.get("resourceDetails") or {}).get("id") or a["id"].split("/providers/Microsoft.Security")[0]
            key = a.get("name") or ""
            if (rid.lower(), key.lower()) in self.advisor:
                continue  # already reported by Azure Advisor
            yield NormalizedFinding(
                provider="azure", source=self.source, native_id=a["id"], scope_external_id=scope.external_id,
                title=p.get("displayName") or md.get("displayName") or key, severity=sev(md.get("severity")), native_state="ACTIVE",
                organization_id=self.settings.azure_tenant_id, resource_id=rid, resource_name=rid.rsplit("/", 1)[-1],
                resource_type="/".join(rid.split("/providers/", 1)[-1].split("/")[:2]) if "/providers/" in rid else None, resource_group=_rg(rid),
                description=md.get("description") or (p.get("status") or {}).get("description"), category=", ".join(md.get("categories") or []) or "Security",
                finding_type="Defender assessment", control_id=key, remediation=md.get("remediationDescription"),
                remediation_url=(p.get("links") or {}).get("azurePortalUri"), native_workflow_status=(p.get("status") or {}).get("cause"),
                first_observed_at=parse_ts((p.get("status") or {}).get("firstEvaluationDate")),
                last_observed_at=parse_ts((p.get("status") or {}).get("statusChangeDate")), raw={"status": p.get("status"), "metadata": md})


class DefenderAlertCollector:
    provider, source = "azure", "defender_alert"

    def __init__(self, settings: Settings, rest: AzureRest | None = None):
        self.settings, self.rest = settings, rest or AzureRest(settings)

    def plan(self, scopes: list):
        return [Partition(s.external_id, "global", lambda since, scope=s: self._list(scope)) for s in scopes], []

    def _list(self, scope) -> Iterator[NormalizedFinding]:
        for a in self.rest.pages(f"{ARM}/subscriptions/{scope.external_id}/providers/Microsoft.Security/alerts", {"api-version": "2022-01-01"}):
            p = a.get("properties") or {}
            status = (p.get("status") or "").lower()
            rid = next((r.get("azureResourceId") for r in p.get("resourceIdentifiers") or [] if r.get("azureResourceId")), None)
            yield NormalizedFinding(
                provider="azure", source=self.source, native_id=a["id"], scope_external_id=scope.external_id,
                title=p.get("alertDisplayName") or a.get("name"), severity=sev(p.get("severity")),
                native_state="ACTIVE" if status in ("active", "inprogress") else "RESOLVED", organization_id=self.settings.azure_tenant_id,
                resource_id=rid, resource_name=p.get("compromisedEntity"), resource_group=_rg(rid), description=p.get("description"),
                category="Threat detection", finding_type=p.get("alertType"), remediation="\n".join(p.get("remediationSteps") or []) or None,
                remediation_url=p.get("alertUri"), native_workflow_status=p.get("status"), first_observed_at=parse_ts(p.get("startTimeUtc")),
                last_observed_at=parse_ts(p.get("timeGeneratedUtc")), native_updated_at=parse_ts(p.get("timeGeneratedUtc")),
                raw={"intent": p.get("intent"), "entities": (p.get("entities") or [])[:10], "productName": p.get("productName")})


class AzurePolicyCollector:
    provider, source = "azure", "azure_policy"

    def __init__(self, settings: Settings, rest: AzureRest | None = None):
        self.settings, self.rest = settings, rest or AzureRest(settings)

    def plan(self, scopes: list):
        return [Partition(s.external_id, "global", lambda since, scope=s: self._list(scope), absence_resolves=True) for s in scopes], []

    def _list(self, scope) -> Iterator[NormalizedFinding]:
        url = (f"{ARM}/subscriptions/{scope.external_id}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
               f"?api-version=2019-10-01&$filter=complianceState eq 'NonCompliant'&$top=1000")
        for st in self.rest.pages(url, method="POST", body={}):
            rid = st.get("resourceId") or ""
            definition = st.get("policyDefinitionName") or ""
            yield NormalizedFinding(
                provider="azure", source=self.source, native_id=f"{rid}|{st.get('policyAssignmentId')}|{st.get('policyDefinitionReferenceId') or definition}",
                scope_external_id=scope.external_id, title=f"Non-compliant with policy {st.get('policyDefinitionReferenceId') or definition}"[:255],
                severity="Medium", native_state="ACTIVE", organization_id=self.settings.azure_tenant_id, region=st.get("resourceLocation"),
                resource_id=rid, resource_name=rid.rsplit("/", 1)[-1] or None, resource_type=st.get("resourceType"), resource_group=st.get("resourceGroup"),
                description=f"Policy assignment {st.get('policyAssignmentName')} ({st.get('policyDefinitionAction')}).", category="Policy compliance",
                finding_type="Azure Policy", compliance_standard=st.get("policySetDefinitionName"), control_id=definition,
                last_observed_at=parse_ts(st.get("timestamp")), raw={"assignment": st.get("policyAssignmentId"), "effect": st.get("policyDefinitionAction")})

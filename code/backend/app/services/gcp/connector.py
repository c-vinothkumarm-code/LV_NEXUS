"""GCP discovery and onboarding validation using read-only OAuth scopes."""
from __future__ import annotations

from collections import deque
from datetime import UTC, datetime, timedelta

from google.api_core import exceptions as gexc

from app.core.config import Settings
from app.core.logging import safe_error
from app.services.connector import (
    CHECK_AUDIT,
    CHECK_AUTH,
    CHECK_BILLING,
    CHECK_CONFIGURATION,
    CHECK_MONITORING,
    CHECK_PERMISSIONS,
    FAIL,
    PASS,
    UNKNOWN,
    CheckResult,
    DiscoveredScope,
    skipped,
)
from app.services.reliability import GCP_TIMEOUT

_DENIED = (gexc.PermissionDenied, gexc.Forbidden, gexc.Unauthenticated)
_API_BATCH = 20


class GcpClients:
    """Lazily built Google API clients sharing one read-only credential."""

    def __init__(self, scopes: list[str]):
        self._scopes = scopes
        self._creds = None
        self._cache: dict[str, object] = {}

    def credentials(self):
        if self._creds is None:
            import google.auth
            import google.auth.transport.requests

            self._creds, _ = google.auth.default(scopes=self._scopes)
            self._creds.refresh(google.auth.transport.requests.Request())
        return self._creds

    def _get(self, key, factory):
        if key not in self._cache:
            self._cache[key] = factory(credentials=self.credentials())
        return self._cache[key]

    @property
    def projects(self):
        from google.cloud import resourcemanager_v3
        return self._get("projects", resourcemanager_v3.ProjectsClient)

    @property
    def folders(self):
        from google.cloud import resourcemanager_v3
        return self._get("folders", resourcemanager_v3.FoldersClient)

    @property
    def service_usage(self):
        from google.cloud import service_usage_v1
        return self._get("service_usage", service_usage_v1.ServiceUsageClient)

    @property
    def billing(self):
        from google.cloud import billing_v1
        return self._get("billing", billing_v1.CloudBillingClient)

    @property
    def logging(self):
        from google.cloud.logging_v2.services.logging_service_v2 import LoggingServiceV2Client
        return self._get("logging", LoggingServiceV2Client)


def _enum_name(value) -> str:
    return getattr(value, "name", str(value))


class GcpConnector:
    provider = "gcp"

    def __init__(self, settings: Settings, clients=None):
        self.settings = settings
        self.clients = clients or GcpClients(settings.gcp_scopes)
        self._auth: CheckResult | None = None

    def missing_configuration(self) -> list[str]:
        return [] if self.settings.gcp_organization_id else ["GCP_ORGANIZATION_ID"]

    # -- discovery: walk the organisation and every nested folder -------
    def discover(self) -> list[DiscoveredScope]:
        scopes: list[DiscoveredScope] = []
        queue = deque([f"organizations/{self.settings.gcp_organization_id}"])
        seen_parents: set[str] = set()
        while queue:
            parent = queue.popleft()
            if parent in seen_parents:
                continue
            seen_parents.add(parent)
            for p in self.clients.projects.list_projects(parent=parent, timeout=GCP_TIMEOUT):  # pager handles pagination
                state = _enum_name(p.state)
                scopes.append(DiscoveredScope(
                    provider="gcp", external_id=p.project_id, name=p.display_name or p.project_id,
                    provider_state=state, is_active=state == "ACTIVE", parent=parent,
                    attrs={"project_number": p.name.split("/")[-1]}))
            for f in self.clients.folders.list_folders(parent=parent, timeout=GCP_TIMEOUT):
                if _enum_name(f.state) == "ACTIVE":
                    queue.append(f.name)
        return scopes

    # -- validation ----------------------------------------------------
    def _auth_check(self) -> CheckResult:
        if self._auth is None:
            try:
                self.clients.credentials()
                self._auth = CheckResult(PASS, "Service identity credentials obtained")
            except Exception as exc:  # noqa: BLE001 - any credential failure is an auth failure
                self._auth = CheckResult(FAIL, f"Could not obtain Google credentials: {safe_error(exc, 200)}",
                                         "Attach the control-plane service account or configure Workload Identity Federation")
        return self._auth

    def _permissions(self, project_id: str) -> tuple[CheckResult, set[str]]:
        required = list(self.settings.gcp_required_permissions)
        try:
            resp = self.clients.projects.test_iam_permissions(resource=f"projects/{project_id}", permissions=required, timeout=GCP_TIMEOUT)
        except _DENIED as exc:
            return CheckResult(FAIL, f"IAM permission test denied: {safe_error(exc, 200)}",
                               "Grant the control-plane service account its read-only roles on this project - requires approval"), set()
        except gexc.GoogleAPICallError as exc:
            return CheckResult(UNKNOWN, f"IAM permission test failed: {safe_error(exc, 200)}"), set()
        granted = set(resp.permissions)
        missing = [p for p in required if p not in granted]
        if missing:
            return CheckResult(FAIL, f"Missing permissions: {', '.join(missing)}",
                               f"Grant read-only roles providing {', '.join(missing)} - requires approval"), granted
        return CheckResult(PASS, f"All {len(required)} required permissions granted"), granted

    def _apis(self, project_number: str) -> tuple[CheckResult, set[str]]:
        required = list(self.settings.gcp_required_apis)
        enabled: set[str] = set()
        try:
            for i in range(0, len(required), _API_BATCH):
                names = [f"projects/{project_number}/services/{a}" for a in required[i:i + _API_BATCH]]
                resp = self.clients.service_usage.batch_get_services(
                    request={"parent": f"projects/{project_number}", "names": names})
                enabled |= {s.name.split("/")[-1] for s in resp.services if _enum_name(s.state) == "ENABLED"}
        except _DENIED as exc:
            return CheckResult(UNKNOWN, f"Cannot read enabled APIs: {safe_error(exc, 200)}",
                               "Grant serviceusage.services.get (Service Usage Viewer) - requires approval"), enabled
        except gexc.GoogleAPICallError as exc:
            return CheckResult(UNKNOWN, f"API check failed: {safe_error(exc, 200)}"), enabled
        missing = [a for a in required if a not in enabled]
        if missing:
            return CheckResult(FAIL, f"Required APIs not enabled: {', '.join(missing)}",
                               f"Enable {', '.join(missing)} on the project - requires approval"), enabled
        return CheckResult(PASS, "All required APIs enabled"), enabled

    def _audit(self, project_id: str) -> CheckResult:
        since = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        flt = f'logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity" AND timestamp>="{since}"'
        try:
            pager = self.clients.logging.list_log_entries(
                request={"resource_names": [f"projects/{project_id}"], "filter": flt, "page_size": 1})
            found = next(iter(pager), None) is not None
        except _DENIED as exc:
            return CheckResult(FAIL, f"Admin Activity audit log is not readable: {safe_error(exc, 200)}",
                               "Grant Logs Viewer (roles/logging.viewer) - requires approval")
        except gexc.GoogleAPICallError as exc:
            return CheckResult(UNKNOWN, f"Audit log check failed: {safe_error(exc, 200)}")
        return CheckResult(PASS, "Admin Activity audit log readable" + ("" if found else " (no entries in the last 24h)"))

    def _billing(self, project_id: str) -> tuple[CheckResult, str | None]:
        try:
            info = self.clients.billing.get_project_billing_info(name=f"projects/{project_id}", timeout=GCP_TIMEOUT)
        except _DENIED as exc:
            return CheckResult(UNKNOWN, f"Billing association is not readable: {safe_error(exc, 200)}",
                               "Grant billing.resourceAssociations.list (Billing Viewer / Project Billing Viewer) - requires approval"), None
        except gexc.GoogleAPICallError as exc:
            return CheckResult(UNKNOWN, f"Billing check failed: {safe_error(exc, 200)}"), None
        if not info.billing_enabled:
            return CheckResult(FAIL, "No active billing account is linked to this project",
                               "Link the project to the organisation billing account - requires approval"), None
        return CheckResult(PASS, "Billing account linked"), info.billing_account_name

    def validate(self, scope: DiscoveredScope) -> dict[str, CheckResult]:
        auth = self._auth_check()
        if auth.status != PASS:
            return {CHECK_AUTH: auth, **{k: skipped("authentication failed") for k in (
                CHECK_PERMISSIONS, CHECK_CONFIGURATION, CHECK_AUDIT, CHECK_BILLING, CHECK_MONITORING)}}
        pid = scope.external_id
        perms, granted = self._permissions(pid)
        apis, enabled = self._apis(scope.attrs.get("project_number") or pid)
        billing, billing_account = self._billing(pid)
        if billing_account:
            scope.attrs["billing_account"] = billing_account
        if "monitoring.googleapis.com" not in enabled and apis.status != UNKNOWN:
            monitoring = CheckResult(FAIL, "Cloud Monitoring API is not enabled",
                                     "Enable monitoring.googleapis.com - requires approval")
        elif "monitoring.timeSeries.list" not in granted:
            monitoring = CheckResult(FAIL if perms.status != UNKNOWN else UNKNOWN,
                                     "monitoring.timeSeries.list is not granted",
                                     "Grant Monitoring Viewer (roles/monitoring.viewer) - requires approval")
        elif apis.status == UNKNOWN:
            monitoring = CheckResult(UNKNOWN, "Monitoring API state could not be read")
        else:
            monitoring = CheckResult(PASS, "Cloud Monitoring API enabled and time series readable")
        return {CHECK_AUTH: auth, CHECK_PERMISSIONS: perms, CHECK_CONFIGURATION: apis,
                CHECK_AUDIT: self._audit(pid), CHECK_BILLING: billing, CHECK_MONITORING: monitoring}

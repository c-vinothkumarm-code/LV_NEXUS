"""Azure discovery and onboarding validation. Read-only management-plane calls only."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from azure.core.exceptions import AzureError, ClientAuthenticationError, HttpResponseError

from app.core.config import Settings
from app.core.logging import safe_error
from app.services.connector import (
    CHECK_AUDIT,
    CHECK_AUTH,
    CHECK_BILLING,
    CHECK_MONITORING,
    CHECK_PERMISSIONS,
    FAIL,
    PASS,
    UNKNOWN,
    CheckResult,
    DiscoveredScope,
    skipped,
)
from app.services.reliability import AZURE_CLIENT_OPTIONS

_ACTIVE_STATES = {"Enabled", "Warned", "PastDue"}
_ARM_SCOPE = "https://management.azure.com/.default"


def _denied(exc: Exception) -> bool:
    return isinstance(exc, ClientAuthenticationError) or getattr(exc, "status_code", None) in (401, 403)


class AzureClients:
    """Factory for Azure management clients sharing one credential."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._cred = None

    def credential(self):
        if self._cred is None:
            from azure.identity import CertificateCredential, ClientSecretCredential, DefaultAzureCredential

            s = self.settings
            if s.azure_client_certificate_path:  # service principal with a certificate (preferred for unattended use)
                self._cred = CertificateCredential(s.azure_tenant_id, s.azure_client_id, certificate_path=s.azure_client_certificate_path)
            elif s.azure_client_secret:  # injected from a secret store or .env, never from source control
                self._cred = ClientSecretCredential(s.azure_tenant_id, s.azure_client_id, s.azure_client_secret)
            else:  # workload identity federation / managed identity / developer login
                self._cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        return self._cred

    def identity_kind(self) -> str:
        s = self.settings
        return ("service principal (certificate)" if s.azure_client_certificate_path else
                "service principal (client secret)" if s.azure_client_secret else "default credential chain (managed identity or az login)")

    def resources(self, subscription_id: str):
        from azure.mgmt.resource.resources import ResourceManagementClient
        return ResourceManagementClient(self.credential(), subscription_id, **AZURE_CLIENT_OPTIONS)

    def subscriptions(self):
        from azure.mgmt.resource.subscriptions import SubscriptionClient
        return SubscriptionClient(self.credential(), **AZURE_CLIENT_OPTIONS)

    def authorization(self, subscription_id: str):
        from azure.mgmt.authorization import AuthorizationManagementClient
        return AuthorizationManagementClient(self.credential(), subscription_id, **AZURE_CLIENT_OPTIONS)

    def monitor(self, subscription_id: str):
        from azure.mgmt.monitor import MonitorManagementClient
        return MonitorManagementClient(self.credential(), subscription_id, **AZURE_CLIENT_OPTIONS)

    def cost(self):
        from azure.mgmt.costmanagement import CostManagementClient
        return CostManagementClient(self.credential(), **AZURE_CLIENT_OPTIONS)


def month_to_date_query():
    from azure.mgmt.costmanagement.models import QueryAggregation, QueryDataset, QueryDefinition

    return QueryDefinition(type="ActualCost", timeframe="MonthToDate", dataset=QueryDataset(
        aggregation={"totalCost": QueryAggregation(name="Cost", function="Sum")}))


class AzureConnector:
    provider = "azure"

    def __init__(self, settings: Settings, clients=None):
        self.settings = settings
        self.clients = clients or AzureClients(settings)
        self._auth: CheckResult | None = None
        self._role_ids: dict[str, str] = {}  # built-in role name -> definition GUID (same in every subscription)

    def missing_configuration(self) -> list[str]:
        return [] if self.settings.azure_tenant_id else ["AZURE_TENANT_ID"]

    def discover(self) -> list[DiscoveredScope]:
        tenant = (self.settings.azure_tenant_id or "").lower()
        scopes = []
        for sub in self.clients.subscriptions().subscriptions.list():  # ItemPaged handles pagination
            if (sub.tenant_id or "").lower() != tenant:
                continue
            state = str(getattr(sub.state, "value", sub.state))
            scopes.append(DiscoveredScope(
                provider="azure", external_id=sub.subscription_id, name=sub.display_name or sub.subscription_id,
                provider_state=state, is_active=state in _ACTIVE_STATES, attrs={"tenant_id": sub.tenant_id}))
        return scopes

    def _auth_check(self) -> CheckResult:
        if self._auth is None:
            try:
                self.clients.credential().get_token(_ARM_SCOPE)
                self._auth = CheckResult(PASS, "Service principal token acquired")
            except Exception as exc:  # noqa: BLE001
                self._auth = CheckResult(FAIL, f"Service principal authentication failed: {safe_error(exc, 200)}",
                                         "Verify the Entra ID application credentials / federated credential")
        return self._auth

    def _principal_oid(self) -> tuple[str | None, str | None]:
        """(object ID to check, mismatch message). With an app registration (client ID + secret / certificate) the
        service principal's object ID is read from Microsoft Graph, so a stale value in the settings (for example a
        user's object ID left over from `az login`) cannot make every subscription look like it is missing roles."""
        if getattr(self, "_oid", None) is not None:
            return self._oid
        s = self.settings
        configured = (s.azure_principal_object_id or "").strip().lower() or None
        resolved = None
        if s.azure_client_id and (s.azure_client_secret or s.azure_client_certificate_path):
            try:
                from app.services.azure.rest import AzureRest
                data = AzureRest(s, credential=self.clients.credential()).get(
                    f"https://graph.microsoft.com/v1.0/servicePrincipals(appId='{s.azure_client_id}')", {"$select": "id"})
                resolved = (data.get("id") or "").lower() or None
            except Exception:  # noqa: BLE001 - Graph not readable: fall back to the configured value
                resolved = None
        if configured and resolved and configured != resolved:
            self._oid = (resolved, f"AZURE_PRINCIPAL_OBJECT_ID ({configured}) is not the object ID of the service principal "
                                   f"AZURE_CLIENT_ID signs in as ({resolved}); role checks would look at the wrong identity")
        else:
            self._oid = (configured or resolved, None)
        return self._oid

    def _roles(self, sub_id: str) -> tuple[CheckResult, set[str]]:
        """Which of the required built-in roles are assigned to the service principal on this subscription."""
        oid, mismatch = self._principal_oid()
        required = list(self.settings.azure_required_roles)
        if not oid:
            return CheckResult(UNKNOWN, "AZURE_PRINCIPAL_OBJECT_ID is not configured, so role assignments cannot be verified"), set()
        try:
            authz = self.clients.authorization(sub_id)
            assigned = {a.role_definition_id.rsplit("/", 1)[-1].lower()
                        for a in authz.role_assignments.list_for_subscription(filter=f"assignedTo('{oid}')")}
            for name in required:
                if name not in self._role_ids:
                    d = next(iter(authz.role_definitions.list(f"/subscriptions/{sub_id}", filter=f"roleName eq '{name}'")), None)
                    if d is not None:
                        self._role_ids[name] = d.name.lower()
        except (AzureError, HttpResponseError) as exc:
            if _denied(exc):
                return CheckResult(FAIL, f"Role assignments are not readable: {safe_error(exc, 200)}",
                                   f"Assign {', '.join(required)} to the service principal on subscription {sub_id} - requires approval"), set()
            return CheckResult(UNKNOWN, f"Role check failed: {safe_error(exc, 200)}"), set()
        present = {n for n in required if self._role_ids.get(n) in assigned}
        missing = [n for n in required if n not in present]
        note = f" Note: {mismatch}; checked the service principal instead - correct AZURE_PRINCIPAL_OBJECT_ID in backend/.env." if mismatch else ""
        if missing:
            return CheckResult(FAIL, f"Missing role assignments: {', '.join(missing)}.{note}",
                               f"Assign {', '.join(missing)} to the service principal (Tenant Root Group or subscription scope) - requires approval"), present
        return CheckResult(PASS, f"Assigned: {', '.join(required)}.{note}"), present

    def _probe(self, call, ok: str, what: str, role: str) -> CheckResult:
        try:
            call()
        except (AzureError, HttpResponseError) as exc:
            if _denied(exc):
                return CheckResult(FAIL, f"{what} access denied: {safe_error(exc, 200)}",
                                   f"Assign {role} at subscription scope - requires approval")
            return CheckResult(UNKNOWN, f"{what} check failed: {safe_error(exc, 200)}")
        return CheckResult(PASS, ok)

    def validate(self, scope: DiscoveredScope) -> dict[str, CheckResult]:
        auth = self._auth_check()
        if auth.status != PASS:
            return {CHECK_AUTH: auth, **{k: skipped("authentication failed") for k in (
                CHECK_PERMISSIONS, CHECK_AUDIT, CHECK_BILLING, CHECK_MONITORING)}}
        sub_id = scope.external_id
        perms, present = self._roles(sub_id)
        since = (datetime.now(UTC) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        audit = self._probe(
            lambda: next(iter(self.clients.monitor(sub_id).activity_logs.list(
                filter=f"eventTimestamp ge '{since}'", select="eventTimestamp")), None),
            "Activity Log readable", "Activity Log", "Reader / Monitoring Reader")
        # Cost Management throttles hard (429): the probe is retried with back-off so a transient limit is not
        # recorded as "billing not validated", which would make billing_refresh / cost_detail_refresh skip the subscription.
        from app.services import reliability as rel
        billing = self._probe(
            lambda: rel.call("azure", "cost_probe", lambda: self.clients.cost().query.usage(f"/subscriptions/{sub_id}", month_to_date_query()),
                             scope=sub_id, rate_key="azure_cost", attempts=6, base_delay=2.0),
            "Cost Management query succeeded", "Cost Management", "Cost Management Reader")
        if perms.status == UNKNOWN:
            monitoring = CheckResult(UNKNOWN, "Monitoring Reader assignment could not be verified")
        elif "Monitoring Reader" in present:
            monitoring = CheckResult(PASS, "Monitoring Reader assigned")
        else:
            monitoring = CheckResult(FAIL, "Monitoring Reader is not assigned",
                                     "Assign Monitoring Reader at subscription scope - requires approval")
        return {CHECK_AUTH: auth, CHECK_PERMISSIONS: perms, CHECK_AUDIT: audit,
                CHECK_BILLING: billing, CHECK_MONITORING: monitoring}

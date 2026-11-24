"""GCP and Azure connector tests with fake clients, plus checks that the fakes match the real SDK surface."""
from types import SimpleNamespace as NS

from azure.core.exceptions import HttpResponseError
from google.api_core import exceptions as gexc

from app.core.config import Settings
from app.services.azure.connector import AzureConnector
from app.services.connector import FAIL, PASS, UNKNOWN, DiscoveredScope
from app.services.gcp.connector import GcpConnector

ORG = "organizations/999"


def enum(name):
    return NS(name=name)


class FakeGcp:
    def __init__(self):
        self.tree = {  # parent -> (projects, folders)
            ORG: ([("p-root", "Root project", "101", "ACTIVE")], ["folders/1"]),
            "folders/1": ([("p-team", "Team project", "102", "ACTIVE"), ("p-gone", "Deleted", "103", "DELETE_REQUESTED")], ["folders/2"]),
            "folders/2": ([("p-deep", "Deep project", "104", "ACTIVE")], []),
        }
        self.granted = None  # None -> everything requested
        self.enabled = {"compute.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com"}
        self.billing_enabled = True
        self.log_error = None
        self.projects = self.folders = self.service_usage = self.billing = self.logging = self

    def credentials(self):
        return object()

    def list_projects(self, parent, timeout=None):
        return [NS(project_id=i, display_name=n, name=f"projects/{num}", state=enum(st)) for i, n, num, st in self.tree[parent][0]]

    def list_folders(self, parent, timeout=None):
        return [NS(name=f, state=enum("ACTIVE")) for f in self.tree[parent][1]]

    def test_iam_permissions(self, resource, permissions, timeout=None):
        return NS(permissions=list(permissions) if self.granted is None else [p for p in permissions if p in self.granted])

    def batch_get_services(self, request):
        return NS(services=[NS(name=n, state=enum("ENABLED" if n.split("/")[-1] in self.enabled else "DISABLED")) for n in request["names"]])

    def get_project_billing_info(self, name, timeout=None):
        return NS(billing_enabled=self.billing_enabled, billing_account_name="billingAccounts/X" if self.billing_enabled else "")

    def list_log_entries(self, request):
        if self.log_error:
            raise self.log_error
        return iter([NS()])


def gcp(fake=None):
    fake = fake or FakeGcp()
    return GcpConnector(Settings(_env_file=None, gcp_organization_id="999"), clients=fake), fake


def gscope():
    return DiscoveredScope("gcp", "p-team", "Team", "ACTIVE", True, attrs={"project_number": "102"})


def test_gcp_discovery_walks_nested_folders():
    conn, _ = gcp()
    scopes = {s.external_id: s for s in conn.discover()}
    assert set(scopes) == {"p-root", "p-team", "p-gone", "p-deep"}
    assert not scopes["p-gone"].is_active and scopes["p-deep"].attrs["project_number"] == "104"


def test_gcp_validate_all_pass_and_records_billing_account():
    conn, _ = gcp()
    s = gscope()
    r = conn.validate(s)
    assert all(c.status == PASS for c in r.values()), {k: v.detail for k, v in r.items()}
    assert s.attrs["billing_account"] == "billingAccounts/X"


def test_gcp_missing_permission_api_billing_and_audit():
    conn, fake = gcp()
    fake.granted = {"resourcemanager.projects.get", "logging.logEntries.list", "compute.instances.list"}
    fake.enabled = {"logging.googleapis.com", "monitoring.googleapis.com"}
    fake.billing_enabled = False
    fake.log_error = gexc.PermissionDenied("no logs for you")
    r = conn.validate(gscope())
    assert r["permissions"].status == FAIL and "monitoring.timeSeries.list" in r["permissions"].detail
    assert r["configuration"].status == FAIL and "compute.googleapis.com" in r["configuration"].detail
    assert r["billing"].status == FAIL and r["audit_logs"].status == FAIL and r["monitoring"].status == FAIL
    assert all("requires approval" in r[k].remediation for k in ("permissions", "configuration", "billing", "audit_logs"))


def test_gcp_transient_error_is_unknown_not_pass():
    conn, fake = gcp()
    fake.log_error = gexc.ServiceUnavailable("try later")
    assert conn.validate(gscope())["audit_logs"].status == UNKNOWN


def test_gcp_fake_matches_real_sdk_surface():
    from google.cloud import billing_v1, resourcemanager_v3, service_usage_v1
    from google.cloud.logging_v2.services.logging_service_v2 import LoggingServiceV2Client

    for cls, methods in ((resourcemanager_v3.ProjectsClient, ("list_projects", "test_iam_permissions")),
                         (resourcemanager_v3.FoldersClient, ("list_folders",)),
                         (service_usage_v1.ServiceUsageClient, ("batch_get_services",)),
                         (billing_v1.CloudBillingClient, ("get_project_billing_info",)),
                         (LoggingServiceV2Client, ("list_log_entries",))):
        for m in methods:
            assert callable(getattr(cls, m))


# ---------------------------------------------------------------- Azure
TENANT = "tenant-a"
ROLE_GUIDS = {"Reader": "guid-reader", "Monitoring Reader": "guid-mon", "Cost Management Reader": "guid-cost"}


def denied():
    e = HttpResponseError(message="AuthorizationFailed")
    e.status_code = 403
    return e


class FakeAzure:
    def __init__(self):
        self.assigned = set(ROLE_GUIDS.values())
        self.activity_error = self.cost_error = None
        self.subscriptions_list = [NS(subscription_id="sub-1", display_name="Prod", tenant_id=TENANT, state="Enabled"),
                                   NS(subscription_id="sub-2", display_name="Old", tenant_id=TENANT, state="Disabled"),
                                   NS(subscription_id="sub-x", display_name="Other tenant", tenant_id="tenant-b", state="Enabled")]

    def credential(self):
        return NS(get_token=lambda scope: NS(token="t"))

    def subscriptions(self):
        return NS(subscriptions=NS(list=lambda: iter(self.subscriptions_list)))

    def authorization(self, sub_id):
        return NS(role_assignments=NS(list_for_subscription=lambda filter: [
                      NS(role_definition_id=f"/subscriptions/{sub_id}/providers/Microsoft.Authorization/roleDefinitions/{g}") for g in self.assigned]),
                  role_definitions=NS(list=lambda scope, filter: [NS(name=ROLE_GUIDS[filter.split("'")[1]])]))

    def monitor(self, sub_id):
        def _list(filter, select):
            if self.activity_error:
                raise self.activity_error
            return iter([])
        return NS(activity_logs=NS(list=_list))

    def cost(self):
        def _usage(scope, parameters):
            if self.cost_error:
                raise self.cost_error
            return NS(rows=[])
        return NS(query=NS(usage=_usage))


def azure(**kw):
    fake = FakeAzure()
    s = Settings(_env_file=None, azure_tenant_id=TENANT, azure_principal_object_id=kw.pop("oid", "oid-1"))
    return AzureConnector(s, clients=fake), fake


def ascope():
    return DiscoveredScope("azure", "sub-1", "Prod", "Enabled", True)


def test_azure_discovery_filters_tenant_and_state():
    conn, _ = azure()
    scopes = {s.external_id: s for s in conn.discover()}
    assert set(scopes) == {"sub-1", "sub-2"} and scopes["sub-1"].is_active and not scopes["sub-2"].is_active


def test_azure_validate_all_pass():
    conn, _ = azure()
    assert all(c.status == PASS for c in conn.validate(ascope()).values())


def test_azure_missing_roles_and_denied_probes():
    conn, fake = azure()
    fake.assigned = {"guid-reader"}
    fake.cost_error = fake.activity_error = denied()
    r = conn.validate(ascope())
    assert r["permissions"].status == FAIL and "Monitoring Reader" in r["permissions"].detail and "Cost Management Reader" in r["permissions"].detail
    assert r["billing"].status == FAIL and r["audit_logs"].status == FAIL and r["monitoring"].status == FAIL


def test_azure_roles_unverifiable_without_principal_id():
    conn, _ = azure(oid=None)
    r = conn.validate(ascope())
    assert r["permissions"].status == UNKNOWN and r["monitoring"].status == UNKNOWN


def test_azure_fake_matches_real_sdk_surface():
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.costmanagement import CostManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.resource.subscriptions import SubscriptionClient

    cred = NS(get_token=lambda *a, **k: None)
    assert callable(SubscriptionClient(cred).subscriptions.list)
    authz = AuthorizationManagementClient(cred, "s")
    assert callable(authz.role_assignments.list_for_subscription) and callable(authz.role_definitions.list)
    assert callable(MonitorManagementClient(cred, "s").activity_logs.list)
    assert callable(CostManagementClient(cred).query.usage)

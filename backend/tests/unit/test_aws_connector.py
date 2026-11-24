"""AWS connector tests using botocore's Stubber: real SDK request/response validation, no network."""
import boto3
import pytest
from botocore.stub import Stubber

from app.core.config import Settings
from app.services.aws.connector import AwsConnector
from app.services.connector import FAIL, PASS, UNKNOWN, DiscoveredScope

MGMT, MEMBER = "111111111111", "222222222222"
SERVICES = ("organizations", "sts", "ec2", "cloudtrail", "cloudwatch", "ce")


class StubSession:
    """Stands in for boto3.Session; hands out pre-stubbed clients."""

    def __init__(self):
        kw = dict(region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
        self.clients = {s: boto3.client(s, **kw) for s in SERVICES}
        self.stubs = {s: Stubber(c) for s, c in self.clients.items()}
        for st in self.stubs.values():
            st.activate()

    def client(self, service, **_):
        return self.clients[service]


@pytest.fixture()
def env():
    base, member = StubSession(), StubSession()
    conn = AwsConnector(Settings(_env_file=None, aws_member_role_name="mcp-readonly", aws_external_id="ext-1"), base_session=base)
    conn._session_from_credentials = lambda creds: member
    conn._management_id = MGMT
    return conn, base, member


def acct(i, name, status="ACTIVE"):
    return {"Id": i, "Name": name, "Email": f"{name}@example.com", "Status": status}


def scope(i=MEMBER):
    return DiscoveredScope("aws", i, "member", "ACTIVE", True)


def stub_assume(base):
    base.stubs["sts"].add_response("assume_role", {"Credentials": {
        "AccessKeyId": "ASIAXXXXXXXXXXXXXXXX", "SecretAccessKey": "s", "SessionToken": "t", "Expiration": "2030-01-01T00:00:00Z"}},
        {"RoleArn": f"arn:aws:iam::{MEMBER}:role/mcp-readonly", "RoleSessionName": "mcp-control-plane", "ExternalId": "ext-1"})


def stub_probes(member, trails):
    member.stubs["sts"].add_response("get_caller_identity", {"Account": MEMBER})
    member.stubs["ec2"].add_response("describe_regions", {"Regions": []})
    member.stubs["cloudtrail"].add_response("describe_trails", {"trailList": []})
    member.stubs["cloudwatch"].add_response("list_metrics", {"Metrics": []})
    member.stubs["cloudtrail"].add_response("describe_trails", {"trailList": trails}, {"includeShadowTrails": True})


def test_discovery_paginates_and_reads_ou(env):
    conn, base, _ = env
    org = base.stubs["organizations"]
    org.add_response("describe_organization", {"Organization": {"MasterAccountId": MGMT}})
    org.add_response("list_accounts", {"Accounts": [acct(MGMT, "mgmt")], "NextToken": "n1"})
    org.add_response("list_parents", {"Parents": [{"Id": "r-1", "Type": "ROOT"}]}, {"ChildId": MGMT})
    org.add_response("list_accounts", {"Accounts": [acct(MEMBER, "prod"), acct("333333333333", "old", "SUSPENDED")]}, {"NextToken": "n1"})
    org.add_response("list_parents", {"Parents": [{"Id": "ou-1", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": MEMBER})
    org.add_response("describe_organizational_unit", {"OrganizationalUnit": {"Id": "ou-1", "Name": "Workloads"}})
    org.add_response("list_parents", {"Parents": [{"Id": "ou-1", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": "333333333333"})
    scopes = conn.discover()
    assert [s.external_id for s in scopes] == [MGMT, MEMBER, "333333333333"]
    assert scopes[0].attrs["is_management"] and scopes[0].parent == "Root"
    assert scopes[1].parent == "Workloads" and scopes[1].is_active
    assert not scopes[2].is_active and scopes[2].provider_state == "SUSPENDED"
    org.assert_no_pending_responses()


def test_validate_fully_onboarded_member(env):
    conn, base, member = env
    stub_assume(base)
    arn = f"arn:aws:cloudtrail:us-east-1:{MGMT}:trail/org"
    stub_probes(member, [{"Name": "org", "TrailARN": arn, "HomeRegion": "us-east-1"}])
    member.stubs["cloudtrail"].add_response("get_trail_status", {"IsLogging": True}, {"Name": arn})
    base.stubs["ce"].add_response("get_cost_and_usage", {"ResultsByTime": []})
    r = conn.validate(scope())
    assert {k: v.status for k, v in r.items()} == dict.fromkeys(
        ("authentication", "permissions", "audit_logs", "billing", "monitoring"), PASS)
    base.stubs["sts"].assert_no_pending_responses()


def test_assume_role_denied_reports_access_failure_and_task(env):
    conn, base, _ = env
    base.stubs["sts"].add_client_error("assume_role", "AccessDenied", "not authorized")
    r = conn.validate(scope())
    assert r["authentication"].status == FAIL and "requires approval" in r["authentication"].remediation
    assert all(r[k].status == UNKNOWN for k in ("permissions", "audit_logs", "billing", "monitoring"))


def test_missing_cloudtrail_is_identified(env):
    conn, base, member = env
    stub_assume(base)
    stub_probes(member, [])
    base.stubs["ce"].add_response("get_cost_and_usage", {"ResultsByTime": []})
    r = conn.validate(scope())
    assert r["audit_logs"].status == FAIL and "not configured" in r["audit_logs"].detail


def test_trail_present_but_not_logging(env):
    conn, base, member = env
    stub_assume(base)
    arn = f"arn:aws:cloudtrail:us-east-1:{MEMBER}:trail/t"
    stub_probes(member, [{"Name": "t", "TrailARN": arn, "HomeRegion": "us-east-1"}])
    member.stubs["cloudtrail"].add_response("get_trail_status", {"IsLogging": False}, {"Name": arn})
    base.stubs["ce"].add_response("get_cost_and_usage", {"ResultsByTime": []})
    assert conn.validate(scope())["audit_logs"].status == FAIL


def test_missing_monitoring_permission_and_billing_denied(env):
    conn, base, member = env
    stub_assume(base)
    member.stubs["sts"].add_response("get_caller_identity", {"Account": MEMBER})
    member.stubs["ec2"].add_response("describe_regions", {"Regions": []})
    member.stubs["cloudtrail"].add_response("describe_trails", {"trailList": []})
    member.stubs["cloudwatch"].add_client_error("list_metrics", "AccessDenied", "no")
    member.stubs["cloudtrail"].add_response("describe_trails", {"trailList": []}, {"includeShadowTrails": True})
    base.stubs["ce"].add_client_error("get_cost_and_usage", "AccessDeniedException", "no")
    r = conn.validate(scope())
    assert r["permissions"].status == FAIL and "cloudwatch:ListMetrics" in r["permissions"].detail
    assert r["monitoring"].status == FAIL and r["billing"].status == FAIL


def test_requires_role_name():
    assert AwsConnector(Settings(_env_file=None)).missing_configuration() == ["AWS_MEMBER_ROLE_NAME"]

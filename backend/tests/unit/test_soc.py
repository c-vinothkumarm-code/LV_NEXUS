import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

import boto3
from botocore.stub import Stubber

from app.core.config import Settings
from app.models import Severity
from app.services.soc.collectors import AwsAuditCollector
from app.services.soc.normalize import normalize_azure, normalize_cloudtrail, normalize_gcp
from app.services.soc.rules import evaluate, is_untrusted_ip
from tests.helpers import ev

NOW = datetime(2026, 11, 17, 6, 0, tzinfo=UTC)


def rules_for(event):
    return {r.id: sev for r, sev in evaluate(event)}


def trail(name, detail=None, **top):
    return {"EventId": top.pop("EventId", "id-1"), "EventName": name, "EventTime": NOW, "Username": "alice",
            "CloudTrailEvent": json.dumps({"eventName": name, "awsRegion": "ap-south-1", "sourceIPAddress": "198.51.100.7",
                                           "eventSource": "ec2.amazonaws.com", "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/alice"},
                                           **(detail or {})}), **top}


def test_cloudtrail_normalisation_and_denied_outcome():
    e = normalize_cloudtrail(trail("RunInstances", {"errorCode": "Client.UnauthorizedOperation"}), "111111111111")
    assert (e["provider"], e["scope_external_id"], e["region"], e["source_ip"]) == ("aws", "111111111111", "ap-south-1", "198.51.100.7")
    assert e["outcome"] == "denied" and e["principal"].endswith("user/alice") and e["event_timestamp"] == NOW
    assert "unauthorized_access" in rules_for(e) and "vm_created" not in rules_for(e)  # a denied call created nothing


def test_console_login_failure_and_missing_mfa():
    fail = normalize_cloudtrail(trail("ConsoleLogin", {"responseElements": {"ConsoleLogin": "Failure"}}), "1")
    assert fail["outcome"] == "failure" and "failed_authentication" in rules_for(fail)
    ok = normalize_cloudtrail(trail("ConsoleLogin", {"responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}}), "1")
    assert rules_for(ok)["login_without_mfa"] == Severity.MEDIUM


def test_gcp_normalisation():
    e = normalize_gcp({"insertId": "abc", "timestamp": "2026-11-17T06:00:00Z", "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
                       "resource": {"type": "gce_firewall_rule", "labels": {"location": "asia-south1"}},
                       "protoPayload": {"methodName": "v1.compute.firewalls.insert", "serviceName": "compute.googleapis.com",
                                        "authenticationInfo": {"principalEmail": "dev@example.com"}, "requestMetadata": {"callerIp": "192.0.2.4"},
                                        "resourceName": "projects/p/global/firewalls/open", "request": {"sourceRanges": ["0.0.0.0/0"]}}}, "p")
    assert (e["event_name"], e["principal"], e["source_ip"], e["event_category"]) == ("v1.compute.firewalls.insert", "dev@example.com", "192.0.2.4", "admin_activity")
    assert rules_for(e)["network_rule_change"] == Severity.HIGH  # open to 0.0.0.0/0 raises Medium to High


def test_azure_normalisation_skips_in_flight_records():
    base = dict(event_data_id="x1", event_timestamp=NOW, caller="ops@example.com", resource_id="/subscriptions/s/rg/nsg1",
                operation_name=NS(value="Microsoft.Network/networkSecurityGroups/securityRules/write"), resource_type=NS(value="nsg"),
                category=NS(value="Administrative"), http_request=NS(client_ip_address="192.0.2.8"), sub_status=None, level="Informational",
                resource_group_name="rg", properties={}, correlation_id="c", resource_provider_name=NS(value="Microsoft.Network"))
    assert normalize_azure(NS(status=NS(value="Started"), **base), "s") is None
    e = normalize_azure(NS(status=NS(value="Succeeded"), **base), "s")
    assert e["outcome"] == "success" and e["source_ip"] == "192.0.2.8" and "network_rule_change" in rules_for(e)
    denied = normalize_azure(NS(status=NS(value="Failed"), **{**base, "sub_status": NS(value="Forbidden")}), "s")
    assert denied["outcome"] == "denied"


def test_high_risk_rules():
    assert rules_for(ev(name="StopLogging", service="cloudtrail.amazonaws.com"))["audit_logging_disabled"] == Severity.CRITICAL
    assert rules_for(ev(name="DeleteDetector"))["security_service_disabled"] == Severity.CRITICAL
    assert rules_for(ev(name="DeletePublicAccessBlock"))["public_storage_exposure"] == Severity.HIGH
    assert rules_for(ev(name="AttachUserPolicy"))["privilege_escalation"] == Severity.HIGH
    assert "root_account_activity" in rules_for(ev(name="CreateUser", raw={"userIdentityType": "Root"}))
    assert rules_for(ev(provider="azure", name="Microsoft.Authorization/roleAssignments/write"))["privilege_escalation"] == Severity.HIGH
    assert "organization_policy_change" in rules_for(ev(provider="gcp", name="google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy", service="orgpolicy.googleapis.com"))
    assert rules_for(ev(name="DescribeInstances", read_only=True)) == {}


def test_trusted_network_check():
    cidrs = ["203.0.113.0/24"]
    assert not is_untrusted_ip("203.0.113.9", cidrs) and is_untrusted_ip("198.51.100.1", cidrs)
    assert not is_untrusted_ip("cloudtrail.amazonaws.com", cidrs) and not is_untrusted_ip("198.51.100.1", [])


class FakeAws:
    def __init__(self, clients):
        self.clients = clients

    def session_for(self, account_id, is_management):
        return "session"

    def regions(self, session):
        return ["us-east-1", "ap-south-1"]

    def client(self, session, service, region=None):
        return self.clients[region]


def test_cloudtrail_collector_paginates_filters_writes_and_dedups_regions():
    since, until = NOW - timedelta(hours=1), NOW
    clients, stubs = {}, {}
    for region in ("us-east-1", "ap-south-1"):
        clients[region] = boto3.client("cloudtrail", region_name=region, aws_access_key_id="t", aws_secret_access_key="t")
        stubs[region] = Stubber(clients[region])
        stubs[region].activate()
    params = {"StartTime": since, "EndTime": until, "LookupAttributes": [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]}
    stubs["us-east-1"].add_response("lookup_events", {"Events": [trail("CreateUser", EventId="g1")], "NextToken": "t"}, params)
    stubs["us-east-1"].add_response("lookup_events", {"Events": [trail("RunInstances", EventId="a2")]}, {**params, "NextToken": "t"})
    stubs["ap-south-1"].add_response("lookup_events", {"Events": [trail("CreateUser", EventId="g1"), trail("StopLogging", EventId="b3")]}, params)
    events = list(AwsAuditCollector(Settings(_env_file=None), FakeAws(clients)).collect(NS(external_id="111111111111", is_management=False), since, until))
    assert [e["event_id"] for e in events] == ["g1", "a2", "b3"]
    for s in stubs.values():
        s.assert_no_pending_responses()

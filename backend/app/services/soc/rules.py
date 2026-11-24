"""Rule-based detection. Works with no AI service. Each rule is data plus a small predicate.

Rules flag events for analyst review; they never change a review status and never act on a cloud."""
from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass

from app.models import Severity

BASE_SCORE = {Severity.CRITICAL: 90, Severity.HIGH: 70, Severity.MEDIUM: 50, Severity.LOW: 25, Severity.INFORMATIONAL: 10}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    recommendation: str
    match: Callable[[dict], bool]
    escalate: Callable[[dict], bool] | None = None  # when true the finding is raised one severity level

    def severity_for(self, event: dict) -> Severity:
        if self.escalate and self.escalate(event):
            order = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            return order[min(order.index(self.severity) + 1, len(order) - 1)]
        return self.severity


def _name(e: dict) -> str:
    return e["event_name"].lower()


def _raw(e: dict) -> str:
    return json.dumps(e.get("raw") or {}, default=str).lower()


def names(aws=(), gcp_suffix=(), azure_contains=(), ok_only: bool = True) -> Callable[[dict], bool]:
    """Match by provider-specific operation names. GCP methods match by suffix, Azure operations by substring."""
    aws_set = {n.lower() for n in aws}
    gcp_s, az_s = tuple(s.lower() for s in gcp_suffix), tuple(s.lower() for s in azure_contains)

    def m(e: dict) -> bool:
        if ok_only and e.get("outcome") != "success":
            return False
        n = _name(e)
        if e["provider"] == "aws":
            return n in aws_set
        if e["provider"] == "gcp":
            return bool(gcp_s) and n.endswith(gcp_s)
        return bool(az_s) and any(s in n for s in az_s) and not n.endswith("/read")

    return m


def _open_to_world(e: dict) -> bool:
    raw = _raw(e)
    return "0.0.0.0/0" in raw or "::/0" in raw or '"*"' in raw and e["provider"] == "azure"


def _public_principal(e: dict) -> bool:
    raw = _raw(e)
    return any(s in raw for s in ("allusers", "allauthenticatedusers", "authenticatedusers", '"principal": "*"', "allowblobpublicaccess\": true"))


def _is_root(e: dict) -> bool:
    return e["provider"] == "aws" and (e.get("raw") or {}).get("userIdentityType") == "Root"


RULES: list[Rule] = [
    Rule("failed_authentication", "Failed console authentication", Severity.LOW, "authentication",
         "Confirm with the user; repeated failures may indicate credential guessing.",
         lambda e: e["provider"] == "aws" and _name(e) == "consolelogin" and e.get("outcome") != "success"),
    Rule("login_without_mfa", "Console login without MFA", Severity.MEDIUM, "authentication",
         "Enforce MFA for this identity.",
         lambda e: e["provider"] == "aws" and _name(e) == "consolelogin" and e.get("outcome") == "success"
         and ((e.get("raw") or {}).get("additionalEventData") or {}).get("MFAUsed") == "No", escalate=_is_root),
    Rule("root_account_activity", "AWS root account used", Severity.HIGH, "administrative_access",
         "Root should not be used for routine work; verify who used it and why.",
         lambda e: _is_root(e) and not e.get("read_only")),
    Rule("privilege_escalation", "Permissions granted or credentials created", Severity.HIGH, "iam",
         "Verify the change was approved and follows least privilege.",
         names(aws=("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
                    "AddUserToGroup", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "UpdateAssumeRolePolicy",
                    "CreatePolicyVersion", "SetDefaultPolicyVersion"),
               gcp_suffix=("SetIamPolicy", "CreateServiceAccountKey"),
               azure_contains=("microsoft.authorization/roleassignments/write",)), escalate=_public_principal),
    Rule("iam_role_modification", "IAM role or identity modified", Severity.MEDIUM, "iam",
         "Confirm the identity change against the change record.",
         names(aws=("CreateRole", "DeleteRole", "UpdateRole", "CreateUser", "DeleteUser", "DeleteRolePolicy", "DetachRolePolicy",
                    "DeleteAccessKey", "DeactivateMFADevice", "DeleteVirtualMFADevice"),
               gcp_suffix=("CreateRole", "UpdateRole", "DeleteRole", "CreateServiceAccount", "DeleteServiceAccount"),
               azure_contains=("microsoft.authorization/roledefinitions/", "microsoft.authorization/roleassignments/delete"))),
    Rule("public_storage_exposure", "Storage permissions changed", Severity.MEDIUM, "storage",
         "Check that the bucket or container is not publicly readable.",
         names(aws=("PutBucketAcl", "PutBucketPolicy", "DeleteBucketPolicy", "PutPublicAccessBlock", "DeletePublicAccessBlock",
                    "DeleteAccountPublicAccessBlock", "PutAccountPublicAccessBlock", "PutObjectAcl"),
               gcp_suffix=("storage.setIamPermissions", "storage.buckets.update", "storage.buckets.patch"),
               azure_contains=("microsoft.storage/storageaccounts/write", "blobservices/containers/write")),
         escalate=lambda e: _public_principal(e) or "deletepublicaccessblock" in _name(e) or "deleteaccountpublicaccessblock" in _name(e)),
    Rule("network_rule_change", "Security group, firewall or NSG modified", Severity.MEDIUM, "network",
         "Review the rule; ingress open to the internet needs justification.",
         names(aws=("AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "CreateSecurityGroup",
                    "DeleteSecurityGroup", "ModifySecurityGroupRules", "CreateNetworkAclEntry", "ReplaceNetworkAclEntry"),
               gcp_suffix=("firewalls.insert", "firewalls.patch", "firewalls.update", "firewalls.delete"),
               azure_contains=("networksecuritygroups/write", "networksecuritygroups/delete", "securityrules/write", "securityrules/delete")),
         escalate=_open_to_world),
    Rule("vpc_modification", "VPC or virtual network modified", Severity.LOW, "network",
         "Confirm the network change was planned.",
         names(aws=("CreateVpc", "DeleteVpc", "CreateVpcPeeringConnection", "AcceptVpcPeeringConnection", "CreateInternetGateway",
                    "AttachInternetGateway", "CreateRoute", "ReplaceRoute", "DeleteRoute", "CreateNatGateway"),
               gcp_suffix=("networks.insert", "networks.delete", "networks.addPeering", "routes.insert", "routes.delete"),
               azure_contains=("virtualnetworks/write", "virtualnetworks/delete", "virtualnetworkpeerings/write", "routetables/"))),
    Rule("public_ip_exposure", "Public IP address allocated or attached", Severity.MEDIUM, "network",
         "Confirm the resource needs to be reachable from the internet.",
         names(aws=("AllocateAddress", "AssociateAddress"),
               gcp_suffix=("addresses.insert", "instances.addAccessConfig"),
               azure_contains=("publicipaddresses/write",))),
    Rule("vm_created", "Virtual machine created", Severity.INFORMATIONAL, "compute",
         "Confirm the VM is expected and tagged with an owner.",
         names(aws=("RunInstances",), gcp_suffix=("instances.insert",), azure_contains=("microsoft.compute/virtualmachines/write",))),
    Rule("vm_deleted", "Virtual machine deleted", Severity.MEDIUM, "compute",
         "Confirm the deletion was intended.",
         names(aws=("TerminateInstances",), gcp_suffix=("instances.delete",), azure_contains=("microsoft.compute/virtualmachines/delete",))),
    Rule("audit_logging_disabled", "Audit logging stopped or changed", Severity.HIGH, "logging",
         "Restore logging immediately and investigate who changed it.",
         names(aws=("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs", "DeleteLogGroup"),
               gcp_suffix=("DeleteSink", "UpdateSink", "DeleteLog", "CreateExclusion", "UpdateBucket"),
               azure_contains=("diagnosticsettings/delete", "diagnosticsettings/write")),
         escalate=lambda e: any(s in _name(e) for s in ("stoplogging", "deletetrail", "deletesink", "diagnosticsettings/delete"))),
    Rule("security_service_disabled", "Security service disabled or reconfigured", Severity.HIGH, "security_services",
         "Re-enable the service and investigate.",
         names(aws=("DeleteDetector", "DisableSecurityHub", "DeleteConfigurationRecorder", "StopConfigurationRecorder", "DisableMacie",
                    "DeleteMembers", "DisassociateFromMasterAccount", "UpdateDetector", "DeleteWebACL"),
               gcp_suffix=("SecurityCenter.UpdateOrganizationSettings", "SecurityCenterService.UpdateSecurityHealthAnalyticsCustomModule"),
               azure_contains=("microsoft.security/pricings/write", "microsoft.security/securitycontacts/delete",
                               "microsoft.security/autoprovisioningsettings/write")),
         escalate=lambda e: any(s in _name(e) for s in ("deletedetector", "disablesecurityhub", "deleteconfigurationrecorder"))),
    Rule("organization_policy_change", "Organisation policy changed", Severity.HIGH, "governance",
         "Confirm the policy change was approved by Cloud Governance.",
         lambda e: e.get("outcome") == "success" and (
             (e["provider"] == "aws" and (e.get("service") or "").startswith("organizations") and not e.get("read_only")
              and _name(e) in {"attachpolicy", "detachpolicy", "createpolicy", "updatepolicy", "deletepolicy", "enablepolicytype",
                               "disablepolicytype", "leaveorganization", "removeaccountfromorganization"})
             or (e["provider"] == "gcp" and "orgpolicy" in (e.get("service") or "") and not e.get("read_only"))
             or (e["provider"] == "azure" and "microsoft.authorization/policy" in _name(e) and not _name(e).endswith("/read")))),
    Rule("unauthorized_access", "Access denied", Severity.LOW, "access",
         "A single denial is usually benign; look for repetition by the same principal.",
         lambda e: e.get("outcome") == "denied"),
    Rule("resource_deleted", "Resource deleted", Severity.LOW, "change",
         "Confirm the deletion against the change record.",
         lambda e: e.get("outcome") == "success" and not e.get("read_only") and (
             _name(e).startswith(("delete", "terminate", "remove")) or _name(e).endswith((".delete", "/delete")))),
]
RULES_BY_ID = {r.id: r for r in RULES}

# Rules produced by counting or by comparison with history (see engine.py).
AGGREGATE_RULES = {
    "repeated_failed_authentication": ("Repeated failed authentication", Severity.HIGH, "authentication",
                                       "Possible credential guessing. Verify with the user and consider resetting credentials."),
    "repeated_permission_denied": ("Repeated permission denied errors", Severity.MEDIUM, "access",
                                   "Possible permission probing or a broken automation. Identify the caller."),
    "abnormal_data_access": ("Abnormal volume of data access", Severity.MEDIUM, "data_access",
                             "Confirm the data access volume is expected for this principal."),
    "unexpected_source_ip": ("Change made from an untrusted network", Severity.MEDIUM, "network",
                             "Confirm the user's location; add the network to the trusted list if legitimate."),
    "unusual_api_call": ("API call not seen before for this principal", Severity.LOW, "behaviour",
                         "New behaviour for this identity. Confirm it matches their role."),
}


def is_untrusted_ip(ip: str | None, trusted_cidrs: list[str]) -> bool:
    """True only for a real address outside every trusted network. Service names and blanks are ignored."""
    if not ip or not trusted_cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False  # e.g. "cloudtrail.amazonaws.com": an AWS service acting on the account's behalf
    return not any(addr in ipaddress.ip_network(c, strict=False) for c in trusted_cidrs)


def evaluate(event: dict) -> list[tuple[Rule, Severity]]:
    return [(r, r.severity_for(event)) for r in RULES if r.match(event)]

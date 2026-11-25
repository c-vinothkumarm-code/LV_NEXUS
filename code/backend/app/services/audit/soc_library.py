"""SOC detection rule library: categories A-G, MITRE ATT&CK mapping, investigation steps and remediation for every rule.

- Rules AUD-001..037 already existed; they get their library metadata here (only empty fields are filled, nothing an
  administrator changed is overwritten).
- Rules AUD-038 onwards add AWS / GCP / cross-cloud coverage. They use provider-native operation names and event fields.
- Every rule excludes provider-managed identities (AWS service-linked roles, Google-managed service agents) and the
  LV NEXUS read-only identity, so routine platform operations are not reported as suspicious.
- `data_requirements` says which collection a rule depends on (for example AWS read events, or GCP Data Access logs).
  Rules whose data is not collected are shown as "needs data source" instead of silently never firing.
"""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

SOC_CATEGORIES = {
    "A": "Identity and privileged access",
    "B": "Cloud reconnaissance and discovery",
    "C": "Security configuration changes",
    "D": "Network and public exposure",
    "E": "Data security and exfiltration indicators",
    "F": "Infrastructure and workload activity",
    "G": "Governance and compliance",
}

MITRE = {
    "T1078.004": "Valid Accounts: Cloud Accounts", "T1098": "Account Manipulation", "T1098.001": "Additional Cloud Credentials",
    "T1098.003": "Additional Cloud Roles", "T1136.003": "Create Account: Cloud Account", "T1484": "Domain or Tenant Policy Modification",
    "T1484.002": "Trust Modification", "T1556": "Modify Authentication Process", "T1556.006": "Multi-Factor Authentication",
    "T1110.001": "Password Guessing", "T1110.003": "Password Spraying", "T1528": "Steal Application Access Token",
    "T1548": "Abuse Elevation Control Mechanism", "T1580": "Cloud Infrastructure Discovery", "T1526": "Cloud Service Discovery",
    "T1069.003": "Permission Groups Discovery: Cloud Groups", "T1087.004": "Account Discovery: Cloud Account",
    "T1619": "Cloud Storage Object Discovery", "T1046": "Network Service Discovery", "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools", "T1562.007": "Disable or Modify Cloud Firewall", "T1562.008": "Disable or Modify Cloud Logs",
    "T1133": "External Remote Services", "T1190": "Exploit Public-Facing Application", "T1599": "Network Boundary Bridging",
    "T1530": "Data from Cloud Storage", "T1537": "Transfer Data to Cloud Account", "T1485": "Data Destruction",
    "T1555.006": "Credentials from Password Stores: Cloud Secrets Management Stores", "T1552": "Unsecured Credentials",
    "T1496": "Resource Hijacking", "T1578": "Modify Cloud Compute Infrastructure", "T1578.002": "Create Cloud Instance",
    "T1610": "Deploy Container", "T1651": "Cloud Administration Command", "T1531": "Account Access Removal",
    "T1535": "Unused/Unsupported Cloud Regions", "T1486": "Data Encrypted for Impact",
}

LEAF = lambda field, op, value: {"field": field, "op": op, "value": value}  # noqa: E731
OPS = lambda *names: LEAF("operation", "in", list(names))  # noqa: E731   exact provider operation names (case-insensitive)

# provider-managed and LV NEXUS identities: never a detection on their own
MANAGED_EXCLUSIONS = [
    LEAF("actor", "contains_any", ["awsservicerole", "aws-service-role/", "@cloudservices.gserviceaccount.com", "@gcp-sa-",
                                   "@compute-system.iam.gserviceaccount.com", "@container-engine-robot.iam.gserviceaccount.com",
                                   "@cloud-ml.google.com.iam.gserviceaccount.com", "system:serviceaccount:kube-system"]),
    LEAF("actor", "contains_any", ["mcp-control-plane", "cloudnexusreadonly", "cloudnexusreader", "cloudnexusmanagementreader",
                                   "cloudnexus-reader@"]),
]

APPROVED_REGIONS = ["ap-south-1", "ap-south-2", "us-east-1", "asia-south1", "asia-south2", "global"]

# ---------------------------------------------------------------- metadata for the existing rules AUD-001..037
_STEPS_IAM = ("1. Confirm who made the change and whether a change ticket or approval exists. 2. Review what the identity did after "
              "the change (Live audit, same actor, next 24 h). 3. Check whether the granted access is still needed.")
_STEPS_CFG = ("1. Identify who changed the configuration and from which IP. 2. Check for an approved change record. "
              "3. Compare the configuration before and after (raw event). 4. Look for other changes by the same actor in the same hour.")
_STEPS_NET = ("1. Identify the resource, the opened port and the source range. 2. Check whether the resource is meant to be public. "
              "3. Review inbound traffic and sign-ins to the resource since the change.")
_STEPS_DATA = ("1. Identify the data store and the recipient account or identity. 2. Confirm the business purpose with the data owner. "
               "3. Review access to the data since the change.")

EXISTING_META: dict[str, tuple[str, list[str], str, str]] = {
    "AUD-001": ("A", ["T1098.003"], _STEPS_IAM, "Remove the administrator assignment unless it is approved; use a least-privilege role and time-bound (PIM / JIT) access."),
    "AUD-002": ("C", ["T1562.008"], _STEPS_CFG, "Restart CloudTrail logging, restore the trail and event selectors, and restrict cloudtrail:StopLogging with an SCP."),
    "AUD-003": ("D", ["T1562.007", "T1133"], _STEPS_NET, "Restrict the NSG rule source to known ranges or use Azure Bastion / JIT VM access."),
    "AUD-004": ("D", ["T1562.007", "T1133"], _STEPS_NET, "Restrict the firewall source ranges or use IAP TCP forwarding instead of public SSH / RDP."),
    "AUD-005": ("D", ["T1530"], _STEPS_DATA, "Remove public access, re-enable public access blocks and review the bucket / container policy."),
    "AUD-006": ("C", ["T1485", "T1486"], _STEPS_CFG, "Cancel scheduled key deletion, re-enable the key or encryption, and restrict key administration."),
    "AUD-007": ("G", ["T1562.007"], _STEPS_NET, "Confirm the change against the change calendar; revert if not approved."),
    "AUD-008": ("A", ["T1078.004"], _STEPS_IAM, "Root must not be used for daily work: confirm the reason, rotate root credentials if unexpected and enforce MFA."),
    "AUD-009": ("F", ["T1485"], _STEPS_CFG, "Confirm the deletions were planned; restore from backup or snapshots where they were not."),
    "AUD-010": ("C", ["T1562.008", "T1562.001"], _STEPS_CFG, "Re-enable the logging / monitoring service and restrict who can disable it."),
    "AUD-011": ("B", ["T1580", "T1087.004"], _STEPS_IAM, "Check whether the identity is misconfigured automation or probing for permissions; rotate its credentials if unexpected."),
}
_GENERIC = {
    "Privilege Escalation": "A", "Role Assignments": "A", "IAM Changes": "A", "Permission Modifications": "A", "User Creation": "A",
    "User Deletion": "A", "Authentication Failures": "A", "Security Policy Changes": "C", "Key Vault Operations": "C",
    "Secret Access": "E", "Firewall Changes": "D", "Security Group Changes": "D", "Database Changes": "E",
    "VM Configuration Changes": "F", "Organization-Level Changes": "G", "Subscription-Level Changes": "G",
}


def _mitre_from(text: str | None) -> list[str]:
    return list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", text or "")))


# ---------------------------------------------------------------- new rules AUD-038 onwards
def _r(key, name, provider, cat, category, action, severity, mitre, conditions, steps, remediation, description,
       threshold=1, window=0, group_by="principal", requires=None, change_window=None):
    return {"rule_key": key, "name": name, "provider": provider, "soc_category": cat, "category": category, "action": action,
            "severity": severity, "mitre": mitre, "conditions": conditions, "investigation_steps": steps, "remediation": remediation,
            "description": description, "threshold_count": threshold, "threshold_window_minutes": window, "group_by": group_by,
            "data_requirements": requires or [], "change_window": change_window}


ADMIN_PORTS = r'(?i)"fromport": (22|3389|5985|5986|3306|5432|1433|1521|27017|6379|9200)\b'
WORLD = ["0.0.0.0/0", "::/0"]

NEW_RULES: list[dict] = [
    # A. identity and privileged access
    _r("AUD-038", "IAM user created", "aws", "A", "User Creation", "REVIEW_REQUIRED", "Medium", ["T1136.003"],
       {"all": [OPS("CreateUser"), LEAF("raw.requestParameters.userName", "exists", True)]}, _STEPS_IAM,
       "Prefer IAM Identity Center users over IAM users; delete the user if it was not requested through the approved process.",
       "A long-lived IAM user was created (IAM Identity Center users are created in the identity store)."),
    _r("AUD-039", "Long-lived access key created", "aws", "A", "IAM Changes", "SUSPICIOUS", "Medium", ["T1098.001"],
       OPS("CreateAccessKey"), _STEPS_IAM, "Use roles / Identity Center instead of access keys; deactivate the key if it is not approved.",
       "An access key was created for an IAM user. Access keys are long-lived credentials that can be used from anywhere."),
    _r("AUD-040", "MFA device deactivated or deleted", "aws", "A", "Security Policy Changes", "RULE_VIOLATION", "High", ["T1556.006"],
       OPS("DeactivateMFADevice", "DeleteVirtualMFADevice"), _STEPS_IAM, "Re-enable MFA for the user and require MFA through an IAM policy condition.",
       "Multi-factor authentication was removed from an IAM user."),
    _r("AUD-041", "Policy granting all actions created or attached", "aws", "A", "Privilege Escalation", "SUSPICIOUS", "High",
       ["T1098.003", "T1548"],
       {"all": [OPS("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicy", "CreatePolicyVersion"),
                LEAF("raw_text", "regex", r'(?i)action\\*"\s*:\s*\[?\s*\\*"\*\\*"')]}, _STEPS_IAM,
       "Replace the wildcard policy with the specific actions needed; remove the inline policy if not approved.",
       "An inline or managed policy that allows Action \"*\" was created - equivalent to administrator rights."),
    _r("AUD-042", "Role trust policy changed", "aws", "A", "Permission Modifications", "REVIEW_REQUIRED", "High", ["T1098", "T1484.002"],
       OPS("UpdateAssumeRolePolicy"), _STEPS_IAM, "Confirm every principal in the new trust policy is expected; remove unknown accounts.",
       "The trust policy decides who can assume a role, including identities in other AWS accounts."),
    _r("AUD-043", "Role assumed from another AWS account", "aws", "A", "IAM Changes", "REVIEW_REQUIRED", "Medium", ["T1078.004"],
       {"all": [OPS("AssumeRole"), LEAF("raw.userIdentityType", "eq", "AWSAccount")]}, _STEPS_IAM,
       "Confirm the calling account is a known partner or organization account; restrict the trust policy with aws:PrincipalOrgID or an external ID.",
       "Cross-account access into this account. Requires AWS read events (AssumeRole is a read-only event in CloudTrail).",
       requires=["aws_read_events"]),
    _r("AUD-044", "Service account key created", "gcp", "A", "IAM Changes", "SUSPICIOUS", "High", ["T1098.001"],
       LEAF("operation", "endswith", "CreateServiceAccountKey"), _STEPS_IAM,
       "Prefer workload identity / impersonation; delete the key and enforce iam.disableServiceAccountKeyCreation if not approved.",
       "A downloadable, long-lived key was created for a GCP service account."),
    _r("AUD-045", "Owner, editor or security admin role granted (GCP)", "gcp", "A", "Role Assignments", "RULE_VIOLATION", "Critical",
       ["T1098.003"],
       {"all": [LEAF("operation", "endswith", "SetIamPolicy"), LEAF("raw_text", "contains", '"action": "add"'),
                LEAF("raw_text", "contains_any", ['"role": "roles/owner"', '"role": "roles/editor"', '"role": "roles/iam.securityadmin"',
                                                   '"role": "roles/resourcemanager.organizationadmin"', '"role": "roles/iam.serviceaccountadmin"'])]},
       _STEPS_IAM, "Replace basic roles with predefined least-privilege roles; remove the binding if not approved.",
       "A basic (primitive) or IAM-administration role was added to a project, folder or organization IAM policy."),
    _r("AUD-046", "Access granted to a public or external identity (GCP)", "gcp", "A", "Role Assignments", "RULE_VIOLATION", "High",
       ["T1098"],
       {"all": [LEAF("operation", "endswith", "SetIamPolicy"), LEAF("raw_text", "contains", '"action": "add"'),
                LEAF("raw_text", "contains_any", ['"member": "allusers"', '"member": "allauthenticatedusers"', "@gmail.com", "@googlemail.com"])]},
       _STEPS_IAM, "Remove the binding; enforce the iam.allowedPolicyMemberDomains organization policy.",
       "An IAM binding was added for allUsers, allAuthenticatedUsers or a consumer Google account."),
    _r("AUD-047", "Service account impersonation granted", "gcp", "A", "Privilege Escalation", "SUSPICIOUS", "High", ["T1548", "T1098"],
       {"all": [LEAF("operation", "endswith", "SetIamPolicy"), LEAF("raw_text", "contains", '"action": "add"'),
                LEAF("raw_text", "contains_any", ["roles/iam.serviceaccounttokencreator", "roles/iam.serviceaccountuser",
                                                  "roles/iam.workloadidentityuser"])]},
       _STEPS_IAM, "Confirm the grantee needs to act as the service account; remove the binding otherwise.",
       "Someone was allowed to act as a service account and inherit all of its permissions."),
    # B. reconnaissance and discovery
    _r("AUD-048", "Permission probing: many denied list / describe calls", None, "B", "Authentication Failures", "SUSPICIOUS", "Medium",
       ["T1580", "T1526", "T1087.004"],
       {"all": [LEAF("result", "eq", "denied"), LEAF("operation", "regex", r"(?i)(^|[./])(list|describe|get|search)")]}, _STEPS_IAM,
       "If the identity is not misconfigured automation, rotate its credentials and review everything it accessed.",
       "20 or more denied discovery calls by one identity within 10 minutes: typical of stolen credentials being tested.",
       threshold=20, window=10),
    _r("AUD-049", "Large-scale resource enumeration by one identity", None, "B", "Administrative API Calls", "REVIEW_REQUIRED", "Low",
       ["T1580", "T1526", "T1619"],
       LEAF("operation", "regex", r"(?i)(^|[./])(list|describe)"), _STEPS_IAM,
       "Confirm the identity belongs to an inventory / security tool; otherwise investigate as reconnaissance.",
       "300 or more list / describe calls by one identity within 15 minutes. Requires AWS read events or GCP Data Access logs.",
       threshold=300, window=15, requires=["aws_read_events_or_gcp_data_access"]),
    _r("AUD-050", "Full IAM configuration downloaded", "aws", "B", "IAM Changes", "SUSPICIOUS", "Medium", ["T1069.003", "T1087.004"],
       OPS("GetAccountAuthorizationDetails", "GenerateCredentialReport", "GetCredentialReport"), _STEPS_IAM,
       "Confirm the caller is an approved audit tool; otherwise treat as reconnaissance of all users, roles and policies.",
       "One call returns every user, role and policy in the account. Requires AWS read events.", requires=["aws_read_events"]),
    # C. security configuration changes
    _r("AUD-051", "GuardDuty or Security Hub weakened", "aws", "C", "Security Policy Changes", "RULE_VIOLATION", "High", ["T1562.001"],
       OPS("DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount", "DisassociateFromAdministratorAccount", "DeleteMembers",
           "DisableSecurityHub", "BatchDisableStandards", "UpdateStandardsControl", "CreateFilter", "UpdateFilter", "DeleteInvitations"),
       _STEPS_CFG, "Re-enable the detector / standard, delete suppression filters that hide real findings, restrict these APIs with an SCP.",
       "Threat detection or posture checks were turned off, reduced or filtered."),
    _r("AUD-052", "AWS Config or VPC flow logs stopped", "aws", "C", "Security Policy Changes", "RULE_VIOLATION", "High", ["T1562.008"],
       OPS("StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel", "DeleteFlowLogs"), _STEPS_CFG,
       "Restart the recorder / flow logs and restrict these actions with an SCP.", "Configuration history or network logging was stopped."),
    _r("AUD-053", "GCP audit logging or log sink reduced", "gcp", "C", "Security Policy Changes", "RULE_VIOLATION", "High", ["T1562.008"],
       {"any": [{"all": [LEAF("operation", "endswith", "SetIamPolicy"), LEAF("raw_text", "contains", "auditconfigdeltas"),
                         LEAF("raw_text", "contains", '"action": "remove"')]},
                LEAF("operation", "contains_any", ["ConfigServiceV2.DeleteSink", "ConfigServiceV2.UpdateSink", "ConfigServiceV2.DeleteBucket",
                                                   "ConfigServiceV2.UpdateCmekSettings", "ConfigServiceV2.CreateExclusion",
                                                   "ConfigServiceV2.UpdateExclusion"])]},
       _STEPS_CFG, "Restore the audit configuration / sink and remove log exclusions that drop security logs.",
       "Data Access audit configuration removed, or a log sink / bucket / exclusion changed so that logs may be lost."),
    _r("AUD-054", "Security Command Center settings changed", "gcp", "C", "Security Policy Changes", "REVIEW_REQUIRED", "High", ["T1562.001"],
       LEAF("operation", "contains_any", ["SecurityCenter.UpdateOrganizationSettings", "SecurityCenter.UpdateSecurityHealthAnalyticsSettings",
                                          "SecurityCenter.SetFindingState", "SecurityCenter.UpdateMuteConfig", "SecurityCenter.CreateMuteConfig",
                                          "SecurityCenter.UpdateNotificationConfig", "SecurityCenter.DeleteNotificationConfig"]),
       _STEPS_CFG, "Confirm the change; delete mute rules that hide real findings.", "Detection, mute rules or notifications in SCC changed."),
    _r("AUD-055", "Default EBS encryption disabled", "aws", "C", "Encryption Configuration Changes", "RULE_VIOLATION", "High", ["T1562"],
       OPS("DisableEbsEncryptionByDefault"), _STEPS_CFG, "Re-enable EBS encryption by default in the region.",
       "New EBS volumes in this region will no longer be encrypted automatically."),
    _r("AUD-056", "Monitoring alarm or alert policy deleted", None, "C", "Security Policy Changes", "REVIEW_REQUIRED", "Medium", ["T1562.001"],
       {"any": [OPS("DeleteAlarms", "DisableAlarmActions"), LEAF("operation", "contains_any", ["AlertPolicyService.DeleteAlertPolicy",
                                                                                            "AlertPolicyService.UpdateAlertPolicy"])]},
       _STEPS_CFG, "Restore the alarm / alert policy.", "A CloudWatch alarm or Cloud Monitoring alert policy was removed or disabled."),
    # D. network and public exposure
    _r("AUD-057", "Security group opens management or database port to the internet", "aws", "D", "Security Group Changes",
       "RULE_VIOLATION", "Critical", ["T1133", "T1562.007"],
       {"all": [OPS("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"), LEAF("raw_text", "contains_any", WORLD),
                LEAF("raw_text", "regex", ADMIN_PORTS)]}, _STEPS_NET,
       "Remove the 0.0.0.0/0 or ::/0 rule; use Session Manager, a bastion or a VPN for administration.",
       "SSH, RDP, WinRM or a database port was opened to any IPv4 / IPv6 address."),
    _r("AUD-058", "Security group opened to the internet", "aws", "D", "Security Group Changes", "REVIEW_REQUIRED", "High", ["T1190"],
       {"all": [OPS("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"), LEAF("raw_text", "contains_any", WORLD),
                {"not": LEAF("raw_text", "regex", ADMIN_PORTS)}, {"not": LEAF("raw_text", "regex", r'(?i)"fromport": (80|443)\b')}]},
       _STEPS_NET, "Restrict the source range unless this is an approved public service.",
       "An inbound rule from any address was added on a port other than 80 / 443."),
    _r("AUD-059", "Network ACL allows all inbound traffic", "aws", "D", "Firewall Changes", "REVIEW_REQUIRED", "Medium", ["T1562.007"],
       {"all": [OPS("CreateNetworkAclEntry", "ReplaceNetworkAclEntry"), LEAF("raw.requestParameters.cidrBlock", "eq", "0.0.0.0/0"),
                LEAF("raw.requestParameters.ruleAction", "eq", "allow"), LEAF("raw.requestParameters.egress", "eq", "false")]},
       _STEPS_NET, "Restrict the ACL entry to required ports and ranges.", "A subnet-level allow-all inbound rule was added."),
    _r("AUD-060", "Public IP attached to a resource", None, "D", "Public IP Changes", "REVIEW_REQUIRED", "Medium", ["T1133"],
       {"any": [OPS("AssociateAddress"), LEAF("operation", "endswith", "compute.instances.addAccessConfig"),
                LEAF("operation", "contains", "microsoft.network/publicipaddresses/write")]},
       _STEPS_NET, "Confirm the resource must be reachable from the internet; remove the public IP otherwise.",
       "A public IP address was associated with an instance or created."),
    _r("AUD-061", "Network route or peering changed", None, "D", "Network Configuration Changes", "REVIEW_REQUIRED", "Medium", ["T1599"],
       {"any": [OPS("CreateVpcPeeringConnection", "AcceptVpcPeeringConnection", "CreateRoute", "ReplaceRoute", "CreateTransitGatewayVpcAttachment",
                    "AcceptTransitGatewayVpcAttachment"),
                LEAF("operation", "contains_any", ["compute.networks.addPeering", "compute.routes.insert", "virtualnetworkpeerings/write",
                                                   "routetables/routes/write"])]},
       _STEPS_NET, "Confirm the peer network / route target belongs to the organization.",
       "Traffic paths between networks changed; an unexpected peer can expose private networks."),
    _r("AUD-062", "Load balancer created as internet-facing", "aws", "D", "Network Configuration Changes", "REVIEW_REQUIRED", "Medium", ["T1190"],
       {"all": [OPS("CreateLoadBalancer"), LEAF("raw_text", "contains", '"scheme": "internet-facing"')]}, _STEPS_NET,
       "Confirm the endpoint is approved, protected by WAF and uses TLS.", "A new public endpoint was published."),
    # E. data security and exfiltration indicators
    _r("AUD-063", "Snapshot or image shared with another account", "aws", "E", "Database Changes", "SUSPICIOUS", "High", ["T1537"],
       {"all": [OPS("ModifySnapshotAttribute", "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute", "ModifyImageAttribute"),
                LEAF("raw_text", "contains_any", ["createvolumepermission", '"attributename": "restore"', "launchpermission"]),
                LEAF("raw_text", "contains_any", ['"add"', "valuestoadd", '"group": "all"'])]},
       _STEPS_DATA, "Remove the sharing permission and check whether the snapshot was copied by the other account.",
       "A disk, database snapshot or machine image was shared outside this account (or made public)."),
    _r("AUD-064", "Disk snapshot or image access granted (GCP)", "gcp", "E", "Database Changes", "SUSPICIOUS", "High", ["T1537"],
       LEAF("operation", "contains_any", ["compute.snapshots.setIamPolicy", "compute.images.setIamPolicy", "compute.disks.setIamPolicy"]),
       _STEPS_DATA, "Remove the binding unless the sharing is approved.", "Someone was given access to a disk snapshot, disk or image."),
    _r("AUD-065", "Database export started", None, "E", "Database Changes", "REVIEW_REQUIRED", "High", ["T1530", "T1537"],
       {"any": [OPS("StartExportTask", "CreateDBSnapshot", "ExportTableToPointInTime"),
                LEAF("operation", "contains_any", ["cloudsql.instances.export", "SqlInstancesService.Export",
                                                   "microsoft.sql/servers/databases/export/action", "bigquery.jobs.create.extract"])]},
       _STEPS_DATA, "Confirm the export destination and purpose with the data owner.", "Data was exported from a managed database."),
    _r("AUD-066", "Bucket replication or ownership changed", "aws", "E", "Storage Public Access Changes", "REVIEW_REQUIRED", "Medium", ["T1537"],
       OPS("PutBucketReplication", "PutBucketOwnershipControls", "PutBucketLogging"), _STEPS_DATA,
       "Confirm the replication destination belongs to the organization.", "Objects may be copied to another bucket or account."),
    _r("AUD-067", "Unusual volume of object downloads (GCP)", "gcp", "E", "Secret Access", "SUSPICIOUS", "High", ["T1530"],
       LEAF("operation", "eq", "storage.objects.get"), _STEPS_DATA,
       "Confirm the reader and purpose; revoke the identity's access if unexpected.",
       "500 or more object reads by one identity within 15 minutes. Requires GCP Data Access logs for Cloud Storage. "
       "AWS S3 object downloads are CloudTrail data events, which LookupEvents does not return; use an S3 data-event trail and SIEM.",
       threshold=500, window=15, requires=["gcp_data_access"]),
    _r("AUD-068", "Bulk object deletion (GCP)", "gcp", "E", "Resource Deletion", "SUSPICIOUS", "High", ["T1485"],
       LEAF("operation", "eq", "storage.objects.delete"), _STEPS_DATA,
       "Stop the identity, check object versioning / retention and restore deleted data.",
       "200 or more objects deleted by one identity within 15 minutes. Requires GCP Data Access logs.", threshold=200, window=15,
       requires=["gcp_data_access"]),
    _r("AUD-069", "Secrets or keys read by an identity from another account", "aws", "E", "Secret Access", "SUSPICIOUS", "High",
       ["T1555.006", "T1552"],
       {"all": [OPS("GetSecretValue", "Decrypt", "GetParameter", "GetParameters"), LEAF("raw.userIdentityType", "eq", "AWSAccount")]},
       _STEPS_DATA, "Confirm the cross-account consumer; restrict the secret / key policy.", "Requires AWS read events.",
       requires=["aws_read_events"]),
    _r("AUD-070", "Unusual KMS decrypt volume", "aws", "E", "Key Management Operations", "REVIEW_REQUIRED", "Medium", ["T1552"],
       OPS("Decrypt"), _STEPS_DATA, "Confirm the workload; investigate if the identity does not normally decrypt data.",
       "200 or more KMS Decrypt calls by one identity within 15 minutes. Requires AWS read events.", threshold=200, window=15,
       requires=["aws_read_events"]),
    # F. infrastructure and workload activity
    _r("AUD-071", "GPU or very large instance launched", None, "F", "VM Creation", "SUSPICIOUS", "High", ["T1496", "T1578.002"],
       {"all": [{"any": [OPS("RunInstances"), LEAF("operation", "endswith", "compute.instances.insert")]},
                LEAF("raw_text", "regex", r'(?i)"(instancetype|machinetype)":\s*"[^"]*(p3\.|p4d|p4de|p5|g4dn|g5\.|g6\.|trn1|inf2|x2iedn|u-\d|a2-|a3-|g2-|n1-ultramem|m3-)')]},
       _STEPS_CFG, "Confirm the workload and owner; stop the instance if it is not approved (cryptomining is the common abuse).",
       "Accelerated or memory-optimised compute was started; these types are expensive and commonly abused."),
    _r("AUD-072", "Burst of instance launches by one identity", None, "F", "VM Creation", "SUSPICIOUS", "High", ["T1496", "T1578.002"],
       {"any": [OPS("RunInstances", "CreateFleet", "RequestSpotInstances"), LEAF("operation", "endswith", "compute.instances.insert")]},
       _STEPS_CFG, "Confirm with the owner; stop unknown instances and rotate the identity's credentials.",
       "10 or more instance launches by one identity within 30 minutes.", threshold=10, window=30),
    _r("AUD-073", "Instance launched outside the approved regions", None, "F", "VM Creation", "REVIEW_REQUIRED", "Medium", ["T1535"],
       {"all": [{"any": [OPS("RunInstances", "CreateFleet"), LEAF("operation", "endswith", "compute.instances.insert")]},
                LEAF("region", "exists", True), LEAF("region", "not_in", APPROVED_REGIONS)]}, _STEPS_CFG,
       "Confirm the region is approved; terminate the instance and restrict regions with an SCP / organization policy otherwise.",
       "Edit this rule's region list to match the regions your organization has approved."),
    _r("AUD-074", "Container platform or workload deployed", None, "F", "VM Creation", "REVIEW_REQUIRED", "Low", ["T1610"],
       {"any": [OPS("CreateCluster", "RunTask", "CreateService", "RegisterTaskDefinition"),
                LEAF("operation", "contains_any", ["container.clusters.create", "ClusterManager.CreateCluster", "run.services.create",
                                                   "microsoft.containerservice/managedclusters/write", "microsoft.containerinstance/containergroups/write"])]},
       _STEPS_CFG, "Confirm the deployment came from the approved pipeline.", "A container cluster, service or task was created."),
    _r("AUD-075", "Instance startup script or user data changed", None, "F", "VM Configuration Changes", "SUSPICIOUS", "High", ["T1651"],
       {"any": [{"all": [OPS("ModifyInstanceAttribute"), LEAF("raw_text", "contains", "userdata")]},
                {"all": [LEAF("operation", "contains_any", ["compute.instances.setMetadata", "compute.projects.setCommonInstanceMetadata"]),
                         LEAF("raw_text", "contains_any", ["startup-script", "ssh-keys", "windows-startup-script"])]}]},
       _STEPS_CFG, "Review the new script / SSH keys; revert and investigate the instance if the change is unknown.",
       "Code that runs at boot, or project-wide SSH keys, changed."),
    _r("AUD-076", "Compute created or deleted outside business hours", None, "F", "VM Creation", "REVIEW_REQUIRED", "Low", ["T1578"],
       {"any": [OPS("RunInstances", "TerminateInstances"), LEAF("operation", "endswith", "compute.instances.insert"),
                LEAF("operation", "endswith", "compute.instances.delete"), LEAF("operation", "contains", "microsoft.compute/virtualmachines/delete")]},
       _STEPS_CFG, "Confirm against the change calendar.", "Fires only outside Mon-Fri 09:00-19:00 IST.",
       change_window={"days": [0, 1, 2, 3, 4], "start": "09:00", "end": "19:00", "tz": "Asia/Kolkata"}),
    # G. governance and compliance
    _r("AUD-077", "Organization guardrail (SCP / org policy) changed", None, "G", "Organization-Level Changes", "RULE_VIOLATION", "High",
       ["T1484"],
       {"any": [OPS("DetachPolicy", "DeletePolicy", "UpdatePolicy", "DisablePolicyType", "LeaveOrganization", "RemoveAccountFromOrganization"),
                LEAF("operation", "contains_any", ["SetOrgPolicy", "ClearOrgPolicy", "OrgPolicy.UpdatePolicy", "OrgPolicy.DeletePolicy",
                                                   "OrgPolicy.CreatePolicy"])]},
       _STEPS_CFG, "Confirm the change was approved by the cloud governance board; restore the previous policy otherwise.",
       "Service control policies or organization policies are the guardrails for every account / project."),
    _r("AUD-078", "Resource created outside the approved regions", None, "G", "Administrative API Calls", "REVIEW_REQUIRED", "Low", ["T1535"],
       {"all": [{"any": [LEAF("operation", "regex", r"^(Create|Run)[A-Z]"), LEAF("operation", "regex", r"\.(insert|create)$")]},
                LEAF("region", "exists", True), LEAF("region", "not_in", APPROVED_REGIONS)]}, _STEPS_CFG,
       "Move or delete the resource; restrict regions with an SCP / gcp.resourceLocations.",
       "Edit this rule's region list to match the regions your organization has approved."),
    _r("AUD-079", "Public endpoint for a database or cache created", None, "G", "Database Changes", "RULE_VIOLATION", "High", ["T1190"],
       {"any": [{"all": [OPS("CreateDBInstance", "ModifyDBInstance", "CreateDBCluster", "ModifyDBCluster"),
                         LEAF("raw_text", "contains", '"publiclyaccessible": true')]},
                {"all": [LEAF("operation", "contains_any", ["cloudsql.instances.create", "cloudsql.instances.update", "SqlInstancesService.Insert",
                                                            "SqlInstancesService.Patch", "SqlInstancesService.Update"]),
                         LEAF("raw_text", "contains", "0.0.0.0/0")]}]},
       _STEPS_NET, "Disable public accessibility and use private connectivity.", "A managed database was made reachable from the internet."),
]

for _rule in NEW_RULES:  # required metadata on every rule (explicit check: asserts are removed with python -O)
    if _rule["soc_category"] not in SOC_CATEGORIES or not all(m in MITRE for m in _rule["mitre"]):
        raise ValueError(f"SOC rule {_rule['rule_key']}: unknown category or MITRE technique")


def mitre_objects(ids: list[str]) -> list[dict]:
    return [{"id": i, "name": MITRE.get(i, ""), "url": f"https://attack.mitre.org/techniques/{i.replace('.', '/')}/"} for i in ids]


def apply_soc_library(db: Session) -> dict:
    """Additive and idempotent: create AUD-038+ when missing, and fill only EMPTY library fields on existing rules."""
    from app.models.vuln import DetectionRule, DetectionRuleHistory
    from app.services.vuln.defaults import rule_snapshot

    have = {r.rule_key: r for r in db.scalars(select(DetectionRule))}
    created = filled = 0
    for spec in NEW_RULES:
        if spec["rule_key"] in have:
            continue
        rule = DetectionRule(**{k: v for k, v in spec.items() if k not in ("mitre",)}, mitre=mitre_objects(spec["mitre"]),
                             exclusions=MANAGED_EXCLUSIONS, enabled=True, owner="security team", updated_by="system default",
                             notify=spec["severity"] in ("Critical", "High") and spec["action"] != "REVIEW_REQUIRED",
                             create_case=spec["action"] != "REVIEW_REQUIRED", match_count=0)
        db.add(rule)
        db.flush()
        db.add(DetectionRuleHistory(rule_id=rule.id, version=1, action="created", actor="system default", snapshot=rule_snapshot(rule)))
        created += 1
    for key, rule in have.items():
        cat, mitre, steps, fix = EXISTING_META.get(key, (_GENERIC.get(rule.category or "", "G"), _mitre_from(rule.description), _STEPS_CFG, None))
        changed = False
        for attr, value in (("soc_category", cat), ("mitre", mitre_objects(mitre) if mitre else None), ("investigation_steps", steps),
                            ("remediation", fix or "Revert the change if it was not approved and restrict who can make it."),
                            ("exclusions", MANAGED_EXCLUSIONS), ("data_requirements", [])):
            if getattr(rule, attr) in (None, "") and value is not None:
                setattr(rule, attr, value)
                changed = True
        filled += changed
    return {"created": created, "metadata_filled": filled}


def data_available(settings) -> dict[str, bool]:
    """Which optional collections are switched on (rules that need data that is not collected cannot fire)."""
    aws_read = bool(getattr(settings, "soc_aws_include_read_events", False))
    gcp_da = bool(getattr(settings, "soc_gcp_include_data_access", False))
    return {"aws_read_events": aws_read, "gcp_data_access": gcp_da, "aws_read_events_or_gcp_data_access": aws_read or gcp_da}


def rule_fields(conditions) -> tuple[list[str], list[str]]:
    """(event fields the rule reads, provider operation names it lists) - for the rule library page."""
    fields, ops = set(), []

    def walk(c):
        if not isinstance(c, dict):
            return
        for k in ("all", "any"):
            for x in c.get(k, []) or []:
                walk(x)
        if "not" in c:
            walk(c["not"])
        if "field" in c:
            fields.add(c["field"])
            if c["field"] == "operation" and c.get("op") in ("in", "eq", "contains_any", "contains", "endswith"):
                v = c.get("value")
                ops.extend(v if isinstance(v, list) else [v])
    walk(conditions)
    return sorted(fields | {"actor", "event_timestamp"}), list(dict.fromkeys(str(o) for o in ops))

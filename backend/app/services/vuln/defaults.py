"""Default SLA policies, notification rules and example audit detection rules. Seeded once; administrators change them
afterwards (existing rows are never overwritten)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DetectionRule, DetectionRuleHistory, NotificationRule, SecuritySlaPolicy

SLA_DEFAULTS = {"Critical": 24, "High": 7 * 24, "Medium": 30 * 24, "Low": 90 * 24}

NOTIFICATION_DEFAULTS = {
    "new_critical_finding": "New Critical finding: immediate notification",
    "new_high_finding": "New High finding: security team notification",
    "critical_unassigned": "Critical finding still unassigned: escalation",
    "finding_overdue": "Finding past its remediation SLA: owner reminder (Critical/High also escalated)",
    "finding_reappeared": "Previously resolved finding reappeared: reopen notification",
    "exception_pending": "Exception submitted: approver notification",
    "exception_expiring": "Exception nearing expiry: owner and approver notification",
    "exception_expired": "Exception expired: reassessment alert",
    "audit_rule_violation": "Audit rule violation (Critical / High): immediate alert",
    "audit_suspicious": "Suspicious audit activity (High / Critical): security analyst alert",
    "investigation_overdue": "Investigation open beyond its SLA: escalation",
    "sync_completed": "Daily security synchronization summary",
    "sync_failed": "Security synchronization failed or partially failed: integration administrator",
    "audit_anomaly": "Live audit anomaly (High / Critical): new country, failure spike, privilege change, mass deletion",
    "job_run_problem": "A scheduled collection run failed or only partly completed: platform administrator",
}

LEAF = lambda field, op, value: {"field": field, "op": op, "value": value}  # noqa: E731

DETECTION_DEFAULTS: list[dict] = [
    {"rule_key": "AUD-001", "name": "Owner / administrator permissions granted", "category": "Role Assignments", "action": "RULE_VIOLATION", "severity": "Critical",
     "description": "A role assignment or policy attachment grants Owner, Administrator or organization-level admin rights. Add the approved change "
                    "reference or an authorization rule for expected grants.",
     "conditions": {"any": [
         {"all": [LEAF("operation", "in", ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy"]),
                  LEAF("raw_text", "contains_any", ["AdministratorAccess", "\"*\""])]},
         {"all": [LEAF("operation", "contains", "roleAssignments/write"),
                  LEAF("raw_text", "contains_any", ["8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Owner", "User Access Administrator"])]},
         {"all": [LEAF("operation", "in", ["SetIamPolicy", "setIamPolicy"]), LEAF("raw_text", "contains_any", ["roles/owner", "roles/editor", "roles/resourcemanager.organizationAdmin"])]},
     ]}},
    {"rule_key": "AUD-002", "name": "AWS CloudTrail logging stopped or deleted", "provider": "aws", "category": "Security Policy Changes",
     "action": "RULE_VIOLATION", "severity": "Critical",
     "conditions": LEAF("operation", "in", ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"])},
    {"rule_key": "AUD-003", "name": "Azure NSG rule allowing inbound from any source to sensitive ports", "provider": "azure",
     "category": "Firewall Changes", "action": "RULE_VIOLATION", "severity": "High",
     "conditions": {"all": [LEAF("operation", "contains", "networkSecurityGroups"), LEAF("operation", "contains", "write"),
                            LEAF("raw_text", "contains_any", ["\"*\"", "0.0.0.0/0", "Internet", "Any"]),
                            LEAF("raw_text", "contains_any", ["\"22\"", "\"3389\"", "\"1433\"", "\"3306\"", "\"5432\""])]}},
    {"rule_key": "AUD-004", "name": "GCP firewall exposing SSH or RDP to the internet", "provider": "gcp", "category": "Firewall Changes",
     "action": "RULE_VIOLATION", "severity": "High",
     "conditions": {"all": [LEAF("operation", "contains_any", ["firewalls.insert", "firewalls.patch", "firewalls.update"]),
                            LEAF("raw_text", "contains", "0.0.0.0/0"), LEAF("raw_text", "contains_any", ["\"22\"", "\"3389\""])]}},
    {"rule_key": "AUD-005", "name": "Storage made publicly accessible", "category": "Storage Public Access Changes", "action": "RULE_VIOLATION", "severity": "High",
     "conditions": {"any": [
         {"all": [LEAF("operation", "in", ["PutBucketAcl", "PutBucketPolicy", "DeletePublicAccessBlock", "PutBucketPublicAccessBlock"]),
                  LEAF("raw_text", "contains_any", ["AllUsers", "\"Principal\":\"*\"", "\"Principal\": \"*\"", "BlockPublicAcls\":false"])]},
         {"all": [LEAF("operation", "contains", "storage.setIamPermissions"), LEAF("raw_text", "contains_any", ["allUsers", "allAuthenticatedUsers"])]},
         {"all": [LEAF("operation", "contains", "storageAccounts/write"), LEAF("raw_text", "contains_any", ["allowBlobPublicAccess\":true", "publicNetworkAccess\":\"Enabled"])]},
     ]}},
    {"rule_key": "AUD-006", "name": "Encryption or key management weakened", "category": "Key Management Operations", "action": "RULE_VIOLATION", "severity": "High",
     "conditions": LEAF("operation", "contains_any", ["DisableKey", "ScheduleKeyDeletion", "DeleteBucketEncryption", "PutKeyPolicy",
                                                      "CryptoKeyVersion.Destroy", "DestroyCryptoKeyVersion", "vaults/delete", "keys/delete"])},
    {"rule_key": "AUD-007", "name": "Security group or firewall changed outside the approved change window", "category": "Security Group Changes",
     "action": "REVIEW_REQUIRED", "severity": "Medium",
     "description": "Fires only outside Mon-Fri 09:00-19:00 IST. Adjust the window to your change calendar.",
     "change_window": {"days": [0, 1, 2, 3, 4], "start": "09:00", "end": "19:00", "tz": "Asia/Kolkata"},
     "conditions": LEAF("operation", "contains_any", ["AuthorizeSecurityGroup", "RevokeSecurityGroup", "ModifySecurityGroupRules",
                                                      "networkSecurityGroups/write", "securityRules/write", "firewalls."])},
    {"rule_key": "AUD-008", "name": "Root / break-glass account used", "provider": "aws", "category": "Privilege Escalation",
     "action": "SUSPICIOUS", "severity": "High",
     "conditions": {"all": [LEAF("raw_text", "contains", "\"Root\""), {"not": LEAF("operation", "in", ["ConsoleLogin"])}]}},
    {"rule_key": "AUD-009", "name": "Resource deletion burst by one actor", "category": "Resource Deletion", "action": "SUSPICIOUS", "severity": "High",
     "description": "10 or more delete operations by the same actor within 30 minutes.", "threshold_count": 10, "threshold_window_minutes": 30,
     "conditions": {"any": [LEAF("operation", "regex", r"(?i)^(Delete|Terminate|Remove)"), LEAF("operation", "regex", r"(?i)(/delete|\.delete)$")]}},
    {"rule_key": "AUD-010", "name": "Audit logging or security monitoring disabled", "category": "Security Policy Changes", "action": "RULE_VIOLATION",
     "severity": "Critical",
     "conditions": LEAF("operation", "contains_any", ["DeleteFlowLogs", "DisableSecurityHub", "DeleteDetector", "DisableOrganizationAdminAccount",
                                                      "diagnosticSettings/delete", "logProfiles/delete", "DeleteSink", "UpdateSink", "DeleteConfigRule",
                                                      "StopConfigurationRecorder"])},
    {"rule_key": "AUD-011", "name": "Repeated failed or denied calls by one actor", "category": "Authentication Failures", "action": "SUSPICIOUS",
     "severity": "Medium", "description": "5 or more denied calls by the same actor within 15 minutes.", "threshold_count": 5, "threshold_window_minutes": 15,
     "conditions": LEAF("result", "eq", "denied")},
]


# Standards-based SOC detections (MITRE ATT&CK for Cloud / Azure AD, CIS Microsoft Azure Foundations, Microsoft Sentinel
# analytics). Added to existing installations by key; rules already present (including edited ones) are never overwritten.
OP = lambda *names: LEAF("operation", "contains_any", list(names))  # noqa: E731
DETECTION_DEFAULTS += [
    {"rule_key": "AUD-012", "name": "Privileged Entra ID directory role granted", "provider": "azure", "category": "Privilege Escalation",
     "action": "RULE_VIOLATION", "severity": "Critical",
     "description": "MITRE T1098.003 (Additional Cloud Roles). Global / Privileged Role / Security / User / Application administrator assigned "
                    "(active or PIM-eligible). Confirm the approved access request.",
     "conditions": {"all": [OP("Add member to role", "Add eligible member to role", "Add member to role in PIM completed"),
                            LEAF("raw_text", "contains_any", ["Global Administrator", "Privileged Role Administrator", "Security Administrator",
                                                              "User Administrator", "Application Administrator", "Cloud Application Administrator",
                                                              "Privileged Authentication Administrator", "Exchange Administrator",
                                                              "Conditional Access Administrator", "Authentication Administrator"])]}},
    {"rule_key": "AUD-013", "name": "Credentials added to an application or service principal", "provider": "azure", "category": "IAM Changes",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1098.001 (Additional Cloud Credentials). New client secret or certificate: a common persistence technique.",
     "conditions": OP("Add service principal credentials", "Update application – Certificates and secrets management",
                      "Update application - Certificates and secrets management")},
    {"rule_key": "AUD-014", "name": "Consent or app role granted to an application", "provider": "azure", "category": "Permission Modifications",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1528 (Steal Application Access Token) / illicit consent grant. Review the permissions the app received.",
     "conditions": OP("Consent to application", "Add delegated permission grant", "Add app role assignment to service principal")},
    {"rule_key": "AUD-015", "name": "MFA or authentication methods removed", "provider": "azure", "category": "Security Policy Changes",
     "action": "RULE_VIOLATION", "severity": "High",
     "description": "MITRE T1556.006 (Modify Authentication Process: MFA). Strong authentication disabled or security info deleted / reset.",
     "conditions": OP("Disable Strong Authentication", "Admin deleted security info", "Reset user's security info", "Delete security info",
                      "Admin updated security info")},
    {"rule_key": "AUD-016", "name": "Conditional Access policy created, changed or deleted", "provider": "azure", "category": "Security Policy Changes",
     "action": "REVIEW_REQUIRED", "severity": "High",
     "description": "MITRE T1556 (Modify Authentication Process). CIS Azure 1.x. Confirm the change against the change record.",
     "conditions": OP("conditional access policy")},
    {"rule_key": "AUD-017", "name": "External (guest) user invited", "provider": "azure", "category": "User Creation",
     "action": "REVIEW_REQUIRED", "severity": "Medium",
     "description": "MITRE T1136.003 (Create Account: Cloud Account). CIS Azure 1.x: guest access should be approved.",
     "conditions": {"any": [OP("Invite external user", "Redeem external user invite"),
                            {"all": [LEAF("operation", "eq", "Add user"), LEAF("raw_text", "contains", "#EXT#")]}]}},
    {"rule_key": "AUD-018", "name": "Domain federation or authentication trust changed", "provider": "azure", "category": "Organization-Level Changes",
     "action": "RULE_VIOLATION", "severity": "Critical",
     "description": "MITRE T1484.002 (Domain Trust Modification). A changed federation trust can let an attacker sign in as any user.",
     "conditions": OP("Set domain authentication", "Set federation settings on domain", "Add unverified domain", "Verify domain",
                      "Update domain")},
    {"rule_key": "AUD-019", "name": "Repeated failed sign-ins for one account (brute force)", "provider": "azure", "category": "Authentication Failures",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1110.001 (Password Guessing). 10 or more failed Entra sign-ins for the same account within 15 minutes.",
     "threshold_count": 10, "threshold_window_minutes": 15,
     "conditions": {"all": [LEAF("operation", "eq", "Sign-in"), LEAF("result", "eq", "failure")]}},
    {"rule_key": "AUD-020", "name": "Failed sign-ins from one IP across accounts (password spray)", "provider": "azure",
     "category": "Authentication Failures", "action": "SUSPICIOUS", "severity": "High", "group_by": "source_ip",
     "description": "MITRE T1110.003 (Password Spraying). 20 or more failed sign-ins from the same IP address within 30 minutes.",
     "threshold_count": 20, "threshold_window_minutes": 30,
     "conditions": {"all": [LEAF("operation", "eq", "Sign-in"), LEAF("result", "eq", "failure")]}},
    {"rule_key": "AUD-021", "name": "Risky sign-in reported by Entra ID Protection", "provider": "azure", "category": "Authentication Failures",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1078.004 (Valid Accounts: Cloud Accounts). Entra rated the sign-in medium or high risk.",
     "conditions": {"all": [LEAF("operation", "eq", "Sign-in"), LEAF("raw.riskLevel", "in", ["medium", "high"])]}},
    {"rule_key": "AUD-022", "name": "Successful sign-in using legacy authentication", "provider": "azure", "category": "Authentication Failures",
     "action": "REVIEW_REQUIRED", "severity": "Medium",
     "description": "MITRE T1078. CIS Azure: block legacy authentication; these protocols bypass MFA.",
     "conditions": {"all": [LEAF("operation", "eq", "Sign-in"), LEAF("result", "eq", "success"),
                            LEAF("raw.clientApp", "contains_any", ["Exchange ActiveSync", "IMAP", "POP", "Authenticated SMTP", "Other clients",
                                                                   "MAPI", "Exchange Web Services", "AutoDiscover"])]}},
    {"rule_key": "AUD-023", "name": "Custom Azure role created or changed", "provider": "azure", "category": "Permission Modifications",
     "action": "REVIEW_REQUIRED", "severity": "High",
     "description": "MITRE T1098 (Account Manipulation). CIS Azure 1.x: custom subscription administrator roles should not exist.",
     "conditions": OP("microsoft.authorization/roledefinitions/write", "microsoft.authorization/roledefinitions/delete")},
    {"rule_key": "AUD-024", "name": "Global administrator elevated access to all subscriptions", "provider": "azure", "category": "Privilege Escalation",
     "action": "RULE_VIOLATION", "severity": "Critical",
     "description": "MITRE T1078.004. 'Access management for Azure resources' gives User Access Administrator at root scope.",
     "conditions": OP("microsoft.authorization/elevateaccess/action")},
    {"rule_key": "AUD-025", "name": "Resource lock removed", "provider": "azure", "category": "Security Policy Changes",
     "action": "REVIEW_REQUIRED", "severity": "High",
     "description": "MITRE T1485 (Data Destruction) precursor: delete locks protect critical resources.",
     "conditions": OP("microsoft.authorization/locks/delete")},
    {"rule_key": "AUD-026", "name": "Azure Policy assignment removed or exemption created", "provider": "azure", "category": "Security Policy Changes",
     "action": "RULE_VIOLATION", "severity": "High",
     "description": "MITRE T1562 (Impair Defenses). Governance guardrail weakened.",
     "conditions": OP("microsoft.authorization/policyassignments/delete", "microsoft.authorization/policyexemptions/write")},
    {"rule_key": "AUD-027", "name": "Defender for Cloud protection reduced", "provider": "azure", "category": "Security Policy Changes",
     "action": "RULE_VIOLATION", "severity": "High",
     "description": "MITRE T1562.001 (Disable or Modify Tools). Defender plan changed, security contacts or workspace settings removed.",
     "conditions": OP("microsoft.security/pricings/write", "microsoft.security/securitycontacts/delete", "microsoft.security/workspacesettings/delete",
                      "microsoft.security/autoprovisioningsettings/write")},
    {"rule_key": "AUD-028", "name": "Monitoring alert rule deleted or disabled", "provider": "azure", "category": "Security Policy Changes",
     "action": "RULE_VIOLATION", "severity": "High",
     "description": "MITRE T1562.008 (Disable Cloud Logs). Alert rules or action groups removed.",
     "conditions": OP("microsoft.insights/activitylogalerts/delete", "microsoft.insights/metricalerts/delete",
                      "microsoft.insights/scheduledqueryrules/delete", "microsoft.insights/actiongroups/delete",
                      "microsoft.alertsmanagement/actionrules/write")},
    {"rule_key": "AUD-029", "name": "Key Vault access policy changed or vault purged", "provider": "azure", "category": "Key Vault Operations",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1555.006 (Cloud Secrets Management Stores). Access to secrets changed, or deleted vault purged.",
     "conditions": OP("microsoft.keyvault/vaults/accesspolicies/write", "microsoft.keyvault/locations/deletedvaults/purge",
                      "microsoft.keyvault/vaults/purge")},
    {"rule_key": "AUD-030", "name": "Storage account keys listed or regenerated", "provider": "azure", "category": "Secret Access",
     "action": "REVIEW_REQUIRED", "severity": "Medium",
     "description": "MITRE T1552 (Unsecured Credentials). Account keys give full data access; 5 or more by one actor within 60 minutes.",
     "threshold_count": 5, "threshold_window_minutes": 60,
     "conditions": OP("microsoft.storage/storageaccounts/listkeys/action", "microsoft.storage/storageaccounts/regeneratekey/action",
                      "microsoft.storage/storageaccounts/listaccountsas/action")},
    {"rule_key": "AUD-031", "name": "Disk or snapshot exported (download link created)", "provider": "azure", "category": "Database Changes",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1537 (Transfer Data to Cloud Account). A SAS link to a disk / snapshot allows copying the whole disk.",
     "conditions": OP("microsoft.compute/disks/begingetaccess/action", "microsoft.compute/snapshots/begingetaccess/action")},
    {"rule_key": "AUD-032", "name": "Command executed on a VM (Run Command or extension)", "provider": "azure", "category": "VM Configuration Changes",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1651 (Cloud Administration Command). Code run on a VM through the control plane.",
     "conditions": OP("microsoft.compute/virtualmachines/runcommand/action", "microsoft.compute/virtualmachines/runcommands/write",
                      "microsoft.compute/virtualmachines/extensions/write")},
    {"rule_key": "AUD-033", "name": "Database firewall opened to all addresses", "provider": "azure", "category": "Firewall Changes",
     "action": "RULE_VIOLATION", "severity": "High",
     "description": "CIS Azure 4.x: SQL / PostgreSQL / MySQL servers must not allow 0.0.0.0-255.255.255.255.",
     "conditions": {"all": [OP("microsoft.sql/servers/firewallrules/write", "microsoft.dbforpostgresql/", "microsoft.dbformysql/"),
                            LEAF("operation", "contains", "firewallrules/write"), LEAF("raw_text", "contains", "255.255.255.255")]}},
    {"rule_key": "AUD-034", "name": "Subscription moved, renamed or cancelled", "provider": "azure", "category": "Subscription-Level Changes",
     "action": "RULE_VIOLATION", "severity": "High",
     "description": "MITRE T1484 (Domain or Tenant Policy Modification). Subscription left its management group or was cancelled.",
     "conditions": OP("microsoft.management/managementgroups/subscriptions/write", "microsoft.management/managementgroups/subscriptions/delete",
                      "microsoft.subscription/cancel/action", "microsoft.subscription/rename/action", "microsoft.subscription/aliases/write")},
    {"rule_key": "AUD-035", "name": "Role assignment changed outside business hours", "category": "Role Assignments",
     "action": "REVIEW_REQUIRED", "severity": "Medium",
     "description": "MITRE T1098. Fires only outside Mon-Fri 09:00-19:00 IST; adjust the window to your change calendar.",
     "change_window": {"days": [0, 1, 2, 3, 4], "start": "09:00", "end": "19:00", "tz": "Asia/Kolkata"},
     "conditions": OP("roleassignments/write", "roleassignments/delete", "Add member to role", "AttachUserPolicy", "AttachRolePolicy", "SetIamPolicy")},
    {"rule_key": "AUD-036", "name": "Many role assignments removed by one actor", "category": "Role Assignments",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1531 (Account Access Removal). 5 or more role assignments deleted by the same actor within 15 minutes.",
     "threshold_count": 5, "threshold_window_minutes": 15,
     "conditions": OP("microsoft.authorization/roleassignments/delete", "Remove member from role", "DetachUserPolicy", "DetachRolePolicy")},
    {"rule_key": "AUD-037", "name": "Many users deleted or disabled by one actor", "provider": "azure", "category": "User Deletion",
     "action": "SUSPICIOUS", "severity": "High",
     "description": "MITRE T1531 (Account Access Removal). 10 or more users deleted or disabled by the same actor within 30 minutes.",
     "threshold_count": 10, "threshold_window_minutes": 30,
     "conditions": OP("Delete user", "Disable account", "Hard delete user")},
]


def seed_security_defaults(db: Session) -> None:
    have = {p.severity for p in db.scalars(select(SecuritySlaPolicy))}
    for severity, hours in SLA_DEFAULTS.items():
        if severity not in have:
            db.add(SecuritySlaPolicy(severity=severity, target_hours=hours, pause_on_exception=True, updated_by="system default"))
    have = {r.event_type for r in db.scalars(select(NotificationRule))}
    for event_type, desc in NOTIFICATION_DEFAULTS.items():
        if event_type not in have:
            db.add(NotificationRule(event_type=event_type, description=desc, enabled=True, channels="email,google_chat", updated_by="system default"))
    have = {r.rule_key for r in db.scalars(select(DetectionRule))}
    for spec in DETECTION_DEFAULTS:
        if spec["rule_key"] in have:
            continue
        rule = DetectionRule(**{"provider": None, "description": None, "threshold_count": 1, "threshold_window_minutes": 0,
                                "notify": spec["severity"] in ("Critical", "High"), "create_case": spec["action"] != "REVIEW_REQUIRED",
                                "owner": "security team", "updated_by": "system default", **spec})
        db.add(rule)
        db.flush()
        db.add(DetectionRuleHistory(rule_id=rule.id, version=1, action="created", actor="system default", snapshot=rule_snapshot(rule)))
    db.flush()
    from app.services.audit.soc_library import apply_soc_library
    apply_soc_library(db)


def rule_snapshot(r: DetectionRule) -> dict:
    cols = ("rule_key", "name", "description", "provider", "category", "conditions", "action", "severity", "threshold_count",
            "threshold_window_minutes", "group_by", "change_window", "approved_change_reference", "create_case", "notify", "owner", "enabled",
            "soc_category", "mitre", "investigation_steps", "remediation", "exclusions", "data_requirements")
    return {c: getattr(r, c) for c in cols}

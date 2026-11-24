# Vulnerability management, cloud audit operations and daily security synchronization

This module adds three sections to LatentView CloudNexus: **Vulnerabilities**, **Cloud Audit** and **Integrations**.
All collection is read-only. Nothing in this module changes a cloud resource, and AI output is advisory only.

## 1. What is collected

| Cloud | Source | How | Scope |
|---|---|---|---|
| AWS | Security Hub CSPM (`GetFindings`) | Cross-region **aggregation region** of the administrator account when `AWS_SECURITYHUB_AGGREGATION_REGION` is set (one read covers linked regions and members), otherwise every enabled region of every eligible account through the existing read-only member role | FSBP, CIS, NIST and other enabled standards, AWS Config controls, integrated vulnerability detections, all severities |
| Azure | **Azure Advisor** recommendations | Per subscription (`Microsoft.Advisor/recommendations`), management groups through Azure Resource Graph | Category **Security** becomes findings. Cost, reliability (HighAvailability), performance and operational-excellence recommendations are stored with `is_security = false` and never counted as vulnerabilities |
| GCP | Security Command Center (`v1 …/sources/-/findings`) | Organization level when `GCP_ORGANIZATION_ID` is set and readable (covers folders and projects); otherwise each project | Whatever the enabled SCC tier produces: misconfiguration, vulnerability, threat, posture, IAM |
| All | CloudTrail, Azure Activity Log, GCP Cloud Audit Logs | Existing incremental collectors (`security_events`, every 5 minutes, 30-minute overlap) | Unchanged |

## 2. Daily synchronization (`security_findings_sync`)

* Runs at **02:00 UTC** every day (change it under Integrations › Schedule; the schedule is kept across restarts and upgrades).
* The first run of every account/region is a full listing; later runs are incremental from the stored watermark with a
  60-minute overlap, plus a full reconciliation every `SECURITY_SYNC_FULL_EVERY_DAYS` (Advisor is always a full listing).
* One run at a time: the database job lock is shared by scheduled, manual and retry runs (lock TTL 6 hours). A run that
  is interrupted is closed as FAILED (“Abandoned”) when the next run starts.
* Pagination, exponential back-off with jitter, `Retry-After` honoured, 429/5xx retried; permission, not-enabled,
  throttling and other errors are classified and recorded per account/subscription/project and region.
* A failing scope never stops the run, and a failed or denied call is **never** read as zero findings. Run status:
  COMPLETED, PARTIALLY_COMPLETED, FAILED (RUNNING / RETRYING while in progress).
* Retry (Integrations › Failed jobs) re-runs only the failing partitions.
* A summary is queued to email and Google Chat after every run; a separate alert when the run is not COMPLETED.

### Status preservation rules
Each finding keeps two independent states: **native state** (ACTIVE / RESOLVED / SUPPRESSED / NOT_APPLICABLE, from the
provider) and **internal workflow status** (OPEN, UNDER_REVIEW, EXCEPTION, RESOLVED, REOPENED, FALSE_POSITIVE).
A sync updates provider metadata only. It never changes owner, analyst, comments, evidence, exceptions, history or the
internal status, with one recorded exception: a finding marked RESOLVED that the provider reports active again (or still
observes more than 24 hours after resolution) is set to **REOPENED** and flagged for reassessment
(`SECURITY_REOPEN_ON_REAPPEAR`). Missing findings are never deleted; they are marked natively resolved only by the
provider’s own state (Security Hub ARCHIVED/RESOLVED/PASSED, SCC INACTIVE) or by a complete, successful Advisor listing.

## 3. Vulnerability management
* Workflow transitions are enforced by the API; RESOLVED, FALSE_POSITIVE and REOPENED need a reason; FALSE_POSITIVE needs
  an exception approver or security admin; EXCEPTION is entered only through an approved exception.
* Exceptions: request (justification ≥ 20 characters, risk acceptance, risk owner, validity ≤ `EXCEPTION_MAX_DAYS`) →
  PENDING_APPROVAL → ACTIVE or REJECTED → EXPIRED or CLOSED. The requester cannot approve their own request. Approval does
  not change the provider status. The SLA clock pauses only if the severity’s SLA policy says so. Expiry returns the
  finding to OPEN with “needs reassessment”; owners and approvers are notified before expiry.
* SLA defaults: Critical 24 h, High 7 days, Medium 30 days, Low 90 days, from first detection. Policy changes recompute
  due dates and are recorded in each finding’s history. An hourly job sends owner reminders, escalates overdue
  Critical/High and unassigned Critical findings (once per item per day).
* Evidence: links, ticket IDs, text, or files up to 10 MB stored in `EVIDENCE_DIR` named by SHA-256, always downloaded
  as attachments. History, comments, evidence and exception approvals are append-only (database triggers on MySQL,
  PostgreSQL and Azure SQL plus an application guard).

## 4. Cloud audit operations (rule engine)
Every collected audit event is evaluated by the `audit_rule_evaluation` job (every 5 minutes) and classified:

| Classification | Meaning | Investigation | Case | Alert |
|---|---|---|---|---|
| NORMAL | No rule matched | none | no | no |
| AUTHORIZED | Covered by an approved, scoped authorization rule | none | no | no |
| REVIEW_REQUIRED | A review rule matched | DETECTED (review queue) | no | no |
| SUSPICIOUS | A threshold / pattern rule fired | DETECTED | yes, per rule threshold | if the rule notifies (High/Critical) |
| RULE_VIOLATION | A violation rule matched | DETECTED | yes | if the rule notifies (High/Critical) |

* Investigation statuses: DETECTED, REVIEWING, INVESTIGATING, AUTHORIZED (needs `audit:authorize`, reason and approval
  reference; applies to that event only), ESCALATED (Cloud Security / Cloud Governance / CISO), NO_ACTION_REQUIRED and
  CLOSED (reason required), REOPENED. An analyst can flag an unflagged activity for review.
* Rules (Cloud Audit › Detection rules): conditions with all / any / not over operation, actor, source IP and CIDR,
  scope, region, resource, category, result, time, raw event fields and “first time this actor used this operation in
  30 days”; frequency thresholds with time windows grouped by actor, IP, resource or scope; approved change windows;
  severity, action, case and notification settings, owner, enabled. Every save creates a new version in the rule
  history; “Test” is a dry run against stored events. Eleven example rules are seeded and can be changed or disabled.
* Flagged events of the same rule and actor within `AUDIT_CASE_GROUP_HOURS` share one case. Flagged events of different
  rules by the same actor, IP or resource become a **PROPOSED** correlation case that an analyst must validate.
* Normal and authorized activity is never deleted and stays searchable and exportable.

## 5. Roles
| Role | Can |
|---|---|
| admin (super admin) | everything |
| security_admin | security rules, SLA, notifications, schedule, exception approval, investigations |
| cloud_admin | integrations, discovery, findings triage, synchronization (run / retry) |
| security_analyst | all findings, triage, request exceptions, investigate and authorize audit activity |
| cloud_engineer | only findings assigned to them: comments, evidence, verification requests |
| exception_approver | approve / reject exceptions (never their own) |
| auditor | read-only findings, audit, history; export reports |
Permissions are enforced by the API on every request; the UI hides what a role cannot use.

## 6. Cloud permissions (read-only)
* **AWS** — administrator / aggregation account: `securityhub:GetFindings`, `DescribeHub`, `ListMembers`,
  `ListFindingAggregators`, `GetFindingAggregator`; member accounts (per-account mode): the existing read-only role with Security Hub read
  (`securityhub:Get*`, `List*`, `Describe*`; check that your role's policy includes them); `organizations:ListAccounts`, `ec2:DescribeRegions`, `cloudtrail:LookupEvents`.
* **Azure** — Reader on each subscription (Advisor recommendations), `Microsoft.ResourceGraph/resources/read`,
  optional Management Group Reader at the tenant root for management-group names; Reader/Monitoring Reader for the
  Activity Log.
* **GCP** — `roles/securitycenter.findingsViewer` at the organization (or each project), `roles/browser` /
  `roles/resourcemanager.organizationViewer`, `roles/logging.viewer`; the Security Command Center API enabled.
No remediation permission is needed or used. Credentials stay where they were (certificate / secret in `.env`, SSO /
workload identity locally); the database stores identifiers only.

## 7. Reports
Vulnerabilities, Cloud Audit and Integrations pages export CSV, Excel and PDF (`/api/v1/security/reports/<name>`):
posture, AWS / Azure / GCP findings, Critical & High, open register, exception and expired-exception registers, SLA,
audit activity, authorized, suspicious, open and closed investigations, daily synchronization, integration health.
Standards are listed as the providers report them (for example CIS, FSBP, NIST in Security Hub); the platform does not
claim compliance beyond that provider mapping.

## 8. Deploy / upgrade
```
cd backend
pip install -r requirements.txt        # adds openpyxl and fpdf2
python -m alembic upgrade head         # migration 0003: 18 tables, append-only triggers
cd ../frontend && npm install && npm run build
```
Restart the API and the scheduler. Then in the UI: Integrations › Cloud integrations › **Sync now** (first run is a
full baseline). Check Integrations › Region coverage and Permissions for ACCESS DENIED or PARTIALLY CONFIGURED scopes.

## 9. Limitations
* Not yet validated against live AWS, Azure or GCP: collectors are tested against simulated API responses.
* Advisor recommendations carry no first-detected time and often no location; “locations” come from what Advisor reports.
* SCC incremental reads use `event_time`; findings that become INACTIVE without a new event are caught by the full
  reconciliation (default weekly; set `SECURITY_SYNC_FULL_EVERY_DAYS=1` for daily).
* Event-driven audit collection (EventBridge / Event Grid / Pub/Sub log sinks) is not built; audit logs are polled every
  5 minutes. Rule conditions cannot yet check the actor’s assigned IAM roles directly.
* Retention: findings, history and audit records are kept indefinitely; define a retention policy before production.
* No Redis or Celery: the existing database-backed scheduler and locks are used.

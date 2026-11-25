# Cloud Services & Asset Management – increment 1 (Modules 1, 2 and 7)

Status: implemented and tested in the sandbox (backend 401 passed / 1 skipped on SQLite, 400 passed / 2 skipped on
MariaDB 10.11; UI smoke 39/39 pages in light and dark). Live cloud collection is not yet verified – see "Validate on
your clouds" below. Increments 2 (resource-level access + expiry workflow) and 3 (daily Sheets governance log) follow.

## What was there and what was reused

| Existing | Reused for |
|---|---|
| `vm_inventory` + `vm_metrics` (job `vm_metrics`, every 15 min) | servers, power state, IPs, size; CPU / network averages for activity |
| `cloud_resources` (job `resource_inventory`) | all other cloud services (VMs are excluded there, so nothing is counted twice) |
| `audit_events` (SOC collection: CloudTrail, Activity Log, Cloud Audit Logs) | last management activity, last remote login, stop time – no extra cloud calls |
| `cost_detail_records` (resource breakdown) | estimated monthly cost per resource (last 30 days) |
| `access_assignments` | "who has access to this resource" on the asset page (direct vs inherited) |
| notification queue + rules + e-mail channel (Cc) | SPOC inactivity digests, de-duplicated per SPOC and period |
| central audit trail (`audit_trail`, hash chain) + append-only triggers | metadata changes, policy changes, imports, exports |
| RBAC (`require_any`, scoped users), Explorer categories and owner-tag logic | new `assets:*` permissions, project-owner scoping |

## New pieces

- **Tables (migration 0014, new tables only):** `asset_details` (collected), `asset_metadata` (business, never written by
  a sync), `asset_metadata_history` and `asset_inventory_changes` (append-only, triggers), `asset_activity_snapshots`
  (one row per asset per day), `asset_policy` (thresholds).
- **Jobs:** `asset_details_sync` (every 6 h, read-only) and `asset_activity_review` (daily 09:10): classification,
  daily snapshot, change tracking, SPOC digests. Catalogue now has 29 jobs.
- **API** `/api/v1/assets`: list (filters, KPIs, facets), `/kpis`, `/item`, `PUT /metadata`, `/export?format=csv|xlsx`,
  `POST /import` (dry run, then `apply`), `/import/template`, `GET|PUT /policy`.
- **UI:** new navigation section **Cloud Services Management** → *Asset inventory* (KPIs, filters, Excel/CSV export,
  import) and *Activity review* (needs-review list, thresholds); asset detail page with collected details, business
  metadata form, daily activity history, inventory changes, metadata change history and resource access.
- **Permissions:** `assets:read`, `assets:edit`, `assets:import`, `assets:configure`. Cloud Admin has all four;
  Governance Manager read + configure; Infra Operator and Project Owner read + edit (Project Owners only see their
  assigned scopes); other roles read. Inventory collection uses only the read-only cloud identities – the app has no
  permission-modification capability.

## Where each attribute comes from

| Attribute | AWS | Azure | GCP |
|---|---|---|---|
| IP address, server name, status, region, size | EC2 (vm_metrics) | Compute + Network | Compute Engine |
| Hostname | SSM ComputerName, else private DNS | VM agent computer name, else OS profile | custom hostname, else internal DNS name (flagged) |
| Guest OS | SSM PlatformName/Version (agent), else EC2 platform details (flagged) | VM agent instance view (Resource Graph), else image reference | boot-disk licence |
| CPUs, memory | DescribeInstanceTypes / CPU options | VM sizes | machine types |
| NIC, provisioned space | ENIs, DescribeVolumes | NICs, managed disks | NICs, attached disks |
| Used space | guest agent metrics only (CloudWatch / Azure Monitor / Ops Agent) – otherwise "Not collected" | | |
| Cloud-native backup | AWS Backup protected resources | Azure Backup protected items (Resource Graph) | snapshot schedules on the disks |
| Commvault backup | manual field (no Commvault integration yet) | | |
| Last activity | latest audit event on the resource | | |
| Last login | Session Manager / Instance Connect events | Entra ID VM login events | IAP / OS Login events – guest OS logins need log forwarding |
| Estimated monthly cost | resource-level cost records, last 30 days | | |

Every empty value carries the reason ("permission missing", "agent not reporting", …) – never a guess or zero.

## Activity classification (configurable under Activity review → Thresholds)

- **Terminated / Deleted:** reported deleted by the provider. **Stopped:** stopped / deallocated power state (duration
  from stop events or the daily history; never claimed when unknown).
- Running servers with at least 24 h of monitoring data in the 14-day window: **Inactive** when average CPU < 2 %,
  network < 50 MB/day and no management activity for 30 days; **Low Activity** when CPU < 10 %; otherwise **Active**.
- Not enough monitoring data → **Unknown** (never Inactive). Other services: **Active** when changed in the last 30 days,
  otherwise **Unknown** (no utilisation metric).
- Recommended actions are advice only. Nothing is stopped, deallocated or deleted by LV NEXUS.

## Deploy

1. Copy the files, then in `backend`: `pip install -r requirements.txt` (no new packages) and
   `python -m alembic upgrade head` → **0014**. Re-run `python -m app.database.triggers` if triggers could not be created.
2. Restart the API and the scheduler. The two new jobs appear in Administration → Automation.
3. **AWS:** update the member-role StackSet with the new `deploy/aws/cloudnexus-member-role.yaml` (adds the read-only
   policy `lvnexus-asset-details-read`: ec2:DescribeInstances / DescribeInstanceTypes / DescribeVolumes,
   ssm:DescribeInstanceInformation, backup:ListProtectedResources). Guest OS needs the SSM agent on the instance.
   **Azure:** no change (Reader covers Compute, Resource Graph and Recovery Services reads). **GCP:** no change
   (`roles/compute.viewer`).
4. Run `asset_details_sync` once, then `asset_activity_review` (Automation → Run now).
5. Fill business metadata: export the register to Excel, fill the light-blue columns, import (check → apply).

## Validate on your clouds (not done in the build environment)

For each cloud, after step 4: pick 2–3 known servers and compare hostname, OS, vCPU, memory, disks and backup with the
console; check that a server you know is idle is not shown as Active and that missing agents show "Not collected".
Pre-flight lists any permission failure per scope.

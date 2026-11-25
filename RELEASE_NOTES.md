# LV NEXUS Prod-V0.2 – release notes

**Version:** 0.2.0 · **Date:** 25-11-2026 · **Type:** production release (replaces Demo-V0.1)

LV NEXUS is LatentView's read-only multi-cloud governance, security operations and FinOps platform for AWS,
Microsoft Azure and Google Cloud.

## Changes since Demo-V0.1

- **Split into two packages.** Application code in `LV-NEXUS-PROD\Prod-V0.2`; container package (Dockerfiles, compose,
  nginx, MySQL, scripts and the build source) in `LV NEXUS CONATINER\Prod-V0.2`.
- **Demo mode removed.** No `DEMO_MODE` setting, no demo loader, no demo banner, no fictional data. The API no longer
  reports a `demo_mode` flag.
- **No sample or test data shipped.** The test suite and its fictional fixtures, UI test scripts and test-data screenshots
  are kept in the development copy only.
- **Cloud Services & Asset Management (enhancement increment 1, Modules 1, 2 and 7):**
  - one inventory of servers and services across AWS, Azure and GCP with collected details (hostname, guest OS and its
    source, CPUs, memory, NICs, provisioned storage, native backup status) – a field the provider did not return is shown
    as "Not collected", never guessed;
  - 19 manually maintained business fields (SPOC, reporting manager, department, owner, classification, CIA, PII,
    Commvault backup, planned end date, …) that automated synchronisation never overwrites, with append-only history;
  - activity classification (Active, Low Activity, Inactive, Stopped, Terminated / Deleted, Unknown) with configurable
    thresholds and advice-only recommendations – nothing is stopped or deleted automatically;
  - daily SPOC digest with the reporting manager in Cc; Excel / CSV export and a validated two-step import;
  - permissions `assets:read`, `assets:edit`, `assets:import`, `assets:configure`; every change in the audit trail;
  - AWS member-role template: new read-only inline policy `lvnexus-asset-details-read`.

## Database

Migrations 0001 → **0014** (0014 adds six asset-management tables; new tables only, existing data untouched).
48 append-only audit triggers.

## Known limitations

- Asset management is verified with automated tests only; it has not yet been run against live AWS / Azure / GCP.
- Frontend lint shows 152 advisory warnings (no errors); see CHECKS.md note A.
- Container images were not built in the release environment; build and scan them on your server or CI (container package CHECKS.md).
- MFA status and root / break-glass password rotation are not collected; reports say so.
- Increments 2 (resource-level access governance, expiry reminders, extension / revocation workflow) and 3 (daily
  Google Sheets governance log) are not in this release.

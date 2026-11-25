# Schedules (Asia/Kolkata)

The authoritative catalogue is `backend/app/database/seed.py` (`JOB_CATALOGUE`); the dashboard reads it from the
`automation_jobs` table. Only jobs marked implemented have a Cloud Run Job in Terraform.

| Job | Cron | Status |
|---|---|---|
| account_discovery | `*/15 * * * *` | implemented |
| resource_inventory, vm_metrics | `*/15 * * * *` | Phase 5 |
| security_events | `*/5 * * * *` | Phase 3 |
| billing_refresh | `0 * * * *` | Phase 4 |
| soc_daily_review / vm_daily_review / billing_daily_review / consolidated_daily_report | 07:00 / 07:30 / 08:00 / 08:30 | Phases 3-7 |
| weekly_reports | Monday 09:00 | Phase 7 |
| monthly_reports | 1st of month 09:00 | Phase 7 |

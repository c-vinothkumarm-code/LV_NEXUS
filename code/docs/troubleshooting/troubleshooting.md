# Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Discovery run `failed`: "No cloud provider is enabled" | All of `AWS_ENABLED`, `GCP_ENABLED`, `AZURE_ENABLED` are false | Enable a provider and set its prerequisites |
| Run `failed`/`partial`: "Provider not configured: missing ..." | A required setting is empty | Set the named variable |
| AWS scope `Access Failed` | Member role missing or trust/external ID mismatch | Complete the approval task: create the read-only role |
| GCP scope `Pending Access` | Service account lacks a listed permission on that project | Grant the read-only role named in the task |
| Azure permissions `unknown` | `AZURE_PRINCIPAL_OBJECT_ID` not set | Set the service principal object ID |
| Execution shows `skipped_overlap` | Previous run still holds the lock | Wait; locks expire after `DISCOVERY_LOCK_TTL_SECONDS` |
| Dashboard says "not collected" | That module's collector has never succeeded | See Automation Status for the job and reason |

## Resolved during the build

- `azure-mgmt-resource` 26 no longer ships `SubscriptionClient`; switched to `azure-mgmt-resource-subscriptions`.
- New inventory rows were treated as monitoring-disabled before first flush (column default not yet applied); the engine now sets `monitoring_enabled=True` explicitly. Covered by the workflow tests.
- Lock UPDATE compared naive and aware datetimes in the ORM session on SQLite; lock statements now skip session synchronisation.
- A failed first discovery was displayed as "collected"; collection state now distinguishes `failed` from `collected`.
- MySQL: sessions defaulted to REPEATABLE READ, so a long-lived session did not see rows committed by a job; engines now use READ COMMITTED.
- MySQL: creating triggers as a non-privileged user fails with error 1419 when binary logging is on; trigger creation moved to `python -m app.database.triggers`, with the fix documented, and the application-level guard always active.
- Timestamps: MySQL `DATETIME` drops the timezone; all timestamp columns now use `UTCDateTime`, which stores UTC and returns aware values on every database.
- Scheduler: a cron slot was detected one poll late because the previous-slot lookup excluded the exact minute; fixed and tested.
- Windows: `uvloop` is skipped on Windows and `tzdata` was added so `Asia/Kolkata` schedules resolve.

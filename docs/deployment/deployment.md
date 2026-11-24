# Deployment (not yet performed - requires explicit approval)

1. Choose the GCP management project; enable Cloud Run, Cloud Scheduler, Pub/Sub, Secret Manager, Artifact Registry, Cloud SQL.
2. Create Cloud SQL for PostgreSQL 16; store `DATABASE_URL` and a 32+ character `SECRET_KEY` in Secret Manager.
3. Build and push the image: `docker build -t REGION-docker.pkg.dev/PROJECT/mcp/control-plane:TAG .`
4. Review `infrastructure/terraform/main.tf` (draft), run `terraform plan`, get approval, then apply.
5. Put the service behind an HTTPS load balancer / IAP; set `FRONTEND_URL`, `CORS_ORIGINS`, the OAuth redirect
   URI `https://HOST/api/v1/auth/callback`, `ALLOWED_EMAIL_DOMAINS`, `BOOTSTRAP_ADMIN_EMAILS`.
6. Grant the control-plane service account its read-only roles (see README checklist); configure AWS and Azure trust.
7. Run `account_discovery` once manually and check Automation Status before enabling the schedule.

Event-driven discovery: create an organisation log sink for project-creation audit entries to topic
`mcp-scope-events`, add a push subscription with OIDC authentication to `/api/v1/events/pubsub`, and set
`PUBSUB_PUSH_AUDIENCE` / `PUBSUB_PUSH_SERVICE_ACCOUNT`.

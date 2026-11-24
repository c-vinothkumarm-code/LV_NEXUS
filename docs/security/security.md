# Security model

- **AWS**: default credential chain or web identity for the management account, then `sts:AssumeRole` into a
  read-only role per member account with an external ID. Application settings have no field for access keys.
- **GCP**: Application Default Credentials restricted to read-only OAuth scopes
  (`cloud-platform.read-only`, `cloud-billing.readonly`, `logging.read`).
- **Azure**: service principal (secret from Secret Manager, or workload identity federation) with Reader,
  Monitoring Reader, Cost Management Reader.
- **Secrets**: environment only; `.env` is git-ignored; log output and stored error text pass through a redaction filter.
- **Application**: Google OIDC sign-in with a domain allow-list, signed HttpOnly SameSite cookie, RBAC from the
  database, CSRF header on writes, security headers, admin actions in an append-only audit table, API docs disabled in production.
- **History**: `onboarding_records`, `security_reviews`, `admin_audit_logs` reject UPDATE/DELETE (ORM guard + PostgreSQL trigger).
- **Guard tests** (`backend/tests/security`): RBAC and session forgery, secrets never returned by the API,
  connectors contain no mutating SDK calls, no cloud IDs or keys in source.

Roles: `admin`, `soc_analyst`, `finops_analyst`, `infra_operator`, `viewer`. New users get `viewer`; addresses in
`BOOTSTRAP_ADMIN_EMAILS` get `admin`.

# Google Workspace sign-in and the access registry

The Command Center accepts only verified LatentView Google Workspace accounts, and only people an administrator has
authorized. A successful Google sign-in on its own grants nothing.

## How a sign-in is decided (all on the server)

1. **Request.** `/api/v1/auth/login` sends the browser to Google with Authorization Code + **PKCE (S256)**, a random
   **state** and **nonce** (kept in a signed, HttpOnly, 10-minute cookie), scopes `openid email profile`,
   `access_type=online` (no refresh token) and `hd=<domain>` (a hint for Google's account chooser only; not trusted).
2. **Callback.** The server checks the state, exchanges the code with the PKCE verifier and the client secret, and
   verifies the ID token: signature against Google's published keys, issuer, audience (our client ID), expiry,
   issued-at, subject and the **nonce** (a missing nonce fails). The Google access token is discarded.
3. **Corporate identity.** `email_verified` must be true; the verified **`hd` claim** must equal
   `GOOGLE_ALLOWED_DOMAIN`; and the e-mail must end in `@<domain>`. All three are required: a personal Google account
   registered with a corporate-looking address has no `hd` claim and is refused. Nothing the browser sends (for
   example an `email` query parameter) is used.
4. **Authorization.** The person must be in the access registry with status ACTIVE and an unexpired access date, or be
   in `BOOTSTRAP_ADMIN_EMAILS`, or (optional) be a member of a mapped Google group. On first sign-in the Google subject
   ID is bound to the registry entry; a later sign-in with a different subject for the same address (a deleted and
   re-created account) is refused.
5. **Session.** A new server-side session row is created and referenced by an HttpOnly, SameSite=Lax cookie (Secure in
   production). Any session presented by the same browser is ended first (session fixation protection).

### Messages people see

| Situation | Message |
|---|---|
| Not a LatentView Workspace account, or unverified e-mail | Access denied. This application is restricted to authorized LatentView corporate accounts. |
| Valid LatentView account, not in the registry | Your LatentView Google Workspace account has been successfully authenticated, but application access has not been provisioned. Please contact the platform administrator. |
| Suspended / revoked; access expired; identity changed | Specific messages asking the person to contact the administrator |
| Too many failures from one network | Throttled for the configured window |

The server redirects to `/login?error=<code>`; the page shows the server's own message for that code (no free text
from the URL is displayed).

## Sessions

- Lifetime `SESSION_TTL_MINUTES` (default 480); idle timeout `SESSION_IDLE_MINUTES` (60); renewals rotate the session
  ID and never extend beyond `SESSION_ABSOLUTE_MAX_MINUTES` (720) from the original sign-in. The dashboard renews
  automatically only while the person is active.
- **Logout** revokes the session row: a copied cookie stops working immediately.
- **Suspension, revocation or a role change** by an administrator ends all of that person's open sessions.
- State-changing requests require the `X-Requested-With: mcp-dashboard` header (CSRF protection).

## Access registry (Administration & Settings > Access registry)

For each person: e-mail, display name, Google identity bound (yes/no), role, status (ACTIVE / SUSPENDED / REVOKED),
authorized date, access expiry, last sign-in, created by, modified by, role source and open sessions. Administrators
provision people in advance (only addresses of the allowed domain), set expiry, suspend, revoke, reactivate and end
sessions. Every change is in the append-only administrative audit log; every sign-in attempt, denial (with reason),
logout and throttle is in the append-only sign-in activity log, with a 24-hour failure summary.

## Roles

Role names are stable identifiers stored in the database; the UI shows the business label.

| Label | Role name | Purpose |
|---|---|---|
| Super Admin | admin | Full platform administration |
| Cloud Admin | cloud_admin | Cloud integrations, inventory and operations |
| Security Admin | security_admin | Security rules, SLA, notifications, exceptions |
| Security Analyst | security_analyst | Security findings, investigations and remediation |
| FinOps Analyst | finops_analyst | Cost, budgets, forecasts and optimization (requests budgets; does not approve them) |
| Access Administrator | access_admin | Access requests, reviews, extensions and revocations (module in a later phase) |
| Governance Manager | governance_manager | Policies, approvals and compliance |
| Finance Approver | finance_approver | Financial approvals and budget revisions (module in a later phase) |
| Executive / CISO | executive | Executive dashboards and reports, read-only |
| Project Owner | project_owner | Only the accounts / subscriptions / projects an administrator assigns |
| Auditor | auditor | Read-only security, audit and governance records, exports |
| Viewer | viewer | Read-only dashboards |
| Exception Approver, Cloud Engineer, SOC Analyst, Infrastructure Operator | exception_approver, cloud_engineer, soc_analyst, infra_operator | Earlier operational roles, unchanged |

**Project Owner scope.** Administrators assign accounts, subscriptions or projects on the Access registry page (only
scopes present in the discovered inventory). The server then limits the scope list, security findings (plus findings
assigned to the person), virtual machines and resources, and global search to those scopes. A Project Owner with no
assignment sees nothing. Organisation-wide pages (Command Center, cost, SOC, audit) are not available to this role.

## Optional: Google group based roles

Set `GOOGLE_GROUP_LOOKUP_ENABLED=true`, `GOOGLE_WORKSPACE_ADMIN_GROUPS` (members become administrators) and/or
`GOOGLE_GROUP_ROLE_MAP` (`group@latentview.com=role,...`). At sign-in the backend reads the person's group memberships
(direct and nested) from the **Cloud Identity API** with its own Application Default Credentials; that identity needs
the Workspace **Groups Reader** admin role. If the lookup fails, no group role is granted (fail closed) and a person
whose access came from a group is refused until the lookup works; individually provisioned people are unaffected. An
administrator's explicit role change converts that person to the registry ("allowlist") source.

## Google Cloud / Workspace configuration

1. Google Cloud console > APIs & Services > **OAuth consent screen**: User type **Internal** (only your Workspace
   organisation can use it). Scopes: `openid`, `email`, `profile` only.
2. **Credentials > Create credentials > OAuth client ID > Web application.**
   - Authorized JavaScript origins: the application address (for example `https://command.latentview.com`; locally
     `http://localhost:5173`).
   - Authorized redirect URI: `<application address>/api/v1/auth/callback` (locally
     `http://localhost:5173/api/v1/auth/callback`). It must match `GOOGLE_REDIRECT_URI` (or FRONTEND_URL + path) exactly.
3. Put the client ID in `GOOGLE_CLIENT_ID` and the secret in `GOOGLE_CLIENT_SECRET` (Secret Manager in production;
   never commit it). Set `GOOGLE_ALLOWED_DOMAIN=latentview.com`, `AUTH_MODE=google`, a strong `SESSION_SECRET`
   (`python -c "import secrets; print(secrets.token_urlsafe(48))"`), and `BOOTSTRAP_ADMIN_EMAILS` for the first admin.
4. Optional group roles: enable the **Cloud Identity API**, grant the service account the **Groups Reader** admin role in
   the Workspace Admin console (Account > Admin roles), and set the group variables above.
5. Production: `APP_ENV=production` refuses to start unless FRONTEND_URL / GOOGLE_REDIRECT_URI use HTTPS and the session
   secret is strong; cookies are then marked Secure.

## Verification checklist

- [ ] Personal Gmail account: refused with the external-account message.
- [ ] LatentView account not in the registry: refused with the not-provisioned message.
- [ ] Provisioned account: signs in; role and expiry shown in Access registry; `google_sub` bound.
- [ ] Suspend that account while signed in: next request returns to the sign-in page.
- [ ] Sign out, then replay the old cookie: refused.
- [ ] Ten wrong attempts from one IP: throttled.
- [ ] Sign-in activity shows each attempt with reason.

Automated: `backend/tests/security/test_google_workspace_sso.py` (20 tests: PKCE, state, nonce, issuer, audience,
expiry, signature, `hd`, `email_verified`, look-alike domains, provisioning, suspension, expiry, identity binding,
logout revocation, admin revocation, fixation, rotation, idle timeout, throttling, group mapping fail-closed).

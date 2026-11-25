# LV NEXUS – production go-live runbook

Target: one hardened Linux server in the office network (Ubuntu 22.04/24.04 LTS or RHEL 9) running Docker Engine and
Compose v2. Everything LV NEXUS does towards AWS, Azure and Google Cloud is read-only.

```
users ──HTTPS 443──► proxy (nginx, TLS 1.2/1.3) ──► api (FastAPI + web app) ──► db (MySQL 8.4, internal network only)
                                                    scheduler (1 instance) ──► AWS / Azure / Google APIs, SMTP, Google Chat
```

| Item | What is in the repository |
|---|---|
| Image | `Dockerfile` (multi-stage, non-root uid 10001, no compilers, health check), `.dockerignore` (keeps `.env`, keys, venvs out of the image), `docker-entrypoint.sh` (roles: `api`, `scheduler`, `migrate`, `job <name>`, `validate <cloud>`) |
| Stack | `deploy/production/docker-compose.yml`: read-only root filesystems, `no-new-privileges`, all Linux capabilities dropped, memory/CPU limits, log rotation, internal database network |
| Proxy | `deploy/production/nginx/`: HTTPS only, HSTS, rate limits for sign-in and API, SSE support for Live audit, hidden-file blocking, no server version |
| Database | `deploy/production/mysql/conf.d/lvnexus.cnf`: utf8mb4, `local_infile=0`, durable binlog (7 days) |
| Operations | `deploy/production/scripts/`: `install.sh`, `deploy.sh` (backup → migrate → health gate → automatic rollback), `backup.sh` (AES-256 encrypted), `restore.sh`, `healthcheck.sh`; `systemd/` units (start on boot, nightly backup 01:30) |
| Settings | `deploy/production/lvnexus.env.example` (placeholders only) |

## 1. Server

| | Minimum | Recommended |
|---|---|---|
| CPU / RAM | 4 vCPU / 8 GB | 8 vCPU / 16 GB |
| Disk | 100 GB SSD, encrypted (LUKS / BitLocker-equivalent) | 200 GB + separate backup volume |
| Network | inbound 443 (and 80 for redirect) from the corporate network / VPN only; outbound 443 to `*.amazonaws.com`, `management.azure.com`, `graph.microsoft.com`, `login.microsoftonline.com`, `*.googleapis.com`, `oauth2.googleapis.com`, SMTP 587, `chat.googleapis.com` |
| DNS / TLS | a host name (e.g. `lvnexus.latentview.internal`) and a certificate for it from the corporate CA |

```bash
# as an administrator on the server
sudo apt-get update && sudo apt-get -y upgrade
# Docker Engine + Compose plugin: https://docs.docker.com/engine/install/ubuntu/
sudo ufw default deny incoming && sudo ufw allow from <corporate CIDR> to any port 443 proto tcp \
  && sudo ufw allow from <corporate CIDR> to any port 80 proto tcp && sudo ufw allow from <admin CIDR> to any port 22 proto tcp && sudo ufw enable
sudo git clone <LatentView repository URL> /opt/lvnexus && cd /opt/lvnexus/deploy/production
```

## 2. One-time setup

```bash
sudo ./scripts/install.sh lvnexus.latentview.internal
sudo cp /path/to/fullchain.pem certs/fullchain.pem && sudo cp /path/to/privkey.pem certs/privkey.pem
sudo ./scripts/install.sh lvnexus.latentview.internal      # re-run: validates the certificate, keeps every secret
sudo nano secrets/lvnexus.env                               # replace every <placeholder>
```

After adding or replacing files in `secrets/cloud`, re-run `install.sh` (it resets their owner to the container user).

`install.sh` generates the database passwords, the session secret and the backup key (in `secrets/`, mode 600) and never
overwrites them on later runs. **Copy `secrets/backup_key` into the company password vault** – backups cannot be
restored without it.

Cloud identities for the server (no long-lived keys):

| Cloud | Put in `secrets/cloud/` | Setting |
|---|---|---|
| Azure | certificate + private key of the Entra app (`azure-lvnexus.pem`) | `AZURE_CLIENT_CERTIFICATE_PATH`, leave `AZURE_CLIENT_SECRET` empty |
| AWS | `aws/aws_signing_helper` (download from AWS, verify its checksum, `chmod 755`), `aws/server.pem` + `aws/server.key` (certificate from the CA registered as Roles Anywhere trust anchor) and `aws/config` (below) | `AWS_PROFILE=cloudnexus-prod`, `AWS_EXTERNAL_ID` |
| GCP | Workload Identity Federation configuration file `gcp-lvnexus.json` | `GCP_CREDENTIALS_FILE` |

`secrets/cloud/aws/config` (ARNs from the outputs of `deploy/aws/cloudnexus-management-role.yaml`):

```ini
[profile cloudnexus-prod]
region = ap-south-1
credential_process = /run/secrets/cloud/aws/aws_signing_helper credential-process --certificate /run/secrets/cloud/aws/server.pem --private-key /run/secrets/cloud/aws/server.key --trust-anchor-arn <TrustAnchorArn> --profile-arn <ProfileArn> --role-arn <RoleArn>
```

Google sign-in: add `https://<host>/api/v1/auth/callback` as an authorised redirect URI of the OAuth client.

## 3. Deploy (and every upgrade)

```bash
cd /opt/lvnexus && sudo git pull && cd deploy/production
sudo ./scripts/deploy.sh 1.0.0
```

The script checks the settings and certificate, builds `lvnexus:1.0.0`, starts the database, takes an encrypted backup
(on upgrades), runs `migrate` (database migrations + reference data), starts `api`, `scheduler` and `proxy`, waits for
the HTTPS health check, and rolls the application back to the last good image if the check fails.

Using an image that your CI built and scanned instead: `sudo LVNEXUS_IMAGE=<registry>/lvnexus:1.0.0 ./scripts/deploy.sh 1.0.0`.
External / managed MySQL instead of the bundled one: `sudo BUNDLED_DB=false ./scripts/deploy.sh 1.0.0` with
`DATABASE_URL` pointing at it (TLS required).

## 4. Verify

```bash
sudo ./scripts/healthcheck.sh
sudo docker compose exec api docker-entrypoint.sh validate azure     # aws | gcp
sudo docker compose exec scheduler docker-entrypoint.sh job connection_health
```

Then sign in at `https://<host>` with a corporate account listed in `BOOTSTRAP_ADMIN_EMAILS` and open **System health**.

## 5. Operations

| Task | Command |
|---|---|
| Status / logs | `sudo docker compose ps` · `sudo docker compose logs -f --tail 100 api scheduler` |
| Run a job now | `sudo docker compose exec scheduler docker-entrypoint.sh job compliance_evaluation` |
| Backup now | `sudo ./scripts/backup.sh manual` (nightly by `lvnexus-backup.timer`; copy off-server with `BACKUP_OFFSITE_DIR`) |
| Restore | `sudo ./scripts/restore.sh backups/lvnexus-<time>-<label>.sql.gz.enc` (asks for confirmation) |
| Roll back the application | `sudo LVNEXUS_IMAGE=lvnexus:<previous> docker compose up -d api scheduler proxy` |
| Roll back a database migration | restore the pre-deploy backup taken by `deploy.sh` (migrations are not reversed automatically) |
| Renew the certificate | replace `certs/*.pem`, then `sudo docker compose restart proxy` |
| Rotate the session secret | change `SESSION_SECRET`, `sudo docker compose up -d api` (signs everyone out) |

## 6. Go-live checklist

- [ ] Server patched, disk encrypted, firewall limited to the corporate network, SSH key-only
- [ ] Certificate from the corporate CA, valid > 30 days, host name in DNS
- [ ] `secrets/lvnexus.env` complete; `APP_ENV=production`, `AUTH_MODE=google`; no `<placeholder>` left
- [ ] Azure certificate (no client secret), AWS Roles Anywhere, GCP federation; `validate` passes for each cloud
- [ ] `BOOTSTRAP_ADMIN_EMAILS` has at least two administrators (separation of duties)
- [ ] `backup_key` stored in the password vault; first backup taken and a test restore done on a non-production copy
- [ ] SAST (organisation SonarQube) and container image scan passed on the commit being deployed
- [ ] `healthcheck.sh` all green; sign-in and every module checked by the application owner

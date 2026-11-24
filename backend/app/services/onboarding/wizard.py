"""Guided cloud onboarding ("Onboard a cloud"), in the style of SIEM / CNAPP / observability tools.

For each cloud the wizard produces an onboarding kit filled in with the organisation's own identifiers: the access
templates and scripts a cloud administrator deploys once at the top level (AWS organization, Azure tenant root
management group, Google Cloud organization), the server credential configuration, and a live verification.

Security model
- LV NEXUS never creates identities, roles or permissions itself and never holds cloud administrator rights: a person
  deploys the kit through the normal change process. The wizard only generates text and reads the result back.
- No long-lived secrets: AWS IAM Roles Anywhere (X.509), an Entra app with a certificate credential, Google Workload
  Identity Federation (X.509). Private keys are created on the LV NEXUS server and never leave it.
- Read-only roles at the top level, so new accounts / subscriptions / projects are covered automatically.
- The AWS external ID is generated here (cryptographically random) and is shown only to connection managers.
- Verification calls the same read-only connector code the scheduled jobs use; a failure is reported as a failure,
  never as "0 findings" or as connected.
"""
from __future__ import annotations

import configparser
import json
import os
import re
import secrets
import shlex
import stat
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlencode

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import CloudConnection, utcnow
from app.services import connections

PROVIDERS = ("aws", "azure", "gcp")
TEMPLATES = Path(__file__).parent / "templates"
WIZARD_KEY = "_wizard"  # wizard-only identifiers inside CloudConnection.config (never credentials)
PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
SAMPLE_SCOPES = 3

# Paths inside the backend container (LV NEXUS CONATINER/secrets/cloud is mounted read-only at /run/secrets/cloud)
SERVER_DIR = "/run/secrets/cloud"
HOST_DIR = "secrets/cloud"  # the same folder on the server, relative to the LV NEXUS CONATINER folder

AZURE_ROLES = ("Reader", "Security Reader", "Monitoring Reader", "Cost Management Reader")
# well-known application ID of Microsoft Graph (a public constant, not a tenant or account ID)
GRAPH_APP_ID = "00000003-0000-0000-c000-" + "0" * 12
GRAPH_PERMISSIONS = ("User.Read.All", "Group.Read.All", "Application.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All")
GCP_ORG_ROLES = ("roles/browser", "roles/cloudasset.viewer", "roles/compute.viewer", "roles/logging.viewer", "roles/monitoring.viewer",
                 "roles/securitycenter.findingsViewer", "roles/iam.securityReviewer")
GCP_PROJECT_ROLES = ("roles/serviceusage.serviceUsageConsumer", "roles/bigquery.jobUser")

# wizard-only inputs: key -> (label, help, pattern, required)
INPUTS: dict[str, dict[str, tuple[str, str, str | None, bool]]] = {
    "aws": {
        "management_account_id": ("Management account ID", "12-digit ID of the AWS Organizations management account.", r"^\d{12}$", True),
        "root_ou_id": ("Organization root ID", "Root of the organization (r-xxxx), from AWS Organizations. The member role is deployed to every account under it, including new ones.",
                       r"^r-[0-9a-z]{4,32}$", True),
        "certificate_cn": ("Server certificate CN", "Common name of the LV NEXUS server certificate issued by your CA. Only this certificate can use the role.",
                           r"^[A-Za-z0-9.\-_]{3,64}$", True),
        "allowed_source_ips": ("Server egress IPs (optional)", "Public egress IP ranges of the LV NEXUS server, comma separated CIDR. When set, the roles only work from there.",
                               r"^\s*\d{1,3}(\.\d{1,3}){3}/\d{1,2}(\s*,\s*\d{1,3}(\.\d{1,3}){3}/\d{1,2})*\s*$", False),
        "trust_anchor_arn": ("Trust anchor ARN", "Output TrustAnchorArn of the management stack (step 2).", r"^arn:aws:rolesanywhere:[a-z0-9-]+:\d{12}:trust-anchor/[0-9a-f-]{36}$", False),
        "profile_arn": ("Profile ARN", "Output ProfileArn of the management stack (step 2).", r"^arn:aws:rolesanywhere:[a-z0-9-]+:\d{12}:profile/[0-9a-f-]{36}$", False),
        "role_arn": ("Management role ARN", "Output RoleArn of the management stack (step 2).", r"^arn:aws:iam::\d{12}:role/[\w+=,.@\-/]{1,128}$", False),
    },
    "azure": {
        "app_name": ("App registration name", "Name of the Entra app registration LV NEXUS signs in as.", r"^[\w .\-]{3,64}$", False),
    },
    "gcp": {
        "host_project_id": ("Host project ID", "Project that holds the LV NEXUS service account and the workload identity pool (e.g. a security tooling project).",
                            r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$", True),
        "host_project_number": ("Host project number", "Numeric project number of the host project.", r"^\d{6,20}$", True),
        "billing_account_id": ("Billing account ID (optional)", "XXXXXX-XXXXXX-XXXXXX, for billing data.", r"^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", False),
        "certificate_cn": ("Server certificate CN", "Common name of the LV NEXUS server certificate issued by your CA.", r"^[A-Za-z0-9.\-_]{3,64}$", True),
    },
}
DEFAULTS = {"azure": {"app_name": "LV NEXUS Reader"}, "aws": {"certificate_cn": "lvnexus-server"}, "gcp": {"certificate_cn": "lvnexus-server"}}

FILES: dict[str, dict[str, str]] = {  # file name -> label, per provider
    "aws": {"cloudnexus-management-role.yaml": "Management account template (Roles Anywhere + read-only role)",
            "cloudnexus-member-role.yaml": "Member account template (StackSet, every account)",
            "aws-onboarding.sh": "AWS CLI script for the cloud administrator",
            "aws-server-certificate.sh": "Server script: key and certificate request",
            "aws-config": "Server credential configuration (secrets/cloud/aws/config)"},
    "azure": {"azure-server-certificate.sh": "Server script: key pair and public certificate",
              "azure-onboarding.sh": "Azure CLI script for the cloud administrator"},
    "gcp": {"gcp-server-certificate.sh": "Server script: key and certificate request",
            "gcp-onboarding.sh": "gcloud script for the cloud administrator"},
}


class WizardError(ValueError):
    """Invalid wizard input; the message is safe to show."""


# ---------------------------------------------------------------- state

def _conn(db: Session, provider: str, create: bool = False) -> CloudConnection | None:
    conn = db.scalar(select(CloudConnection).where(CloudConnection.provider == provider))
    if conn is None and create:
        conn = CloudConnection(provider=provider, enabled=False, config={})
        db.add(conn)
        db.flush()
    return conn


def _wizard(conn: CloudConnection | None) -> dict:
    return dict((conn.config or {}).get(WIZARD_KEY) or {}) if conn else {}


def _store_wizard(conn: CloudConnection, data: dict) -> None:
    cfg = dict(conn.config or {})
    cfg[WIZARD_KEY] = data
    conn.config = cfg  # new dict so the JSON column is marked changed


def inputs_for(provider: str, conn: CloudConnection | None) -> dict:
    return {**DEFAULTS.get(provider, {}), **(_wizard(conn).get("inputs") or {})}


def clean_inputs(provider: str, raw: dict) -> dict:
    spec = INPUTS[provider]
    unknown = set(raw) - set(spec)
    if unknown:
        raise WizardError(f"Unknown field: {', '.join(sorted(unknown))}")
    out = {}
    for key, (label, _help, pattern, _req) in spec.items():
        value = str(raw.get(key) or "").strip()
        if not value:
            continue
        if pattern and not re.match(pattern, value):
            raise WizardError(f"{label}: the value is not in the expected format")
        out[key] = value
    return out


def save_inputs(db: Session, provider: str, config: dict, wizard_inputs: dict, actor: str) -> CloudConnection:
    """Saves the connection identifiers (same rules as Cloud connections) and the wizard-only identifiers.
    The connection keeps its enabled state: it is only switched on by activate() after a passing verification."""
    inputs = clean_inputs(provider, wizard_inputs)
    conn = _conn(db, provider)
    enabled = bool(conn.enabled) if conn else False
    wizard = _wizard(conn)
    conn = connections.save(db, provider, enabled, config, keep_sensitive=True, actor=actor)
    wizard["inputs"] = {**(wizard.get("inputs") or {}), **inputs}
    for key in set(INPUTS[provider]) - set(inputs):  # a field cleared in the form is removed
        wizard["inputs"].pop(key, None)
    _store_wizard(conn, wizard)
    return conn


def ensure_external_id(db: Session, settings: Settings, actor: str, rotate: bool = False) -> tuple[str, bool]:
    """Returns (external id, newly generated). An external ID already in use (from the environment or saved earlier) is
    kept, so working member roles are not broken; rotate=True replaces it (the StackSet must then be updated)."""
    eff = connections.effective_settings(db, settings)
    if eff.aws_external_id and not rotate:
        return eff.aws_external_id, False
    value = secrets.token_urlsafe(32)
    conn = _conn(db, "aws", create=True)
    cfg = dict(conn.config or {})
    cfg["aws_external_id"] = value
    conn.config, conn.updated_by = cfg, actor
    return value, True


# ---------------------------------------------------------------- kit

def _q(value: str | None, placeholder: str) -> str:
    return shlex.quote(value) if value else placeholder


def _cmd(label: str, text: str) -> dict:
    return {"label": label, "text": text}


def kit(db: Session, provider: str, settings: Settings, can_manage: bool) -> dict:
    if provider not in PROVIDERS:
        raise WizardError("Unknown cloud provider")
    conn = _conn(db, provider)
    eff = connections.effective_settings(db, settings)
    inp = inputs_for(provider, conn)
    build = {"aws": _aws_kit, "azure": _azure_kit, "gcp": _gcp_kit}[provider]
    data = build(eff, inp, settings, can_manage)
    wiz = _wizard(conn)
    data.update({
        "provider": provider,
        "connection": next(p for p in connections.describe(db, settings) if p["provider"] == provider),
        "inputs": [{"key": k, "label": lab, "help": h, "required": req, "value": inp.get(k, "")} for k, (lab, h, _p, req) in INPUTS[provider].items()],
        "files": [{"name": n, "label": lab} for n, lab in FILES[provider].items()],
        "last_verify": wiz.get("last_verify"),
        "activated_at": wiz.get("activated_at"),
        "can_manage": can_manage,
    })
    return data


def _aws_kit(eff: Settings, inp: dict, settings: Settings, can_manage: bool) -> dict:
    region = eff.aws_default_region or "us-east-1"
    ext = eff.aws_external_id
    ext_shown = ext if can_manage else None
    role = eff.aws_member_role_name or "CloudNexusReadOnly"
    console = f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}"
    links = [{"label": "CloudFormation: create stack (upload the management template)", "url": f"{console}#/stacks/create"},
             {"label": "CloudFormation: create StackSet (upload the member template)", "url": f"{console}#/stacksets/create"},
             {"label": "AWS Organizations: find the root ID", "url": "https://console.aws.amazon.com/organizations/v2/home/accounts"}]
    base = (settings.onboarding_aws_template_base_url or "").rstrip("/")
    if not re.match(r"^https://[a-z0-9.\-]+\.amazonaws\.com(/[\w.\-/]*)?$", base):
        base = ""  # CloudFormation quick-create only accepts templates hosted in S3
    if base:
        params = {"templateURL": f"{base}/cloudnexus-management-role.yaml", "stackName": "CloudNexusManagement",
                  "param_CertificateCommonName": inp.get("certificate_cn", ""), "param_MemberRoleName": role}
        if inp.get("allowed_source_ips"):
            params["param_AllowedSourceIps"] = inp["allowed_source_ips"]
        links.insert(0, {"label": "Launch the management stack (quick create)", "url": f"{console}#/stacks/quickcreate?{urlencode(params, quote_via=quote)}"})
    ready = bool(inp.get("trust_anchor_arn") and inp.get("profile_arn") and inp.get("role_arn"))
    return {
        "title": "Amazon Web Services",
        "summary": "IAM Roles Anywhere gives the LV NEXUS server 1-hour credentials from its X.509 certificate (no access keys). "
                   "A StackSet with automatic deployment puts the read-only member role in every account, including accounts created later.",
        "secret_notice": None if can_manage else "The external ID and the full scripts are shown to connection managers only.",
        "external_id": {"value": ext_shown, "is_set": bool(ext)},
        "steps": [
            {"id": "certificate", "who": "LV NEXUS server administrator", "title": "Create the server key and certificate request",
             "body": "Run on the LV NEXUS server, in the LV NEXUS CONATINER folder. The private key is created there and never leaves the server. "
                     "Send the request (.csr) to your certificate authority and save the issued certificate as secrets/cloud/aws/server.pem. "
                     "Keep the CA certificate (PEM) for the next step.",
             "files": ["aws-server-certificate.sh"]},
            {"id": "management", "who": "AWS administrator (management account)", "title": "Deploy the management stack once",
             "body": "Creates the Roles Anywhere trust anchor (your CA), the read-only role CloudNexusManagementReader and the Roles Anywhere profile. "
                     "Read-only with explicit denies on data content and secrets. Copy the three outputs into this page.",
             "files": ["cloudnexus-management-role.yaml", "aws-onboarding.sh"], "links": links[: 2 if base else 1]},
            {"id": "members", "who": "AWS administrator (management account)", "title": "Deploy the member role to every account",
             "body": f"A service-managed StackSet targets the organization root with automatic deployment, so the read-only role {role} is created "
                     "in every current and future account. Its trust is limited to the management role, the external ID and, optionally, the server IP.",
             "files": ["cloudnexus-member-role.yaml", "aws-onboarding.sh"], "links": [x for x in links if "StackSet" in x["label"] or "Organizations" in x["label"]]},
            {"id": "server", "who": "LV NEXUS server administrator", "title": "Install the server credential configuration",
             "body": "Download aws-config into secrets/cloud/aws/config, put aws_signing_helper (from AWS, checksum verified) next to it, "
                     "and set in secrets/lvnexus.env: AWS_ENABLED=true, AWS_CONFIG_FILE=/run/secrets/cloud/aws/config, AWS_PROFILE=cloudnexus-prod. "
                     "Re-run scripts/setup.sh (file ownership) and restart the backend and scheduler.",
             "files": ["aws-config"], "ready": ready},
        ],
    }


def _azure_kit(eff: Settings, inp: dict, settings: Settings, can_manage: bool) -> dict:
    tenant = eff.azure_tenant_id
    links = [{"label": "Entra admin center: App registrations", "url": "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"}]
    if tenant and eff.azure_client_id:
        links.append({"label": "Grant admin consent (Microsoft Graph read permissions)",
                      "url": f"https://login.microsoftonline.com/{quote(tenant)}/adminconsent?client_id={quote(eff.azure_client_id)}"})
    return {
        "title": "Microsoft Azure",
        "summary": "An Entra app registration signs in with a certificate whose private key stays on the LV NEXUS server (no client secret). "
                   "Read-only roles on the tenant root management group are inherited by every current and future subscription.",
        "secret_notice": None,
        "external_id": None,
        "steps": [
            {"id": "certificate", "who": "LV NEXUS server administrator", "title": "Create the key pair on the server",
             "body": "Run on the LV NEXUS server. Writes secrets/cloud/azure-lvnexus.pem (private key + certificate, readable by the backend only) "
                     "and lvnexus-azure.crt, the public certificate to give to the Azure administrator.",
             "files": ["azure-server-certificate.sh"]},
            {"id": "app", "who": "Azure / Entra administrator", "title": "Create the app, assign read-only roles at the root",
             "body": "Creates (or reuses) the app registration, adds the public certificate, assigns " + ", ".join(AZURE_ROLES) +
                     " on the tenant root management group, and requests the read-only Microsoft Graph application permissions " + ", ".join(GRAPH_PERMISSIONS) +
                     ". Assigning at the root needs User Access Administrator there (elevate access in Entra, then remove it again).",
             "files": ["azure-onboarding.sh"], "links": links[:1]},
            {"id": "consent", "who": "Global Administrator / Privileged Role Administrator", "title": "Grant admin consent",
             "body": "Consent to the Microsoft Graph read permissions. Enter the application (client) ID and principal object ID printed by the script "
                     "on this page first; the consent link then appears here.", "links": links[1:]},
            {"id": "server", "who": "LV NEXUS server administrator", "title": "Point the server at the certificate",
             "body": "In secrets/lvnexus.env: AZURE_ENABLED=true, AZURE_CLIENT_CERTIFICATE_PATH=/run/secrets/cloud/azure-lvnexus.pem and leave "
                     "AZURE_CLIENT_SECRET empty. Restart the backend and scheduler. Optional: a Conditional Access policy for workload identities "
                     "that allows this app only from the server's IP (Entra Workload ID licence).", "files": []},
        ],
    }


def _gcp_kit(eff: Settings, inp: dict, settings: Settings, can_manage: bool) -> dict:
    return {
        "title": "Google Cloud",
        "summary": "Workload Identity Federation with the server's X.509 certificate lets LV NEXUS act as a read-only service account "
                   "without any service-account key. Roles bound on the organization are inherited by every current and future project.",
        "secret_notice": None,
        "external_id": None,
        "steps": [
            {"id": "certificate", "who": "LV NEXUS server administrator", "title": "Create the server key and certificate request",
             "body": "Run on the LV NEXUS server. Send the .csr to your certificate authority; save the issued certificate as secrets/cloud/gcp/server.pem "
                     "and the CA chain as secrets/cloud/gcp/ca-chain.pem.", "files": ["gcp-server-certificate.sh"]},
            {"id": "org", "who": "Google Cloud organization administrator", "title": "Create the reader account, bind roles, set up federation",
             "body": "Creates the service account lvnexus-reader in the host project, binds " + ", ".join(GCP_ORG_ROLES) +
                     " on the organization, creates the workload identity pool with an X.509 provider trusting your CA, allows only the server "
                     "certificate's CN to act as the reader, and writes the credential configuration gcp-lvnexus.json (contains no key). "
                     "Recommended: organization policy iam.disableServiceAccountKeyCreation.", "files": ["gcp-onboarding.sh"],
             "links": [{"label": "Google Cloud console: Workload Identity Federation", "url": "https://console.cloud.google.com/iam-admin/workload-identity-pools"}]},
            {"id": "server", "who": "LV NEXUS server administrator", "title": "Install the credential configuration",
             "body": "Copy gcp-lvnexus.json into secrets/cloud/. In secrets/lvnexus.env: GCP_ENABLED=true, GCP_ORGANIZATION_ID, "
                     "GCP_CREDENTIALS_FILE=/run/secrets/cloud/gcp-lvnexus.json. Re-run scripts/setup.sh and restart the backend and scheduler.", "files": []},
        ],
    }


# ---------------------------------------------------------------- files

def render_file(db: Session, provider: str, name: str, settings: Settings) -> str:
    if provider not in PROVIDERS or name not in FILES[provider]:
        raise WizardError("Unknown file")
    conn = _conn(db, provider)
    eff = connections.effective_settings(db, settings)
    inp = inputs_for(provider, conn)
    if name.endswith(".yaml"):
        return (TEMPLATES / provider / name).read_text(encoding="utf-8")
    return _RENDER[name](eff, inp)


def _header(title: str) -> str:
    return (f"#!/usr/bin/env bash\n# LV NEXUS onboarding: {title}\n# Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC. Review before running. "
            "Read-only access only; nothing here grants write access.\nset -Eeuo pipefail\n")


def _csr_script(cloud: str, cn: str, folder: str) -> str:
    return _header(f"{cloud} server key and certificate request (run on the LV NEXUS server, in the LV NEXUS CONATINER folder)") + f"""
DIR={folder}
CN={shlex.quote(cn)}
umask 077
mkdir -p "$DIR"
if [[ -s "$DIR/server.key" ]]; then echo "$DIR/server.key exists: keeping it"; else
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/server.key"
fi
openssl req -new -key "$DIR/server.key" -subj "/CN=$CN" -out "$DIR/server.csr"
chown 10001:10001 "$DIR/server.key" 2>/dev/null || true
chmod 600 "$DIR/server.key"
echo "Send $DIR/server.csr to your certificate authority (client authentication certificate, CN=$CN)."
echo "Save the issued certificate as $DIR/server.pem. The private key stays on this server."
"""


def _aws_csr(eff: Settings, inp: dict) -> str:
    return _csr_script("AWS", inp.get("certificate_cn") or "lvnexus-server", f"{HOST_DIR}/aws")


def _gcp_csr(eff: Settings, inp: dict) -> str:
    return _csr_script("Google Cloud", inp.get("certificate_cn") or "lvnexus-server", f"{HOST_DIR}/gcp")


def _aws_script(eff: Settings, inp: dict) -> str:
    region = eff.aws_default_region or "us-east-1"
    role = eff.aws_member_role_name or "CloudNexusReadOnly"
    ips = (inp.get("allowed_source_ips") or "").replace(" ", "")
    ip_param = f" AllowedSourceIps={shlex.quote(ips)}" if ips else ""
    ip_param_set = f" ParameterKey=AllowedSourceIps,ParameterValue={shlex.quote(ips.replace(',', chr(92) + ','))}" if ips else ""
    return _header("AWS (run with administrator credentials for the ORGANIZATIONS MANAGEMENT ACCOUNT, e.g. in CloudShell)") + f"""
REGION={shlex.quote(region)}
MANAGEMENT_ACCOUNT_ID={_q(inp.get('management_account_id'), '<12-digit management account id>')}
ROOT_OU_ID={_q(inp.get('root_ou_id'), '<r-xxxx>')}
CERT_CN={_q(inp.get('certificate_cn'), '<server certificate CN>')}
MEMBER_ROLE={shlex.quote(role)}
EXTERNAL_ID={_q(eff.aws_external_id, '<external id from LV NEXUS>')}
CA_PEM_FILE=ca.pem      # certificate of the CA that signed the LV NEXUS server certificate

# 1. management account: Roles Anywhere trust anchor + read-only role + profile
aws cloudformation deploy --region "$REGION" --stack-name CloudNexusManagement \\
  --template-file cloudnexus-management-role.yaml --capabilities CAPABILITY_NAMED_IAM \\
  --parameter-overrides CACertificatePem="$(cat "$CA_PEM_FILE")" CertificateCommonName="$CERT_CN" MemberRoleName="$MEMBER_ROLE"{ip_param}
aws cloudformation describe-stacks --region "$REGION" --stack-name CloudNexusManagement \\
  --query "Stacks[0].Outputs[].[OutputKey,OutputValue]" --output table
echo ">> Enter TrustAnchorArn, ProfileArn and RoleArn in LV NEXUS (Onboard a cloud > AWS)."

# 2. every member account, now and in future: service-managed StackSet with automatic deployment
#    (needs trusted access for CloudFormation StackSets in AWS Organizations, enabled once in the console)
if ! aws cloudformation describe-stack-set --region "$REGION" --stack-set-name CloudNexusReadOnly >/dev/null 2>&1; then
  aws cloudformation create-stack-set --region "$REGION" --stack-set-name CloudNexusReadOnly \\
    --template-body file://cloudnexus-member-role.yaml --capabilities CAPABILITY_NAMED_IAM \\
    --permission-model SERVICE_MANAGED --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \\
    --parameters ParameterKey=ManagementAccountId,ParameterValue="$MANAGEMENT_ACCOUNT_ID" \\
                 ParameterKey=ExternalId,ParameterValue="$EXTERNAL_ID" ParameterKey=RoleName,ParameterValue="$MEMBER_ROLE"{ip_param_set}
fi
aws cloudformation create-stack-instances --region "$REGION" --stack-set-name CloudNexusReadOnly \\
  --deployment-targets OrganizationalUnitIds="$ROOT_OU_ID" --regions "$REGION" \\
  --operation-preferences FailureTolerancePercentage=10,MaxConcurrentPercentage=25
echo ">> StackSet deployment started. The management account itself is covered by the management role."
echo ">> New accounts in the organization receive the role automatically."
"""


def _aws_config(eff: Settings, inp: dict) -> str:
    region = eff.aws_default_region or "us-east-1"
    d = f"{SERVER_DIR}/aws"
    return (f"# LV NEXUS server: AWS credential configuration (IAM Roles Anywhere). Save as {HOST_DIR}/aws/config\n"
            "# Temporary credentials (1 hour) come from the server certificate; there is no access key anywhere.\n"
            "[profile cloudnexus-prod]\n"
            f"region = {region}\n"
            f"credential_process = {d}/aws_signing_helper credential-process --certificate {d}/server.pem --private-key {d}/server.key "
            f"--trust-anchor-arn {inp.get('trust_anchor_arn') or '<TrustAnchorArn>'} --profile-arn {inp.get('profile_arn') or '<ProfileArn>'} "
            f"--role-arn {inp.get('role_arn') or '<RoleArn>'}\n")


def _azure_cert(eff: Settings, inp: dict) -> str:
    return _header("Azure server key pair (run on the LV NEXUS server, in the LV NEXUS CONATINER folder)") + f"""
DIR={HOST_DIR}
umask 077
mkdir -p "$DIR"
if [[ -s "$DIR/azure-lvnexus.pem" ]]; then
  echo "$DIR/azure-lvnexus.pem exists: keeping it (delete it first to rotate)"
else
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 -subj "/CN=lvnexus-azure" \\
    -keyout "$DIR/azure.key.tmp" -out lvnexus-azure.crt
  cat "$DIR/azure.key.tmp" lvnexus-azure.crt > "$DIR/azure-lvnexus.pem" && rm -f "$DIR/azure.key.tmp"
fi
chown 10001:10001 "$DIR/azure-lvnexus.pem" 2>/dev/null || true
chmod 600 "$DIR/azure-lvnexus.pem"
openssl x509 -in "$DIR/azure-lvnexus.pem" -out lvnexus-azure.crt
openssl x509 -in lvnexus-azure.crt -noout -subject -enddate -fingerprint -sha256
echo "Give lvnexus-azure.crt (PUBLIC certificate only) to the Azure administrator. Rotate before it expires (365 days)."
"""


def _azure_script(eff: Settings, inp: dict) -> str:
    roles = " ".join(shlex.quote(r) for r in AZURE_ROLES)
    graph = " ".join(GRAPH_PERMISSIONS)
    return _header("Azure / Entra ID (run as an Entra administrator with Azure CLI, e.g. in Cloud Shell)") + f"""
TENANT_ID={_q(eff.azure_tenant_id, '<tenant id>')}
APP_NAME={shlex.quote(inp.get('app_name') or 'LV NEXUS Reader')}
CERT_FILE=lvnexus-azure.crt          # public certificate from the LV NEXUS server (azure-server-certificate.sh)
GRAPH={GRAPH_APP_ID}
ROOT_SCOPE="/providers/Microsoft.Management/managementGroups/$TENANT_ID"   # tenant root management group

az account show --query tenantId -o tsv | grep -qx "$TENANT_ID" || az login --tenant "$TENANT_ID"

# 1. app registration (reused if it exists) with the server certificate; no client secret is created
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
[[ -n "$APP_ID" ]] || APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad app credential reset --id "$APP_ID" --cert "@$CERT_FILE" --append --display-name lvnexus-server >/dev/null
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || az ad sp create --id "$APP_ID" --query id -o tsv)

# 2. read-only Azure roles on the tenant root management group: inherited by every current and future subscription
for ROLE in {roles}; do
  if [[ -z "$(az role assignment list --assignee "$SP_ID" --role "$ROLE" --scope "$ROOT_SCOPE" --query "[0].id" -o tsv)" ]]; then
    az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal --role "$ROLE" --scope "$ROOT_SCOPE" >/dev/null
  fi
  echo "role ok: $ROLE"
done

# 3. read-only Microsoft Graph application permissions (IDs looked up by name)
for PERM in {graph}; do
  ID=$(az ad sp show --id "$GRAPH" --query "appRoles[?value=='$PERM'].id | [0]" -o tsv)
  az ad app permission add --id "$APP_ID" --api "$GRAPH" --api-permissions "$ID=Role" 2>/dev/null || true
  echo "graph permission requested: $PERM"
done

echo
echo ">> Enter in LV NEXUS (Onboard a cloud > Azure):"
echo "   Application (client) ID: $APP_ID"
echo "   Principal object ID:     $SP_ID"
echo ">> Then grant admin consent: https://login.microsoftonline.com/$TENANT_ID/adminconsent?client_id=$APP_ID"
"""


def _gcp_script(eff: Settings, inp: dict) -> str:
    org_roles = " ".join(GCP_ORG_ROLES)
    proj_roles = " ".join(GCP_PROJECT_ROLES)
    billing = inp.get("billing_account_id")
    billing_block = (f'gcloud billing accounts add-iam-policy-binding {shlex.quote(billing)} --member "serviceAccount:$SA" --role roles/billing.viewer >/dev/null\n'
                     'echo "billing viewer ok"\n') if billing else "# billing account ID not given: add roles/billing.viewer on the billing account later for billing data\n"
    bq_project = (eff.gcp_billing_query_project or "").strip()
    bq_block = (f'gcloud projects add-iam-policy-binding {shlex.quote(bq_project)} --member "serviceAccount:$SA" --role roles/bigquery.jobUser --condition=None >/dev/null\n'
                if bq_project else "")
    return _header("Google Cloud (run as an organization administrator with gcloud, e.g. in Cloud Shell)") + f"""
ORG_ID={_q(eff.gcp_organization_id, '<organization id>')}
HOST_PROJECT={_q(inp.get('host_project_id'), '<host project id>')}
HOST_PROJECT_NUMBER={_q(inp.get('host_project_number'), '<host project number>')}
CERT_CN={_q(inp.get('certificate_cn'), '<server certificate CN>')}
CA_PEM_FILE=ca.pem                   # certificate of the CA that signed the LV NEXUS server certificate
POOL=lvnexus-pool
PROVIDER=lvnexus-x509
SA_NAME=lvnexus-reader
SA="$SA_NAME@$HOST_PROJECT.iam.gserviceaccount.com"

# 1. read-only service account (no key is ever created for it)
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com cloudresourcemanager.googleapis.com \\
  cloudasset.googleapis.com --project "$HOST_PROJECT"
gcloud iam service-accounts describe "$SA" --project "$HOST_PROJECT" >/dev/null 2>&1 || \\
  gcloud iam service-accounts create "$SA_NAME" --project "$HOST_PROJECT" --display-name "LV NEXUS reader (read-only)"

# 2. read-only roles on the organization: inherited by every current and future project
for ROLE in {org_roles}; do
  gcloud organizations add-iam-policy-binding "$ORG_ID" --member "serviceAccount:$SA" --role "$ROLE" --condition=None >/dev/null
  echo "org role ok: $ROLE"
done
for ROLE in {proj_roles}; do
  gcloud projects add-iam-policy-binding "$HOST_PROJECT" --member "serviceAccount:$SA" --role "$ROLE" --condition=None >/dev/null
done
{bq_block}{billing_block}
# 3. Workload Identity Federation: X.509 provider trusting your CA; only the server certificate CN may act as the reader
python3 - "$CA_PEM_FILE" > trust-store.yaml <<'PY'
import json, sys
pem = open(sys.argv[1]).read().strip()
print("trustStore:\\n  trustAnchors:\\n  - pemCertificate: " + json.dumps(pem))
PY
gcloud iam workload-identity-pools describe "$POOL" --project "$HOST_PROJECT" --location global >/dev/null 2>&1 || \\
  gcloud iam workload-identity-pools create "$POOL" --project "$HOST_PROJECT" --location global --display-name "LV NEXUS"
gcloud iam workload-identity-pools providers describe "$PROVIDER" --project "$HOST_PROJECT" --location global --workload-identity-pool "$POOL" >/dev/null 2>&1 || \\
  gcloud iam workload-identity-pools providers create-x509 "$PROVIDER" --project "$HOST_PROJECT" --location global \\
    --workload-identity-pool "$POOL" --trust-store-config-path trust-store.yaml \\
    --attribute-mapping "google.subject=assertion.subject.dn.cn" --attribute-condition "assertion.subject.dn.cn == '$CERT_CN'"
gcloud iam service-accounts add-iam-policy-binding "$SA" --project "$HOST_PROJECT" --role roles/iam.workloadIdentityUser \\
  --member "principal://iam.googleapis.com/projects/$HOST_PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/subject/$CERT_CN" >/dev/null

# 4. credential configuration for the server (paths inside the LV NEXUS backend container; contains no key)
gcloud iam workload-identity-pools create-cred-config \\
  "//iam.googleapis.com/projects/$HOST_PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER" \\
  --service-account "$SA" --credential-cert-path {SERVER_DIR}/gcp/server.pem \\
  --credential-cert-private-key-path {SERVER_DIR}/gcp/server.key \\
  --credential-cert-trust-chain-path {SERVER_DIR}/gcp/ca-chain.pem \\
  --credential-cert-configuration-output-file {SERVER_DIR}/gcp/certificate_config.json \\
  --output-file gcp-lvnexus.json
echo ">> Copy gcp-lvnexus.json to the LV NEXUS server: {HOST_DIR}/gcp-lvnexus.json"
echo ">> Recommended: enforce the organization policy constraints/iam.disableServiceAccountKeyCreation."
"""


_RENDER = {"aws-onboarding.sh": _aws_script, "aws-config": _aws_config, "aws-server-certificate.sh": _aws_csr,
           "azure-server-certificate.sh": _azure_cert, "azure-onboarding.sh": _azure_script,
           "gcp-server-certificate.sh": _gcp_csr, "gcp-onboarding.sh": _gcp_script}


# ---------------------------------------------------------------- verification

def _step(key: str, title: str, status: str, detail: str, fix: str | None = None) -> dict:
    return {"key": key, "title": title, "status": status, "detail": detail, "fix": fix if status != PASS else None}


def _file_check(path: str | None, what: str, secret: bool = False) -> tuple[str, str, str | None]:
    """Presence and protection of a credential file. Never reads secret content beyond what a check needs."""
    if not path:
        return FAIL, f"{what}: path not set", "Set the path in secrets/lvnexus.env and restart the backend."
    p = Path(path)
    if not p.is_file():
        return FAIL, f"{what} not found on the server", f"Place the file at {path} (folder {HOST_DIR} on the server) and re-run scripts/setup.sh."
    if not os.access(p, os.R_OK):
        return FAIL, f"{what} is not readable by the backend", "Re-run scripts/setup.sh to set the owner (uid 10001)."
    if secret and os.name == "nt":  # Windows: no POSIX mode bits, access comes from the folder's NTFS permissions
        return PASS, f"{what} present (Windows: keep it in a folder only the service account can read – NTFS permissions)", None
    mode = stat.S_IMODE(p.stat().st_mode)
    if secret and mode & 0o077:
        return WARN, f"{what} is readable by other users on the server (mode {oct(mode)})", "chmod 600 the file (scripts/setup.sh does this)."
    return PASS, f"{what} present and protected", None


def _cert_days(path: str) -> int | None:
    from cryptography import x509
    data = Path(path).read_bytes()
    start = data.find(b"-----BEGIN CERTIFICATE-----")
    if start < 0:
        return None
    cert = x509.load_pem_x509_certificate(data[start:])
    return (cert.not_valid_after_utc - datetime.now(UTC)).days


def _credential_checks(provider: str, eff: Settings) -> list[dict]:
    production = eff.app_env == "production"
    out: list[dict] = []
    if provider == "aws":
        cfg_path = os.environ.get("AWS_CONFIG_FILE")
        profile = eff.aws_profile
        if not cfg_path or not profile:
            st = FAIL if production else WARN
            out.append(_step("credential", "Server credential (Roles Anywhere)", st,
                             "No Roles Anywhere configuration: the backend uses the local CLI sign-in (development only).",
                             "Install the aws-config file and set AWS_CONFIG_FILE and AWS_PROFILE=cloudnexus-prod."))
            return out
        st, detail, fix = _file_check(cfg_path, "AWS config file")
        if st == FAIL:
            return [_step("credential", "Server credential (Roles Anywhere)", st, detail, fix)]
        parser = configparser.RawConfigParser()
        parser.read(cfg_path, encoding="utf-8")
        section = f"profile {profile}" if parser.has_section(f"profile {profile}") else profile
        proc = parser.get(section, "credential_process", fallback="") if parser.has_section(section) else ""
        if "aws_signing_helper" not in proc:
            out.append(_step("credential", "Server credential (Roles Anywhere)", FAIL if production else WARN,
                             f"Profile {profile} has no Roles Anywhere credential_process.", "Use the aws-config file generated by this wizard."))
            return out
        parts = shlex.split(proc)
        args = {parts[i]: parts[i + 1] for i in range(len(parts) - 1) if parts[i].startswith("--")}
        checks = [_file_check(parts[0], "aws_signing_helper"), _file_check(args.get("--certificate"), "Server certificate"),
                  _file_check(args.get("--private-key"), "Server private key", secret=True)]
        if parts and Path(parts[0]).is_file() and not os.access(parts[0], os.X_OK):
            checks.append((FAIL, "aws_signing_helper is not executable", "chmod 755 secrets/cloud/aws/aws_signing_helper"))
        if any("<" in args.get(k, "<") for k in ("--trust-anchor-arn", "--profile-arn", "--role-arn")):
            checks.append((FAIL, "The ARNs in the config file are still placeholders", "Enter the three stack outputs in step 4 and download aws-config again."))
        worst = FAIL if any(c[0] == FAIL for c in checks) else WARN if any(c[0] == WARN for c in checks) else PASS
        detail = "; ".join(c[1] for c in checks)
        fix = next((c[2] for c in checks if c[0] != PASS), None)
        cert = args.get("--certificate")
        if worst != FAIL and cert:
            days = _cert_days(cert)
            if days is not None and days < 30:
                worst = FAIL if days < 0 else WARN
                detail += f"; server certificate {'expired' if days < 0 else f'expires in {days} days'}"
                fix = fix or "Renew the server certificate with your CA."
        out.append(_step("credential", "Server credential (Roles Anywhere)", worst, detail, fix))
    elif provider == "azure":
        if eff.azure_client_certificate_path:
            st, detail, fix = _file_check(eff.azure_client_certificate_path, "Certificate file", secret=True)
            if st != FAIL:
                text = Path(eff.azure_client_certificate_path).read_bytes()
                if b"PRIVATE KEY-----" not in text or b"-----BEGIN CERTIFICATE-----" not in text:
                    st, detail, fix = FAIL, "The PEM file must contain the private key and the certificate", "Re-run azure-server-certificate.sh."
                else:
                    days = _cert_days(eff.azure_client_certificate_path)
                    if days is not None and days < 30:
                        st = FAIL if days < 0 else WARN
                        detail += f"; certificate {'expired' if days < 0 else f'expires in {days} days'}"
                        fix = "Create a new key pair, add the new public certificate to the app (append), then switch the file."
            if st != FAIL and eff.azure_client_secret:
                st, detail, fix = WARN, detail + "; a client secret is also set", "Remove AZURE_CLIENT_SECRET: the certificate is used."
            out.append(_step("credential", "Server credential (certificate)", st, detail, fix))
        elif eff.azure_client_secret:
            out.append(_step("credential", "Server credential (certificate)", WARN,
                             "A client secret is used. It works, but it is a long-lived secret.", "Switch to a certificate (step 1 and 4) and remove the secret."))
        else:
            out.append(_step("credential", "Server credential (certificate)", FAIL if production else WARN,
                             "No app credential configured: the backend uses the local az login (development only).",
                             "Set AZURE_CLIENT_ID and AZURE_CLIENT_CERTIFICATE_PATH."))
    else:
        path = eff.gcp_credentials_file
        if not path:
            out.append(_step("credential", "Server credential (federation)", FAIL if production else WARN,
                             "No credential configuration: the backend uses the local gcloud sign-in (development only).",
                             "Install gcp-lvnexus.json and set GCP_CREDENTIALS_FILE."))
            return out
        st, detail, fix = _file_check(path, "Credential configuration")
        if st != FAIL:
            try:
                kind = json.loads(Path(path).read_text(encoding="utf-8")).get("type")
            except (OSError, ValueError):
                kind = None
            if kind == "external_account":
                detail += " (workload identity federation, no key)"
            elif kind == "service_account":
                st, detail, fix = WARN, "A service-account KEY file is used: a long-lived secret.", "Replace it with workload identity federation (this wizard) and delete the key."
            else:
                st, detail, fix = FAIL, "The file is not a Google credential configuration", "Use gcp-lvnexus.json from gcp-onboarding.sh."
        out.append(_step("credential", "Server credential (federation)", st, detail, fix))
    return out


def verify(db: Session, provider: str, settings: Settings, actor: str) -> dict:
    """Read-only end-to-end check of one cloud. Records the result; never enables the connection by itself."""
    from app.services.registry import build_connector

    if provider not in PROVIDERS:
        raise WizardError("Unknown cloud provider")
    if settings.demo_mode:
        raise WizardError("Demo mode: no cloud is called. Run the verification after leaving demo mode.")
    eff = connections.effective_settings(db, settings).model_copy(update={connections.ENABLED_FIELD[provider]: True})
    steps: list[dict] = []
    connector = build_connector(provider, eff)
    missing = connector.missing_configuration() + connections.missing_required(provider, {k: getattr(eff, k, None) for k in connections.FIELDS[provider]})
    missing = sorted(set(missing))
    steps.append(_step("settings", "Connection settings", FAIL if missing else PASS,
                       f"Missing: {', '.join(missing)}" if missing else "All required identifiers are set.",
                       "Fill in the missing values in step 1."))
    steps += _credential_checks(provider, eff)
    scopes = []
    if not missing:
        try:
            scopes = connector.discover()
            active = [s for s in scopes if s.is_active]
            noun = {"aws": "account", "gcp": "project", "azure": "subscription"}[provider]
            if active:
                who = connector.identity_kind() if hasattr(connector, "identity_kind") else "the configured identity"
                steps.append(_step("signin", "Sign-in and discovery", PASS, f"Signed in ({who}); {len(scopes)} {noun}s visible ({len(active)} active)."))
            else:
                steps.append(_step("signin", "Sign-in and discovery", FAIL, f"Signed in, but no active {noun}s are visible.",
                                   "Check that the roles were assigned at the top level (organization / root management group)."))
            scopes = active
        except Exception as exc:  # noqa: BLE001 - reported to the user as the reason
            steps.append(_step("signin", "Sign-in and discovery", FAIL, safe_error(exc, 300),
                               "Check the server credential and that step 2 was deployed in the right account / tenant / organization."))
    else:
        steps.append(_step("signin", "Sign-in and discovery", FAIL, "Not run: settings are incomplete.", "Complete step 1."))
    sample = scopes[:SAMPLE_SCOPES]
    if sample:
        per_check: dict[str, dict] = {}
        for sc in sample:
            try:
                results = connector.validate(sc)
            except Exception as exc:  # noqa: BLE001
                results = {"validation": type("R", (), {"status": "fail", "detail": safe_error(exc, 200), "remediation": None})()}
            for check, res in results.items():
                st = str(getattr(res.status, "value", res.status)).lower()
                agg = per_check.setdefault(check, {"pass": 0, "fail": 0, "other": 0, "detail": None, "fix": None})
                if st == "pass":
                    agg["pass"] += 1
                elif st == "fail":
                    agg["fail"] += 1
                    agg["detail"] = agg["detail"] or f"{sc.name}: {res.detail or 'failed'}"
                    agg["fix"] = agg["fix"] or getattr(res, "remediation", None)
                else:
                    agg["other"] += 1
        for check, agg in sorted(per_check.items()):
            critical = check in ("authentication", "permissions", "validation")
            status = PASS if not agg["fail"] else (FAIL if critical else WARN)
            detail = f"{agg['pass']} of {len(sample)} sampled pass" + (f"; {agg['detail']}" if agg["detail"] else "") + \
                (f"; {agg['other']} not applicable / unknown" if agg["other"] else "")
            steps.append(_step(f"check:{check}", f"Read access: {check.replace('_', ' ')}", status, detail[:400], agg["fix"]))
    worst = FAIL if any(s["status"] == FAIL for s in steps) else WARN if any(s["status"] == WARN for s in steps) else PASS
    result = {"provider": provider, "status": worst, "at": utcnow().isoformat(), "by": actor, "steps": steps,
              "scopes_visible": len(scopes), "sampled": [s.external_id for s in sample]}
    conn = _conn(db, provider, create=True)
    wizard = _wizard(conn)
    wizard["last_verify"] = result
    _store_wizard(conn, wizard)
    conn.last_test_at, conn.last_test_ok = utcnow(), worst != FAIL
    conn.last_test_detail = f"Onboarding verification: {worst}. " + "; ".join(f"{s['title']}: {s['status']}" for s in steps)[:900]
    return result


def activate(db: Session, provider: str, actor: str, max_age_hours: int = 24) -> CloudConnection:
    """Switches the cloud on, only after a verification without failures in the last 24 hours."""
    conn = _conn(db, provider)
    last = _wizard(conn).get("last_verify") if conn else None
    if not last:
        raise WizardError("Run the verification first.")
    if last["status"] == FAIL:
        raise WizardError("The last verification failed. Fix the failed checks and verify again.")
    age = utcnow() - datetime.fromisoformat(last["at"])
    if age.total_seconds() > max_age_hours * 3600:
        raise WizardError("The last verification is older than 24 hours. Verify again.")
    conn.enabled, conn.updated_by = True, actor
    wizard = _wizard(conn)
    wizard["activated_at"], wizard["activated_by"] = utcnow().isoformat(), actor
    _store_wizard(conn, wizard)
    return conn


def overview(db: Session, settings: Settings) -> list[dict]:
    eff = connections.effective_settings(db, settings)
    out = []
    for provider in PROVIDERS:
        conn = _conn(db, provider)
        last = _wizard(conn).get("last_verify")
        out.append({"provider": provider, "enabled": bool(getattr(eff, connections.ENABLED_FIELD[provider])),
                    "last_verify": None if not last else {"status": last["status"], "at": last["at"], "scopes_visible": last.get("scopes_visible")},
                    "activated_at": _wizard(conn).get("activated_at")})
    return out

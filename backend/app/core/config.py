"""Application settings. Every value comes from the environment (or Secret Manager
mounted as environment variables on Cloud Run). No cloud scope IDs are hardcoded."""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_KEY = "change-me-local-only"

CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    # One .env at the repository root serves both `docker compose` and running from backend/ in VS Code.
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore", case_sensitive=False,
                                      env_parse_none_str="",  # a blank value in .env means "not set"
                                      populate_by_name=True)

    app_name: str = "LV NEXUS · LatentView Analytics"
    app_env: str = "local"  # local | test | production
    database_url: str = "mysql+pymysql://mcp:mcp@127.0.0.1:3306/mcp?charset=utf8mb4"
    redis_url: str | None = None
    azure_key_vault_url: str | None = None  # https://<vault>.vault.azure.net — secrets are read from here (required in production)
    frontend_url: str = "http://localhost:5173"
    cors_origins: CsvList = ["http://localhost:5173"]
    frontend_dist: str | None = None  # serve built SPA from the API container when set

    # --- authentication / sessions ---
    secret_key: str = Field(default=_INSECURE_KEY, repr=False, validation_alias=AliasChoices("secret_key", "SESSION_SECRET"))
    auth_mode: str = "dev"  # dev | google | entra
    # DEMO_MODE=true: the application runs on a separate SQLite demo database with FICTIONAL sample data (python -m app.demo_data)
    # and shows a "Demo data" banner on every page. Refused when APP_ENV=production or when DATABASE_URL is not a demo SQLite file.
    demo_mode: bool = False
    dev_user_email: str = "dev-admin@localhost"
    google_oauth_client_id: str | None = Field(default=None, validation_alias=AliasChoices("google_oauth_client_id", "GOOGLE_CLIENT_ID"))
    google_oauth_client_secret: str | None = Field(default=None, repr=False,
                                                   validation_alias=AliasChoices("google_oauth_client_secret", "GOOGLE_CLIENT_SECRET"))
    google_redirect_uri: str | None = None  # default: FRONTEND_URL + /api/v1/auth/callback; must match the OAuth client exactly
    google_allowed_domain: str | None = None  # Google Workspace primary domain (checked against the verified `hd` claim AND the email)
    # Google group e-mail -> application role. Membership is read server-side (Cloud Identity API) at sign-in.
    google_workspace_admin_groups: CsvList = []  # members become platform administrators (super admin)
    google_group_role_map: CsvList = []  # "group@domain=role" entries, e.g. finops@latentview.com=finops_analyst
    google_group_lookup_enabled: bool = False
    entra_tenant_id: str | None = None  # Microsoft Entra ID sign-in (single tenant)
    entra_client_id: str | None = None
    entra_client_secret: str | None = Field(default=None, repr=False)
    # A verified corporate identity alone grants nothing: people must be provisioned (or be in a mapped Google group).
    auth_auto_provision: bool = False
    allowed_email_domains: CsvList = []
    bootstrap_admin_emails: CsvList = []
    session_ttl_minutes: int = 480         # lifetime of one session
    session_idle_minutes: int = 60         # signed out after this long without activity
    session_absolute_max_minutes: int = 720  # renewals never extend a sign-in beyond this
    auth_throttle_failures: int = 10       # failed sign-ins per IP address within the window before throttling
    auth_throttle_window_minutes: int = 15
    rate_limit_per_minute: int = 1200       # API requests per client IP per minute (0 = off)
    auth_rate_limit_per_minute: int = 30    # sign-in endpoints per client IP per minute
    pubsub_push_audience: str | None = None
    pubsub_push_service_account: str | None = None

    # --- AWS (read-only, STS only, never static keys) ---
    aws_enabled: bool = False
    aws_default_region: str = "us-east-1"
    aws_profile: str | None = None  # local CLI profile for the management account (aws sso login --profile ...)
    aws_member_role_name: str | None = None
    aws_external_id: str | None = None
    aws_management_role_arn: str | None = None  # assumed via web identity when set
    aws_web_identity_audience: str | None = None
    # optional: https URL of an S3 folder where your cloud team published the LV NEXUS CloudFormation templates; enables the
    # one-click "quick create" link in Onboard a cloud > AWS (CloudFormation only accepts templates from S3 for that link)
    onboarding_aws_template_base_url: str | None = None

    # --- GCP ---
    gcp_enabled: bool = False
    gcp_organization_id: str | None = None
    # Credential file for every Google Cloud read (resources, logs, SCC, BigQuery billing): a service-account key or a
    # workload-identity-federation config. Empty = Application Default Credentials (gcloud login / attached identity).
    gcp_credentials_file: str | None = None
    gcp_scopes: CsvList = [
        "https://www.googleapis.com/auth/cloud-platform.read-only",
        "https://www.googleapis.com/auth/cloud-billing.readonly",
        "https://www.googleapis.com/auth/logging.read",
    ]
    gcp_required_apis: CsvList = [
        "compute.googleapis.com",
        "logging.googleapis.com",
        "monitoring.googleapis.com",
    ]
    gcp_required_permissions: CsvList = [
        "resourcemanager.projects.get",
        "logging.logEntries.list",
        "monitoring.timeSeries.list",
        "compute.instances.list",
    ]

    # --- Azure ---
    azure_enabled: bool = False
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = Field(default=None, repr=False)
    azure_client_certificate_path: str | None = None  # PEM with private key; preferred over a client secret
    azure_principal_object_id: str | None = None
    azure_required_roles: CsvList = ["Reader", "Monitoring Reader", "Cost Management Reader"]

    aws_regions: CsvList = []  # empty = every region enabled in the account

    # --- SOC ---
    soc_initial_lookback_hours: int = 24
    # native security findings (AWS Security Hub, Azure Advisor, Google SCC) and vulnerability management
    security_sync_enabled: bool = True
    aws_securityhub_aggregation_region: str | None = None  # Security Hub cross-region aggregation region; empty = read every region
    aws_securityhub_admin_account_id: str | None = None     # delegated administrator; defaults to the management account
    security_sync_full_every_days: int = 7
    security_sync_lock_ttl_seconds: int = 6 * 3600          # a full multi-cloud listing can take hours; no second run meanwhile                  # full reconciliation interval; incremental in between
    security_sync_overlap_minutes: int = 60                 # re-read before the watermark: provider updates can lag
    security_reopen_on_reappear: bool = True                # RESOLVED internally + active again natively -> REOPENED
    exception_default_days: int = 90
    exception_max_days: int = 365
    exception_expiry_notice_days: int = 14
    evidence_dir: str = "../evidence-store"                  # outside the web root; files named by SHA-256
    evidence_max_bytes: int = 10 * 1024 * 1024
    audit_case_group_hours: int = 24                        # flagged events from the same rule and actor within this window share a case
    investigation_sla_hours: int = 72                       # open investigations older than this are escalated
    critical_unassigned_hours: int = 4
    soc_overlap_minutes: int = 30  # re-read this much before the checkpoint: cloud logs can arrive late; duplicates are skipped by event ID
    soc_max_events_per_scope: int = 5000
    soc_aws_include_read_events: bool = False
    # SOC incident e-mail (services/audit/soc_alert.py)
    soc_alert_recipients: CsvList = []           # SOC / security distribution list; empty = NOTIFY_EMAIL_TO
    soc_alert_subject_prefix: str = "LV NEXUS SOC ALERT"
    soc_notify_affected_user: bool = False       # also e-mail the affected user (corporate domain only, never for identity-compromise rules)
    soc_affected_user_domains: CsvList = []      # empty = GOOGLE_ALLOWED_DOMAIN
    soc_gcp_include_data_access: bool = False
    soc_trusted_cidrs: CsvList = []  # when set, write activity from other addresses is flagged
    soc_failed_auth_threshold: int = 5
    soc_denied_threshold: int = 10
    soc_data_access_threshold: int = 1000

    # --- FinOps ---
    gcp_billing_export_table: str | None = None  # project.dataset.gcp_billing_export_v1_XXXX
    gcp_billing_query_project: str | None = None
    fx_usd_inr_rate: float | None = None  # manual rate; stored with every converted record
    finops_lookback_days: int = 35
    finops_final_after_days: int = 5  # days after month end before data is treated as final
    billing_periods_history: int = 6  # closed billing periods kept per subscription (each queried once, then cached)
    finops_anomaly_sigma: float = 3.0
    finops_anomaly_min_usd: float = 10.0
    log_format: str = "json"                        # json (structured, one object per line) | text
    access_workflows_enabled: bool = False          # legacy request / approval / review / revocation-plan API (UI removed)
    dry_run: bool = False                           # run every workflow without writing results, Sheets or messages
    circuit_breaker_threshold: int = 4              # consecutive transient failures before a provider is skipped for the run
    cost_detail_days: int = 35                      # days re-read by cost_detail_refresh (resource / region / SKU detail)
    cost_tag_keys: CsvList = ["environment", "cost-center", "business-entity"]  # tag / label keys used for allocation views
    cost_include_amortized: bool = True             # also read amortized cost (AWS AmortizedCost, Azure AmortizedCost)
    aws_resource_cost_enabled: bool = False         # Cost Explorer resource-level data (opt-in in AWS; last 14 days only)
    gcp_billing_detailed_export_table: str | None = None  # resource-level export: project.dataset.gcp_billing_export_resource_v1_XXXX
    financial_year_start_month: int = 4             # April (India); used for the "financial year" period
    # live audit anomaly detection (each principal is compared with its own history)
    anomaly_baseline_days: int = 30
    anomaly_min_baseline_events: int = 20           # below this a principal has no baseline yet: no "new IP / country / hour" alerts
    anomaly_failure_threshold: int = 10             # failed or denied calls by one principal within the window
    anomaly_failure_window_minutes: int = 15
    anomaly_mass_delete_threshold: int = 20         # successful delete / terminate calls by one principal within the window
    anomaly_mass_delete_window_minutes: int = 10
    anomaly_timezone: str = "Asia/Kolkata"          # for the "unusual hours" rule
    anomaly_rare_hour_share: float = 0.02           # an hour holding less than this share of the principal's history is unusual

    # --- VM monitoring (defaults; override per environment with VM_THRESHOLD_OVERRIDES JSON) ---
    vm_cpu_warning: float = 80
    vm_cpu_critical: float = 90
    vm_memory_warning: float = 85
    vm_memory_critical: float = 95
    vm_disk_warning: float = 85
    vm_disk_critical: float = 95
    vm_threshold_overrides: str | None = None  # {"prod": {"cpu": [70, 85]}}
    vm_metric_window_minutes: int = 30

    # --- Google Sheets / notifications ---
    sheets_enabled: bool = False
    sheets_spreadsheet_id: str | None = None
    notify_email_enabled: bool = False
    # Monthly audit report (official LatentView Word layout): cover-table values
    audit_report_prepared_by: str = "Cloud Team"
    audit_report_reviewed_by: str | None = None  # name of the reviewer shown on the cover; empty = filled in by hand
    audit_report_version: str = "v3.0"
    gmail_sender: str | None = Field(default=None, validation_alias=AliasChoices("gmail_sender", "GMAIL_SENDER", "EMAIL_SENDER"))  # From address
    email_transport: str = "smtp"  # smtp (Google Workspace / Microsoft 365 / any relay) | gmail_api (service account with domain-wide delegation)
    smtp_host: str | None = None  # e.g. smtp.gmail.com, smtp-relay.gmail.com, smtp.office365.com
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = Field(default=None, repr=False)  # app password; Key Vault in production
    smtp_starttls: bool = True
    # Service-account key file for Google Sheets (and the Gmail API transport). Locally a path outside the project folder;
    # in production use workload identity instead of a key file.
    google_application_credentials: str | None = None
    notify_email_to: CsvList = []
    chat_webhook_url: str | None = Field(default=None, repr=False)
    dashboard_url: str | None = None
    notify_max_attempts: int = 3
    notify_queue_max_age_hours: int = 24
    audit_retention_days: int = 365  # LV NEXUS never deletes audit events younger than this (CERT-In 180 d, DPDP 1 year)  # queued messages older than this are expired, never sent late

    # --- AI (optional; rule-based detection never depends on it) ---
    ai_provider: str = "none"  # none | gemini | openai
    gemini_api_key: str | None = Field(default=None, repr=False)
    gemini_model: str | None = None
    openai_api_key: str | None = Field(default=None, repr=False)
    openai_model: str | None = None
    ai_max_findings_per_run: int = 20

    # --- automation ---
    discovery_lock_ttl_seconds: int = 840
    api_retry_attempts: int = 5

    @field_validator(
        "cors_origins", "allowed_email_domains", "bootstrap_admin_emails", "gcp_scopes", "google_workspace_admin_groups", "google_group_role_map",
        "gcp_required_apis", "gcp_required_permissions", "azure_required_roles", "aws_regions", "soc_trusted_cidrs",
        "notify_email_to", "cost_tag_keys", "soc_alert_recipients", "soc_affected_user_domains", mode="before",
    )
    @classmethod
    def _split_csv(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    @property
    def corporate_domains(self) -> set[str]:
        """Domains allowed to sign in. GOOGLE_ALLOWED_DOMAIN takes precedence over ALLOWED_EMAIL_DOMAINS."""
        if self.google_allowed_domain:
            return {self.google_allowed_domain.lower().strip()}
        return {d.lower() for d in self.allowed_email_domains}

    @model_validator(mode="after")
    def _production_guards(self):
        if self.auth_mode not in ("dev", "google", "entra"):
            raise ValueError("AUTH_MODE must be dev, google or entra")
        if self.app_env == "production":
            if self.auth_mode == "dev":
                raise ValueError("AUTH_MODE=dev is not allowed when APP_ENV=production")
            if self.demo_mode:
                raise ValueError("DEMO_MODE is not allowed when APP_ENV=production")
            if self.secret_key == _INSECURE_KEY or len(self.secret_key) < 32:
                raise ValueError("SESSION_SECRET (SECRET_KEY) must be a strong value (>=32 chars) in production")
            for url in filter(None, (self.frontend_url, self.google_redirect_uri)):
                if not url.startswith("https://"):
                    raise ValueError("FRONTEND_URL and GOOGLE_REDIRECT_URI must use HTTPS in production")
        if self.demo_mode:
            if not (self.database_url.startswith("sqlite") and "demo" in self.database_url.rsplit("/", 1)[-1].lower()):
                raise ValueError("DEMO_MODE needs a separate demo database: DATABASE_URL=sqlite:///./lvnexus-demo.db (never the real database)")
            # demo data only: no cloud is called and nothing is sent, whatever .env says
            self.aws_enabled = self.azure_enabled = self.gcp_enabled = False
            self.notify_email_enabled = False
            self.chat_webhook_url = None
            self.sheets_enabled = False
        if self.google_redirect_uri and not self.google_redirect_uri.rstrip("/").endswith("/api/v1/auth/callback"):
            raise ValueError("GOOGLE_REDIRECT_URI must point to <application address>/api/v1/auth/callback")
        return self


@lru_cache
def get_settings() -> Settings:
    """Settings from the environment / .env, with secrets from Azure Key Vault when AZURE_KEY_VAULT_URL is set."""
    from app.core import secrets
    s = Settings()
    if s.azure_key_vault_url and s.app_env != "test":
        secrets.load_key_vault(s.azure_key_vault_url)
        s = Settings()
    else:
        secrets.load_key_vault(None)
    secrets.mark_dotenv(s)
    if s.gcp_credentials_file and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        # Google client libraries read their credential file from the process environment, not from .env.
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = s.gcp_credentials_file
    return s

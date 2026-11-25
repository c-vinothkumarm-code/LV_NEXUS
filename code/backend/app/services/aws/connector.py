"""AWS discovery and onboarding validation. Read-only API calls only; STS credentials only."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import Settings
from app.core.logging import safe_error
from app.services.connector import (
    CHECK_AUDIT,
    CHECK_AUTH,
    CHECK_BILLING,
    CHECK_MONITORING,
    CHECK_PERMISSIONS,
    FAIL,
    PASS,
    UNKNOWN,
    CheckResult,
    DiscoveredScope,
    skipped,
)

_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure",
           "UnrecognizedClientException", "InvalidClientTokenId"}
_ACTIVE_STATES = {"ACTIVE"}


def _code(exc: Exception) -> str:
    return exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else type(exc).__name__


class AwsConnector:
    provider = "aws"

    def __init__(self, settings: Settings, base_session: boto3.Session | None = None):
        self.settings = settings
        self._base = base_session
        self._cfg = Config(retries={"mode": "adaptive", "max_attempts": 8}, connect_timeout=10, read_timeout=30)
        self._management_id: str | None = None
        self._payer_billing: CheckResult | None = None
        self._ou_names: dict[str, str] = {}

    # -- configuration -------------------------------------------------
    def missing_configuration(self) -> list[str]:
        missing = []
        if not self.settings.aws_member_role_name:
            missing.append("AWS_MEMBER_ROLE_NAME")
        if self.settings.aws_management_role_arn and not self.settings.aws_web_identity_audience:
            missing.append("AWS_WEB_IDENTITY_AUDIENCE")
        return missing

    # -- sessions ------------------------------------------------------
    def base_session(self) -> boto3.Session:
        """Management-account session. Uses web identity federation when configured, otherwise the
        default credential chain (SSO profile / instance role). Static access keys are never read
        from application settings."""
        if self._base is None:
            s = self.settings
            if s.aws_management_role_arn:
                import google.auth.transport.requests
                from google.oauth2 import id_token

                token = id_token.fetch_id_token(google.auth.transport.requests.Request(), s.aws_web_identity_audience)
                sts = boto3.client("sts", region_name=s.aws_default_region, config=self._cfg)
                creds = sts.assume_role_with_web_identity(
                    RoleArn=s.aws_management_role_arn, RoleSessionName="mcp-control-plane",
                    WebIdentityToken=token)["Credentials"]
                self._base = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"], region_name=s.aws_default_region)
            else:
                self._base = boto3.Session(profile_name=s.aws_profile or None, region_name=s.aws_default_region)
        return self._base

    def _client(self, session: boto3.Session, service: str, region: str | None = None):
        return session.client(service, region_name=region or self.settings.aws_default_region, config=self._cfg)

    def session_for(self, account_id: str, is_management: bool) -> boto3.Session:
        """Session for a collector working from the stored inventory."""
        if is_management:
            self._management_id = account_id
        return self.member_session(account_id)

    def client(self, session: boto3.Session, service: str, region: str | None = None):
        return self._client(session, service, region)

    def regions(self, session: boto3.Session) -> list[str]:
        if self.settings.aws_regions:
            return list(self.settings.aws_regions)
        return sorted(r["RegionName"] for r in self._client(session, "ec2").describe_regions()["Regions"])

    def member_session(self, account_id: str) -> boto3.Session:
        if account_id == self._management_id:
            return self.base_session()
        s = self.settings
        params = {"RoleArn": f"arn:aws:iam::{account_id}:role/{s.aws_member_role_name}",
                  "RoleSessionName": "mcp-control-plane"}
        if s.aws_external_id:
            params["ExternalId"] = s.aws_external_id
        creds = self._sts_call(self.base_session(), "assume_role", **params)["Credentials"]
        return self._session_from_credentials(creds)

    def _sts_call(self, session: boto3.Session, op: str, **params):
        """STS in the configured region; if that account has the regional STS endpoint deactivated
        (RegionDisabledException), retry once on us-east-1, which AWS keeps active for every account."""
        try:
            return getattr(self._client(session, "sts"), op)(**params)
        except ClientError as exc:
            if _code(exc) != "RegionDisabledException" or self.settings.aws_default_region == "us-east-1":
                raise
            return getattr(self._client(session, "sts", "us-east-1"), op)(**params)

    def _session_from_credentials(self, creds: dict) -> boto3.Session:
        """Short-lived STS credentials only; they live in memory for one run and are never persisted."""
        return boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                             aws_session_token=creds["SessionToken"], region_name=self.settings.aws_default_region)

    # -- discovery -----------------------------------------------------
    def _ou_name(self, org, account_id: str) -> str | None:
        parents = org.list_parents(ChildId=account_id).get("Parents", [])
        if not parents:
            return None
        parent = parents[0]
        if parent["Type"] == "ROOT":
            return "Root"
        pid = parent["Id"]
        if pid not in self._ou_names:
            self._ou_names[pid] = org.describe_organizational_unit(OrganizationalUnitId=pid)["OrganizationalUnit"]["Name"]
        return self._ou_names[pid]

    def discover(self) -> list[DiscoveredScope]:
        org = self._client(self.base_session(), "organizations")
        self._management_id = org.describe_organization()["Organization"]["MasterAccountId"]
        scopes = []
        for page in org.get_paginator("list_accounts").paginate():
            for acct in page["Accounts"]:
                state = acct.get("State") or acct.get("Status") or "UNKNOWN"
                try:
                    ou = self._ou_name(org, acct["Id"])
                except ClientError:
                    ou = None  # OU lookup is optional metadata
                scopes.append(DiscoveredScope(
                    provider="aws", external_id=acct["Id"], name=acct.get("Name", ""), provider_state=state,
                    is_active=state in _ACTIVE_STATES, parent=ou,
                    attrs={"email": acct.get("Email"), "is_management": acct["Id"] == self._management_id}))
        return scopes

    # -- validation ----------------------------------------------------
    def _payer_billing_check(self) -> CheckResult:
        if self._payer_billing is None:
            end = datetime.now(UTC).date()
            try:
                self._client(self.base_session(), "ce", "us-east-1").get_cost_and_usage(
                    TimePeriod={"Start": (end - timedelta(days=1)).isoformat(), "End": end.isoformat()},
                    Granularity="DAILY", Metrics=["UnblendedCost"])
                self._payer_billing = CheckResult(PASS, "Cost Explorer readable from the payer account (consolidated billing)")
            except (ClientError, BotoCoreError) as exc:
                denied = _code(exc) in _DENIED
                self._payer_billing = CheckResult(
                    FAIL if denied else UNKNOWN, f"Cost Explorer check failed: {safe_error(exc)}",
                    "Grant ce:GetCostAndUsage (read-only) to the management-account role" if denied else None)
        return self._payer_billing

    def _audit_check(self, session: boto3.Session) -> CheckResult:
        ct = self._client(session, "cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        if not trails:
            return CheckResult(FAIL, "CloudTrail is not configured for this account",
                               "Enable an organisation trail or an account trail (requires approval)")
        logging_trails, errors = [], []
        for t in trails:
            try:
                home = t.get("HomeRegion") or self.settings.aws_default_region
                if self._client(session, "cloudtrail", home).get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
                    logging_trails.append(t.get("Name", t["TrailARN"]))
            except (ClientError, BotoCoreError) as exc:
                errors.append(safe_error(exc, 120))
        if logging_trails:
            return CheckResult(PASS, f"{len(logging_trails)} trail(s) logging: {', '.join(logging_trails[:3])}")
        if errors:
            return CheckResult(UNKNOWN, f"Trail status could not be read: {errors[0]}")
        return CheckResult(FAIL, f"{len(trails)} trail(s) exist but none is logging",
                           "Start logging on the CloudTrail trail (requires approval)")

    def validate(self, scope: DiscoveredScope) -> dict[str, CheckResult]:
        role = self.settings.aws_member_role_name
        try:
            session = self.member_session(scope.external_id)
            self._sts_call(session, "get_caller_identity")
        except (ClientError, BotoCoreError) as exc:
            code = _code(exc)
            why = "cross-account role access denied" if code in _DENIED else "role assumption failed"
            fix = (f"Check that the StackSet instance for account {scope.external_id} is CURRENT, that AWS_EXTERNAL_ID matches "
                   "the StackSet ExternalId, and that you signed in with the CloudNexusReader permission set - requires approval")
            if code == "RegionDisabledException":
                fix = (f"In account {scope.external_id}: IAM > Account settings > Security Token Service (STS) > activate the "
                       f"endpoint for {self.settings.aws_default_region} and us-east-1 - requires approval")
            elif code not in _DENIED:
                fix = (f"Create read-only IAM role '{role}' in account {scope.external_id} trusting the "
                       "management account (with external ID) - requires approval")
            return {
                CHECK_AUTH: CheckResult(FAIL, f"STS AssumeRole for role '{role}': {why} ({safe_error(exc, 200)})", fix),
                **{k: skipped("authentication failed") for k in (CHECK_PERMISSIONS, CHECK_AUDIT, CHECK_BILLING, CHECK_MONITORING)},
            }
        results = {CHECK_AUTH: CheckResult(PASS, "STS AssumeRole succeeded")}

        probes = {
            "ec2:DescribeRegions": lambda: self._client(session, "ec2").describe_regions(),
            "cloudtrail:DescribeTrails": lambda: self._client(session, "cloudtrail").describe_trails(),
            "cloudwatch:ListMetrics": lambda: self._client(session, "cloudwatch").list_metrics(Namespace="AWS/EC2"),
        }
        denied, errored = [], []
        for action, call in probes.items():
            try:
                call()
            except (ClientError, BotoCoreError) as exc:
                (denied if _code(exc) in _DENIED else errored).append(action)
        if denied:
            results[CHECK_PERMISSIONS] = CheckResult(
                FAIL, f"Missing read permissions: {', '.join(denied)}",
                f"Attach read-only policies covering {', '.join(denied)} to role '{role}' - requires approval")
        elif errored:
            results[CHECK_PERMISSIONS] = CheckResult(UNKNOWN, f"Probe errors (not permission-related): {', '.join(errored)}")
        else:
            results[CHECK_PERMISSIONS] = CheckResult(PASS, "Read-only probes succeeded (EC2, CloudTrail, CloudWatch)")

        if "cloudtrail:DescribeTrails" in denied:
            results[CHECK_AUDIT] = skipped("cloudtrail:DescribeTrails denied")
        else:
            try:
                results[CHECK_AUDIT] = self._audit_check(session)
            except (ClientError, BotoCoreError) as exc:
                results[CHECK_AUDIT] = CheckResult(UNKNOWN, f"CloudTrail check failed: {safe_error(exc, 200)}")

        results[CHECK_BILLING] = self._payer_billing_check()
        if "cloudwatch:ListMetrics" in denied:
            results[CHECK_MONITORING] = CheckResult(FAIL, "CloudWatch metrics are not readable",
                                                    f"Grant cloudwatch:ListMetrics/GetMetricData to role '{role}' - requires approval")
        elif "cloudwatch:ListMetrics" in errored:
            results[CHECK_MONITORING] = CheckResult(UNKNOWN, "CloudWatch probe errored")
        else:
            results[CHECK_MONITORING] = CheckResult(PASS, "CloudWatch metrics readable")
        return results

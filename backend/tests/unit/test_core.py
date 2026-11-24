import pytest

from app.core.config import Settings
from app.core.logging import redact, safe_error
from app.models import OnboardingStatus as S
from app.services.connector import FAIL, PASS, UNKNOWN
from app.services.onboarding.status import derive_status
from app.utils.retry import with_backoff


def checks(**kw):
    base = {"authentication": PASS, "permissions": PASS, "audit_logs": PASS, "billing": PASS, "monitoring": PASS}
    base.update(kw)
    return {k: {"status": v} for k, v in base.items()}


@pytest.mark.parametrize("c,active,enabled,expected", [
    (checks(), True, True, S.FULLY_ONBOARDED),
    ({}, True, True, S.DISCOVERED),
    (checks(), False, True, S.INACTIVE),
    (checks(), True, False, S.MONITORING_DISABLED),
    (checks(authentication=FAIL), True, True, S.ACCESS_FAILED),
    (checks(authentication=UNKNOWN), True, True, S.ACCESS_FAILED),
    (checks(permissions=FAIL), True, True, S.PENDING_ACCESS),
    (checks(permissions=UNKNOWN), True, True, S.PENDING_ACCESS),
    (checks(audit_logs=FAIL), True, True, S.PARTIALLY_ONBOARDED),
    (checks(billing=UNKNOWN), True, True, S.PARTIALLY_ONBOARDED),
    (checks(audit_logs=FAIL, billing=FAIL, monitoring=UNKNOWN), True, True, S.PENDING_CONFIGURATION),
    (checks(configuration=FAIL), True, True, S.PARTIALLY_ONBOARDED),
])
def test_derive_status(c, active, enabled, expected):
    assert derive_status(c, is_active=active, monitoring_enabled=enabled) == expected


def test_unknown_is_never_fully_onboarded():
    for key in ("authentication", "permissions", "audit_logs", "billing", "monitoring", "configuration"):
        assert derive_status(checks(**{key: UNKNOWN}), is_active=True, monitoring_enabled=True) != S.FULLY_ONBOARDED


def test_redaction_removes_credentials():
    text = ("Authorization: Bearer abc.def client_secret=supersecret AKIAABCDEFGHIJKLMNOP "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxx")
    out = redact(text)
    for secret in ("supersecret", "AKIAABCDEFGHIJKLMNOP", "eyJhbGciOiJIUzI1NiJ9", "ya29.a0AfH6"):
        assert secret not in out


def test_safe_error_is_bounded_and_redacted():
    msg = safe_error(RuntimeError("token=abc123 " + "x" * 1000))
    assert "abc123" not in msg and len(msg) <= 400


def test_production_rejects_dev_auth_and_weak_secret():
    with pytest.raises(ValueError):
        Settings(_env_file=None, app_env="production", auth_mode="dev", secret_key="x" * 40)
    with pytest.raises(ValueError):
        Settings(_env_file=None, app_env="production", auth_mode="google")
    with pytest.raises(ValueError):  # HTTPS only in production
        Settings(_env_file=None, app_env="production", auth_mode="google", secret_key="k" * 40)
    with pytest.raises(ValueError):  # redirect URI must be our callback
        Settings(_env_file=None, google_redirect_uri="https://evil.example.com/steal")
    assert Settings(_env_file=None, app_env="production", auth_mode="google", secret_key="k" * 40,
                    frontend_url="https://cloud.example.com")


def test_csv_settings(monkeypatch):
    monkeypatch.setenv("GCP_REQUIRED_APIS", "a.googleapis.com, b.googleapis.com")
    assert Settings(_env_file=None).gcp_required_apis == ["a.googleapis.com", "b.googleapis.com"]


def test_no_cloud_scope_ids_in_default_settings():
    s = Settings(_env_file=None, gcp_organization_id=None)
    assert s.gcp_organization_id is None and s.azure_tenant_id is None and s.aws_member_role_name is None


class Throttled(Exception):
    status_code = 429


def test_backoff_retries_throttling_then_succeeds():
    calls, sleeps = [], []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise Throttled()
        return "ok"

    assert with_backoff(fn, sleep=sleeps.append) == "ok"
    assert len(calls) == 3 and len(sleeps) == 2 and sleeps[1] > 0


def test_backoff_does_not_retry_permission_errors():
    calls = []

    def fn():
        calls.append(1)
        raise PermissionError("denied")

    with pytest.raises(PermissionError):
        with_backoff(fn, sleep=lambda s: None)
    assert len(calls) == 1


def test_env_example_loads_as_is(tmp_path, monkeypatch):
    """Copying .env.example to .env unchanged must start the application (blank values mean 'not set')."""
    import pathlib

    example = pathlib.Path(__file__).resolve().parents[3] / ".env.example"
    for key in ("DATABASE_URL", "APP_ENV", "AUTH_MODE", "AWS_ENABLED", "GCP_ENABLED", "AZURE_ENABLED"):
        monkeypatch.delenv(key, raising=False)
    s = Settings(_env_file=example)
    assert s.fx_usd_inr_rate is None and s.soc_trusted_cidrs == [] and s.aws_regions == [] and s.gcp_organization_id is None
    assert s.database_url.startswith("mysql+pymysql://") and s.ai_provider == "none" and s.sheets_enabled is False

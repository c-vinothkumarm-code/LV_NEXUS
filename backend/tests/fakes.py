"""In-memory connector used to exercise the onboarding workflow without any cloud call."""
from __future__ import annotations

from app.services.connector import CHECK_AUDIT, CHECK_AUTH, CHECK_BILLING, CHECK_MONITORING, CHECK_PERMISSIONS, FAIL, PASS, CheckResult, DiscoveredScope


def all_pass() -> dict[str, CheckResult]:
    return {k: CheckResult(PASS, "ok") for k in (CHECK_AUTH, CHECK_PERMISSIONS, CHECK_AUDIT, CHECK_BILLING, CHECK_MONITORING)}


def auth_failed() -> dict[str, CheckResult]:
    return {CHECK_AUTH: CheckResult(FAIL, "AccessDenied assuming role", "Create read-only role - requires approval")}


class FakeConnector:
    def __init__(self, provider: str, scopes: dict[str, dict] | None = None, missing=None, discover_error=None):
        self.provider = provider
        self.scopes = scopes or {}  # external_id -> {"name", "active", "checks"}
        self.missing = missing or []
        self.discover_error = discover_error
        self.validate_calls: list[str] = []

    def missing_configuration(self):
        return self.missing

    def discover(self):
        if self.discover_error:
            raise self.discover_error
        return [DiscoveredScope(self.provider, ext, v.get("name", ext), "ACTIVE" if v.get("active", True) else "SUSPENDED",
                                v.get("active", True)) for ext, v in self.scopes.items()]

    def validate(self, scope):
        self.validate_calls.append(scope.external_id)
        checks = self.scopes[scope.external_id].get("checks")
        if isinstance(checks, Exception):
            raise checks
        return checks if checks is not None else all_pass()

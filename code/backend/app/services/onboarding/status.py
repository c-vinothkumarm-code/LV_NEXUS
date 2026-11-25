"""Derive the onboarding readiness status from validation checks. Unknown is never treated as pass."""
from __future__ import annotations

from app.models import OnboardingStatus as S
from app.services.connector import CHECK_AUTH, CHECK_CONFIGURATION, CHECK_PERMISSIONS, INTEGRATION_CHECKS, NOT_APPLICABLE, PASS


def derive_status(checks: dict[str, dict], *, is_active: bool, monitoring_enabled: bool) -> S:
    if not is_active:
        return S.INACTIVE
    if not monitoring_enabled:
        return S.MONITORING_DISABLED
    if not checks:
        return S.DISCOVERED

    def st(key: str) -> str | None:
        return (checks.get(key) or {}).get("status")

    if st(CHECK_AUTH) != PASS:
        return S.ACCESS_FAILED
    if st(CHECK_PERMISSIONS) != PASS:
        return S.PENDING_ACCESS
    integration = [st(k) for k in INTEGRATION_CHECKS if st(k) != NOT_APPLICABLE]
    passed = sum(1 for s in integration if s == PASS)
    config_ok = st(CHECK_CONFIGURATION) in (PASS, NOT_APPLICABLE, None)
    if passed == len(integration) and config_ok:
        return S.FULLY_ONBOARDED
    if passed == 0:
        return S.PENDING_CONFIGURATION
    return S.PARTIALLY_ONBOARDED


# Scopes in these states are included in scheduled collection jobs.
AUTOMATION_ELIGIBLE = (S.FULLY_ONBOARDED.value, S.PARTIALLY_ONBOARDED.value)

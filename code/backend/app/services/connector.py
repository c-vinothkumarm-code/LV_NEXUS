"""Provider-neutral contract every cloud connector implements."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Protocol

PASS, FAIL, UNKNOWN, NOT_APPLICABLE = "pass", "fail", "unknown", "not_applicable"

CHECK_AUTH = "authentication"
CHECK_PERMISSIONS = "permissions"
CHECK_CONFIGURATION = "configuration"
CHECK_AUDIT = "audit_logs"
CHECK_BILLING = "billing"
CHECK_MONITORING = "monitoring"
INTEGRATION_CHECKS = (CHECK_AUDIT, CHECK_BILLING, CHECK_MONITORING)
ALL_CHECKS = (CHECK_AUTH, CHECK_PERMISSIONS, CHECK_CONFIGURATION, *INTEGRATION_CHECKS)


@dataclass
class CheckResult:
    status: str
    detail: str = ""
    remediation: str | None = None  # human task text; the platform never applies it

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DiscoveredScope:
    provider: str
    external_id: str
    name: str
    provider_state: str
    is_active: bool
    parent: str | None = None
    attrs: dict = field(default_factory=dict)  # provider-specific model columns


class CloudConnector(Protocol):
    provider: str

    def missing_configuration(self) -> list[str]:
        """Names of settings that must be provided before this provider can run."""

    def discover(self) -> list[DiscoveredScope]:
        """Return every scope visible in the organisation. Must raise on failure, never return partial silently."""

    def validate(self, scope: DiscoveredScope) -> dict[str, CheckResult]:
        """Run read-only validation checks for one scope."""


def skipped(reason: str) -> CheckResult:
    return CheckResult(UNKNOWN, f"Not evaluated: {reason}")

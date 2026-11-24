"""Builds the enabled cloud connectors from settings."""
from __future__ import annotations

from app.core.config import Settings
from app.services.connector import CloudConnector


def build_connector(provider: str, settings: Settings) -> CloudConnector:
    if provider == "aws":
        from app.services.aws.connector import AwsConnector
        return AwsConnector(settings)
    if provider == "gcp":
        from app.services.gcp.connector import GcpConnector
        return GcpConnector(settings)
    if provider == "azure":
        from app.services.azure.connector import AzureConnector
        return AzureConnector(settings)
    raise ValueError(f"Unknown provider: {provider}")


def build_connectors(settings: Settings) -> list[CloudConnector]:
    enabled = {"aws": settings.aws_enabled, "gcp": settings.gcp_enabled, "azure": settings.azure_enabled}
    return [build_connector(p, settings) for p, on in enabled.items() if on]


def prerequisites(settings: Settings) -> list[dict]:
    """Configuration checklist. Reports presence only, never values."""
    s = settings

    def item(name: str, ok: bool, note: str = "") -> dict:
        return {"name": name, "configured": bool(ok), "note": note}

    return [
        {"provider": "aws", "enabled": s.aws_enabled, "items": [
            item("AWS_MEMBER_ROLE_NAME", s.aws_member_role_name, "Read-only cross-account role present in every member account"),
            item("AWS_EXTERNAL_ID", s.aws_external_id, "Recommended external ID on the role trust policy"),
            item("AWS_MANAGEMENT_ROLE_ARN", s.aws_management_role_arn, "Optional: management role assumed via Google web identity (no static keys)"),
        ]},
        {"provider": "gcp", "enabled": s.gcp_enabled, "items": [
            item("GCP_ORGANIZATION_ID", s.gcp_organization_id, "Organisation whose folders and projects are discovered"),
            item("Service identity", True, "Application Default Credentials; org-level viewer roles required"),
        ]},
        {"provider": "azure", "enabled": s.azure_enabled, "items": [
            item("AZURE_TENANT_ID", s.azure_tenant_id, "Entra ID tenant"),
            item("AZURE_CLIENT_ID", s.azure_client_id, "Service principal application ID"),
            item("AZURE_CLIENT_SECRET or federated credential", s.azure_client_secret, "Secret from Secret Manager, or workload identity federation"),
            item("AZURE_PRINCIPAL_OBJECT_ID", s.azure_principal_object_id, "Needed to verify role assignments"),
        ]},
    ]

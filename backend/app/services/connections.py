"""Cloud connection settings managed from the dashboard.

Values saved here override the matching entries from .env. Only identifiers are accepted (role name,
organisation ID, tenant ID, ...). Credentials still come from the signed-in identity (CLI login locally,
managed identity or a secret store when hosted); the dashboard never takes a password or key."""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import CloudConnection, utcnow

_GUID = r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"
_REGION = r"^[a-z]{2}(-[a-z]+)+-\d$"

# provider -> field -> (label, help text, pattern or None, required, kind)
FIELDS: dict[str, dict[str, tuple]] = {
    "aws": {
        "aws_profile": ("CLI profile", "Local profile for the management account, as used with `aws sso login --profile`. Leave blank to use the default credentials.", r"^[\w.\-]{1,64}$", False, "text"),
        "aws_member_role_name": ("Member role name", "Read-only IAM role that exists in every member account.", r"^[\w+=,.@\-]{1,64}$", True, "text"),
        "aws_external_id": ("External ID", "External ID on the role's trust policy, if one is used.", r"^[\w+=,.@:/\-]{2,1224}$", False, "sensitive"),
        "aws_default_region": ("Home region", "Region used for global calls.", _REGION, False, "text"),
        "aws_regions": ("Regions to monitor", "Comma separated, e.g. ap-south-1, us-east-1. Leave blank for every enabled region.", None, False, "list"),
    },
    "gcp": {
        "gcp_organization_id": ("Organisation ID", "Numeric ID of the organisation whose folders and projects are discovered.", r"^\d{6,20}$", True, "text"),
        "gcp_billing_export_table": ("Billing export table", "BigQuery table as project.dataset.table. Needed for billing only.", r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$", False, "text"),
        "gcp_billing_query_project": ("Billing query project", "Project that runs the billing query. Defaults to the export table's project.", r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$", False, "text"),
    },
    "azure": {
        "azure_tenant_id": ("Tenant ID", "Microsoft Entra ID tenant (GUID).", _GUID, True, "text"),
        "azure_client_id": ("Application (client) ID", "Service principal application ID. Not needed when signed in with `az login`.", _GUID, False, "text"),
        "azure_principal_object_id": ("Principal object ID", "Object ID of the identity used, so role assignments can be verified.", _GUID, False, "text"),
    },
}
ENABLED_FIELD = {"aws": "aws_enabled", "gcp": "gcp_enabled", "azure": "azure_enabled"}
SIGN_IN = {
    "aws": "Sign in on this computer with `aws sso login --profile <profile>` before testing.",
    "gcp": "Sign in on this computer with `gcloud auth application-default login` before testing.",
    "azure": "Sign in on this computer with `az login --tenant <tenant-id>` before testing.",
}


class ConnectionError_(ValueError):
    """Invalid connection input; the message is safe to show to the user."""


def clean_config(provider: str, raw: dict) -> dict:
    """Validate and normalise submitted values. Unknown keys are rejected; blanks are dropped."""
    spec = FIELDS[provider]
    unknown = set(raw) - set(spec)
    if unknown:
        raise ConnectionError_(f"Unknown setting: {', '.join(sorted(unknown))}")
    out: dict = {}
    for key, (label, _help, pattern, _required, kind) in spec.items():
        value = raw.get(key)
        if kind == "list":
            items = [v.strip() for v in (value if isinstance(value, list) else str(value or "").split(",")) if v and v.strip()]
            bad = [v for v in items if not re.match(_REGION, v)]
            if bad:
                raise ConnectionError_(f"{label}: not a valid region name: {', '.join(bad)}")
            if items:
                out[key] = items
            continue
        value = str(value or "").strip()
        if not value:
            continue
        if pattern and not re.match(pattern, value):
            raise ConnectionError_(f"{label}: the value is not in the expected format")
        out[key] = value
    return out


def missing_required(provider: str, config: dict) -> list[str]:
    return [label for key, (label, _h, _p, required, _k) in FIELDS[provider].items() if required and not config.get(key)]


def effective_settings(db: Session, base: Settings) -> Settings:
    """Settings with dashboard-managed connection values applied on top of the environment."""
    update: dict = {}
    for conn in db.scalars(select(CloudConnection)):
        if conn.provider not in FIELDS:
            continue
        update[ENABLED_FIELD[conn.provider]] = bool(conn.enabled)
        for key in FIELDS[conn.provider]:
            if key in (conn.config or {}):
                update[key] = conn.config[key]
    if base.demo_mode:  # demo database: clouds stay disconnected even if a connection was saved in the dashboard
        update.update({"aws_enabled": False, "azure_enabled": False, "gcp_enabled": False})
    return base.model_copy(update=update) if update else base


def describe(db: Session, base: Settings) -> list[dict]:
    """Current connection state for the dashboard. Sensitive values are reported as set / not set only."""
    saved = {c.provider: c for c in db.scalars(select(CloudConnection))}
    eff = effective_settings(db, base)
    out = []
    for provider, spec in FIELDS.items():
        conn = saved.get(provider)
        fields = []
        for key, (label, help_text, _pattern, required, kind) in spec.items():
            value = getattr(eff, key, None)
            source = "dashboard" if conn and key in (conn.config or {}) else "environment" if value else "not set"
            shown = None if kind == "sensitive" else (", ".join(value) if isinstance(value, list) else value)
            fields.append({"key": key, "label": label, "help": help_text, "required": required, "kind": kind,
                           "value": shown or "", "is_set": bool(value), "source": source})
        out.append({"provider": provider, "enabled": bool(getattr(eff, ENABLED_FIELD[provider])), "managed_in_dashboard": conn is not None,
                    "sign_in": SIGN_IN[provider], "fields": fields,
                    "missing": [f["label"] for f in fields if f["required"] and not f["is_set"]],
                    "last_test": None if conn is None or conn.last_test_at is None else {
                        "at": conn.last_test_at.isoformat(), "ok": conn.last_test_ok, "detail": conn.last_test_detail},
                    "updated_by": conn.updated_by if conn else None})
    return out


def save(db: Session, provider: str, enabled: bool, raw: dict, keep_sensitive: bool, actor: str) -> CloudConnection:
    config = clean_config(provider, raw)
    conn = db.scalar(select(CloudConnection).where(CloudConnection.provider == provider))
    if conn is None:
        conn = CloudConnection(provider=provider, config={})
        db.add(conn)
    if keep_sensitive:  # a blank sensitive field in the form means "leave the stored value as it is"
        for key, spec in FIELDS[provider].items():
            if spec[4] == "sensitive" and key not in config and key in (conn.config or {}):
                config[key] = conn.config[key]
    if enabled and missing_required(provider, config):
        raise ConnectionError_(f"Cannot enable {provider.upper()}: missing {', '.join(missing_required(provider, config))}")
    if conn.config and "_wizard" in conn.config:  # onboarding wizard state (identifiers only) is kept
        config["_wizard"] = conn.config["_wizard"]
    conn.enabled, conn.config, conn.updated_by = enabled, config, actor
    return conn


def test_connection(db: Session, provider: str, base: Settings) -> dict:
    """Read-only check: list the organisation's scopes with the current sign-in. Nothing is stored except the result."""
    from app.services.registry import build_connector

    if base.demo_mode:
        return {"provider": provider, "ok": False, "detail": "Demo mode: no cloud is called. Connect clouds after leaving demo mode.", "scopes_visible": None}
    eff = effective_settings(db, base).model_copy(update={ENABLED_FIELD[provider]: True})
    connector = build_connector(provider, eff)
    missing = connector.missing_configuration()
    if missing:
        ok, detail, count = False, f"Missing settings: {', '.join(missing)}", None
    else:
        try:
            scopes = connector.discover()
            count = len(scopes)
            noun = {"aws": "account", "gcp": "project", "azure": "subscription"}[provider]
            ok, detail = True, f"Connected. {count} {noun}{'' if count == 1 else 's'} visible."
            if count == 0:
                ok, detail = False, f"Signed in, but no {noun}s are visible to this identity."
        except Exception as exc:  # noqa: BLE001 - shown to the user as the reason
            ok, detail, count = False, safe_error(exc, 300), None
    conn = db.scalar(select(CloudConnection).where(CloudConnection.provider == provider))
    if conn is not None:
        conn.last_test_at, conn.last_test_ok, conn.last_test_detail = utcnow(), ok, detail
    return {"provider": provider, "ok": ok, "detail": detail, "scopes_visible": count}

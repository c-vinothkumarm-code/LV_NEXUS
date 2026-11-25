"""Secrets from Azure Key Vault.

When AZURE_KEY_VAULT_URL is set, each secret below is read from the vault at start-up (read-only `secrets/get` with the
app's managed identity / workload identity / az login via DefaultAzureCredential) and takes precedence over the
environment and .env. Values are never logged; only the *source* of each secret is recorded so pre-flight can report it.

Policy (checked by pre-flight, not enforced by crashing so a misconfiguration is visible instead of silent):
- APP_ENV=production: secrets must come from Key Vault. A secret found only in .env or the process environment is a FAIL.
- APP_ENV=local / development / test: .env is fine."""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

# environment variable -> Key Vault secret name (Key Vault names allow letters, digits and dashes)
SECRETS = {
    "DATABASE_URL": "cloudnexus-database-url",
    "SESSION_SECRET": "cloudnexus-session-secret",
    "GOOGLE_CLIENT_SECRET": "cloudnexus-google-client-secret",
    "ENTRA_CLIENT_SECRET": "cloudnexus-entra-client-secret",
    "AZURE_CLIENT_SECRET": "cloudnexus-azure-client-secret",
    "CHAT_WEBHOOK_URL": "cloudnexus-chat-webhook-url",
    "GEMINI_API_KEY": "cloudnexus-gemini-api-key",
    "OPENAI_API_KEY": "cloudnexus-openai-api-key",
    "SMTP_PASSWORD": "cloudnexus-smtp-password",
}
SOURCES: dict[str, str] = {}   # env name -> key_vault | environment | dotenv | unset
STATUS: dict[str, str] = {"state": "not_configured", "message": "AZURE_KEY_VAULT_URL is not set"}


def _token(credential=None) -> str:
    if credential is None:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    return credential.get_token("https://vault.azure.net/.default").token


def load_key_vault(url: str | None, credential=None, http=None) -> dict[str, str]:
    """Read the configured secrets into os.environ. Missing secrets are skipped (they may be optional)."""
    SOURCES.clear()
    for env in SECRETS:
        SOURCES[env] = "environment" if os.environ.get(env) else "unset"
    if not url:
        STATUS.update(state="not_configured", message="AZURE_KEY_VAULT_URL is not set")
        return {}
    import httpx
    loaded: dict[str, str] = {}
    try:
        headers = {"Authorization": f"Bearer {_token(credential)}"}
        client = http or httpx.Client(timeout=httpx.Timeout(15, connect=5))
        for env, name in SECRETS.items():
            r = client.get(f"{url.rstrip('/')}/secrets/{name}", params={"api-version": "7.4"}, headers=headers)
            if r.status_code == 404:
                continue
            if r.status_code in (401, 403):
                raise PermissionError(f"Key Vault refused secrets/get for {name} (HTTP {r.status_code}). Grant the app identity the "
                                      "'Key Vault Secrets User' role on the vault.")
            r.raise_for_status()
            value = r.json().get("value")
            if value:
                os.environ[env] = value
                loaded[env] = name
                SOURCES[env] = "key_vault"
        STATUS.update(state="ok", message=f"{len(loaded)} secret(s) read from Key Vault")
    except Exception as exc:  # noqa: BLE001 - reported by pre-flight; the app still starts so the problem is visible
        from app.core.logging import safe_error
        STATUS.update(state="error", message=safe_error(exc))
        log.error("Key Vault secrets could not be read: %s", STATUS["message"])
    return loaded


def mark_dotenv(settings) -> None:
    """Secrets that have a value but came neither from Key Vault nor the process environment were read from .env."""
    field = {"DATABASE_URL": "database_url", "SESSION_SECRET": "secret_key", "GOOGLE_CLIENT_SECRET": "google_oauth_client_secret",
             "ENTRA_CLIENT_SECRET": "entra_client_secret", "AZURE_CLIENT_SECRET": "azure_client_secret", "CHAT_WEBHOOK_URL": "chat_webhook_url",
             "GEMINI_API_KEY": "gemini_api_key", "OPENAI_API_KEY": "openai_api_key",
             "SMTP_PASSWORD": "smtp_password"}
    for env, f in field.items():
        value = getattr(settings, f, None)
        default = type(settings).model_fields[f].default
        if SOURCES.get(env, "unset") == "unset" and value and value != default and not (env == "SESSION_SECRET" and os.environ.get("SECRET_KEY")):
            SOURCES[env] = "dotenv"
        if env == "SESSION_SECRET" and os.environ.get("SECRET_KEY") and SOURCES.get(env) == "unset":
            SOURCES[env] = "environment"

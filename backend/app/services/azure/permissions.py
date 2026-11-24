"""What to grant when Azure / Microsoft Entra refuses a read, phrased for the identity LV NEXUS actually uses.

LV NEXUS signs in to Azure either as an app registration (AZURE_CLIENT_ID + AZURE_CLIENT_SECRET / certificate:
needs Microsoft Graph *application* permissions with admin consent) or as a person / developer identity via `az login`
or a managed identity without a secret (needs Entra *directory roles*). Telling a user-based setup to "grant an
application permission" sends people down the wrong path, so every fix text comes from here.

All rights listed are read-only. Nothing here grants anything: an administrator does that in the portal."""
from __future__ import annotations

from app.core.config import Settings

# collection source -> (Graph application permission(s), Entra directory role for a signed-in user, what it is for)
GRAPH = {
    "entra_users": ("User.Read.All", "Global Reader (or Directory Readers)", "users and guests"),
    "entra_groups": ("Group.Read.All", "Global Reader (or Directory Readers)", "groups"),
    "entra_group_members": ("Group.Read.All", "Global Reader (or Directory Readers)", "group membership"),
    "entra_service_principals": ("Application.Read.All", "Global Reader (or Directory Readers)", "service principals and managed identities"),
    "entra_app_credentials": ("Application.Read.All", "Global Reader", "app secrets / certificates metadata"),
    "entra_directory_roles": ("RoleManagement.Read.Directory", "Global Reader", "Entra admin roles"),
    "entra_pim_eligible": ("RoleManagement.Read.Directory", "Global Reader", "PIM eligible roles"),
    "directory_audits": ("AuditLog.Read.All", "Global Reader (or Reports Reader / Security Reader)", "Entra audit logs"),
    "sign_ins": ("AuditLog.Read.All", "Global Reader (or Reports Reader / Security Reader)", "Entra sign-in logs"),
}
LICENCE_WORDS = ("requestfromnonpremiumtenant", "premium license", "premium licence", "aad premium", "p1 or p2")


def identity_kind(settings: Settings) -> str:
    """'app' (client secret / certificate), or 'user' (az login, developer sign-in or managed identity)."""
    if settings.azure_client_id and (settings.azure_client_secret or settings.azure_client_certificate_path):
        return "app"
    return "user"


def is_licence_error(text: str | None) -> bool:
    t = (text or "").lower().replace(" ", "")
    return any(w.replace(" ", "") in t for w in LICENCE_WORDS)


def graph_fix(settings: Settings, source: str) -> str:
    src = source.split(":", 1)[0]
    perm, role, what = GRAPH.get(src, ("the Microsoft Graph read permission named in the error", "Global Reader", src))
    if identity_kind(settings) == "app":
        return (f"In Entra ID → App registrations → the LV NEXUS app → API permissions, add Microsoft Graph application permission "
                f"{perm} and click 'Grant admin consent' (a Global Administrator must do this). Needed for {what}.")
    return (f"Ask a Global Administrator to assign the Entra role {role} to the account used by `az login`, then run "
            f"`az logout` and `az login` again so the new role is in the token. Needed for {what}.")


def management_group_fix(settings: Settings) -> str:
    who = "the LV NEXUS app" if identity_kind(settings) == "app" else "the account used by `az login`"
    return ("A Global Administrator turns on Entra ID → Properties → 'Access management for Azure resources', then assigns "
            f"Reader on Management groups → Tenant Root Group → Access control (IAM) to {who}, and turns the setting off again.")


def licence_note(source: str) -> str:
    return (f"{GRAPH.get(source, ('', '', source))[2].capitalize()} need a Microsoft Entra ID P1 or P2 licence in the tenant; "
            "the tenant does not have one, so this source is not available (not an error in LV NEXUS).")


def fix_for_source(settings: Settings, source: str, message: str | None = None) -> str | None:
    """Fix text for an Azure / Entra coverage entry, or None when the source is not an Azure directory source."""
    src = source.split(":", 1)[0]
    if src == "azure_management_groups" or "microsoft.management" in (message or "").lower():
        return management_group_fix(settings)
    if src in GRAPH or src.startswith("entra_"):
        return graph_fix(settings, src)
    return None

"""Server-side Google Workspace group lookup for role mapping.

Group membership is read by the backend from the Cloud Identity API with the application's own Google credentials
(Application Default Credentials: the Cloud Run service account, or `gcloud auth application-default login` locally).
That identity needs the Workspace "Groups Reader" admin role. Nothing from the browser is used.

If the lookup fails, no group-based role is granted (fail closed) and the reason is recorded; people who were
provisioned individually by an administrator keep their registry role."""
from __future__ import annotations

import logging

import httpx

from app.core.config import Settings
from app.core.security import ROLES

log = logging.getLogger(__name__)
_SCOPE = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
_URL = "https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchTransitiveGroups"


class GroupLookupError(RuntimeError):
    pass


def role_map(settings: Settings) -> dict[str, str]:
    """group e-mail -> role. Workspace admin groups map to the platform administrator role."""
    out: dict[str, str] = {}
    for entry in settings.google_group_role_map:
        group, _, role = entry.partition("=")
        group, role = group.strip().lower(), role.strip()
        if group and role in ROLES:
            out[group] = role
        else:
            log.warning("Ignoring GOOGLE_GROUP_ROLE_MAP entry %r (format group@domain=role, role must exist)", entry)
    for group in settings.google_workspace_admin_groups:
        out[group.strip().lower()] = "admin"
    return out


def _token() -> str:
    import google.auth
    import google.auth.transport.requests

    creds, _ = google.auth.default(scopes=[_SCOPE])
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


def lookup_groups(email: str) -> set[str]:
    """All groups (direct and nested) the person belongs to. Raises GroupLookupError on any failure."""
    try:
        headers = {"Authorization": f"Bearer {_token()}"}
        query = f"member_key_id == '{email}' && 'cloudidentity.googleapis.com/groups.discussion_forum' in labels"
        groups: set[str] = set()
        page = None
        for _ in range(20):
            params = {"query": query, "pageSize": 200, **({"pageToken": page} if page else {})}
            r = httpx.get(_URL, headers=headers, params=params, timeout=15)
            if r.status_code != 200:
                raise GroupLookupError(f"Cloud Identity API returned {r.status_code}")
            body = r.json()
            groups |= {m["groupKey"]["id"].lower() for m in body.get("memberships", []) if m.get("groupKey", {}).get("id")}
            page = body.get("nextPageToken")
            if not page:
                break
        return groups
    except GroupLookupError:
        raise
    except Exception as exc:  # credentials missing, network, unexpected payload
        raise GroupLookupError(type(exc).__name__) from None


def roles_for(email: str, settings: Settings, lookup=lookup_groups) -> tuple[list[str], str | None, str | None]:
    """(roles, matched group, error). Empty roles with no error = not in any mapped group."""
    mapping = role_map(settings)
    if not settings.google_group_lookup_enabled or not mapping:
        return [], None, None
    try:
        groups = lookup(email)
    except GroupLookupError as exc:
        return [], None, str(exc)
    matched = sorted(g for g in groups if g in mapping)
    if not matched:
        return [], None, None
    roles = sorted({mapping[g] for g in matched})
    return roles, matched[0], None

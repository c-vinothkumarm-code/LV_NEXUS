"""Audit activity categories and the detection-rule condition language.

Conditions are a JSON tree:  {"all": [...]} (AND), {"any": [...]} (OR), {"not": {...}} (NOT), or a leaf
{"field": <name>, "op": <operator>, "value": <value>}. String comparisons are case-insensitive.

Fields: provider, scope, region, operation, actor, source_ip, resource_id, resource_type, category, result
(success | failure | denied), user_agent, hour_utc, weekday_utc (0 = Monday), raw_text (the full event as JSON text),
raw.<dotted.path>, actor_new_operation (True when this actor has not performed this operation in the previous 30 days).
Operators: eq, neq, in, not_in, contains, contains_any, startswith, endswith, regex, cidr, not_cidr, exists, gt, gte, lt, lte.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

FIELDS = {"provider", "scope", "region", "operation", "actor", "source_ip", "resource_id", "resource_type", "category", "result",
          "user_agent", "hour_utc", "weekday_utc", "raw_text", "actor_new_operation"}
OPS = {"eq", "neq", "in", "not_in", "contains", "contains_any", "startswith", "endswith", "regex", "cidr", "not_cidr", "exists",
       "gt", "gte", "lt", "lte"}

# (category, provider-neutral substrings of the operation name); first match wins, order matters
CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("Authentication Failures", ("consolelogin_failure", "signin_failure")),
    ("Privilege Escalation", ("assumerolewithsaml_root", "elevateaccess", "createaccesskey", "updateassumerolepolicy")),
    ("Role Assignments", ("roleassignments", "setiampolicy", "attachrolepolicy", "attachuserpolicy", "attachgrouppolicy", "addusertogroup")),
    ("Permission Modifications", ("putuserpolicy", "putrolepolicy", "putgrouppolicy", "createpolicy", "deletepolicy", "roledefinitions",
                                  "detachrolepolicy", "detachuserpolicy", "setiampermissions")),
    ("User Creation", ("createuser", "createloginprofile", "serviceaccounts.create", "users/write")),
    ("User Deletion", ("deleteuser", "deleteloginprofile", "serviceaccounts.delete", "users/delete")),
    ("IAM Changes", ("iam.", "createrole", "deleterole", "updaterole", "createserviceaccountkey", "microsoft.authorization")),
    ("Security Group Changes", ("securitygroup", "networksecuritygroups", "securityrules")),
    ("Firewall Changes", ("firewall", "networkacl", "wafv2", "firewallpolicies")),
    ("Public IP Changes", ("allocateaddress", "associateaddress", "publicipaddresses", "addresses.insert")),
    ("Storage Public Access Changes", ("putbucketacl", "putbucketpolicy", "publicaccessblock", "storage.setiampermissions", "storageaccounts/write")),
    ("Encryption Configuration Changes", ("bucketencryption", "encryption", "diskencryption")),
    ("Key Vault Operations", ("microsoft.keyvault",)),
    ("Key Management Operations", ("kms", "cloudkms", "cryptokey", "schedulekeydeletion", "disablekey")),
    ("Secret Access", ("getsecretvalue", "secretmanager", "secrets/", "getparameter")),
    ("VM Creation", ("runinstances", "virtualmachines/write", "instances.insert")),
    ("VM Deletion", ("terminateinstances", "virtualmachines/delete", "instances.delete")),
    ("VM Configuration Changes", ("modifyinstance", "stopinstances", "startinstances", "instances.set", "virtualmachines/")),
    ("Database Changes", ("rds", "dbinstance", "sql.", "microsoft.sql", "dynamodb", "cloudsql", "documentdb")),
    ("Security Policy Changes", ("stoplogging", "deletetrail", "updatetrail", "diagnosticsettings", "securityhub", "guardduty", "deletesink",
                                 "microsoft.security", "policyassignments", "configrule", "configurationrecorder", "flowlogs")),
    ("Organization-Level Changes", ("organizations", "organization.", "managementgroups")),
    ("Subscription-Level Changes", ("microsoft.subscription", "subscriptions/write")),
    ("Project-Level Changes", ("projects.create", "projects.delete", "projects.update", "createproject", "deleteproject")),
    ("Network Configuration Changes", ("vpc", "subnet", "routetable", "virtualnetworks", "networks.", "routes.", "peering", "natgateway")),
    ("Resource Deletion", ("delete", "terminate", "remove")),
]


def categorize(operation: str | None, result: str | None = None) -> str:
    op = (operation or "").lower()
    if result == "denied":
        return "Unauthorized Access Attempts"
    for category, keys in CATEGORY_RULES:
        if any(k in op for k in keys):
            return category
    return "Administrative API Calls"


class EventView:
    """Attribute access for one audit event. `actor_new_operation` is computed only when a rule uses it."""

    def __init__(self, e, lookup_history=None):
        self.e, self._lookup = e, lookup_history
        raw = e.raw or {}
        ts = e.event_timestamp if e.event_timestamp.tzinfo else e.event_timestamp.replace(tzinfo=UTC)
        self.ts = ts
        self.values = {"provider": e.provider, "scope": e.scope_external_id, "region": e.region, "operation": e.event_name,
                       "actor": e.principal, "source_ip": e.source_ip, "resource_id": e.resource_id, "resource_type": e.resource_type,
                       "result": raw.get("outcome") or "success", "user_agent": raw.get("userAgent") or raw.get("user_agent"),
                       "hour_utc": ts.hour, "weekday_utc": ts.weekday()}
        self.values["category"] = categorize(e.event_name, self.values["result"])
        self._raw = raw
        self._raw_text: str | None = None

    def get(self, field: str):
        if field in self.values:
            return self.values[field]
        if field == "raw_text":
            if self._raw_text is None:
                self._raw_text = json.dumps(self._raw, default=str)
            return self._raw_text
        if field == "actor_new_operation":
            if "actor_new_operation" not in self.values:
                self.values["actor_new_operation"] = bool(self._lookup and self._lookup(self.e))
            return self.values["actor_new_operation"]
        if field.startswith("raw."):
            cur = self._raw
            for part in field[4:].split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            return cur
        return None


def _s(v) -> str:
    return "" if v is None else str(v).lower()


def _leaf(c: dict, ev: EventView) -> bool:
    op, want = c["op"], c.get("value")
    have = ev.get(c["field"])
    if op == "exists":
        return (have not in (None, "")) == bool(want if want is not None else True)
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, b = float(have), float(want)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op in ("cidr", "not_cidr"):
        try:
            ip = ipaddress.ip_address(str(have))
        except ValueError:
            return False  # no usable IP: neither inside nor outside
        inside = any(ip in ipaddress.ip_network(n, strict=False) for n in (want if isinstance(want, list) else [want]))
        return inside if op == "cidr" else not inside
    h = _s(have) if not isinstance(have, bool) else ("true" if have else "false")
    if op == "eq":
        return h == _s(want)
    if op == "neq":
        return h != _s(want)
    if op == "in":
        return h in {_s(x) for x in want or []}
    if op == "not_in":
        return h not in {_s(x) for x in want or []}
    if op == "contains":
        return _s(want) in h
    if op == "contains_any":
        return any(_s(x) in h for x in want or [])
    if op == "startswith":
        return h.startswith(_s(want))
    if op == "endswith":
        return h.endswith(_s(want))
    if op == "regex":
        return re.search(str(want), "" if have is None else str(have)) is not None
    return False


def evaluate(cond: dict | None, ev: EventView) -> bool:
    if not cond:
        return False
    if "all" in cond:
        return all(evaluate(c, ev) for c in cond["all"])
    if "any" in cond:
        return any(evaluate(c, ev) for c in cond["any"])
    if "not" in cond:
        return not evaluate(cond["not"], ev)
    return _leaf(cond, ev)


def validate(cond, depth: int = 0) -> None:
    """Raise ValueError with a readable message for a malformed condition tree."""
    if depth > 12:
        raise ValueError("Conditions are nested too deeply")
    if not isinstance(cond, dict) or not cond:
        raise ValueError("Each condition must be an object")
    for key in ("all", "any"):
        if key in cond:
            if not isinstance(cond[key], list) or not cond[key]:
                raise ValueError(f"'{key}' needs a non-empty list")
            for c in cond[key]:
                validate(c, depth + 1)
            return
    if "not" in cond:
        return validate(cond["not"], depth + 1)
    f, op = cond.get("field"), cond.get("op")
    if not (f in FIELDS or str(f).startswith("raw.")):
        raise ValueError(f"Unknown field '{f}'")
    if op not in OPS:
        raise ValueError(f"Unknown operator '{op}'")
    if op in ("in", "not_in", "contains_any") and not isinstance(cond.get("value"), list):
        raise ValueError(f"'{op}' needs a list value")
    if op == "regex":
        try:
            re.compile(str(cond.get("value")))
        except re.error as exc:
            raise ValueError(f"Invalid regular expression: {exc}") from exc
    if op in ("cidr", "not_cidr"):
        for n in cond.get("value") if isinstance(cond.get("value"), list) else [cond.get("value")]:
            try:
                ipaddress.ip_network(str(n), strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR '{n}'") from exc


def in_change_window(window: dict | None, ts: datetime) -> bool:
    """True when the event falls inside the approved change window (so a window-based rule does NOT fire)."""
    if not window:
        return False
    local = ts.astimezone(ZoneInfo(window.get("tz") or "UTC"))
    if local.weekday() not in set(window.get("days", range(7))):
        return False
    start, end = (window.get("start") or "00:00"), (window.get("end") or "23:59")
    return start <= local.strftime("%H:%M") <= end


def window_start(ts: datetime, minutes: int) -> datetime:
    return ts - timedelta(minutes=minutes)

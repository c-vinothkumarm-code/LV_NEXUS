"""Standards-based SOC detections (MITRE ATT&CK / CIS Azure): each fires on a realistic Azure Activity Log or Entra ID
event, stays quiet on routine activity, and thresholds need the stated frequency."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.models import AuditEvent, DetectionRule
from app.services.audit.engine import match_rule
from app.services.audit.rules import EventView
from app.services.vuln.defaults import DETECTION_DEFAULTS

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=UTC)  # Wednesday 10:30 IST (inside business hours)
RULES = {d["rule_key"]: d for d in DETECTION_DEFAULTS}


def _rule(key):
    spec = {"provider": None, "threshold_count": 1, "threshold_window_minutes": 0, "group_by": "principal", "change_window": None, **RULES[key]}
    return DetectionRule(**{k: v for k, v in spec.items() if k != "description"})


def _ev(op, raw=None, actor="alice@contoso.example", ip="203.0.113.5", ts=T0, n=0, scope="sub-1"):
    return AuditEvent(id=None, event_id=f"x{n}-{op}", provider="azure", scope_external_id=scope, event_timestamp=ts, event_name=op, principal=actor,
                      source_ip=ip, raw={"outcome": "success", **(raw or {})})


CASES = [
    ("AUD-012", "Add member to role", {"targetResources": [{"modifiedProperties": [{"newValue": "\"Global Administrator\""}]}]}),
    ("AUD-013", "Add service principal credentials", None),
    ("AUD-014", "Consent to application", None),
    ("AUD-015", "Disable Strong Authentication", None),
    ("AUD-016", "Update conditional access policy", None),
    ("AUD-017", "Invite external user", None),
    ("AUD-018", "Set federation settings on domain", None),
    ("AUD-021", "Sign-in", {"riskLevel": "high"}),
    ("AUD-022", "Sign-in", {"clientApp": "IMAP4"}),
    ("AUD-023", "Microsoft.Authorization/roleDefinitions/write", None),
    ("AUD-024", "Microsoft.Authorization/elevateAccess/action", None),
    ("AUD-025", "Microsoft.Authorization/locks/delete", None),
    ("AUD-026", "Microsoft.Authorization/policyAssignments/delete", None),
    ("AUD-027", "Microsoft.Security/pricings/write", None),
    ("AUD-028", "Microsoft.Insights/activityLogAlerts/delete", None),
    ("AUD-029", "Microsoft.KeyVault/vaults/accessPolicies/write", None),
    ("AUD-031", "Microsoft.Compute/disks/beginGetAccess/action", None),
    ("AUD-032", "Microsoft.Compute/virtualMachines/runCommand/action", None),
    ("AUD-033", "Microsoft.Sql/servers/firewallRules/write", {"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}),
    ("AUD-034", "Microsoft.Subscription/cancel/action", None),
]


@pytest.mark.parametrize("key,op,raw", CASES)
def test_rule_fires_on_matching_event(db, key, op, raw):
    e = _ev(op, raw)
    db.add(e)
    db.commit()
    assert match_rule(db, _rule(key), EventView(e)), key


def test_routine_activity_does_not_fire(db):
    routine = [_ev("Sign-in"), _ev("Microsoft.Compute/virtualMachines/read"), _ev("Microsoft.Storage/storageAccounts/read"),
               _ev("Add member to role", {"targetResources": [{"displayName": "Reports Reader"}]}), _ev("Update user")]
    db.add_all(routine)
    db.commit()
    new_keys = [k for k in RULES if int(k.split("-")[1]) >= 12]
    fired = {(k, e.event_name) for e in routine for k in new_keys if match_rule(db, _rule(k), EventView(e))}
    assert fired == set()


def test_brute_force_needs_ten_failures_and_spray_groups_by_ip(db):
    for i in range(9):
        db.add(_ev("Sign-in", {"outcome": "failure"}, n=i, ts=T0 + timedelta(minutes=i)))
    db.commit()
    last = _ev("Sign-in", {"outcome": "failure"}, n=99, ts=T0 + timedelta(minutes=10))
    assert match_rule(db, _rule("AUD-019"), EventView(_ev("Sign-in", {"outcome": "failure"}, n=98, ts=T0 + timedelta(minutes=9)))) is None
    db.add(last)
    db.commit()
    assert "threshold 10" in match_rule(db, _rule("AUD-019"), EventView(last))
    for i in range(20):  # 20 different accounts, one IP
        db.add(_ev("Sign-in", {"outcome": "failure"}, actor=f"user{i}@contoso.example", ip="198.51.100.7", n=200 + i, ts=T0 + timedelta(minutes=i)))
    db.commit()
    probe = _ev("Sign-in", {"outcome": "failure"}, actor="user19@contoso.example", ip="198.51.100.7", n=219, ts=T0 + timedelta(minutes=19))
    assert "same source_ip" in match_rule(db, _rule("AUD-020"), EventView(probe))


def test_role_change_after_hours_only(db):
    day, night = _ev("Microsoft.Authorization/roleAssignments/write"), _ev("Microsoft.Authorization/roleAssignments/write", ts=T0 + timedelta(hours=14), n=1)
    db.add_all([day, night])
    db.commit()
    assert match_rule(db, _rule("AUD-035"), EventView(day)) is None
    assert "outside the approved change window" in match_rule(db, _rule("AUD-035"), EventView(night))

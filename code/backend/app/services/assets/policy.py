"""Activity classification thresholds and inactivity notification settings (configurable in the UI)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetPolicy

KEY = "activity"
DEFAULTS: dict = {
    "window_days": 14,                 # utilisation window (VM metrics collected every 15 minutes)
    "min_coverage_hours": 24,          # less monitoring data than this -> Unknown
    "low_cpu_percent": 10.0,           # average CPU below this -> Low Activity
    "inactive_cpu_percent": 2.0,       # average CPU below this ...
    "inactive_network_mb_per_day": 50.0,  # ... and network below this ...
    "inactive_days": 30,               # ... and no management activity for this many days -> Inactive
    "stopped_review_days": 30,         # stopped longer than this -> recommend review
    "service_active_days": 30,         # non-VM services: management activity within this -> Active (no utilisation metric)
    "activity_lookback_days": 180,     # how far back audit events are searched for last activity / login
    "notify_enabled": True,
    "notify_every_days": 7,            # one digest per SPOC per period
    "notify_classifications": ["Inactive", "Stopped"],
}
LIMITS = {"window_days": (1, 90), "min_coverage_hours": (1, 720), "low_cpu_percent": (0, 100), "inactive_cpu_percent": (0, 100),
          "inactive_network_mb_per_day": (0, 1_000_000), "inactive_days": (1, 3650), "stopped_review_days": (1, 3650),
          "service_active_days": (1, 3650), "activity_lookback_days": (7, 3650), "notify_every_days": (1, 90)}


class PolicyError(ValueError):
    pass


def get(db: Session) -> dict:
    row = db.scalar(select(AssetPolicy).where(AssetPolicy.key == KEY))
    return {**DEFAULTS, **((row.value or {}) if row else {})}


def save(db: Session, values: dict, actor: str) -> tuple[dict, dict]:
    unknown = set(values) - set(DEFAULTS)
    if unknown:
        raise PolicyError(f"Unknown setting: {', '.join(sorted(unknown))}")
    clean: dict = {}
    for k, v in values.items():
        if k in LIMITS:
            lo, hi = LIMITS[k]
            try:
                num = float(v)
            except (TypeError, ValueError) as exc:
                raise PolicyError(f"{k} must be a number") from exc
            if not lo <= num <= hi:
                raise PolicyError(f"{k} must be between {lo} and {hi}")
            clean[k] = int(num) if isinstance(DEFAULTS[k], int) else num
        elif k == "notify_enabled":
            clean[k] = bool(v)
        elif k == "notify_classifications":
            allowed = {"Inactive", "Stopped", "Low Activity", "Unknown"}
            if not isinstance(v, list) or not set(v) <= allowed:
                raise PolicyError(f"notify_classifications: choose from {', '.join(sorted(allowed))}")
            clean[k] = sorted(set(v))
    current = get(db)
    if clean.get("inactive_cpu_percent", current["inactive_cpu_percent"]) > clean.get("low_cpu_percent", current["low_cpu_percent"]):
        raise PolicyError("inactive_cpu_percent must not be higher than low_cpu_percent")
    row = db.scalar(select(AssetPolicy).where(AssetPolicy.key == KEY))
    if row is None:
        row = AssetPolicy(key=KEY, value={})
        db.add(row)
    before = {k: current[k] for k in clean}
    row.value = {**(row.value or {}), **clean}
    row.updated_by = actor
    return get(db), before

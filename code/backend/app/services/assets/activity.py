"""Activity classification of assets. Pure functions: the inputs come from data LV NEXUS already collected
(VM power state and 15-minute metrics, audit events, resource state) - no extra cloud calls.

Classes: Active · Low Activity · Inactive · Stopped · Terminated / Deleted · Unknown.
Nothing here ever stops or deletes a resource: the result is a recommendation for the SPOC to validate."""
from __future__ import annotations

from datetime import UTC, datetime

ACTIVE, LOW, INACTIVE, STOPPED, GONE, UNKNOWN = "Active", "Low Activity", "Inactive", "Stopped", "Terminated / Deleted", "Unknown"
CLASSES = (ACTIVE, LOW, INACTIVE, STOPPED, GONE, UNKNOWN)
STOPPED_STATES = {"stopped", "stopping", "deallocated", "deallocating", "suspended", "terminated_stopped", "vm stopped", "vm deallocated", "disabled"}
GONE_STATES = {"deleted", "terminated", "terminating"}


def _aware(v: datetime | None) -> datetime | None:
    return None if v is None else v if v.tzinfo else v.replace(tzinfo=UTC)


def _days(since: datetime | None, now: datetime) -> float | None:
    since = _aware(since)
    return None if since is None else (now - since).total_seconds() / 86400


def classify(*, kind: str, state: str | None, deleted: bool, metrics: dict | None, last_activity_at: datetime | None,
             stopped_since: datetime | None, policy: dict, now: datetime | None = None) -> tuple[str, str]:
    """Returns (classification, reason). `metrics` = {"cpu_avg", "network_mb_per_day", "coverage_hours", "samples"} or None."""
    now = now or datetime.now(UTC)
    st = (state or "").lower()
    idle_days = _days(last_activity_at, now)
    activity_txt = f"last management activity {idle_days:.0f} days ago" if idle_days is not None else "no management activity recorded"
    if deleted or st in GONE_STATES:
        return GONE, "Reported deleted / terminated by the provider"
    if st in STOPPED_STATES:
        d = _days(stopped_since, now)
        return STOPPED, f"Power state {state}" + (f" for {d:.0f} day(s)" if d is not None and d >= 1 else " since today" if d is not None
                                                  else " (stop time not recorded)")
    if kind != "server":
        if idle_days is not None and idle_days <= policy["service_active_days"]:
            return ACTIVE, f"No utilisation metric for this service type; {activity_txt}"
        return UNKNOWN, f"No utilisation metric for this service type; {activity_txt}"
    if st not in ("running", "") and st != "unknown":
        return UNKNOWN, f"Power state '{state}' not recognised"
    if not metrics or not metrics.get("samples") or (metrics.get("coverage_hours") or 0) < policy["min_coverage_hours"]:
        cov = (metrics or {}).get("coverage_hours") or 0
        return UNKNOWN, f"Not enough monitoring data ({cov:.0f} h of {policy['min_coverage_hours']} h needed) – check that metrics are collected"
    cpu, net = metrics.get("cpu_avg"), metrics.get("network_mb_per_day")
    if cpu is None:
        return UNKNOWN, "CPU metric not reported"
    window = f"{policy['window_days']}-day average CPU {cpu:.1f}%"
    quiet_net = net is None or net < policy["inactive_network_mb_per_day"]
    quiet_mgmt = idle_days is None or idle_days >= policy["inactive_days"]
    if cpu < policy["inactive_cpu_percent"] and quiet_net and quiet_mgmt:
        net_txt = "network not reported" if net is None else f"network {net:.0f} MB/day"
        return INACTIVE, f"{window}, {net_txt}, {activity_txt}"
    if cpu < policy["low_cpu_percent"]:
        return LOW, f"{window} (below {policy['low_cpu_percent']}%)"
    return ACTIVE, window


def recommend(classification: str, *, kind: str, stopped_days: float | None, policy: dict, backup_protected: bool | None,
              environment: str | None, planned_end_date=None, today=None) -> str:
    """Recommended action. Never an automatic action: every change needs business validation and approval."""
    parts = {
        ACTIVE: "No action",
        LOW: "Review right-sizing with the SPOC (smaller size or schedule)",
        INACTIVE: "Confirm business need with the SPOC; if not needed, stop / deallocate after approval (no automatic action)",
        UNKNOWN: "Enable monitoring (metrics / agent) so activity can be assessed" if kind == "server" else "Review usage with the asset owner",
        GONE: "Confirm decommissioning and close the record",
        STOPPED: ("Stopped (since when is not recorded yet): confirm with the SPOC whether it is still needed" if stopped_days is None else
                  "Stopped longer than the review period: confirm if still needed; back up, then delete after approval"
                  if stopped_days >= policy["stopped_review_days"] else "Stopped recently: re-check at the next review"),
    }
    action = parts[classification]
    extra = []
    if planned_end_date and today and planned_end_date < today and classification not in (GONE,):
        extra.append(f"planned end date {planned_end_date.isoformat()} has passed")
    if kind == "server" and backup_protected is False and (environment or "").lower() == "production" and classification != GONE:
        extra.append("no backup recorded for a production server")
    return action + ("; " + "; ".join(extra) if extra else "")

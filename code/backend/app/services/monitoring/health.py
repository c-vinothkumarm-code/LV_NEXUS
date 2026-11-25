"""VM health evaluation. Missing data is reported as missing; it never counts as healthy."""
from __future__ import annotations

import json

from app.core.config import Settings
from app.models import Severity

CHECKED = (("cpu", "cpu_percent"), ("memory", "memory_percent"), ("disk", "disk_percent"))
SENSITIVE_PORTS = {"22", "3389", "3306", "5432", "1433", "27017", "6379", "9200"}


def thresholds(settings: Settings, environment: str | None) -> dict[str, tuple[float, float]]:
    t = {"cpu": (settings.vm_cpu_warning, settings.vm_cpu_critical), "memory": (settings.vm_memory_warning, settings.vm_memory_critical),
         "disk": (settings.vm_disk_warning, settings.vm_disk_critical)}
    if settings.vm_threshold_overrides and environment:
        try:
            for k, v in (json.loads(settings.vm_threshold_overrides).get(environment.lower()) or {}).items():
                if k in t and len(v) == 2:
                    t[k] = (float(v[0]), float(v[1]))
        except (ValueError, TypeError, AttributeError):
            pass  # a malformed override must not stop monitoring; defaults apply
    return t


def port_is_sensitive(port: str) -> bool:
    if port == "all" or port.endswith("/all"):
        return True
    rng = port.split("/")[-1]
    lo, _, hi = rng.partition("-")
    try:
        return any(int(lo) <= int(p) <= int(hi or lo) for p in SENSITIVE_PORTS)
    except ValueError:
        return False


def evaluate(vm: dict, settings: Settings) -> tuple[str, list[str], list[dict]]:
    """Returns (health_status, missing_metrics, alerts).

    health_status: healthy | partial | warning | critical | stopped | unknown
      partial = the metrics that are available are within thresholds, but some required metrics are missing."""
    alerts: list[dict] = []
    if vm.get("public_ip") and vm.get("exposed_ports"):
        risky = [p for p in vm["exposed_ports"] if port_is_sensitive(p)]
        alerts.append({"type": "public_port_exposure", "severity": (Severity.HIGH if risky else Severity.MEDIUM).value,
                       "message": f"Open to the internet on {', '.join(vm['exposed_ports'][:8])} (public IP {vm['public_ip']})"})
    if vm["power_state"] != "running":
        return ("stopped" if vm["power_state"] in ("stopped", "deallocated") else "unknown"), [], alerts
    m, t = vm["metrics"], thresholds(settings, vm.get("environment"))
    missing = [name for name, key in CHECKED if m.get(key) is None]
    worst = "healthy"
    for name, key in CHECKED:
        value = m.get(key)
        if value is None:
            continue
        warn, crit = t[name]
        if value >= crit:
            worst = "critical"
            alerts.append({"type": f"{name}_high", "severity": Severity.CRITICAL.value, "value": value, "threshold": crit,
                           "message": f"{name.upper()} at {value:.1f}% (critical threshold {crit:g}%)"})
        elif value >= warn:
            worst = "warning" if worst != "critical" else worst
            alerts.append({"type": f"{name}_high", "severity": Severity.MEDIUM.value, "value": value, "threshold": warn,
                           "message": f"{name.upper()} at {value:.1f}% (warning threshold {warn:g}%)"})
    if missing:
        alerts.append({"type": "missing_metrics", "severity": Severity.LOW.value,
                       "message": f"No {', '.join(missing)} metrics. Memory and disk usually need a guest monitoring agent."})
    if len(missing) == len(CHECKED):
        return "unknown", missing, alerts
    if worst == "healthy" and missing:
        return "partial", missing, alerts
    return worst, missing, alerts

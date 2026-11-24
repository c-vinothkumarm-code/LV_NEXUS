"""Live, read-only validation of a cloud connection, using the same connector code the scheduled jobs use.

    python -m app.validate_cloud aws            # every AWS account the management role can see
    python -m app.validate_cloud gcp --max 20   # first 20 GCP projects
    python -m app.validate_cloud azure

For each account / subscription / project it runs the onboarding checks (authentication, permissions, audit logs,
billing, monitoring, security findings) against the real APIs and prints PASS / FAIL / UNKNOWN with the exact fix.
Writes validation-<cloud>-<time>.md next to it. Nothing is changed in the cloud or in the LV NEXUS database."""
from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import configure_logging, safe_error


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.validate_cloud")
    ap.add_argument("provider", choices=["aws", "gcp", "azure"])
    ap.add_argument("--max", type=int, default=50, help="validate at most this many scopes (default 50)")
    a = ap.parse_args(argv)
    configure_logging("WARNING")
    s = get_settings()
    if not getattr(s, f"{a.provider}_enabled"):
        print(f"{a.provider.upper()}_ENABLED is false in backend/.env: set it to true and fill the {a.provider.upper()}_* values first.")
        return 2
    from app.services.registry import build_connectors
    conn = next((c for c in build_connectors(s) if c.provider == a.provider), None)
    if conn is None:
        print(f"No connector built for {a.provider}")
        return 2
    missing = conn.missing_configuration()
    if missing:
        print(f"Missing settings for {a.provider}: {', '.join(missing)}")
        return 2
    lines = [f"# LV NEXUS live validation: {a.provider.upper()}", f"Run {datetime.now(UTC):%Y-%m-%d %H:%M} UTC, read-only", ""]
    t0 = time.monotonic()
    try:
        scopes = conn.discover()
    except Exception as exc:  # noqa: BLE001
        msg = safe_error(exc, 400)
        print(f"DISCOVERY FAILED: {msg}")
        lines.append(f"Discovery FAILED: {msg}")
        _write(a.provider, lines)
        return 1
    active = [x for x in scopes if x.is_active]
    print(f"Discovery OK: {len(scopes)} found, {len(active)} active ({time.monotonic() - t0:.1f} s). Validating up to {a.max}...\n")
    lines += [f"Discovery: {len(scopes)} found, {len(active)} active", "", "| Scope | Check | Result | Detail | Fix |", "| --- | --- | --- | --- | --- |"]
    worst = 0
    counts = {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0}
    for sc in active[: a.max]:
        try:
            results = conn.validate(sc)
        except Exception as exc:  # noqa: BLE001
            results = {"validation": type("R", (), {"status": "fail", "detail": safe_error(exc, 300), "remediation": None})()}
        print(f"{sc.name} ({sc.external_id})")
        for check, res in results.items():
            st = str(res.status).lower()
            counts[st] = counts.get(st, 0) + 1
            worst = max(worst, 1 if st == "fail" else 0)
            mark = {"pass": "PASS ", "fail": "FAIL ", "unknown": "UNKN ", "not_applicable": "N/A  "}.get(st, st.upper()[:5])
            print(f"   {mark} {check:<20} {(res.detail or '')[:110]}")
            if st != "pass" and getattr(res, "remediation", None):
                print(f"         fix: {res.remediation[:150]}")
            lines.append(f"| {sc.name} | {check} | {st.upper()} | {(res.detail or '').replace('|', '/')[:200]} | {(getattr(res, 'remediation', '') or '').replace('|', '/')[:200]} |")
    summary = ", ".join(f"{k}: {v}" for k, v in counts.items() if v)
    print(f"\nSummary: {summary}")
    lines += ["", f"Summary: {summary}"]
    path = _write(a.provider, lines)
    print(f"Report written to {path}")
    return worst


def _write(provider: str, lines: list[str]) -> Path:
    p = Path(f"validation-{provider}-{datetime.now(UTC):%Y%m%d-%H%M}.md").resolve()
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


if __name__ == "__main__":
    sys.exit(main())

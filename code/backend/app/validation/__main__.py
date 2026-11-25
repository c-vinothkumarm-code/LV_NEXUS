"""Validation and evidence tools (read-only towards every cloud).

  python -m app.validation preflight                 configuration, database, scheduler, freshness
  python -m app.validation azure --hours 24 --days 7 reconcile Azure against the application
  python -m app.validation evidence --tests          build the review evidence pack (zip)

Reports are written to ../evidence/ (next to backend/). Exit code 1 when any check FAILs."""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.database.session import get_session_factory
from app.services.connections import effective_settings

OUT = Path(__file__).resolve().parents[3] / "evidence"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.validation")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pf = sub.add_parser("preflight")
    pf.add_argument("--demo", action="store_true", help="treat developer sign-in as a warning, not a failure")
    az = sub.add_parser("azure")
    az.add_argument("--hours", type=int, default=24, help="activity-log window to compare")
    az.add_argument("--days", type=int, default=7, help="cost window to compare (complete days)")
    ev = sub.add_parser("evidence")
    ev.add_argument("--days", type=int, default=14)
    ev.add_argument("--tests", action="store_true", help="also run the automated test suite and include its results")
    for p in (pf, az, ev):
        p.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    configure_logging("WARNING", fmt="text")
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    with get_session_factory()() as db:
        s = effective_settings(db, get_settings())
        if args.cmd == "preflight":
            from .preflight import run_preflight
            rep = run_preflight(db, s, for_review=not args.demo)
            rep.print()
            print("written:", *rep.write(args.out, f"preflight-{stamp}"))
            return 1 if rep.overall == "FAIL" else 0
        if args.cmd == "azure":
            from app.services.azure.connector import AzureClients

            from .azure_reconcile import AzureReconciler
            rec = AzureReconciler(db, s, AzureClients(s))
            try:
                rep = rec.run(args.hours, args.days)
            except SystemExit:
                rep = rec.report
            rep.print()
            print("written:", *rep.write(args.out, f"azure-reconciliation-{stamp}"))
            return 1 if rep.overall == "FAIL" else 0
        from .evidence import build_pack
        latest = sorted(args.out.glob("*.md")) + sorted(args.out.glob("*.json")) if args.out.exists() else []
        z = build_pack(db, s, args.out, args.days, args.tests, [p for p in latest if p.is_file()])
        print("evidence pack:", z)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

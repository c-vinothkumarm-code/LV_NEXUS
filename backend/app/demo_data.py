"""Load FICTIONAL demo data into a separate SQLite demo database, to review LV NEXUS before any cloud is connected.

    $env:DEMO_MODE="true"; $env:DATABASE_URL="sqlite:///./lvnexus-demo.db"; python -m app.demo_data

Safety
- Runs only with DEMO_MODE=true and a SQLite file whose name contains "demo" (enforced by the settings), never on MySQL
  or the real database, never with APP_ENV=production.
- Everything is invented (contoso / example.com / 1000000000xx accounts). No cloud is called. The application shows a
  "Demo data" banner on every page while DEMO_MODE is on.
- Refuses to load twice into the same file; delete the file (or use --reset) to start again.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.config import get_settings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.demo_data")
    ap.add_argument("--reset", action="store_true", help="delete the demo database file first")
    a = ap.parse_args(argv)
    s = get_settings()  # validates: DEMO_MODE only with a demo SQLite file, never in production
    if not s.demo_mode:
        print("Set DEMO_MODE=true and DATABASE_URL=sqlite:///./lvnexus-demo.db first (a separate demo database).")
        return 2
    path = Path(s.database_url.split("///", 1)[-1])
    if a.reset and path.exists():
        path.unlink()
        print(f"deleted {path}")

    from sqlalchemy import func, select

    from app.database.seed import seed_reference_data
    from app.database.session import get_engine, get_session_factory
    from app.models import AuditEvent, CloudAccount
    from app.models.base import Base
    from app.scheduler.engine import JobContext
    try:
        from tests.integration import sample_estate
    except ImportError:
        print("Run this from the backend folder (it uses tests/integration/sample_estate.py, the fictional estate).")
        return 2

    Base.metadata.create_all(get_engine())  # a fresh demo file only; the real database is migrated with alembic
    now = datetime.now(UTC)
    with get_session_factory()() as db:
        if (db.scalar(select(func.count()).select_from(CloudAccount)) or 0) > 0:
            print(f"{path} already has demo data. Use --reset to load it again.")
            return 0
        seed_reference_data(db)
        db.commit()
        sample_estate.seed(db)
        db.commit()
        acct = db.scalar(select(CloudAccount.external_id).order_by(CloudAccount.id)) or "demo-aws"
        sg = {"outcome": "success", "requestParameters": {"groupId": "sg-0demo", "ipPermissions": {"items": [
            {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}}
        events = [
            ("aws", acct, "AuthorizeSecurityGroupIngress", f"arn:aws:sts::{acct}:assumed-role/Admin/dev.user@example.com", sg, 3, "sg-0demo", "ap-south-1"),
            ("aws", acct, "CreateUser", f"arn:aws:sts::{acct}:assumed-role/Admin/cloud.admin@example.com", {"requestParameters": {"userName": "new.joiner"}}, 6, None, "ap-south-1"),
            ("aws", acct, "CreateAccessKey", f"arn:aws:iam::{acct}:user/new.joiner", {"requestParameters": {"userName": "new.joiner"}}, 5, None, "ap-south-1"),
            ("gcp", "demo-analytics", "SetIamPolicy", "dev.user@example.com", {"serviceData": {"policyDelta": {"bindingDeltas": [
                {"action": "ADD", "role": "roles/owner", "member": "user:contractor@example.com"}]}}}, 8, None, "global"),
            ("aws", acct, "StopLogging", f"arn:aws:sts::{acct}:assumed-role/Admin/dev.user@example.com", {"requestParameters": {"name": "org-trail"}}, 2, None, "ap-south-1"),
            ("azure", "sub-prod", "Microsoft.Authorization/roleAssignments/write", "ops@example.com",
             {"properties": {"requestbody": '{"properties":{"principalId":"p-1","roleDefinitionId":"/x/roleDefinitions/acdd72a7"}}'}}, 10, None, None),
            ("aws", acct, "RunInstances", f"arn:aws:sts::{acct}:assumed-role/Admin/dev.user@example.com",
             {"requestParameters": {"instanceType": "p4d.24xlarge"}}, 4, "i-0demo", "ap-south-1"),
        ]
        for i, (prov, scope, op, actor, raw, hours, res, region) in enumerate(events, 1):
            db.add(AuditEvent(event_id=f"demo-{i}", provider=prov, scope_external_id=scope, region=region, event_timestamp=now - timedelta(hours=hours),
                              event_name=op, principal=actor, source_ip="203.0.113.10", resource_id=res, raw={"outcome": "success", **raw},
                              collected_at=now - timedelta(hours=hours) + timedelta(minutes=6)))
        db.add(AuditEvent(event_id="entra-audit:demo-8", provider="azure", scope_external_id="tenant-demo", event_timestamp=now - timedelta(hours=20),
                          event_name="Add user", principal="it.admin@example.com", source_ip="203.0.113.10",
                          raw={"outcome": "success", "targetResources": [{"userPrincipalName": "intern@example.com"}]}, collected_at=now - timedelta(hours=19)))
        db.commit()
        from app.services.audit.engine import run_audit_evaluation
        from app.services.compliance.engine import run_compliance_job
        ctx = JobContext(db=db, execution_id=None, job=None)
        run_audit_evaluation(ctx, s)
        try:
            run_compliance_job(ctx, s)
        except Exception as exc:  # noqa: BLE001 - compliance is optional in the demo
            print("compliance evaluation skipped:", exc)
        db.commit()
    print(f"Demo database ready: {path.resolve()} (fictional data only). Start the API with the same DEMO_MODE and DATABASE_URL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

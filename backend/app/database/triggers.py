"""Database-level append-only enforcement for history tables, per dialect.

    python -m app.database.triggers      # (re)create the triggers; safe to run again

MySQL note: with binary logging on, creating triggers needs a privileged user or
`SET GLOBAL log_bin_trust_function_creators = 1` (run once as root in MySQL Workbench)."""
from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.engine import Connection

IMMUTABLE_TABLES = ("onboarding_records", "security_reviews", "admin_audit_logs",
                    "finding_status_history", "finding_comments", "security_evidence", "exception_approvals",
                    "audit_status_history", "audit_notes", "audit_rule_history",
                    "access_audit_logs",
                    "budget_revisions", "budget_approvals", "budget_audit_events",
                    "access_approvals", "access_audit_events",
                    "control_evidence", "governance_audit_events", "ai_action_events",
                    "identity_change_events", "audit_trail", "ai_analysis_results")
log = logging.getLogger(__name__)


def trigger_statements(dialect: str, tables: set[str] | None = None) -> list[str]:
    stmts: list[str] = []
    if dialect == "postgresql":
        stmts.append("CREATE OR REPLACE FUNCTION mcp_deny_mutation() RETURNS trigger AS $$ BEGIN "
                     "RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END; $$ LANGUAGE plpgsql")
    for t in IMMUTABLE_TABLES:
        if tables is not None and t not in tables:
            continue  # table created by a later migration: its own migration adds the trigger
        if dialect == "postgresql":
            stmts += [f"DROP TRIGGER IF EXISTS {t}_immutable ON {t}",
                      f"CREATE TRIGGER {t}_immutable BEFORE UPDATE OR DELETE ON {t} FOR EACH ROW EXECUTE FUNCTION mcp_deny_mutation()"]
        elif dialect == "mysql":
            for action in ("UPDATE", "DELETE"):
                name = f"{t}_no_{action.lower()}"
                stmts += [f"DROP TRIGGER IF EXISTS {name}",
                          f"CREATE TRIGGER {name} BEFORE {action} ON {t} FOR EACH ROW "
                          f"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '{t} is append-only'"]
        elif dialect == "mssql":
            stmts.append(f"CREATE OR ALTER TRIGGER {t}_immutable ON {t} INSTEAD OF UPDATE, DELETE AS "
                         f"THROW 51000, '{t} is append-only', 1;")
    return stmts


def create_triggers(conn: Connection) -> bool:
    """Returns True when all triggers were created. Failure is logged, never fatal: the ORM guard still applies."""
    ok = True
    from sqlalchemy import inspect
    present = set(inspect(conn).get_table_names())
    for stmt in trigger_statements(conn.dialect.name, present):
        try:
            conn.execute(text(stmt))
        except Exception as exc:  # noqa: BLE001 - typically MySQL error 1419 (missing privilege)
            ok = False
            log.warning("Could not create append-only trigger: %s", str(exc).splitlines()[0][:200])
    return ok


if __name__ == "__main__":
    from app.database.session import get_engine

    logging.basicConfig(level=logging.INFO)
    with get_engine().begin() as c:
        print("append-only triggers created" if create_triggers(c) else
              "triggers NOT created - see warning above; application-level guard remains active")

from sqlalchemy import func, select

from app.models import AutomationExecutionLog, AutomationJob, CloudAccount, CloudProject, CloudSubscription, NotificationLog, OnboardingRecord, RemediationRecord
from app.models import OnboardingStatus as S
from app.scheduler.engine import run_job
from app.services.connector import FAIL, PASS, CheckResult
from app.services.onboarding.engine import run_discovery
from tests.fakes import FakeConnector, all_pass, auth_failed


def run(factory, *connectors):
    return run_job(factory, "account_discovery", lambda ctx: run_discovery(ctx, connectors), trigger="manual")


def count(db, model, *where):
    return db.scalar(select(func.count()).select_from(model).where(*where))


def three_clouds():
    return (FakeConnector("aws", {f"{i}" * 12: {"name": f"acct-{i}"} for i in range(1, 7)}),
            FakeConnector("gcp", {f"proj-{i}": {} for i in range(22)}),
            FakeConnector("azure", {f"sub-{i}": {} for i in range(11)}))


def test_discovers_all_scopes_across_three_clouds(session_factory, db):
    entry = run(session_factory, *three_clouds())
    assert entry.status == "success" and entry.scopes_total == 39 and entry.scopes_failed == 0
    assert (count(db, CloudAccount), count(db, CloudProject), count(db, CloudSubscription)) == (6, 22, 11)
    assert count(db, CloudAccount, CloudAccount.onboarding_status == S.FULLY_ONBOARDED.value) == 6
    assert count(db, OnboardingRecord, OnboardingRecord.event_type == "discovered") == 39
    assert count(db, NotificationLog, NotificationLog.status == "queued") == 2  # queued, never marked sent here
    assert count(db, NotificationLog, NotificationLog.status == "sent") == 0


def test_rerun_is_idempotent(session_factory, db):
    conns = three_clouds()
    run(session_factory, *conns)
    records, notifications = count(db, OnboardingRecord), count(db, NotificationLog)
    entry = run(session_factory, *conns)
    assert entry.status == "success" and entry.summary["new_scopes"] == 0
    assert count(db, CloudProject) == 22 and count(db, OnboardingRecord) == records and count(db, NotificationLog) == notifications


def test_new_scope_detected_without_code_change(session_factory, db):
    aws = FakeConnector("aws", {"1" * 12: {}})
    run(session_factory, aws)
    aws.scopes["9" * 12] = {"name": "brand-new"}
    entry = run(session_factory, aws)
    assert entry.summary["providers"]["aws"]["new"] == 1
    row = db.scalar(select(CloudAccount).where(CloudAccount.external_id == "9" * 12))
    assert row.name == "brand-new" and row.onboarding_status == S.FULLY_ONBOARDED.value


def test_access_failure_is_reported_with_exact_scope_and_creates_task(session_factory, db):
    aws = FakeConnector("aws", {"1" * 12: {}, "2" * 12: {"name": "locked", "checks": auth_failed()}})
    entry = run(session_factory, aws)
    assert entry.status == "partial" and entry.scopes_failed == 1
    assert entry.failures == [{"provider": "aws", "scope": "2" * 12, "name": "locked", "reason": "AccessDenied assuming role"}]
    row = db.scalar(select(CloudAccount).where(CloudAccount.external_id == "2" * 12))
    assert row.onboarding_status == S.ACCESS_FAILED.value
    task = db.scalar(select(RemediationRecord))
    assert task.status == "pending_approval" and task.scope_external_id == "2" * 12 and "requires approval" in task.proposed_action


def test_task_resolves_when_check_passes_and_is_not_duplicated(session_factory, db):
    aws = FakeConnector("aws", {"2" * 12: {"checks": auth_failed()}})
    run(session_factory, aws)
    run(session_factory, aws)
    assert count(db, RemediationRecord) == 1
    aws.scopes["2" * 12]["checks"] = all_pass()
    run(session_factory, aws)
    db.expire_all()
    assert db.scalar(select(RemediationRecord)).status == "resolved"
    statuses = [r.new_status for r in db.scalars(select(OnboardingRecord).order_by(OnboardingRecord.id))]
    assert statuses == [S.DISCOVERED.value, S.ACCESS_FAILED.value, S.FULLY_ONBOARDED.value]


def test_rejected_task_is_not_reopened(session_factory, db):
    aws = FakeConnector("aws", {"2" * 12: {"checks": auth_failed()}})
    run(session_factory, aws)
    task = db.scalar(select(RemediationRecord))
    task.status = "rejected"
    db.commit()
    run(session_factory, aws)
    db.expire_all()
    assert db.scalar(select(RemediationRecord)).status == "rejected" and count(db, RemediationRecord) == 1


def test_missing_audit_logging_is_partial_onboarding(session_factory, db):
    checks = all_pass() | {"audit_logs": CheckResult(FAIL, "CloudTrail is not configured", "Enable trail - requires approval")}
    run(session_factory, FakeConnector("aws", {"3" * 12: {"checks": checks}}))
    row = db.scalar(select(CloudAccount))
    assert row.onboarding_status == S.PARTIALLY_ONBOARDED.value and row.checks["audit_logs"]["status"] == FAIL
    assert row.checks["billing"]["status"] == PASS


def test_discovery_failure_does_not_touch_inventory_and_is_not_success(session_factory, db):
    gcp = FakeConnector("gcp", {"proj-1": {}})
    run(session_factory, gcp)
    gcp.discover_error = RuntimeError("503 backend unavailable token=abc")
    entry = run(session_factory, gcp, FakeConnector("aws", {"1" * 12: {}}))
    assert entry.status == "partial"
    assert any(f["provider"] == "gcp" and "Discovery failed" in f["reason"] and "abc" not in f["reason"] for f in entry.failures)
    assert db.scalar(select(CloudProject)).onboarding_status == S.FULLY_ONBOARDED.value  # not marked inactive


def test_removed_and_suspended_scopes_become_inactive(session_factory, db):
    aws = FakeConnector("aws", {"1" * 12: {}, "2" * 12: {}, "3" * 12: {"active": False}})
    run(session_factory, aws)
    assert "3" * 12 not in aws.validate_calls  # inactive scopes are not validated
    del aws.scopes["2" * 12]
    run(session_factory, aws)
    by_id = {r.external_id: r.onboarding_status for r in db.scalars(select(CloudAccount))}
    assert by_id == {"1" * 12: S.FULLY_ONBOARDED.value, "2" * 12: S.INACTIVE.value, "3" * 12: S.INACTIVE.value}


def test_unconfigured_or_absent_providers_fail_loudly(session_factory):
    entry = run(session_factory)
    assert entry.status == "failed" and "No cloud provider is enabled" in entry.failures[0]["reason"]
    entry = run(session_factory, FakeConnector("azure", missing=["AZURE_TENANT_ID"]))
    assert entry.status == "failed" and "AZURE_TENANT_ID" in entry.failures[0]["reason"]


def test_validation_exception_never_counts_as_onboarded(session_factory, db):
    entry = run(session_factory, FakeConnector("azure", {"sub-1": {"checks": RuntimeError("boom")}}))
    assert entry.status == "partial" and entry.scopes_failed == 1
    assert db.scalar(select(CloudSubscription)).onboarding_status == S.ACCESS_FAILED.value


def test_monitoring_disabled_scope_is_skipped(session_factory, db):
    aws = FakeConnector("aws", {"1" * 12: {}})
    run(session_factory, aws)
    row = db.scalar(select(CloudAccount))
    row.monitoring_enabled = False
    db.commit()
    aws.validate_calls.clear()
    run(session_factory, aws)
    db.expire_all()
    assert aws.validate_calls == [] and db.scalar(select(CloudAccount)).onboarding_status == S.MONITORING_DISABLED.value


def test_overlapping_execution_is_prevented(session_factory, db):
    inner = {}

    def job(ctx):
        inner["entry"] = run(session_factory, FakeConnector("aws", {"1" * 12: {}}))
        return run_discovery(ctx, [FakeConnector("aws", {"1" * 12: {}})])

    outer = run_job(session_factory, "account_discovery", job)
    assert inner["entry"].status == "skipped_overlap" and outer.status == "success"
    assert db.scalar(select(AutomationJob).where(AutomationJob.name == "account_discovery")).lock_owner is None


def test_job_exception_is_recorded_and_lock_released(session_factory, db):
    def boom(ctx):
        raise RuntimeError("explode password=hunter2")

    entry = run_job(session_factory, "account_discovery", boom)
    assert entry.status == "failed" and "hunter2" not in entry.error and entry.finished_at is not None
    assert run(session_factory, FakeConnector("aws", {"1" * 12: {}})).status == "success"
    assert count(db, AutomationExecutionLog) == 2


def test_abandoned_run_is_closed_as_failed(session_factory, db):
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "account_discovery"))
    db.add(AutomationExecutionLog(job_id=job.id, job_name="account_discovery", status="running"))  # process died mid-run
    db.commit()
    assert run(session_factory, FakeConnector("aws", {"1" * 12: {}})).status == "success"
    db.expire_all()
    rows = db.scalars(select(AutomationExecutionLog).order_by(AutomationExecutionLog.id)).all()
    assert rows[0].status == "failed" and rows[0].error.startswith("Abandoned") and rows[0].finished_at is not None

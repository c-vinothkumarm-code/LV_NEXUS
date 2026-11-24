"""The Azure reconciliation and preflight tools, against fake Azure clients and the real database layer."""
import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

from sqlalchemy import select

from app.core.config import Settings
from app.models import AutomationExecutionLog, CloudSubscription, VMInventory
from app.services.finops.engine import upsert_records
from app.services.soc.engine import run_security_events
from app.validation.azure_reconcile import AzureReconciler
from app.validation.evidence import build_pack
from app.validation.preflight import run_preflight
from tests.helpers import ListCollector, ev, onboard, run
from tests.unit.test_finops import row

TENANT = "tenant-a"
S = Settings(_env_file=None, azure_enabled=True, azure_tenant_id=TENANT)
ROLE = {"r-reader": "Reader", "r-mon": "Monitoring Reader", "r-cost": "Cost Management Reader", "r-contrib": "Contributor"}


def jwt_like(**claims):
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"x.{body}.y"


class FakeAzure:
    def __init__(self, subs, roles, vms, events, cost, idtyp="app"):
        self.subs, self.roles, self.vms, self.events, self.cost_rows, self.idtyp = subs, roles, vms, events, cost, idtyp

    def credential(self):
        claims = {"tid": TENANT, "oid": "oid-1", "appid": "app-1"} | ({"idtyp": "app"} if self.idtyp == "app" else {"upn": "me@x"})
        return NS(get_token=lambda scope: NS(token=jwt_like(**claims), expires_on=int((datetime.now(UTC) + timedelta(hours=1)).timestamp())))

    def subscriptions(self):
        return NS(subscriptions=NS(list=lambda: [NS(subscription_id=s, display_name=n, tenant_id=TENANT, state="Enabled") for s, n in self.subs.items()]))

    def authorization(self, sub):
        return NS(role_assignments=NS(list_for_subscription=lambda filter: [NS(role_definition_id=r) for r in self.roles.get(sub, [])]),
                  role_definitions=NS(get_by_id=lambda rid: NS(role_name=ROLE[rid])))

    def compute(self, sub):
        vms = self.vms.get(sub, {})

        def list_all(status_only=None):
            if status_only:
                return [NS(id=i, instance_view=NS(statuses=[NS(code=f"PowerState/{p}")])) for i, (_n, p) in vms.items()]
            return [NS(id=i, name=n) for i, (n, _p) in vms.items()]
        return NS(virtual_machines=NS(list_all=list_all))

    def monitor(self, sub):
        return NS(activity_logs=NS(list=lambda filter, select: [NS(event_data_id=e, status=NS(value=st)) for e, st in self.events.get(sub, [])]))

    def cost(self):
        return NS(query=NS(usage=lambda scope, q: NS(columns=[NS(name="Cost"), NS(name="Currency")],
                                                     rows=[[self.cost_rows.get(scope.rsplit("/", 1)[-1], 0), "USD"]])))


def setup(session_factory, db):
    onboard(session_factory, azure=["sub-1", "sub-2"])
    for sub in ("sub-1", "sub-2"):
        row_ = db.scalar(select(CloudSubscription).where(CloudSubscription.external_id == sub))
        row_.name = f"Prod {sub}"
    db.add_all([VMInventory(provider="azure", scope_external_id="sub-1", instance_id="/subs/sub-1/vm/a", name="a", power_state="running"),
                VMInventory(provider="azure", scope_external_id="sub-1", instance_id="/subs/sub-1/vm/b", name="b", power_state="stopped")])
    db.commit()
    now = datetime.now(UTC)
    evs = [ev(provider="azure", scope="sub-1", event_id=f"ev{i}", name="Microsoft.Compute/virtualMachines/read", read_only=True,
              ts=now - timedelta(hours=2, minutes=i)) for i in range(3)]
    run(session_factory, "security_events", lambda ctx: run_security_events(ctx, S, [ListCollector("azure", {"sub-1": evs})]))
    first = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == "security_events"))
    first.started_at = now - timedelta(days=3)  # pretend collection has been running for days
    db.commit()
    for d in range(2, 9):
        upsert_records(db, S, [row(provider="azure", scope="sub-1", service="VM", cost="10", day=now.date() - timedelta(days=d))])
    db.commit()


def good_azure():
    return FakeAzure(subs={"sub-1": "Prod sub-1", "sub-2": "Prod sub-2"},
                     roles={"sub-1": ["r-reader", "r-mon", "r-cost"], "sub-2": ["r-reader", "r-mon", "r-cost"]},
                     vms={"sub-1": {"/subs/sub-1/VM/a": ("a", "running"), "/subs/sub-1/vm/b": ("b", "deallocated")}},
                     events={"sub-1": [("ev0", "Succeeded"), ("ev1", "Succeeded"), ("ev2", "Failed"), ("ev2-start", "Started")]},
                     cost={"sub-1": 70.0, "sub-2": 0})


def reconcile(db, fake):
    r = AzureReconciler(db, S, fake, compute_factory=fake.compute)
    return {c.id: c for c in r.run(hours=24, days=7).checks}, r.report


def test_reconciliation_passes_when_azure_and_app_agree(session_factory, db):
    setup(session_factory, db)
    checks, rep = reconcile(db, good_azure())
    assert {k: c.status for k, c in checks.items()} == {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "PASS", "R5": "PASS", "R6": "PASS", "R7": "PASS"}, \
        {k: c.detail for k, c in checks.items()}
    assert checks["R5"].data["by_subscription"]["sub-1"]["matched"] == 3 and rep.overall == "PASS"
    assert checks["R6"].data["by_subscription"]["sub-1"]["USD"]["difference"] == 0.0


def test_reconciliation_flags_every_kind_of_mismatch(session_factory, db):
    setup(session_factory, db)
    fake = good_azure()
    fake.subs["sub-3"] = "New sub"                               # discovered by Azure, missing in the app
    fake.roles["sub-1"].append("r-contrib")                      # write-capable role
    fake.vms["sub-1"]["/subs/sub-1/vm/c"] = ("c", "running")     # VM the app has not seen
    fake.events["sub-1"].append(("ev9", "Succeeded"))            # event the app missed
    fake.cost_rows["sub-1"] = 90.0                               # app total differs by more than 5%
    fake.idtyp = "user"
    checks, rep = reconcile(db, fake)
    assert checks["R1"].status == "WARN" and "service principal" in checks["R1"].detail
    assert checks["R2"].status == "FAIL" and checks["R2"].data["missing_in_app"] == ["sub-3"]
    assert checks["R3"].status == "FAIL" and checks["R3"].data["write_capable_roles"] == {"sub-1": ["Contributor"]}
    assert checks["R4"].status == "FAIL" and checks["R4"].data["by_subscription"]["sub-1"]["missing_in_app"] == ["c"]
    assert checks["R5"].status == "FAIL" and checks["R5"].data["by_subscription"]["sub-1"]["missing_sample"] == ["ev9"]
    assert checks["R6"].status == "FAIL" and rep.overall == "FAIL"
    md = rep.markdown()
    assert "| R3 Read-only access (RBAC) | FAIL |" in md


def test_preflight_and_evidence_pack(session_factory, db, tmp_path):
    setup(session_factory, db)
    for e in db.scalars(select(AutomationExecutionLog)):
        e.trigger = "manual"  # nothing has been started by the scheduler yet
    db.commit()
    rep = run_preflight(db, S, for_review=True)
    checks = {c.id: c for c in rep.checks}
    assert checks["P2"].status == "PASS" and checks["P5"].status == "FAIL"  # developer sign-in fails a review
    assert checks["P7"].status == "FAIL"  # no scheduled (unattended) run yet
    assert run_preflight(db, S, for_review=False).checks[4].status == "WARN"
    z = build_pack(db, S.model_copy(update={"azure_client_secret": "sup3r-secret"}), tmp_path, extra=[])
    import zipfile
    names = zipfile.ZipFile(z).namelist()
    assert any(n.endswith("job_executions.csv") for n in names) and any(n.endswith("manifest.json") for n in names)
    blob = b"".join(zipfile.ZipFile(z).read(n) for n in names)
    assert b"sup3r-secret" not in blob  # configuration is exported as presence only

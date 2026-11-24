from datetime import UTC, datetime
from types import SimpleNamespace as NS

import boto3
from botocore.stub import ANY, Stubber
from sqlalchemy import select

from app.core.config import Settings
from app.models import CloudResource, VMAlert, VMInventory, VMMetric
from app.services.monitoring.collectors import METRIC_KEYS, AwsVmCollector, AzureVmCollector, GcpVmCollector
from app.services.monitoring.engine import run_vm_metrics, store_scope
from app.services.monitoring.health import evaluate, port_is_sensitive
from tests.helpers import onboard, run

S = Settings(_env_file=None)


def vm(iid="i-1", state="running", ports=(), public=None, itype="t3.micro", env=None, **metrics):
    m = dict.fromkeys(METRIC_KEYS)
    m.update(metrics)
    return {"instance_id": iid, "name": iid, "region": "ap-south-1", "instance_type": itype, "power_state": state, "public_ip": public,
            "private_ip": "10.0.0.5", "environment": env, "launched_at": None, "exposed_ports": list(ports), "metrics": m}


def test_missing_metrics_are_never_healthy():
    assert evaluate(vm(cpu_percent=20, memory_percent=30, disk_percent=40), S)[0] == "healthy"
    status, missing, alerts = evaluate(vm(cpu_percent=20), S)
    assert status == "partial" and missing == ["memory", "disk"] and [a["type"] for a in alerts] == ["missing_metrics"]
    assert evaluate(vm(), S)[0] == "unknown"
    assert evaluate(vm(state="stopped"), S)[0] == "stopped" and evaluate(vm(state="deallocated"), S)[0] == "stopped"


def test_thresholds_and_environment_overrides():
    assert evaluate(vm(cpu_percent=85, memory_percent=10, disk_percent=10), S)[0] == "warning"
    status, _, alerts = evaluate(vm(cpu_percent=50, memory_percent=96, disk_percent=10), S)
    assert status == "critical" and alerts[0]["type"] == "memory_high" and alerts[0]["threshold"] == 95
    strict = Settings(_env_file=None, vm_threshold_overrides='{"prod": {"cpu": [40, 60]}}')
    assert evaluate(vm(env="prod", cpu_percent=50, memory_percent=10, disk_percent=10), strict)[0] == "warning"
    assert evaluate(vm(env="dev", cpu_percent=50, memory_percent=10, disk_percent=10), strict)[0] == "healthy"
    assert evaluate(vm(env="prod", cpu_percent=50, memory_percent=10, disk_percent=10), Settings(_env_file=None, vm_threshold_overrides="not json"))[0] == "healthy"


def test_public_exposure_needs_public_ip_and_flags_sensitive_ports():
    assert port_is_sensitive("tcp/22") and port_is_sensitive("tcp/3000-4000") and port_is_sensitive("all") and not port_is_sensitive("tcp/443")
    _, _, alerts = evaluate(vm(public="198.51.100.4", ports=["tcp/22"], cpu_percent=1, memory_percent=1, disk_percent=1), S)
    assert alerts[0]["type"] == "public_port_exposure" and alerts[0]["severity"] == "High"
    assert evaluate(vm(ports=["tcp/22"], cpu_percent=1, memory_percent=1, disk_percent=1), S)[2] == []  # no public IP, not exposed


def test_inventory_history_alert_lifecycle_and_deletion(db):
    scope = "1" * 12
    stats = store_scope(db, S, "aws", scope, [vm("i-1", cpu_percent=95), vm("i-2", state="stopped")])
    db.commit()
    assert stats["created"] == 2 and db.scalar(select(VMInventory).where(VMInventory.instance_id == "i-1")).health_status == "critical"
    open_types = lambda: sorted(a.alert_type for a in db.scalars(select(VMAlert).where(VMAlert.status == "open")))  # noqa: E731
    assert open_types() == ["cpu_high", "missing_metrics"]
    store_scope(db, S, "aws", scope, [vm("i-1", cpu_percent=95)])  # same condition: no duplicate alert; i-2 disappeared
    db.commit()
    assert open_types() == ["cpu_high", "missing_metrics"]
    gone = db.scalar(select(VMInventory).where(VMInventory.instance_id == "i-2"))
    assert gone.deleted_at is not None and db.scalar(select(CloudResource).where(CloudResource.resource_id == "i-2")).state == "deleted"
    store_scope(db, S, "aws", scope, [vm("i-1", itype="t3.large", cpu_percent=10, memory_percent=10, disk_percent=10)])
    db.commit()
    assert open_types() == [] and db.scalar(select(VMInventory).where(VMInventory.instance_id == "i-1")).health_status == "healthy"
    recorded = sorted(a.alert_type for a in db.scalars(select(VMAlert).where(VMAlert.status == "recorded")))
    assert recorded == ["vm_created", "vm_created", "vm_deleted", "vm_resized"]
    metrics = db.scalars(select(VMMetric).order_by(VMMetric.id)).all()
    assert len(metrics) == 3 and metrics[0].memory_percent is None and metrics[0].missing_metrics == ["memory", "disk"]  # NULL, not 0


def test_aws_vm_collector_reads_instances_groups_and_metrics():
    kw = dict(region_name="ap-south-1", aws_access_key_id="t", aws_secret_access_key="t")
    ec2, cw = boto3.client("ec2", **kw), boto3.client("cloudwatch", **kw)
    e, c = Stubber(ec2), Stubber(cw)
    inst = lambda iid, state, **x: {"InstanceId": iid, "InstanceType": "t3.micro", "State": {"Name": state}, "PrivateIpAddress": "10.0.0.1",  # noqa: E731
                                    "SecurityGroups": [{"GroupId": "sg-1"}], "Tags": [{"Key": "Name", "Value": f"web-{iid}"}, {"Key": "Environment", "Value": "prod"}], **x}
    e.add_response("describe_instances", {"Reservations": [{"Instances": [inst("i-1", "running", PublicIpAddress="198.51.100.9"), inst("i-2", "stopped"), inst("i-3", "terminated")]}]})
    e.add_response("describe_security_groups", {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}, {"GroupIds": ["sg-1"]})
    c.add_response("get_metric_data", {"MetricDataResults": [{"Id": "q0_cpu_percent", "Values": [42.5]}, {"Id": "q0_network_in_bytes", "Values": [1000.0]},
                                                             {"Id": "q0_memory_percent", "Values": []}, {"Id": "q0_disk_percent", "Values": [61.0]},
                                                             {"Id": "q0_disk_percent", "Values": [88.0]}]},
                   {"MetricDataQueries": ANY, "StartTime": ANY, "EndTime": ANY})
    e.activate()
    c.activate()
    conn = NS(session_for=lambda a, m: None, regions=lambda s: ["ap-south-1"], client=lambda s, svc, region=None: {"ec2": ec2, "cloudwatch": cw}[svc])
    vms = {v["instance_id"]: v for v in AwsVmCollector(S, conn).collect(NS(external_id="1" * 12, is_management=False))}
    assert set(vms) == {"i-1", "i-2"} and vms["i-1"]["exposed_ports"] == ["tcp/22"] and vms["i-1"]["environment"] == "prod"
    m = vms["i-1"]["metrics"]
    assert m["cpu_percent"] == 42.5 and m["memory_percent"] is None and m["disk_percent"] == 88.0  # worst filesystem; memory missing stays None
    assert vms["i-2"]["power_state"] == "stopped" and vms["i-2"]["metrics"]["cpu_percent"] is None
    c.assert_no_pending_responses()


def test_gcp_vm_collector_firewall_exposure_and_metrics():
    fw = [NS(direction="INGRESS", disabled=False, source_ranges=["0.0.0.0/0"], target_tags=["web"], target_service_accounts=[], allowed=[NS(I_p_protocol="tcp", ports=["80", "8000-8100"])]),
          NS(direction="INGRESS", disabled=False, source_ranges=["10.0.0.0/8"], target_tags=[], target_service_accounts=[], allowed=[NS(I_p_protocol="tcp", ports=["22"])])]
    nic = NS(network_i_p="10.1.0.2", access_configs=[NS(nat_i_p="203.0.113.5")])
    mk = lambda i, name, tags, status="RUNNING": NS(id=i, name=name, zone="https://x/zones/asia-south1-a", machine_type="https://x/machineTypes/e2-small",  # noqa: E731
                                                    status=status, network_interfaces=[nic], tags=NS(items=tags), labels={"env": "prod"}, creation_timestamp="2026-01-01T00:00:00+00:00")
    instances = NS(aggregated_list=lambda project: [("zones/asia-south1-a", NS(instances=[mk(11, "web-1", ["web"]), mk(12, "db-1", ["db"], "TERMINATED")]))])

    def series(request):
        mt = request["filter"]
        if "cpu/utilization" in mt:
            return [NS(resource=NS(labels={"instance_id": "11"}), points=[NS(value={"double_value": 0.37})])]
        return []

    class Value(dict):
        double_value = property(lambda s: s["double_value"])

    def list_time_series(request, timeout=None):
        return [NS(resource=t.resource, points=[NS(value=Value(t.points[0].value))]) for t in series(request)]

    c = GcpVmCollector(S, None, instances=instances, firewalls=NS(list=lambda project: fw), metrics=NS(list_time_series=list_time_series))
    vms = {v["name"]: v for v in c.collect(NS(external_id="proj-a"))}
    assert vms["web-1"]["exposed_ports"] == ["tcp/80", "tcp/8000-8100"] and vms["web-1"]["public_ip"] == "203.0.113.5"
    assert round(vms["web-1"]["metrics"]["cpu_percent"], 1) == 37.0 and vms["web-1"]["metrics"]["memory_percent"] is None
    assert vms["db-1"]["power_state"] == "stopped" and vms["db-1"]["exposed_ports"] == [] and vms["db-1"]["instance_type"] == "e2-small"


def test_azure_vm_collector_power_state_nsg_and_metrics():
    sub = "sub-1"
    vid = f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/app1"
    nic_id, pip_id, nsg_id = "/nic/1", "/pip/1", "/nsg/1"
    rule = NS(direction="Inbound", access="Allow", source_address_prefix="*", source_address_prefixes=[], destination_port_range="3389",
              destination_port_ranges=[], protocol="Tcp")
    network = NS(public_ip_addresses=NS(list_all=lambda: [NS(id=pip_id, ip_address="203.0.113.77")]),
                 network_security_groups=NS(list_all=lambda: [NS(id=nsg_id, security_rules=[rule])]),
                 network_interfaces=NS(list_all=lambda: [NS(id=nic_id, network_security_group=NS(id=nsg_id),
                                                            ip_configurations=[NS(private_ip_address="10.2.0.4", public_ip_address=NS(id=pip_id))])]))
    full = NS(id=vid, name="app1", location="centralindia", hardware_profile=NS(vm_size="Standard_B2s"), tags={"env": "prod"}, time_created=None,
              network_profile=NS(network_interfaces=[NS(id=nic_id)]))
    status = NS(id=vid, instance_view=NS(statuses=[NS(code="ProvisioningState/succeeded"), NS(code="PowerState/running")]))
    compute = NS(virtual_machines=NS(list_all=lambda status_only=None: [status] if status_only else [full]))
    metric = lambda name, **pt: NS(name=NS(value=name), timeseries=[NS(data=[NS(average=pt.get("average"), total=pt.get("total"))])])  # noqa: E731
    monitor = NS(metrics=NS(list=lambda *a, **k: NS(value=[metric("Percentage CPU", average=91.0), metric("Network In Total", total=5000.0)])))
    conn = NS(clients=NS(monitor=lambda s: monitor))
    [v] = AzureVmCollector(S, conn, compute=lambda s: compute, network=lambda s: network).collect(NS(external_id=sub))
    assert (v["power_state"], v["public_ip"], v["private_ip"], v["exposed_ports"], v["instance_type"]) == ("running", "203.0.113.77", "10.2.0.4", ["tcp/3389"], "Standard_B2s")
    assert v["metrics"]["cpu_percent"] == 91.0 and v["metrics"]["memory_percent"] is None and v["metrics"]["disk_percent"] is None
    health, missing, alerts = evaluate(v, S)
    assert health == "critical" and missing == ["memory", "disk"] and {a["type"] for a in alerts} == {"public_port_exposure", "cpu_high", "missing_metrics"}


def test_vm_job_reports_scope_failures(session_factory, db):
    onboard(session_factory, aws=["1" * 12, "2" * 12])

    class C:
        provider = "aws"

        def collect(self, scope):
            if scope.external_id.startswith("2"):
                raise RuntimeError("UnauthorizedOperation")
            return [vm("i-1", cpu_percent=10, memory_percent=10, disk_percent=10)]

    entry = run(session_factory, "vm_metrics", lambda ctx: run_vm_metrics(ctx, S, [C()]))
    assert entry.status == "partial" and entry.scopes_failed == 1 and entry.failures[0]["scope"] == "2" * 12 and entry.summary["vms"] == 1
    assert db.scalar(select(VMInventory)).health_status == "healthy"


def test_sdk_surface_used_by_vm_collectors_exists():
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from google.cloud import compute_v1, monitoring_v3

    cred = NS(get_token=lambda *a, **k: None)
    assert callable(ComputeManagementClient(cred, "s").virtual_machines.list_all)
    n = NetworkManagementClient(cred, "s")
    assert all(callable(x.list_all) for x in (n.network_interfaces, n.network_security_groups, n.public_ip_addresses))
    assert callable(compute_v1.InstancesClient.aggregated_list) and callable(compute_v1.FirewallsClient.list)
    assert callable(monitoring_v3.MetricServiceClient.list_time_series)
    assert datetime.now(UTC)


def test_azure_resource_inventory_lists_skips_vms_and_marks_deletions(session_factory, db):
    from app.models import CloudResource
    from app.services.inventory import AzureResourceCollector, run_resource_inventory

    onboard(session_factory, azure=["sub-1"])
    items = [NS(id="/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/st1", type="Microsoft.Storage/storageAccounts",
                name="st1", location="centralindia", kind="StorageV2", sku=NS(name="Standard_LRS"), tags={"env": "prod"}),
             NS(id="/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1", type="Microsoft.Compute/virtualMachines",
                name="vm1", location="centralindia", kind=None, sku=None, tags=None),
             NS(id="/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg1", type="Microsoft.Network/networkSecurityGroups",
                name="nsg1", location="southindia", kind=None, sku=None, tags={})]
    conn = NS(clients=NS(resources=lambda sub: NS(resources=NS(list=lambda: list(items)))))
    collector = AzureResourceCollector(S, conn)
    entry = run(session_factory, "resource_inventory", lambda ctx: run_resource_inventory(ctx, S, [collector], ["aws"]))
    assert entry.status == "success" and entry.summary["by_provider"]["azure"]["resources"] == 2 and entry.summary["not_supported"] == ["aws"]
    st = db.scalar(select(CloudResource).where(CloudResource.name == "st1"))
    assert st.attributes["resource_group"] == "rg-app" and st.region == "centralindia" and st.state == "present"
    assert db.scalar(select(CloudResource).where(CloudResource.name == "vm1")) is None  # VMs belong to vm_metrics
    items.pop()  # nsg1 deleted in Azure
    run(session_factory, "resource_inventory", lambda ctx: run_resource_inventory(ctx, S, [collector], []))
    db.expire_all()
    assert db.scalar(select(CloudResource).where(CloudResource.name == "nsg1")).state == "deleted"
    assert db.scalar(select(CloudResource).where(CloudResource.name == "st1")).state == "present"


def test_azure_resource_sdk_surface():
    from azure.mgmt.resource.resources import ResourceManagementClient
    assert callable(ResourceManagementClient(NS(get_token=lambda *a, **k: None), "s").resources.list)


def test_scheduler_survives_database_outage(monkeypatch):
    import app.workers.local_scheduler as ls

    calls = {"n": 0}

    class Boom:
        def __enter__(self):
            calls["n"] += 1
            if calls["n"] == 4:
                raise SystemExit("stop test")
            raise RuntimeError("database is restarting")

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ls, "get_session_factory", lambda: (lambda: Boom()))
    monkeypatch.setattr(ls.time, "sleep", lambda s: None)
    try:
        ls.main()
    except SystemExit:
        pass
    assert calls["n"] == 4  # kept retrying instead of exiting on the first error

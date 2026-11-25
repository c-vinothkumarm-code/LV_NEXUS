"""VM discovery and metric collection. Read-only. A metric that the platform cannot provide is returned
as None (never zero), so the health engine can report it as missing."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.config import Settings
from app.services.reliability import AZURE_CLIENT_OPTIONS, GCP_TIMEOUT

WORLD = {"0.0.0.0/0", "::/0", "*", "internet", "any"}
METRIC_KEYS = ("cpu_percent", "memory_percent", "disk_percent", "disk_total_gb", "disk_used_gb", "network_in_bytes", "network_out_bytes")


def _vm(**kw) -> dict:
    vm = {"name": None, "region": None, "instance_type": None, "power_state": "unknown", "public_ip": None, "private_ip": None,
          "environment": None, "launched_at": None, "exposed_ports": [], "metrics": dict.fromkeys(METRIC_KEYS)}
    vm.update(kw)
    return vm


def _port(proto, lo=None, hi=None) -> str:
    proto = str(proto or "all").lower()
    if proto in ("-1", "all", "*") or lo in (None, "", "*"):
        return "all" if proto in ("-1", "all", "*") else f"{proto}/all"
    return f"{proto}/{lo}" if hi in (None, lo) else f"{proto}/{lo}-{hi}"


def _env(tags: dict) -> str | None:
    for k, v in (tags or {}).items():
        if k.lower() in ("environment", "env"):
            return str(v)[:32]
    return None


class AwsVmCollector:
    provider = "aws"

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def _exposed(self, ec2, group_ids: set[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        ids = sorted(group_ids)
        for i in range(0, len(ids), 100):
            for g in ec2.describe_security_groups(GroupIds=ids[i:i + 100])["SecurityGroups"]:
                ports = []
                for perm in g.get("IpPermissions", []):
                    cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])] + [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                    if any(c in WORLD for c in cidrs):
                        ports.append(_port(perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort")))
                out[g["GroupId"]] = ports
        return out

    def _metrics(self, cw, instance_ids: list[str], start: datetime, end: datetime) -> dict[str, dict]:
        result = {i: dict.fromkeys(METRIC_KEYS) for i in instance_ids}
        period = max(300, self.settings.vm_metric_window_minutes * 60)
        for n in range(0, len(instance_ids), 90):
            chunk = instance_ids[n:n + 90]
            queries, index = [], {}
            for j, iid in enumerate(chunk):
                dim = [{"Name": "InstanceId", "Value": iid}]
                for key, metric, stat in (("cpu_percent", "CPUUtilization", "Average"), ("network_in_bytes", "NetworkIn", "Sum"),
                                          ("network_out_bytes", "NetworkOut", "Sum")):
                    qid = f"q{j}_{key}"
                    index[qid] = (iid, key)
                    queries.append({"Id": qid, "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": metric, "Dimensions": dim},
                                                              "Period": period, "Stat": stat}})
                # Guest metrics exist only where the CloudWatch agent is installed; SEARCH copes with its extra dimensions.
                for key, metric in (("memory_percent", "mem_used_percent"), ("disk_percent", "disk_used_percent")):
                    qid = f"q{j}_{key}"
                    index[qid] = (iid, key)
                    queries.append({"Id": qid, "Expression": f"SEARCH('Namespace=\"CWAgent\" MetricName=\"{metric}\" InstanceId=\"{iid}\"', 'Average', {period})"})
            for page in cw.get_paginator("get_metric_data").paginate(MetricDataQueries=queries, StartTime=start, EndTime=end):
                for r in page["MetricDataResults"]:
                    key = index.get(r["Id"])
                    if key and r.get("Values"):
                        iid, name = key
                        prev = result[iid][name]
                        result[iid][name] = r["Values"][0] if prev is None else max(prev, r["Values"][0])  # worst filesystem wins
        return result

    def collect(self, scope) -> list[dict]:
        session = self.connector.session_for(scope.external_id, getattr(scope, "is_management", False))
        end = datetime.now(UTC)
        start = end - timedelta(minutes=self.settings.vm_metric_window_minutes)
        vms: list[dict] = []
        for region in self.connector.regions(session):
            ec2 = self.connector.client(session, "ec2", region)
            found, groups = [], set()
            for page in ec2.get_paginator("describe_instances").paginate():
                for res in page["Reservations"]:
                    for i in res["Instances"]:
                        state = i["State"]["Name"]
                        if state == "terminated":
                            continue
                        tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
                        sgs = [g["GroupId"] for g in i.get("SecurityGroups", [])]
                        groups.update(sgs)
                        found.append((sgs, _vm(instance_id=i["InstanceId"], name=tags.get("Name") or i["InstanceId"], region=region,
                                               instance_type=i.get("InstanceType"), power_state="running" if state == "running" else "stopped" if state in ("stopped", "stopping") else state,
                                               public_ip=i.get("PublicIpAddress"), private_ip=i.get("PrivateIpAddress"), environment=_env(tags),
                                               launched_at=i.get("LaunchTime"))))
            if not found:
                continue
            exposed = self._exposed(ec2, groups)
            running = [vm["instance_id"] for _, vm in found if vm["power_state"] == "running"]
            metrics = self._metrics(self.connector.client(session, "cloudwatch", region), running, start, end) if running else {}
            for sgs, vm in found:
                vm["exposed_ports"] = sorted({p for g in sgs for p in exposed.get(g, [])})
                vm["metrics"] = metrics.get(vm["instance_id"], vm["metrics"])
                vms.append(vm)
        return vms


class GcpVmCollector:
    provider = "gcp"
    _METRICS = (  # key, metric type, extra filter, aligner, combine, scale
        ("cpu_percent", "compute.googleapis.com/instance/cpu/utilization", "", "ALIGN_MEAN", max, 100.0),
        ("network_in_bytes", "compute.googleapis.com/instance/network/received_bytes_count", "", "ALIGN_DELTA", sum, 1.0),
        ("network_out_bytes", "compute.googleapis.com/instance/network/sent_bytes_count", "", "ALIGN_DELTA", sum, 1.0),
        ("memory_percent", "agent.googleapis.com/memory/percent_used", ' AND metric.labels.state="used"', "ALIGN_MEAN", max, 1.0),
        ("disk_percent", "agent.googleapis.com/disk/percent_used", ' AND metric.labels.state="used"', "ALIGN_MEAN", max, 1.0),
    )

    def __init__(self, settings: Settings, connector, instances=None, firewalls=None, metrics=None):
        self.settings, self.connector = settings, connector
        self._instances, self._firewalls, self._metric_client = instances, firewalls, metrics

    def _client(self, attr: str, factory):
        if getattr(self, attr) is None:
            setattr(self, attr, factory(credentials=self.connector.clients.credentials()))
        return getattr(self, attr)

    def _series(self, project_id: str) -> dict[str, dict]:
        from google.cloud import monitoring_v3

        client = self._client("_metric_client", monitoring_v3.MetricServiceClient)
        end = datetime.now(UTC)
        window = self.settings.vm_metric_window_minutes * 60
        interval = {"start_time": end - timedelta(seconds=window), "end_time": end}
        out: dict[str, dict] = {}
        for key, metric, extra, aligner, combine, scale in self._METRICS:
            req = {"name": f"projects/{project_id}", "filter": f'metric.type="{metric}"{extra}', "interval": interval,
                   "aggregation": {"alignment_period": {"seconds": window}, "per_series_aligner": aligner}, "view": "FULL"}
            for ts in client.list_time_series(request=req, timeout=GCP_TIMEOUT):
                iid = ts.resource.labels.get("instance_id")
                if not iid or not ts.points:
                    continue
                v = ts.points[0].value
                value = (v.double_value if "double_value" in v else float(v.int64_value)) * scale
                slot = out.setdefault(iid, dict.fromkeys(METRIC_KEYS))
                slot[key] = value if slot[key] is None else combine(slot[key], value)
        return out

    def collect(self, scope) -> list[dict]:
        from google.cloud import compute_v1

        pid = scope.external_id
        rules = []
        for fw in self._client("_firewalls", compute_v1.FirewallsClient).list(project=pid):
            if fw.direction == "INGRESS" and not fw.disabled and any(r in WORLD for r in fw.source_ranges):
                flat = []
                for a in fw.allowed:
                    if a.ports:
                        for p in a.ports:
                            lo, _, hi = str(p).partition("-")
                            flat.append(_port(a.I_p_protocol, lo, hi or None))
                    else:
                        flat.append(_port(a.I_p_protocol))
                rules.append((set(fw.target_tags), bool(fw.target_service_accounts), flat))
        vms = []
        for _zone, scoped in self._client("_instances", compute_v1.InstancesClient).aggregated_list(project=pid):
            for i in scoped.instances:
                nic = i.network_interfaces[0] if i.network_interfaces else None
                public = next((a.nat_i_p for a in (nic.access_configs if nic else []) if a.nat_i_p), None)
                tags = set(i.tags.items) if i.tags else set()
                exposed = sorted({p for target, sa_scoped, ports in rules if not sa_scoped and (not target or target & tags) for p in ports})
                state = {"RUNNING": "running", "TERMINATED": "stopped", "STOPPING": "stopped", "SUSPENDED": "stopped"}.get(i.status, i.status.lower())
                vms.append(_vm(instance_id=str(i.id), name=i.name, region=i.zone.rsplit("/", 1)[-1], instance_type=i.machine_type.rsplit("/", 1)[-1],
                               power_state=state, public_ip=public, private_ip=nic.network_i_p if nic else None, environment=_env(dict(i.labels)),
                               launched_at=datetime.fromisoformat(i.creation_timestamp) if i.creation_timestamp else None, exposed_ports=exposed))
        if any(v["power_state"] == "running" for v in vms):
            series = self._series(pid)
            for v in vms:
                v["metrics"] = series.get(v["instance_id"], v["metrics"])
        return vms


class AzureVmCollector:
    provider = "azure"

    def __init__(self, settings: Settings, connector, compute=None, network=None):
        self.settings, self.connector = settings, connector
        self._compute, self._network = compute, network

    def _clients(self, sub_id: str):
        if self._compute is not None:
            return self._compute(sub_id), self._network(sub_id)
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient

        cred = self.connector.clients.credential()
        return ComputeManagementClient(cred, sub_id, **AZURE_CLIENT_OPTIONS), NetworkManagementClient(cred, sub_id, **AZURE_CLIENT_OPTIONS)

    @staticmethod
    def _power(vm) -> str:
        codes = [s.code for s in (getattr(getattr(vm, "instance_view", None), "statuses", None) or []) if (s.code or "").startswith("PowerState/")]
        state = codes[0].split("/", 1)[1] if codes else "unknown"
        return {"running": "running", "deallocated": "deallocated", "deallocating": "deallocated", "stopped": "stopped", "stopping": "stopped"}.get(state, state)

    def _vm_metrics(self, sub_id: str, resource_id: str) -> dict:
        end = datetime.now(UTC)
        start = end - timedelta(minutes=self.settings.vm_metric_window_minutes)
        resp = self.connector.clients.monitor(sub_id).metrics.list(
            resource_id, timespan=f"{start:%Y-%m-%dT%H:%M:%SZ}/{end:%Y-%m-%dT%H:%M:%SZ}", interval="PT5M",
            metricnames="Percentage CPU,Network In Total,Network Out Total", aggregation="Average,Total")
        out = dict.fromkeys(METRIC_KEYS)  # memory and filesystem usage need a guest agent / VM Insights: left as None
        for m in resp.value or []:
            points = [d for ts in (m.timeseries or []) for d in (ts.data or [])]
            name = m.name.value
            if name == "Percentage CPU":
                vals = [d.average for d in points if d.average is not None]
                out["cpu_percent"] = sum(vals) / len(vals) if vals else None
            elif name in ("Network In Total", "Network Out Total"):
                vals = [d.total for d in points if d.total is not None]
                out["network_in_bytes" if "In" in name else "network_out_bytes"] = sum(vals) if vals else None
        return out

    def collect(self, scope) -> list[dict]:
        sub = scope.external_id
        compute, network = self._clients(sub)
        public = {p.id.lower(): p.ip_address for p in network.public_ip_addresses.list_all()}
        nsgs = {}
        for g in network.network_security_groups.list_all():
            ports = []
            for r in g.security_rules or []:
                sources = [str(r.source_address_prefix or "").lower()] + [str(x).lower() for x in (r.source_address_prefixes or [])]
                if str(r.direction) == "Inbound" and str(r.access) == "Allow" and any(s in WORLD for s in sources):
                    for pr in ([r.destination_port_range] if r.destination_port_range else []) + list(r.destination_port_ranges or []):
                        ports.append(_port(r.protocol, *(str(pr).split("-") + [None])[:2]))
            nsgs[g.id.lower()] = ports
        nics = {}
        for n in network.network_interfaces.list_all():
            cfg = (n.ip_configurations or [None])[0]
            pid = getattr(getattr(cfg, "public_ip_address", None), "id", None)
            nics[n.id.lower()] = {"private": getattr(cfg, "private_ip_address", None), "public": public.get(pid.lower()) if pid else None,
                                  "ports": nsgs.get(n.network_security_group.id.lower(), []) if n.network_security_group else []}
        power = {v.id.lower(): self._power(v) for v in compute.virtual_machines.list_all(status_only="true")}
        vms = []
        for v in compute.virtual_machines.list_all():
            refs = [r.id.lower() for r in (v.network_profile.network_interfaces if v.network_profile else [])]
            nic = next((nics[r] for r in refs if r in nics), {"private": None, "public": None, "ports": []})
            state = power.get(v.id.lower(), "unknown")
            vm = _vm(instance_id=v.id, name=v.name, region=v.location, instance_type=v.hardware_profile.vm_size if v.hardware_profile else None,
                     power_state=state, public_ip=nic["public"], private_ip=nic["private"], environment=_env(v.tags or {}),
                     launched_at=getattr(v, "time_created", None), exposed_ports=sorted(set(nic["ports"])))
            if state == "running":
                vm["metrics"] = self._vm_metrics(sub, v.id)
            vms.append(vm)
        return vms

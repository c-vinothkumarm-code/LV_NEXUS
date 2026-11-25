"""Read-only collection of server details that the VM inventory does not hold: hostname, guest OS, vCPU, memory, NICs,
provisioned disk space and cloud-native backup protection.

No single API returns all of these, so each provider combines several read-only calls. A call that fails (missing
permission, API not enabled, agent not installed) never stops the others: the affected field stays empty and the reason
is recorded in `gaps` for that field, so the UI shows "Not collected – <reason>" instead of a guess or a zero.

AWS:   EC2 DescribeInstances / DescribeInstanceTypes / DescribeVolumes, Systems Manager DescribeInstanceInformation
       (guest OS, computer name – needs the SSM agent), AWS Backup ListProtectedResources.
Azure: Compute VMs / VM sizes / managed disks, Azure Resource Graph (guest OS from the VM agent; Recovery Services
       protected items for Azure Backup).
GCP:   Compute Engine instances / machine types / disks (snapshot schedule policies = cloud-native backup)."""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from app.core.config import Settings
from app.core.logging import safe_error

log = logging.getLogger(__name__)
ARG_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
ARG_VERSION = "2022-10-01"


def _item(resource_id: str, **kw) -> dict:
    base = {"resource_id": resource_id, "hostname": None, "guest_os": None, "guest_os_source": None, "cpus": None, "memory_gb": None,
            "nic_count": None, "provisioned_gb": None, "native_backup_status": None, "native_backup_last_at": None,
            "native_backup_detail": None, "created_at_provider": None, "gaps": {}}
    base.update(kw)
    return base


def _reason(exc: Exception, what: str) -> str:
    text = safe_error(exc, 220)
    low = text.lower()
    if any(k in low for k in ("accessdenied", "unauthorizedoperation", "authorizationfailed", "403", "permission", "forbidden")):
        return f"{what}: permission missing ({text})"
    return f"{what}: {text}"


def _fill_gaps(it: dict, common: dict[str, str]) -> dict:
    """Explain every empty field: a source-level failure, or 'not returned by the provider'."""
    for field, default in (("hostname", "not returned by the provider"), ("guest_os", "not returned by the provider"),
                           ("cpus", "not returned by the provider"), ("memory_gb", "not returned by the provider"),
                           ("nic_count", "not returned by the provider"), ("provisioned_gb", "no attached disks returned"),
                           ("native_backup_status", "not returned by the provider")):
        if it.get(field) in (None, ""):
            it["gaps"].setdefault(field, common.get(field, default))
    return it


# ---------------------------------------------------------------------------------------------- AWS
class AwsAssetCollector:
    provider = "aws"

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def collect(self, scope) -> list[dict]:
        session = self.connector.session_for(scope.external_id, getattr(scope, "is_management", False))
        out: list[dict] = []
        for region in self.connector.regions(session):
            ec2 = self.connector.client(session, "ec2", region)
            instances = [i for page in ec2.get_paginator("describe_instances").paginate() for r in page["Reservations"] for i in r["Instances"]
                         if i["State"]["Name"] != "terminated"]
            if not instances:
                continue
            common: dict[str, str] = {}
            types: dict[str, dict] = {}
            names = sorted({i.get("InstanceType") for i in instances if i.get("InstanceType")})
            try:
                for n in range(0, len(names), 100):
                    for t in ec2.describe_instance_types(InstanceTypes=names[n:n + 100])["InstanceTypes"]:
                        types[t["InstanceType"]] = {"vcpus": (t.get("VCpuInfo") or {}).get("DefaultVCpus"),
                                                    "mem": (t.get("MemoryInfo") or {}).get("SizeInMiB")}
            except Exception as exc:  # noqa: BLE001
                common["memory_gb"] = _reason(exc, "ec2:DescribeInstanceTypes")
            ids = [i["InstanceId"] for i in instances]
            volumes: dict[str, float] = {}
            try:
                for n in range(0, len(ids), 200):
                    pages = ec2.get_paginator("describe_volumes").paginate(Filters=[{"Name": "attachment.instance-id", "Values": ids[n:n + 200]}])
                    for page in pages:
                        for v in page["Volumes"]:
                            for a in v.get("Attachments", []):
                                volumes[a["InstanceId"]] = volumes.get(a["InstanceId"], 0.0) + float(v.get("Size") or 0)
            except Exception as exc:  # noqa: BLE001
                common["provisioned_gb"] = _reason(exc, "ec2:DescribeVolumes")
            ssm_info: dict[str, dict] = {}
            try:
                ssm = self.connector.client(session, "ssm", region)
                for page in ssm.get_paginator("describe_instance_information").paginate():
                    for s in page.get("InstanceInformationList", []):
                        ssm_info[s["InstanceId"]] = s
            except Exception as exc:  # noqa: BLE001
                common["guest_os"] = _reason(exc, "ssm:DescribeInstanceInformation")
            protected: dict[str, datetime | None] | None = {}
            try:
                backup = self.connector.client(session, "backup", region)
                for page in backup.get_paginator("list_protected_resources").paginate():
                    for r in page.get("Results", []):
                        arn = r.get("ResourceArn") or ""
                        if ":instance/" in arn:
                            protected[arn.rsplit("/", 1)[-1]] = r.get("LastBackupTime")
            except Exception as exc:  # noqa: BLE001
                protected = None
                common["native_backup_status"] = _reason(exc, "backup:ListProtectedResources")
            for i in instances:
                iid = i["InstanceId"]
                t = types.get(i.get("InstanceType") or "", {})
                cpu = i.get("CpuOptions") or {}
                cpus = cpu.get("CoreCount") * cpu.get("ThreadsPerCore", 1) if cpu.get("CoreCount") else t.get("vcpus")
                s = ssm_info.get(iid)
                guest, source = None, None
                if s and s.get("PlatformName"):
                    guest, source = f"{s['PlatformName']} {s.get('PlatformVersion') or ''}".strip(), "AWS Systems Manager"
                elif i.get("PlatformDetails"):
                    guest, source = i["PlatformDetails"], "EC2 platform details"
                nics = i.get("NetworkInterfaces") or []
                attach = [(n.get("Attachment") or {}).get("AttachTime") for n in nics if (n.get("Attachment") or {}).get("DeviceIndex") == 0]
                it = _item(iid, hostname=(s or {}).get("ComputerName") or i.get("PrivateDnsName") or None, guest_os=guest, guest_os_source=source,
                           cpus=cpus, memory_gb=round(t["mem"] / 1024, 2) if t.get("mem") else None, nic_count=len(nics),
                           provisioned_gb=volumes.get(iid), created_at_provider=attach[0] if attach and attach[0] else i.get("LaunchTime"))
                if protected is not None:
                    it["native_backup_status"] = "Protected" if iid in protected else "Not protected"
                    it["native_backup_last_at"] = protected.get(iid)
                    it["native_backup_detail"] = "AWS Backup protected resource" if iid in protected else "Not in any AWS Backup plan"
                if source == "EC2 platform details":
                    it["gaps"]["guest_os_version"] = common.get("guest_os") or "SSM agent not reporting for this instance: only the platform is known"
                out.append(_fill_gaps(it, common))
        return out


# ---------------------------------------------------------------------------------------------- Azure
class AzureAssetCollector:
    provider = "azure"

    def __init__(self, settings: Settings, connector, compute=None, rest=None):
        self.settings, self.connector = settings, connector
        self._compute, self._rest = compute, rest

    def _client(self, sub: str):
        if self._compute is not None:
            return self._compute(sub)
        from azure.mgmt.compute import ComputeManagementClient

        from app.services.reliability import AZURE_CLIENT_OPTIONS
        return ComputeManagementClient(self.connector.clients.credential(), sub, **AZURE_CLIENT_OPTIONS)

    def _arg(self, sub: str, query: str) -> list[dict]:
        if self._rest is None:
            from app.services.azure.rest import AzureRest
            self._rest = AzureRest(self.settings)
        rows, token = [], None
        while True:
            body = {"subscriptions": [sub], "query": query, "options": {"resultFormat": "objectArray", **({"$skipToken": token} if token else {})}}
            data = self._rest.request("POST", ARG_URL, params={"api-version": ARG_VERSION}, json=body)
            rows += data.get("data") or []
            token = data.get("$skipToken")
            if not token:
                return rows

    def collect(self, scope) -> list[dict]:
        sub = scope.external_id
        compute = self._client(sub)
        common: dict[str, str] = {}
        vms = list(compute.virtual_machines.list_all())
        if not vms:
            return []
        sizes: dict[tuple[str, str], tuple] = {}
        for loc in sorted({(v.location or "").lower() for v in vms}):
            try:
                for s in compute.virtual_machine_sizes.list(loc):
                    sizes[(loc, s.name.lower())] = (s.number_of_cores, s.memory_in_mb)
            except Exception as exc:  # noqa: BLE001
                common["cpus"] = common["memory_gb"] = _reason(exc, "Microsoft.Compute/locations/vmSizes/read")
        disks: dict[str, float] = {}
        try:
            for d in compute.disks.list():
                if d.managed_by:
                    disks[d.managed_by.lower()] = disks.get(d.managed_by.lower(), 0.0) + float(d.disk_size_gb or 0)
        except Exception as exc:  # noqa: BLE001
            common["provisioned_gb"] = _reason(exc, "Microsoft.Compute/disks/read")
        guest: dict[str, dict] = {}
        try:
            for r in self._arg(sub, "Resources | where type =~ 'microsoft.compute/virtualmachines' | project id=tolower(id), "
                                    "osName=tostring(properties.extended.instanceView.osName), osVersion=tostring(properties.extended.instanceView.osVersion), "
                                    "computerName=tostring(properties.extended.instanceView.computerName)"):
                guest[r.get("id") or ""] = r
        except Exception as exc:  # noqa: BLE001
            common["guest_os"] = _reason(exc, "Azure Resource Graph (Microsoft.ResourceGraph/resources/read)")
        backups: dict[str, dict] | None = {}
        try:
            q = ("RecoveryServicesResources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' "
                 "| where tostring(properties.dataSourceInfo.datasourceType) =~ 'Microsoft.Compute/virtualMachines' "
                 "| project vm=tolower(tostring(properties.sourceResourceId)), last=tostring(properties.lastRecoveryPoint), "
                 "state=tostring(properties.protectionState), vault=tostring(split(id, '/backupFabrics/')[0])")
            for r in self._arg(sub, q):
                backups[r.get("vm") or ""] = r
        except Exception as exc:  # noqa: BLE001
            backups = None
            common["native_backup_status"] = _reason(exc, "Azure Resource Graph – Recovery Services protected items")
        out = []
        for v in vms:
            vid = v.id.lower()
            sp = v.storage_profile
            os_disk = getattr(sp, "os_disk", None)
            img = getattr(sp, "image_reference", None)
            g = guest.get(vid) or {}
            if g.get("osName"):
                os_text, src = f"{g['osName']} {g.get('osVersion') or ''}".strip(), "Azure VM agent (instance view)"
            elif os_disk is not None and getattr(os_disk, "os_type", None):
                extra = f" ({img.offer} {img.sku})" if img is not None and getattr(img, "offer", None) else ""
                os_text, src = f"{os_disk.os_type}{extra}", "VM image reference"
            else:
                os_text, src = None, None
            size = sizes.get(((v.location or "").lower(), (getattr(v.hardware_profile, "vm_size", "") or "").lower()))
            computer = g.get("computerName") or getattr(getattr(v, "os_profile", None), "computer_name", None)
            it = _item(v.id, hostname=computer, guest_os=os_text, guest_os_source=src, cpus=size[0] if size else None,
                       memory_gb=round(size[1] / 1024, 2) if size and size[1] else None,
                       nic_count=len(v.network_profile.network_interfaces or []) if v.network_profile else None,
                       provisioned_gb=disks.get(vid), created_at_provider=getattr(v, "time_created", None))
            if backups is not None:
                b = backups.get(vid)
                state = (b or {}).get("state") or ""
                it["native_backup_status"] = "Not protected" if not b else "Protection stopped" if state.lower() == "protectionstopped" else "Protected"
                it["native_backup_last_at"] = _dt((b or {}).get("last"))
                it["native_backup_detail"] = f"Azure Backup ({state or 'protected'})" if b else "Not protected by Azure Backup"
            out.append(_fill_gaps(it, common))
        return out


def _dt(v) -> datetime | None:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except ValueError:
        return None


# ---------------------------------------------------------------------------------------------- GCP
class GcpAssetCollector:
    provider = "gcp"

    def __init__(self, settings: Settings, connector, instances=None, machine_types=None, disks=None):
        self.settings, self.connector = settings, connector
        self._instances, self._types, self._disks = instances, machine_types, disks

    def _client(self, attr: str, name: str):
        if getattr(self, attr) is None:
            from google.cloud import compute_v1
            setattr(self, attr, getattr(compute_v1, name)(credentials=self.connector.clients.credentials()))
        return getattr(self, attr)

    def collect(self, scope) -> list[dict]:
        from app.services.reliability import GCP_TIMEOUT

        pid = scope.external_id
        common: dict[str, str] = {}
        instances = [(zone, i) for zone, scoped in self._client("_instances", "InstancesClient").aggregated_list(project=pid)
                     for i in (scoped.instances or [])]
        if not instances:
            return []
        disk_info: dict[str, dict] | None = {}
        try:
            for _zone, scoped in self._client("_disks", "DisksClient").aggregated_list(project=pid):
                for d in scoped.disks or []:
                    disk_info[d.self_link] = {"policies": list(d.resource_policies or []), "size": d.size_gb, "licenses": list(d.licenses or [])}
        except Exception as exc:  # noqa: BLE001
            disk_info = None
            common["native_backup_status"] = _reason(exc, "compute.disks.list")
        types: dict[tuple[str, str], tuple] = {}
        out = []
        for _zone, i in instances:
            zone = i.zone.rsplit("/", 1)[-1]
            mtype = i.machine_type.rsplit("/", 1)[-1]
            if (zone, mtype) not in types:
                try:
                    t = self._client("_types", "MachineTypesClient").get(project=pid, zone=zone, machine_type=mtype, timeout=GCP_TIMEOUT)
                    types[(zone, mtype)] = (t.guest_cpus, t.memory_mb)
                except Exception as exc:  # noqa: BLE001
                    types[(zone, mtype)] = (None, None)
                    common["cpus"] = common["memory_gb"] = _reason(exc, "compute.machineTypes.get")
            cpus, mem = types[(zone, mtype)]
            attached = list(i.disks or [])
            size = sum(float(d.disk_size_gb or 0) for d in attached) if attached else None
            boot = next((d for d in attached if d.boot), None)
            licences = list(boot.licenses or []) if boot is not None else []
            os_text = licences[0].rsplit("/", 1)[-1] if licences else None
            it = _item(str(i.id), hostname=i.hostname or None, guest_os=os_text, guest_os_source="boot disk licence" if os_text else None,
                       cpus=cpus, memory_gb=round(mem / 1024, 2) if mem else None, nic_count=len(i.network_interfaces or []),
                       provisioned_gb=size, created_at_provider=_dt(i.creation_timestamp))
            if not i.hostname:
                it["gaps"]["hostname"] = f"no custom hostname; internal DNS name is {i.name}.{zone}.c.{pid}.internal"
                it["hostname"] = f"{i.name}.{zone}.c.{pid}.internal"
            if disk_info is not None:
                policies = [p for d in attached for p in (disk_info.get(d.source) or {}).get("policies", [])]
                it["native_backup_status"] = "Snapshot schedule" if policies else "Not protected"
                it["native_backup_detail"] = (f"Snapshot schedule: {', '.join(sorted({p.rsplit('/', 1)[-1] for p in policies}))}"
                                              if policies else "No snapshot schedule on the attached disks (Backup and DR not checked)")
            out.append(_fill_gaps(it, common))
        return out


COLLECTORS = {"aws": AwsAssetCollector, "azure": AzureAssetCollector, "gcp": GcpAssetCollector}

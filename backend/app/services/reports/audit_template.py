"""Monthly Security & Governance Audit Report in the official LatentView Word layout (DOCX + matching PDF).

The layout comes from templates/monthly_audit_report.docx (the approved report format, with every account-specific
value removed). This module fills it for one AWS account / Azure subscription / GCP project and one month, only from
data LV NEXUS collected for that scope. Rules:
- anything not collected is written as "Not collected", never 0 and never "Compliant";
- the automated report never claims a human review: review status is "Need to Review with SPOC" and the sign-off
  table stays empty for the people who sign;
- MFA status and root / break-glass password rotation are not collected by LV NEXUS and are shown as such.
The PDF is rendered from the filled DOCX itself, so the two always carry the same content."""
from __future__ import annotations

import io
import re
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import CloudResource, CloudSecurityFinding, IamCredential, VMInventory

TEMPLATE = Path(__file__).parent / "templates" / "monthly_audit_report.docx"
NC = "Not collected"
SEV = ("Critical", "High", "Medium", "Low")
REVIEW = "Need to Review with SPOC"
LABEL = {"aws": ("AWS Account", "Account", "Account ID"), "azure": ("Azure Subscription", "Subscription", "Subscription ID"),
         "gcp": ("GCP Project", "Project", "Project ID")}
SOURCE = {"aws": "AWS Security Hub CSPM", "azure": "Microsoft Defender for Cloud", "gcp": "Google Security Command Center"}
INACTIVE = ("stopped", "stopping", "deallocated", "deallocating", "terminated", "suspended", "inactive", "disabled", "vm deallocated", "vm stopped", "terminating")
ACTIVE = ("running", "vm running", "started", "active", "available", "enabled", "succeeded", "ready")
MGMT_PORTS, DB_PORTS = {22, 3389}, {1433, 1521, 3306, 5432, 6379, 9200, 27017}
NET_RE = re.compile(r"security group|securitygroup|network acl|nacl|\bport\b|ports|0\.0\.0\.0|ingress|firewall|\bnsg\b|network security|public ip|internet|exposed|\bssh\b|\brdp\b", re.I)

# Provider wording. AWS text is the approved template wording; Azure / GCP use the equivalent native services.
TEXT = {
    9: {"*": "This report presents the findings of the monthly Cloud Security & Governance Audit of the {short} {noun} {name} ({id}) for {month}. "
             "The audit covered identity and access management, cost governance, vulnerability management, key and secret rotation, active resource "
             "inventory, network security and virtual machine lifecycle."},
    12: {"*": "Scope: the {short} {noun} {name} ({id}), hosted on {platform}. The objectives are to:"},
    13: {"aws": "Validate AWS IAM permissions and enforce least privilege.",
         "azure": "Validate Azure RBAC role assignments and Entra ID access and enforce least privilege.",
         "gcp": "Validate Google Cloud IAM bindings and enforce least privilege."},
    15: {"*": "Track vulnerabilities reported by {source} and confirm remediation within SLA."},
    17: {"aws": "Review active resources, Security Groups and Network ACLs and the lifecycle of EC2 instances.",
         "azure": "Review active resources, Network Security Groups and Azure Firewall rules and the lifecycle of Azure virtual machines.",
         "gcp": "Review active resources, VPC firewall rules and the lifecycle of Compute Engine instances."},
    21: {"aws": "User access and permissions were reviewed in AWS IAM. The review covered IAM users and roles, dormant accounts (no sign-in for 30+ days), "
                "over-privileged roles, MFA status and newly provisioned access.",
         "azure": "User access and permissions were reviewed in Azure RBAC and Microsoft Entra ID. The review covered users, groups and service principals, "
                  "dormant accounts (no sign-in for 30+ days), over-privileged roles, MFA status and newly provisioned access.",
         "gcp": "User access and permissions were reviewed in Google Cloud IAM. The review covered users, groups and service accounts, dormant accounts "
                "(no activity for 30+ days), over-privileged roles, MFA status and newly provisioned access."},
    24: {"aws": "Monthly spend was reviewed against the approved budget using AWS Cost Explorer and AWS Budgets. Status: Within budget (below 90%), "
                "Near limit (90–100%), Exceeds (above 100%).",
         "azure": "Monthly spend was reviewed against the approved budget using Azure Cost Management and Azure Budgets. Status: Within budget (below 90%), "
                  "Near limit (90–100%), Exceeds (above 100%).",
         "gcp": "Monthly spend was reviewed against the approved budget using Cloud Billing reports and Cloud Billing budgets. Status: Within budget "
                "(below 90%), Near limit (90–100%), Exceeds (above 100%)."},
    29: {"*": "Vulnerabilities and misconfigurations were reviewed in {source}."},
    41: {"aws": "Active services were reviewed using AWS Trusted Advisor and Compute Optimizer to find high-cost, idle and unused resources and to cut unnecessary spend.",
         "azure": "Active services were reviewed using Azure Advisor and Azure Cost Management to find high-cost, idle and unused resources and to cut unnecessary spend.",
         "gcp": "Active services were reviewed using Google Cloud Recommender and Active Assist to find high-cost, idle and unused resources and to cut unnecessary spend."},
    45: {"aws": "Idle or orphaned resources – unattached EBS volumes, unused Elastic IPs and old EBS snapshots.",
         "azure": "Idle or orphaned resources – unattached managed disks, unused public IP addresses and old snapshots.",
         "gcp": "Idle or orphaned resources – unattached persistent disks, unused static external IPs and old snapshots."},
    51: {"aws": "Inbound and outbound rules, open ports and internet exposure were reviewed in Security Groups and Network ACLs.",
         "azure": "Inbound and outbound rules, open ports and internet exposure were reviewed in Network Security Groups and Azure Firewall.",
         "gcp": "Inbound and outbound rules, open ports and internet exposure were reviewed in VPC firewall rules and firewall policies."},
    63: {"aws": "EC2 instances were reviewed for status, business use, owner, utilisation and cost.",
         "azure": "Azure virtual machines were reviewed for status, business use, owner, utilisation and cost.",
         "gcp": "Compute Engine instances were reviewed for status, business use, owner, utilisation and cost."},
    71: {"aws": "Stopped VMs still paying for EBS volumes or Elastic IPs.",
         "azure": "Stopped (not deallocated) VMs still paying for compute, and deallocated VMs still paying for managed disks or public IPs.",
         "gcp": "Stopped VMs still paying for persistent disks or static external IPs."},
    78: {"aws": "Enable MFA for every user, especially the root account.",
         "azure": "Enable MFA for every user, especially Global Administrators and subscription Owners.",
         "gcp": "Enable 2-Step Verification for every user, especially Owners and Super Admins."},
    80: {"aws": "Never change default Security Group settings without an approved change request.",
         "azure": "Never change default Network Security Group rules without an approved change request.",
         "gcp": "Never change default VPC firewall rules without an approved change request."},
    81: {"aws": "Release unused Elastic IPs and delete unattached EBS volumes.",
         "azure": "Release unused public IP addresses and delete unattached managed disks.",
         "gcp": "Release unused static external IPs and delete unattached persistent disks."},
    83: {"aws": "Back up critical EBS volumes at least once a month.",
         "azure": "Back up critical managed disks (Azure Backup) at least once a month.",
         "gcp": "Back up critical persistent disks (snapshot schedules) at least once a month."},
    84: {"aws": "Keep logging and monitoring on: AWS CloudTrail, AWS Config and Amazon CloudWatch.",
         "azure": "Keep logging and monitoring on: Azure Activity Log, Azure Policy and Azure Monitor.",
         "gcp": "Keep logging and monitoring on: Cloud Audit Logs, Cloud Asset Inventory and Cloud Monitoring."},
    91: {"aws": "Get Cloud Security approval before changing any network setting (Security Groups and Network ACLs).",
         "azure": "Get Cloud Security approval before changing any network setting (Network Security Groups and Azure Firewall).",
         "gcp": "Get Cloud Security approval before changing any network setting (VPC firewall rules and policies)."},
    92: {"aws": "Change the root account password every month.",
         "azure": "Change the break-glass (emergency access) account passwords every month.",
         "gcp": "Change the Super Admin account passwords every month."},
    93: {"aws": "Use a separate Security Group for each workload.",
         "azure": "Use a separate Network Security Group for each workload.",
         "gcp": "Use separate firewall rules (network tags / service accounts) for each workload."},
    95: {"aws": "Patch the OS and software on EC2 instances and databases regularly.",
         "azure": "Patch the OS and software on Azure VMs and databases regularly.",
         "gcp": "Patch the OS and software on Compute Engine instances and databases regularly."},
}
ATTACH = {"aws": ("All IAM users and roles with role, last sign-in and MFA status",),
          "azure": ("All Entra ID users, groups and service principals with role, last sign-in and MFA status",),
          "gcp": ("All users, groups and service accounts with role, last activity and MFA status",)}
TOOLS = {
    "aws": ["IAM Access Analyzer, IAM Credential Report", "AWS Cost Explorer, AWS Budgets", "AWS Security Hub CSPM, Amazon Inspector",
            "CloudTrail, AWS Config, CloudWatch (enablement checks)", "Security Groups, NACLs, VPC Flow Logs", "Trusted Advisor, Compute Optimizer, EC2 console"],
    "azure": ["Azure RBAC, Microsoft Entra ID sign-in logs", "Azure Cost Management, Azure Budgets", "Microsoft Defender for Cloud",
              "Azure Activity Log, Azure Policy, Azure Monitor (enablement checks)", "Network Security Groups, Azure Firewall, NSG flow logs",
              "Azure Advisor, Azure Resource Graph, VM inventory"],
    "gcp": ["Cloud IAM, Policy Analyzer", "Cloud Billing reports, Cloud Billing budgets", "Security Command Center",
            "Cloud Audit Logs, Cloud Asset Inventory, Cloud Monitoring (enablement checks)", "VPC firewall rules, VPC Flow Logs",
            "Recommender / Active Assist, Compute Engine inventory"],
}
KEYS = {"aws": (("IAM User Access Keys", ("access_key",)), "Root Account Password Rotation"),
        "azure": (("App Registration Secrets / Certificates", ("client_secret", "certificate")), "Break-glass Account Password Rotation"),
        "gcp": (("Service Account Keys", ("sa_key",)), "Super Admin Password Rotation")}


# ---------------------------------------------------------------- helpers

def _aware(v: datetime | None) -> datetime | None:
    return None if v is None else v if v.tzinfo else v.replace(tzinfo=UTC)


def _dmy(v) -> str:
    return v.strftime("%d-%m-%Y") if v else "—"


def _usd(v) -> str:
    return NC if v is None else f"{v:,.2f}"


def _add_months(d: date, n: int) -> date:
    y, m = divmod(d.month - 1 + n, 12)
    return date(d.year + y, m + 1, 1)


def fiscal_quarter(month: date) -> dict:
    """Indian financial year (April–March): Q1 Apr–Jun, Q2 Jul–Sep, Q3 Oct–Dec, Q4 Jan–Mar."""
    fy = month.year if month.month >= 4 else month.year - 1
    q = (month.month - 4) % 12 // 3 + 1
    start = _add_months(date(fy, 4, 1), 3 * (q - 1))
    months = [_add_months(start, i) for i in range(3)]
    label = f"Q{q} FY {fy}-{str(fy + 1)[2:]} ({months[0]:%B} – {months[2]:%B %Y})"
    return {"q": q, "fy": fy, "months": months, "label": label}


def _budget_status(spend: float | None, budget: float | None) -> str:
    if spend is None:
        return NC
    if not budget:
        return "No approved budget"
    u = spend / budget * 100
    return "Exceeds" if u > 100 else "Near limit" if u >= 90 else "Within budget"


# ---------------------------------------------------------------- data

def collect(db: Session, settings: Settings, d: dict) -> dict:
    """Everything the template needs beyond the common report data `d` (from audit_report.build)."""
    provider, scope = d["provider"], d["scope"]
    month = date.fromisoformat(d["month"])
    now = datetime.now(UTC)
    first = month

    # findings (all security findings of the scope, open and closed)
    allf = list(db.scalars(select(CloudSecurityFinding).where(CloudSecurityFinding.provider == provider, CloudSecurityFinding.scope_external_id == scope,
                                                              CloudSecurityFinding.is_security.is_(True))))
    open_f = d["vulns"]["open"] + d["findings"]["open"]
    by_region: dict[str, dict] = {}
    for f in open_f:
        if f.severity in SEV:
            by_region.setdefault(f.region or "Global / not regional", dict.fromkeys(SEV, 0))[f.severity] += 1
    sev_total = {s: sum(r[s] for r in by_region.values()) for s in SEV}

    # quarter: spend vs budget and mitigation tracker
    fq = fiscal_quarter(month)
    cost_by_key = {m["key"]: m["cost_usd"] for m in d["cost"]["months"]}
    budget = d["cost"]["budget"]
    quarter = []
    for m in fq["months"]:
        if m > month:
            quarter.append({"month": m, "future": True})
            continue
        m_start = datetime.combine(m, datetime.min.time(), UTC)
        m_end = datetime.combine(_add_months(m, 1), datetime.min.time(), UTC)
        fixed = dict.fromkeys(SEV, 0)
        remaining = 0
        for f in allf:
            res = _aware(f.resolved_at)
            if res and m_start <= res < m_end and f.severity in SEV:
                fixed[f.severity] += 1
            obs = _aware(f.first_observed_at) or _aware(f.first_synced_at)
            closed_unknown = res is None and f.native_state != "ACTIVE"
            if obs and obs < m_end and not closed_unknown and (res is None or res >= m_end) and f.severity in SEV:
                remaining += 1
        spend = cost_by_key.get(m.strftime("%Y-%m"))
        quarter.append({"month": m, "future": False, "spend": spend, "budget": budget, "status": _budget_status(spend, budget),
                        "fixed": fixed, "remaining": remaining})

    # keys and secrets
    (key_label, kinds), pwd_label = KEYS[provider]
    creds_any = db.scalar(select(IamCredential.id).where(IamCredential.provider == provider).limit(1)) is not None
    creds = [c for c in db.scalars(select(IamCredential).where(IamCredential.provider == provider, IamCredential.scope_external_id == scope,
                                                               IamCredential.removed_at.is_(None), IamCredential.kind.in_(kinds)))]
    active_keys = [c for c in creds if (c.status or "Active").lower() == "active"]
    created = [_aware(c.created_at_provider) for c in active_keys if c.created_at_provider]
    rotated = sum(1 for c in created if first <= c.date() < _add_months(first, 1))
    next_due = min(created) + timedelta(days=90) if created else None
    if not creds_any:
        key_status = NC
    elif not active_keys:
        key_status = "NA"
    elif next_due and next_due < now:
        key_status = "Overdue"
    elif next_due and next_due < now + timedelta(days=15):
        key_status = "Expiring Soon"
    elif next_due:
        key_status = "Compliant"
    else:
        key_status = "Creation date not reported"
    keys = {"label": key_label, "collected": creds_any, "active": len(active_keys) if creds_any else None, "rotated": rotated if creds_any else None,
            "last": max(created) if created else None, "next_due": next_due, "status": key_status, "pwd_label": pwd_label}

    # resources and VMs
    res = list(db.scalars(select(CloudResource).where(CloudResource.provider == provider, CloudResource.scope_external_id == scope, CloudResource.not_deleted())))

    def state_class(s: str | None) -> str:
        s = (s or "").lower()
        return "Inactive" if s in INACTIVE else "Active" if s in ACTIVE or s.startswith("running") else "State not reported" if not s else "Active"

    def owner(r: CloudResource) -> str:
        tags = (r.attributes or {}).get("tags") or {}
        return next((str(v) for k, v in tags.items() if str(k).lower() in ("owner", "owner_email", "owneremail", "created_by", "createdby")), "")
    resources = [{"name": r.name or r.resource_id.rsplit("/", 1)[-1], "id": r.resource_id, "type": r.resource_type, "region": r.region or "",
                  "state": r.state or "", "status": state_class(r.state), "owner": owner(r)} for r in res]
    vms = list(db.scalars(select(VMInventory).where(VMInventory.provider == provider, VMInventory.scope_external_id == scope, VMInventory.deleted_at.is_(None))))
    vm_active = sum(1 for v in vms if state_class(v.power_state) == "Active" and v.power_state)
    vm_inactive = sum(1 for v in vms if state_class(v.power_state) == "Inactive")
    public = [v for v in vms if v.public_ip]
    mgmt = [v for v in public if MGMT_PORTS & set(v.exposed_ports or [])]
    dbp = [v for v in public if DB_PORTS & set(v.exposed_ports or [])]
    net_f = [f for f in open_f if NET_RE.search(f"{f.title or ''} {f.category or ''} {f.resource_type or ''}")]
    return {"fq": fq, "quarter": quarter, "by_region": by_region, "sev_total": sev_total, "open": open_f, "keys": keys,
            "resources": resources, "services": sorted({r["type"] for r in resources}), "inactive_resources": sum(r["status"] == "Inactive" for r in resources),
            "vms": {"collected": bool(vms), "total": len(vms), "active": vm_active, "inactive": vm_inactive, "unknown": len(vms) - vm_active - vm_inactive,
                    "public": len(public), "mgmt": len(mgmt), "db": len(dbp)},
            "network": {"findings": net_f, "collected": d["vulns"]["collected"] or bool(vms)},
            "generated": now, "prepared_by": settings.audit_report_prepared_by or "", "reviewed_by": settings.audit_report_reviewed_by or "",
            "version": settings.audit_report_version or ""}


def _risk(sev: set[str], any_items: bool) -> str:
    return "Critical" if "Critical" in sev else "High" if "High" in sev else "Medium" if any_items else "Low"


def domains(d: dict, t: dict) -> list[tuple[str, str, str, str]]:
    """The seven audit domains of the template: (domain, review status, overall risk, remarks)."""
    v, iam, c, k, vm, net = d["vulns"], d["iam"], d["cost"], t["keys"], t["vms"], t["network"]
    out = []
    if v["collected"]:
        st = t["sev_total"]
        out.append(("Vulnerability Management", REVIEW, _risk({f.severity for f in t["open"]}, bool(t["open"])),
                    f"{len(t['open'])} open (Critical {st['Critical']}, High {st['High']}); {len(d['overdue'])} past SLA"))
    else:
        out.append(("Vulnerability Management", NC, "Not assessed", "Security findings not collected for this scope"))
    if net["collected"]:
        sev = {f.severity for f in net["findings"]} | ({"High"} if vm["mgmt"] or vm["db"] else set())
        exposure = (f"{vm['mgmt']} VM(s) with SSH/RDP and {vm['db']} with database ports open to the internet" if vm["collected"]
                    else "VM exposure not collected")
        out.append(("Network Security", REVIEW, _risk(sev, bool(net["findings"])), f"{len(net['findings'])} open network findings; {exposure}"))
    else:
        out.append(("Network Security", NC, "Not assessed", "Network data not collected"))
    if iam["collected"]:
        nprinc = len({r["principal_id"] for r in iam["privileged"]})
        out.append(("Access Management", REVIEW, "High" if nprinc > 5 else "Medium" if nprinc else "Low",
                    f"{iam['identities']} identities, {nprinc} privileged; {len({r['principal_id'] for r in iam['dormant']})} dormant (30+ days)"))
    else:
        out.append(("Access Management", NC, "Not assessed", "Access inventory not collected"))
    if c["collected"]:
        out.append(("Cost Management", REVIEW, {"Exceeds budget": "High", "Near limit": "Medium", "Within budget": "Low"}.get(c["status"] or "", "Medium"),
                    f"{d['month_label']}: ${_usd(c['month_cost'])}" + (f" of ${_usd(c['budget'])} ({c['utilisation']}%)" if c["utilisation"] is not None else "; no approved budget")))
    else:
        out.append(("Cost Management", NC, "Not assessed", "Billing data not collected"))
    if k["collected"]:
        out.append(("Key / API Rotation", REVIEW, {"Overdue": "High", "Expiring Soon": "Medium"}.get(k["status"], "Low"),
                    f"{k['active']} active key(s), status {k['status']}; password rotation not collected"))
    else:
        out.append(("Key / API Rotation", NC, "Not assessed", "Key inventory not collected"))
    if t["resources"]:
        out.append(("Active Resources", REVIEW, "Medium" if t["inactive_resources"] or d["recommendations"] else "Low",
                    f"{len(t['resources'])} resource(s), {t['inactive_resources']} inactive; {len(d['recommendations'])} optimisation recommendation(s)"))
    else:
        out.append(("Active Resources", NC, "Not assessed", "Resource inventory not collected"))
    if vm["collected"]:
        out.append(("VM Lifecycle", REVIEW, "Medium" if vm["inactive"] else "Low", f"{vm['total']} VMs: {vm['active']} active, {vm['inactive']} inactive"))
    else:
        out.append(("VM Lifecycle", NC, "Not assessed", "VM inventory not collected"))
    return out


# ---------------------------------------------------------------- chart (6.1)

COLORS = {"Critical": (125, 32, 5), "High": (186, 46, 18), "Medium": (208, 97, 42), "Low": (181, 146, 25)}


def severity_chart(t: dict, provider: str, collected: bool) -> tuple[bytes, int, int]:
    """'Findings by Region' matrix (open findings, region × severity) as a PNG, drawn from collected data."""
    from PIL import Image, ImageDraw, ImageFont
    rows = sorted(t["by_region"].items(), key=lambda kv: -sum(kv[1].values()))[:8]
    w = 1438
    h = 190 + 96 * max(len(rows), 1) + (60 if len(t["by_region"]) > 8 else 20)
    im = Image.new("RGB", (w, h), "white")
    dr = ImageDraw.Draw(im)
    f_t, f_s, f_h, f_c = (ImageFont.load_default(size=s) for s in (34, 22, 26, 26))
    dr.rounded_rectangle((4, 4, w - 5, h - 5), 22, outline=(200, 200, 200), width=2)
    dr.text((40, 28), "Findings by Region", fill=(20, 20, 20), font=f_t)
    dr.text((40, 76), f"Open findings from {SOURCE[provider]}, collected by LV NEXUS, {t['generated']:%d-%m-%Y %H:%M} UTC", fill=(90, 90, 90), font=f_s)
    cols = [520, 750, 980, 1210]
    dr.text((40, 132), "Region", fill=(60, 60, 60), font=f_h)
    for x, s in zip(cols, SEV, strict=True):
        dr.rectangle((x, 138, x + 18, 156), fill=COLORS[s])
        dr.text((x + 28, 132), s, fill=(30, 30, 30), font=f_h)
    dr.line((30, 176, w - 30, 176), fill=(200, 200, 200), width=2)
    if not collected or not rows:
        msg = "Security findings not collected for this scope" if not collected else "No open Critical / High / Medium / Low findings"
        dr.text((40, 205), msg, fill=(90, 90, 90), font=f_h)
    for i, (region, c) in enumerate(rows):
        y = 190 + 96 * i
        dr.text((40, y + 28), region[:34], fill=(0, 102, 204), font=f_h)
        for x, s in zip(cols, SEV, strict=True):
            n = c[s]
            if n:
                dr.rectangle((x, y + 4, x + 200, y + 80), fill=COLORS[s])
                tw = dr.textlength(str(n), font=f_c)
                dr.rounded_rectangle((x + 100 - tw / 2 - 10, y + 24, x + 100 + tw / 2 + 10, y + 60), 8, fill="white")
                dr.text((x + 100 - tw / 2, y + 28), str(n), fill=(0, 0, 0), font=f_c)
            else:
                dr.text((x + 92, y + 28), "0", fill=(0, 0, 0), font=f_c)
        if i < len(rows) - 1:
            dr.line((30, y + 92, w - 30, y + 92), fill=(235, 235, 235), width=2)
    if len(t["by_region"]) > 8:
        dr.text((40, h - 50), f"+ {len(t['by_region']) - 8} more region(s), see Attachment C", fill=(90, 90, 90), font=f_s)
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue(), w, h


# ---------------------------------------------------------------- DOCX

def _runs(p):
    from docx.oxml.ns import qn
    return [r for r in p.runs if not r._r.findall(".//" + qn("w:drawing"))]


def _set_par(p, text: str) -> None:
    runs = _runs(p)
    if runs:
        runs[0].text = text
        for r in runs[1:]:
            r.text = ""
    else:
        p.add_run(text)


def _set_cell(cell, text: str) -> None:
    from docx.shared import Pt
    p = cell.paragraphs[0]
    if p.runs:
        p.runs[0].text = text
        for r in p.runs[1:]:
            r.text = ""
    elif text:
        p.add_run(text).font.size = Pt(9)


def _insert_after(p, text: str):
    from docx.text.paragraph import Paragraph
    new = deepcopy(p._p)
    p._p.addnext(new)
    np = Paragraph(new, p._parent)
    _set_par(np, text)
    return np


def _check_template(doc) -> None:
    P = doc.paragraphs
    ok = (len(doc.tables) == 11 and len(P) >= 100 and P[8].text.startswith("1. Executive Summary") and P[62].text.startswith("10. Virtual Machine")
          and P[98].text.startswith("13. Audit Sign-Off") and doc.tables[2].rows[0].cells[0].text == "Audit Domain")
    if not ok:
        raise RuntimeError("The audit report template does not match the expected layout (templates/monthly_audit_report.docx).")


def docx_bytes(d: dict, t: dict) -> bytes:
    import docx
    from docx.oxml.ns import qn
    doc = docx.Document(str(TEMPLATE))
    _check_template(doc)
    P = list(doc.paragraphs)
    T = doc.tables
    prov = d["provider"]
    head, noun, id_label = LABEL[prov]
    short = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}[prov]
    fmt = {"short": short, "noun": d["noun"], "name": d["name"], "id": d["scope"], "month": d["month_label"], "platform": d["provider_name"], "source": SOURCE[prov]}
    first = date.fromisoformat(d["month"])
    last = _add_months(first, 1) - timedelta(days=1)

    # header, cover
    for sec in doc.sections:
        for p in sec.header.paragraphs:
            if "|" in p.text:
                _set_par(p, f"{head}  |  {d['name']} – {d['scope']}  |  {d['month_label']}")
    _set_par(P[1], head)
    _set_par(P[3], f"{d['name']} – {d['scope']}")
    _set_par(P[4], f"Audit Month:  {d['month_label']}")
    own = d["ownership"]
    spoc = own.get("spoc_email") or ""
    spoc = f"{own['spoc_name']} ({spoc})" if own.get("spoc_name") and spoc else (own.get("spoc_name") or spoc or "Not assigned")
    cover = [f"{first:%d} – {last:%d %B %Y}", _dmy(t["generated"]), d["provider_name"], d["name"], d["scope"], spoc,
             "CONFIDENTIAL – Internal Use Only", t["prepared_by"], t["reviewed_by"], t["version"]]
    for i, v in enumerate(cover):
        _set_cell(T[0].rows[i].cells[1], v)
    _set_cell(T[0].rows[3].cells[0], noun)
    _set_cell(T[0].rows[4].cells[0], id_label)
    _set_cell(T[1].rows[1].cells[2], ATTACH[prov][0])
    _set_cell(T[1].rows[3].cells[2], f"Open findings exported from {SOURCE[prov]} with severity and SLA due date")

    # provider wording
    for idx, variants in TEXT.items():
        _set_par(P[idx], variants.get(prov, variants.get("*", "")).format(**fmt))

    # 1. executive summary domains
    for r, (dom, st, risk, rem) in enumerate(domains(d, t), start=1):
        for c, v in enumerate((dom, st, risk, rem)):
            _set_cell(T[2].rows[r].cells[c], v)

    # 3. actions taken: tools per provider; "Done" ticks only when LV NEXUS collected that data (not a human sign-off)
    collected = [d["iam"]["collected"], d["cost"]["collected"], d["vulns"]["collected"], d["compliance"]["collected"],
                 t["network"]["collected"], bool(t["resources"]) or t["vms"]["collected"]]
    for r, (tool, ok) in enumerate(zip(TOOLS[prov], collected, strict=True), start=1):
        _set_cell(T[3].rows[r].cells[1], tool)
        _set_cell(T[3].rows[r].cells[2], "☑" if ok else "☐")
    note = deepcopy(P[10]._p)
    T[3]._tbl.addnext(note)
    from docx.text.paragraph import Paragraph
    _set_par(Paragraph(note, P[10]._parent), "Done: ☑ = LV NEXUS collected this data automatically for the month; ☐ = not collected. "
                                              "It is not a reviewer sign-off – the SPOC review is recorded in Section 13.")

    # 4. access review
    iam = d["iam"]
    vals = ([str(iam["identities"]), str(len({r["principal_id"] for r in iam["removed"]})), NC, str(len({r["principal_id"] for r in iam["privileged"]}))]
            if iam["collected"] else [NC] * 4)
    for c, v in enumerate(vals, start=1):
        _set_cell(T[4].rows[1].cells[c], v)

    # 5. cost, fiscal quarter
    _set_par(P[25], f"5.1 Monthly Spend vs Budget – {t['fq']['label']}")
    tot_b = tot_s = 0.0
    any_b = any_s = False
    exceeded = []
    for r, q in enumerate(t["quarter"], start=1):
        row = T[5].rows[r].cells
        _set_cell(row[0], f"{q['month']:%B}")
        _set_cell(T[6].rows[r].cells[0], f"{q['month']:%B}")
        _set_cell(T[7].rows[r].cells[0], f"{q['month']:%B}")
        if q["future"]:
            for c in range(1, 4):
                _set_cell(row[c], "")
            continue
        _set_cell(row[1], _usd(q["budget"]) if q["budget"] else "No approved budget")
        _set_cell(row[2], _usd(q["spend"]))
        _set_cell(row[3], q["status"])
        if q["budget"]:
            tot_b += q["budget"]
            any_b = True
        if q["spend"] is not None:
            tot_s += q["spend"]
            any_s = True
        six = T[6].rows[r].cells
        for cell in six[1:]:
            for run in cell.paragraphs[0].runs:
                run.bold = None
        if q["budget"] and q["spend"] is not None and q["spend"] > q["budget"]:
            over = q["spend"] - q["budget"]
            exceeded.append((q["budget"], q["spend"], over))
            for c, v in enumerate((_usd(q["budget"]), _usd(q["spend"]), _usd(over), "", "Pending SPOC confirmation"), start=1):
                _set_cell(six[c], v)
        else:
            for c in range(1, 6):
                _set_cell(six[c], "NA")
    qt = T[5].rows[4].cells
    _set_cell(qt[1], _usd(tot_b) if any_b else "No approved budget")
    _set_cell(qt[2], _usd(tot_s) if any_s else NC)
    _set_cell(qt[3], _budget_status(tot_s if any_s else None, tot_b if any_b else None))
    gt = T[6].rows[4].cells
    if exceeded:
        for c, v in enumerate((_usd(sum(e[0] for e in exceeded)), _usd(sum(e[1] for e in exceeded)), _usd(sum(e[2] for e in exceeded)), "", ""), start=1):
            _set_cell(gt[c], v)
    else:
        for c in range(1, 6):
            _set_cell(gt[c], "NA")

    # 6. vulnerabilities: SLA line, chart, mitigation tracker, exceptions
    sla = d["sla_days"]
    _set_par(P[30], "SLA Policy:   " + "   |   ".join(f"{s} – {sla.get(s, '—')} days" for s in SEV))
    png, w, h = severity_chart(t, prov, d["vulns"]["collected"])
    for blip in P[32]._p.iter(qn("a:blip")):
        doc.part.related_parts[blip.get(qn("r:embed"))]._blob = png
    for ext_tag in ("wp:extent", "a:ext"):
        for ext in P[32]._p.iter(qn(ext_tag)):
            ext.set("cy", str(int(int(ext.get("cx")) * h / w)))
    st = t["sev_total"]
    _set_par(P[32], (f"Total = Critical + High + Medium + Low = {st['Critical']} + {st['High']} + {st['Medium']} + {st['Low']} = {sum(st.values())}"
                     if d["vulns"]["collected"] else f"Total = Critical + High + Medium + Low: {NC}"))
    fx = dict.fromkeys(SEV, 0)
    last_remaining = None
    for r, q in enumerate(t["quarter"], start=1):
        cells = T[7].rows[r].cells
        if q["future"]:
            continue
        if not d["vulns"]["collected"]:
            for c in range(1, 7):
                _set_cell(cells[c], NC)
            continue
        for c, s in enumerate(SEV, start=1):
            _set_cell(cells[c], str(q["fixed"][s]))
            fx[s] += q["fixed"][s]
        _set_cell(cells[5], str(sum(q["fixed"].values())))
        _set_cell(cells[6], str(q["remaining"]))
        last_remaining = q["remaining"]
    tot = T[7].rows[4].cells
    for c, s in enumerate(SEV, start=1):
        _set_cell(tot[c], str(fx[s]) if d["vulns"]["collected"] else NC)
    _set_cell(tot[5], str(sum(fx.values())) if d["vulns"]["collected"] else NC)
    _set_cell(tot[6], str(last_remaining) if last_remaining is not None else NC)

    now = t["generated"]
    order = {s: i for i, s in enumerate(SEV)}
    ex = [f for f in t["open"] if f.severity in ("Critical", "High") or (f.sla_due_at and _aware(f.sla_due_at) < now and not f.sla_paused)]
    ex.sort(key=lambda f: (order.get(f.severity, 9), _aware(f.sla_due_at) or now + timedelta(days=9999)))
    tbl = T[8]
    template_row = tbl.rows[1]._tr
    for r in list(tbl.rows)[1:]:
        tbl._tbl.remove(r._tr)
    items = ex[:25] or [None]
    for f in items:
        tr = deepcopy(template_row)
        tbl._tbl.append(tr)
        cells = tbl.rows[-1].cells
        if f is None:
            vals = ["NA" if d["vulns"]["collected"] else NC, "", "", "", "", ""]
        else:
            due = _aware(f.sla_due_at)
            overdue = due is not None and due < now and not f.sla_paused
            status = f"{f.internal_status.replace('_', ' ').title()}{' – SLA breached' if overdue else ''}"
            if getattr(f, "owner", None):
                status += f" / {f.owner}"
            vals = [(f.title or "")[:110], (f.resource_name or f.resource_id or "")[:60], f.severity, _dmy(_aware(f.first_observed_at)), _dmy(due), status]
        for c, v in enumerate(vals):
            _set_cell(cells[c], v)
    if len(ex) > 25:
        _set_par(P[35], f"Showing 25 of {len(ex)} Critical/High findings and SLA breaches; the full list is in Attachment C. "
                        "List only Critical/High findings, SLA breaches and approved exceptions here.")

    # 7. keys and secrets
    k = t["keys"]
    r1 = T[9].rows[1].cells
    for c, v in enumerate((k["label"], "—" if k["active"] is None else str(k["active"]), "—" if k["rotated"] is None else str(k["rotated"]), "90 days",
                           _dmy(k["last"]), _dmy(k["next_due"]), k["status"])):
        _set_cell(r1[c], v)
    r2 = T[9].rows[2].cells
    for c, v in enumerate((k["pwd_label"], "—", "—", "Monthly (30 days)", "—", "—", "Not collected – confirm with SPOC")):
        _set_cell(r2[c], v)

    # 8. active services (result line)
    recs = d["recommendations"]
    if t["resources"]:
        _insert_after(P[41], f"This month: {len(t['resources'])} active resource(s) across {len(t['services'])} resource types, {t['inactive_resources']} inactive; "
                             f"{len(recs)} optimisation recommendation(s) from LV NEXUS.")
    else:
        _insert_after(P[41], f"This month: resource inventory {NC.lower()} for this {d['noun']}.")
    # 9. network (result line)
    vm, nf = t["vms"], t["network"]["findings"]
    if t["network"]["collected"]:
        top = "; ".join((f.title or "")[:70] for f in nf[:3])
        vm_txt = (f"VMs with a public IP: {vm['public']}; with SSH/RDP open to the internet: {vm['mgmt']}; with database ports open: {vm['db']}."
                  if vm["collected"] else f"VM exposure: {NC.lower()}.")
        _insert_after(P[51], f"This month: {len(nf)} open network-exposure finding(s){(' – ' + top) if top else ''}. {vm_txt}")
    else:
        _insert_after(P[51], f"This month: network data {NC.lower()} for this {d['noun']}.")
    # 10. VM counts
    if vm["collected"]:
        _set_par(P[65], f"Total VMs under management: {vm['total']}")
        _set_par(P[66], f"Active VMs: {vm['active']}")
        _set_par(P[67], f"Inactive / Orphaned VMs: {vm['inactive']}" + (f" (power state not reported for {vm['unknown']})" if vm["unknown"] else ""))
    else:
        for i, lbl in ((65, "Total VMs under management"), (66, "Active VMs"), (67, "Inactive / Orphaned VMs")):
            _set_par(P[i], f"{lbl}: {NC}")

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------- PDF (rendered from the filled DOCX)

_REPL = {"–": "-", "—": "-", "’": "'", "‘": "'", "“": '"', "”": '"', "•": "-", "·": "-", "☐": "[ ]", "☑": "[x]", "…": "...", "≥": ">=", "≤": "<=", "₹": "INR "}


def _l1(s: str) -> str:
    for a, b in _REPL.items():
        s = s.replace(a, b)
    return s.encode("latin-1", "replace").decode("latin-1")


def _hex(v, default=(0, 0, 0)):
    s = str(v) if v is not None else ""
    if len(s) != 6 or s.lower() == "auto":
        return default
    return tuple(int(s[i:i + 2], 16) for i in (0, 2, 4))


def pdf_from_docx(docx_data: bytes) -> bytes:
    import docx
    from docx.oxml.ns import qn
    from docx.table import Table
    from docx.text.paragraph import Paragraph
    from fpdf import FPDF, FontFace

    doc = docx.Document(io.BytesIO(docx_data))
    header = next((p.text for s in doc.sections for p in s.header.paragraphs if p.text.strip()), "")
    styles = {s: doc.styles[s] for s in ("Normal", "Heading 1", "Heading 2", "List Paragraph")}

    class PDF(FPDF):
        def header(self):
            if self.page_no() > 1:
                self.set_font("Helvetica", "", 7.5)
                self.set_text_color(127, 127, 127)
                self.cell(0, 5, _l1(header), align="R")
                self.ln(8)

        def footer(self):
            self.set_y(-14)
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(127, 127, 127)
            self.cell(0, 5, _l1("CONFIDENTIAL – Internal Use Only"))
            self.cell(0, 5, f"Page {self.page_no()} of {{nb}}", align="R")

    pdf = PDF(format="A4")
    pdf.set_margins(19, 17, 19)
    pdf.set_auto_page_break(True, 20)
    pdf.add_page()
    usable = pdf.w - 38

    def para_fmt(p):
        st = p.style if p.style is not None else styles["Normal"]
        runs = _runs(p)
        r = runs[0] if runs else None
        size = (r.font.size.pt if r and r.font.size else None) or (st.font.size.pt if st.font.size else 9.5)
        bold = r.bold if r is not None and r.bold is not None else bool(st.font.bold)
        italic = bool(r.italic) if r and r.italic else False
        col = r.font.color.rgb if r and r.font.color and r.font.color.type else (st.font.color.rgb if st.font.color and st.font.color.type else None)
        pf = p.paragraph_format
        before = (pf.space_before.pt if pf.space_before is not None else (st.paragraph_format.space_before.pt if st.paragraph_format.space_before else 2)) * 0.3528
        after = (pf.space_after.pt if pf.space_after is not None else (st.paragraph_format.space_after.pt if st.paragraph_format.space_after else 3)) * 0.3528
        align = {1: "C", 2: "R", 3: "J"}.get(int(p.alignment) if p.alignment is not None else 0, "L")
        return size, bold, italic, _hex(col), before, after, align, st.name

    for el in doc.element.body.iterchildren():
        if el.tag == qn("w:p"):
            p = Paragraph(el, doc)
            if el.findall(".//" + qn("w:br")) and any(b.get(qn("w:type")) == "page" for b in el.iter(qn("w:br"))):
                pdf.add_page()
            size, bold, italic, col, before, after, align, sname = para_fmt(p)
            for blip in el.iter(qn("a:blip")):
                ext = next(el.iter(qn("wp:extent")))
                wmm, hmm = int(ext.get("cx")) / 36000, int(ext.get("cy")) / 36000
                if pdf.get_y() + hmm > pdf.h - 22:
                    pdf.add_page()
                x = pdf.l_margin + (usable - wmm) / 2 if align == "C" else pdf.l_margin
                pdf.image(io.BytesIO(doc.part.related_parts[blip.get(qn("r:embed"))].blob), x=x, w=wmm, h=hmm)
                pdf.ln(1.5)
            text = "".join(r.text for r in _runs(p)).strip()
            if not text:
                pdf.ln(2)
                continue
            if sname.startswith("Heading") and pdf.get_y() > pdf.h - 45:
                pdf.add_page()
            pdf.ln(before)
            pdf.set_font("Helvetica", ("B" if bold else "") + ("I" if italic else ""), size)
            pdf.set_text_color(*col)
            lh = size * 0.47
            if sname == "List Paragraph":
                pdf.set_x(pdf.l_margin + 4)
                pdf.cell(4, lh, "-")
                pdf.multi_cell(usable - 8, lh, _l1(text), align="L", new_x="LMARGIN", new_y="NEXT")
            else:
                pdf.multi_cell(usable, lh, _l1(text), align=align, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(after)
        elif el.tag == qn("w:tbl"):
            t = Table(el, doc)
            widths = [max(c.width or 0, 1) for c in t.rows[0].cells]
            total = sum(widths)
            cols = [w / total * usable for w in widths]
            tcPr = t.rows[0].cells[0]._tc.tcPr
            shd = tcPr.find(qn("w:shd")) if tcPr is not None else None
            first_fill = shd.get(qn("w:fill")) if shd is not None else None
            heading = (first_fill or "").upper() == "1F3864"
            pdf.set_draw_color(191, 191, 191)
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
            with pdf.table(col_widths=cols, width=usable, first_row_as_headings=heading, line_height=4.2, padding=1.4, text_align="LEFT",
                           headings_style=FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=(31, 56, 100)), borders_layout="ALL") as tb:
                for row in t.rows:
                    tr = tb.row()
                    for cell in row.cells:
                        cp = cell._tc.tcPr
                        sh = cp.find(qn("w:shd")) if cp is not None else None
                        fill = sh.get(qn("w:fill")) if sh is not None else None
                        runs = cell.paragraphs[0].runs
                        r0 = runs[0] if runs else None
                        color = _hex(r0.font.color.rgb if r0 is not None and r0.font.color and r0.font.color.type else None)
                        style = FontFace(emphasis="BOLD" if r0 is not None and r0.bold else "", color=color,
                                         fill_color=_hex(fill, None) if fill and fill.lower() != "auto" else None)
                        al = cell.paragraphs[0].alignment
                        tr.cell(_l1(cell.text), style=style, align="CENTER" if al is not None and int(al) == 1 else "LEFT")
            pdf.ln(3)
    return bytes(pdf.output())

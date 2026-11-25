"""CSV / Excel export of the asset register and bulk import of business metadata.

Import rules: rows are matched by Provider + Resource ID (as exported). Only the business-metadata columns are applied;
collected columns in the file are ignored and reported, so an import can never overwrite collected data. A dry run
(default) reports per row what would change; nothing is written until the import is applied."""
from __future__ import annotations

import csv
import io
from datetime import date, datetime

from app.models import MANUAL_FIELDS

MAX_ROWS = 5000
MAX_BYTES = 5 * 1024 * 1024
COLLECTED = [  # (key, header)
    ("provider", "Cloud Provider"), ("scope", "Account / Subscription / Project ID"), ("scope_name", "Account / Subscription / Project"),
    ("resource_id", "Resource ID"), ("kind", "Asset Kind"), ("name", "Server / Resource Name"), ("hostname", "Hostname"),
    ("ip_address", "IP Address"), ("public_ip", "Public IP"), ("region", "Region"), ("resource_type", "Resource Type"), ("category", "Category"),
    ("size", "Size / SKU"), ("server_status", "Server Status"), ("guest_os", "Guest OS"), ("cpus", "CPUs"), ("memory_gb", "Memory Size (GB)"),
    ("nic_count", "NIC"), ("provisioned_gb", "Provisioned Space (GB)"), ("used_gb", "Used Space (GB)"),
    ("native_backup_status", "Cloud Native Backup Status"), ("native_backup_last_at", "Last Cloud Backup"),
    ("create_date", "Create Date"), ("last_activity_at", "Last Activity Date"), ("last_login_at", "Last Login"),
    ("last_monitoring_at", "Last Monitoring Date"), ("activity_status", "Activity Status"), ("activity_reason", "Activity Reason"),
    ("estimated_monthly_cost_usd", "Estimated Monthly Cost (USD)"), ("recommended_action", "Recommended Action"),
]
MANUAL = [(c, label) for c, label, _, _ in MANUAL_FIELDS]
HEADERS = [h for _, h in COLLECTED[:6]] + [h for _, h in MANUAL] + [h for _, h in COLLECTED[6:]]
KEYS = [k for k, _ in COLLECTED[:6]] + [k for k, _ in MANUAL] + [k for k, _ in COLLECTED[6:]]
HEADER_TO_MANUAL = {label.lower(): c for c, label in MANUAL} | {c.lower(): c for c, _ in MANUAL}
COLLECTED_HEADERS = {h.lower() for _, h in COLLECTED} | {k for k, _ in COLLECTED}


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # spreadsheet formula injection guard


def export_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(HEADERS)
    for r in rows:
        w.writerow([_cell(r.get(k)) for k in KEYS])
    return buf.getvalue().encode("utf-8-sig")


def export_xlsx(rows: list[dict], title: str = "Cloud assets") -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = title[:31]
    ws.append(HEADERS)
    manual_cols = {i + 1 for i, k in enumerate(KEYS) if k in dict(MANUAL)}
    for c in range(1, len(HEADERS) + 1):
        cell = ws.cell(row=1, column=c)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="2E75B6" if c in manual_cols else "1F3864")
    for r in rows:
        ws.append([_cell(r.get(k)) for k in KEYS])
    for c in range(1, len(HEADERS) + 1):
        ws.column_dimensions[get_column_letter(c)].width = min(max(len(HEADERS[c - 1]) + 2, 12), 40)
    ws.freeze_panes = "G2"
    info = wb.create_sheet("Read me")
    for line in ("Light-blue columns are business metadata: edit them and import the file back (Cloud Services Management → Import).",
                 "Dark-blue columns are collected from the clouds and are ignored on import.",
                 "Rows are matched on Cloud Provider + Resource ID. Leave a cell empty to clear the value.",
                 "Allowed values: " + "; ".join(f"{label}: {', '.join(allowed)}" for _, label, kind, allowed in MANUAL_FIELDS if allowed)):
        info.append([line])
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


class ImportError_(ValueError):
    pass


def read_table(filename: str, data: bytes) -> list[dict]:
    """Rows as {header (lower-case): value}. Supports .csv and .xlsx."""
    if len(data) > MAX_BYTES:
        raise ImportError_(f"File larger than {MAX_BYTES // 1024 // 1024} MB")
    name = (filename or "").lower()
    if name.endswith(".xlsx"):
        from openpyxl import load_workbook
        try:
            wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        except Exception as exc:  # noqa: BLE001
            raise ImportError_("Not a valid .xlsx file") from exc
        ws = wb.worksheets[0]
        it = ws.iter_rows(values_only=True)
        head = [str(h or "").strip().lower() for h in next(it, [])]
        rows = [{head[i]: v for i, v in enumerate(r) if i < len(head) and head[i]} for r in it if any(c not in (None, "") for c in r)]
    elif name.endswith(".csv"):
        text = data.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        rows = [{(k or "").strip().lower(): v for k, v in r.items() if k} for r in reader]
    else:
        raise ImportError_("Use a .csv or .xlsx file (export the register to get the template)")
    if len(rows) > MAX_ROWS:
        raise ImportError_(f"More than {MAX_ROWS} rows; split the file")
    return rows


def _unquote(v):
    if isinstance(v, str) and v.startswith("'") and v[1:2] in ("=", "+", "-", "@"):
        return v[1:]
    return v


def plan_import(rows: list[dict], known: dict[tuple[str, str], dict]) -> dict:
    """Validate rows against the register. `known` maps (provider, lower resource id) -> current register row."""
    from app.services.assets.metadata import MetadataError, clean

    if not rows:
        return {"rows": [], "valid": 0, "invalid": 0, "changes": 0, "ignored_columns": []}
    headers = set(rows[0])
    if "cloud provider" not in headers and "provider" not in headers or "resource id" not in headers and "resource_id" not in headers:
        raise ImportError_("The file needs the columns 'Cloud Provider' and 'Resource ID'")
    ignored = sorted(h for h in headers if h in COLLECTED_HEADERS and h not in ("cloud provider", "provider", "resource id", "resource_id"))
    out, valid, invalid, changes = [], 0, 0, 0
    for n, raw in enumerate(rows, start=2):
        prov = str(raw.get("cloud provider") or raw.get("provider") or "").strip().lower()
        rid = str(raw.get("resource id") or raw.get("resource_id") or "").strip()
        entry = {"row": n, "provider": prov, "resource_id": rid, "status": "ok", "changes": {}, "error": None}
        current = known.get((prov, rid.lower()))
        if current is None:
            entry.update(status="error", error="Asset not found in the register (or not visible to you)")
            invalid += 1
            out.append(entry)
            continue
        fields = {HEADER_TO_MANUAL[h]: _unquote(v) for h, v in raw.items() if h in HEADER_TO_MANUAL}
        try:
            data = clean(fields)
        except MetadataError as exc:
            entry.update(status="error", error=str(exc))
            invalid += 1
            out.append(entry)
            continue
        for c, v in data.items():
            old = current.get(c)
            new = v.isoformat() if isinstance(v, date) else v
            if (old or None) != (new or None):
                entry["changes"][c] = {"old": old, "new": new}
        entry.update(fields=data, scope=current["scope"], resource_id=current["resource_id"])
        if not entry["changes"]:
            entry["status"] = "unchanged"
        changes += len(entry["changes"])
        valid += 1
        out.append(entry)
    return {"rows": out, "valid": valid, "invalid": invalid, "changes": changes, "ignored_columns": ignored}

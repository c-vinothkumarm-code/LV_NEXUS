"""Reports & Analytics: 15 reports (CSV / Excel / PDF), schedules and the archive of generated files.
Every report checks the requester's permission; scheduled reports are generated with their owner's current permissions."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import log_action
from app.api.serializers import iso
from app.core.security import current_user, require
from app.database.session import get_db
from app.models import User
from app.models.reporting import ReportArchive, ReportSchedule
from app.services.reports.catalogue import REPORTS, Filters, generate

router = APIRouter(prefix="/api/v1/reports", tags=["reports and analytics"])
FORMATS = ("csv", "xlsx", "pdf")


def next_run(s: ReportSchedule, after: datetime) -> datetime:
    t = after.replace(minute=0, second=0, microsecond=0, hour=s.hour_utc)
    if t <= after:
        t += timedelta(days=1)
    if s.frequency == "weekly":
        while t.weekday() != (s.day or 0):
            t += timedelta(days=1)
    elif s.frequency == "monthly":
        while t.day != (s.day or 1):
            t += timedelta(days=1)
    return t


@router.get("/catalogue")
def catalogue(user: User = Depends(current_user)):
    return {"items": [{"key": r.key, "title": r.title, "permission": r.permission, "available": r.permission in user.permission_names}
                      for r in REPORTS.values()], "formats": list(FORMATS)}


@router.get("/run/{key}")
def run_report(key: str, format: str = "csv", provider: str | None = None, scope: str | None = None, date_from: date | None = None,
               date_to: date | None = None, db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    rep = REPORTS.get(key)
    if rep is None:
        raise HTTPException(404, "Unknown report")
    if rep.permission not in user.permission_names:
        raise HTTPException(403, f"This report needs the {rep.permission} permission")
    if format not in FORMATS:
        raise HTTPException(422, "format must be csv, xlsx or pdf")
    content, mime, fname = generate(db, key, format, Filters(provider, scope, date_from, date_to), user)
    log_action(db, user.email, "report.export", key, {"format": format, "provider": provider, "scope": scope})
    db.commit()
    return Response(content, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{fname}"'})


class ScheduleBody(BaseModel):
    report_key: str
    format: str = "xlsx"
    frequency: str
    day: int | None = Field(default=None, ge=0, le=28)
    hour_utc: int = Field(default=3, ge=0, le=23)
    recipients: list[str] = Field(min_length=1, max_length=20)
    filters: dict = {}
    enabled: bool = True

    @field_validator("recipients")
    @classmethod
    def _emails(cls, v: list[str]) -> list[str]:
        import re
        bad = [x for x in v if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", x)]
        if bad:
            raise ValueError(f"not valid e-mail addresses: {', '.join(bad)}")
        return [x.lower() for x in v]


def _sched(s: ReportSchedule) -> dict:
    return {"id": s.id, "report_key": s.report_key, "title": REPORTS[s.report_key].title if s.report_key in REPORTS else s.report_key,
            "format": s.format, "frequency": s.frequency, "day": s.day, "hour_utc": s.hour_utc, "recipients": s.recipients, "filters": s.filters,
            "enabled": s.enabled, "owner_email": s.owner_email, "last_run_at": iso(s.last_run_at), "next_run_at": iso(s.next_run_at),
            "last_status": s.last_status}


@router.get("/schedules")
def schedules(db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    stmt = select(ReportSchedule)
    if "admin:users" not in user.permission_names:
        stmt = stmt.where(ReportSchedule.owner_email == user.email)
    return {"items": [_sched(s) for s in db.scalars(stmt.order_by(ReportSchedule.id))]}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleBody, db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    rep = REPORTS.get(body.report_key)
    if rep is None or rep.permission not in user.permission_names:
        raise HTTPException(403, "You cannot schedule a report you are not allowed to run")
    if body.format not in FORMATS or body.frequency not in ("daily", "weekly", "monthly"):
        raise HTTPException(422, "format must be csv, xlsx or pdf and frequency daily, weekly or monthly")
    s = ReportSchedule(**body.model_dump(), owner_email=user.email)
    s.next_run_at = next_run(s, datetime.now(UTC))
    db.add(s)
    log_action(db, user.email, "report.schedule", body.report_key, {"frequency": body.frequency})
    db.commit()
    return _sched(s)


@router.delete("/schedules/{sid}")
def delete_schedule(sid: int, db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    s = db.get(ReportSchedule, sid)
    if s is None or (s.owner_email != user.email and "admin:users" not in user.permission_names):
        raise HTTPException(404, "Schedule not found")
    s.enabled = False
    log_action(db, user.email, "report.schedule_disabled", s.report_key)
    db.commit()
    return {"status": "disabled"}


@router.get("/archive")
def archive(db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    rows = db.scalars(select(ReportArchive).order_by(ReportArchive.id.desc()).limit(200))
    return {"items": [{"id": a.id, "report_key": a.report_key, "filename": a.filename, "size": a.size, "generated_for": a.generated_for,
                       "at": iso(a.created_at)} for a in rows if REPORTS.get(a.report_key) and REPORTS[a.report_key].permission in user.permission_names]}


@router.get("/archive/{aid}")
def archive_file(aid: int, db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    a = db.get(ReportArchive, aid)
    if a is None or a.report_key not in REPORTS or REPORTS[a.report_key].permission not in user.permission_names:
        raise HTTPException(404, "Report not found")
    return Response(a.content, media_type=a.mime, headers={"Content-Disposition": f'attachment; filename="{a.filename}"'})


def run_due_schedules(db: Session, frontend_url: str) -> dict:
    """Generate due scheduled reports into the archive and e-mail recipients a link (the file stays behind sign-in)."""
    from app.models import NotificationLog
    t = datetime.now(UTC)
    done, failed = 0, 0
    for s in db.scalars(select(ReportSchedule).where(ReportSchedule.enabled.is_(True), ReportSchedule.next_run_at <= t)):
        owner = db.scalar(select(User).where(User.email == s.owner_email))
        rep = REPORTS.get(s.report_key)
        if owner is None or not owner.is_active or rep is None or rep.permission not in owner.permission_names or "reports:export" not in owner.permission_names:
            s.last_status, s.enabled = "Disabled: the owner no longer has permission for this report", False
            failed += 1
            continue
        f = s.filters or {}
        try:
            content, mime, fname = generate(db, s.report_key, s.format, Filters(f.get("provider"), f.get("scope")), owner)
        except Exception as exc:  # noqa: BLE001
            s.last_status = f"Failed: {type(exc).__name__}"
            s.next_run_at = next_run(s, t)
            failed += 1
            continue
        a = ReportArchive(schedule_id=s.id, report_key=s.report_key, filename=fname, mime=mime, content=content, size=len(content), generated_for=owner.email)
        db.add(a)
        db.flush()
        db.add(NotificationLog(channel="email", category="scheduled_report", subject=f"[LV NEXUS] {rep.title}", recipients=list(s.recipients),
                               body=f"The scheduled report '{rep.title}' was generated at {t:%Y-%m-%d %H:%M} UTC. Download it after signing in "
                                    f"(access is checked): {frontend_url.rstrip('/')}/reports?archive={a.id}"))
        s.last_run_at, s.last_status, s.next_run_at = t, f"Generated {fname}", next_run(s, t)
        done += 1
    return {"generated": done, "failed": failed}


@router.get("/governance/preview")
def governance_preview(fmt: str = "html", db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    """Today's Daily Governance Dashboard exactly as it would be e-mailed (html), or its text / Chat versions. Sends nothing."""
    from app.core.config import get_settings
    from app.services.notifications import governance as gov
    subject, text, page, chat = gov.preview(db, get_settings())
    if fmt == "html":
        return Response(page, media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-store"})
    return {"subject": subject, "text": text, "chat": chat}


# ---------------------------------------------------------------- monthly Cloud Security & Governance Audit (per account)

def _audit_month(month: str | None) -> date:
    from app.services.reports.audit_report import previous_month
    if not month:
        return previous_month()
    try:
        y, m = (int(x) for x in month.split("-"))
        d = date(y, m, 1)
    except ValueError:
        raise HTTPException(422, "month must be YYYY-MM") from None
    if d > datetime.now(UTC).date():
        raise HTTPException(422, "month is in the future")
    return d


def _audit_scope(db: Session, provider: str, scope: str):
    from app.services.ownership import scope_name
    if scope_name(db, provider, scope) is None:
        raise HTTPException(404, "Unknown account / subscription / project")


def _audit_reader(user: User = Depends(current_user)) -> User:
    # the report contains IAM, findings and cost: the caller needs every one of those views, not just report export
    need = ("reports:export", "access:read", "vuln:read", "finops:read")
    missing = [p for p in need if p not in user.permission_names]
    if missing:
        raise HTTPException(403, f"Missing permission: {', '.join(missing)}")
    return user


@router.get("/audit/{provider}/{scope}")
def audit_report(provider: str, scope: str, month: str | None = None, format: str = "pdf", db: Session = Depends(get_db),
                 user: User = Depends(_audit_reader)):
    """The monthly audit report for one scope (official LatentView layout): format=pdf, docx, or zip (report + attachments A, B, C)."""
    import base64
    import io
    import zipfile

    from app.core.config import get_settings
    from app.services.reports.audit_report import package
    _audit_scope(db, provider, scope)
    pkg = package(db, get_settings(), provider, scope, _audit_month(month))
    log_action(db, user.email, "report.audit.download", f"{provider}:{scope}:{pkg['data']['month'][:7]}", {"format": format})
    db.commit()
    if format == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for a in pkg["attachments"]:
                z.writestr(a["filename"], base64.b64decode(a["base64"]) if "base64" in a else a["text"].encode("utf-8-sig"))
        name = pkg["pdf_name"].replace(".pdf", ".zip")
        return Response(buf.getvalue(), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})
    if format == "docx":
        return Response(pkg["docx"], media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": f'attachment; filename="{pkg["docx_name"]}"', "Cache-Control": "no-store"})
    return Response(pkg["pdf"], media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{pkg["pdf_name"]}"', "Cache-Control": "no-store"})


@router.post("/audit/{provider}/{scope}/send")
def audit_send(provider: str, scope: str, month: str | None = None, db: Session = Depends(get_db), user: User = Depends(_audit_reader)):
    """Queue the monthly audit e-mail for one scope now (same rules as the scheduled run: once per scope and month)."""
    if "automation:run" not in user.permission_names:
        raise HTTPException(403, "Missing permission: automation:run")
    from app.core.config import get_settings
    from app.services.reports.audit_mail import send_one
    _audit_scope(db, provider, scope)
    result = send_one(db, get_settings(), provider, scope, _audit_month(month))
    log_action(db, user.email, "report.audit.send", f"{provider}:{scope}", {"result": result["status"]})
    db.commit()
    return result


@router.get("/audit/deliveries")
def audit_deliveries(limit: int = 200, db: Session = Depends(get_db), _: User = Depends(require("reports:export"))):
    """Delivery log of the monthly audit e-mails (queued / sent / failed with the reason and attempts)."""
    from app.models import NotificationLog
    rows = db.scalars(select(NotificationLog).where(NotificationLog.category == "security_monthly_audit_report")
                      .order_by(NotificationLog.id.desc()).limit(min(limit, 1000)))
    return {"items": [{"id": n.id, "subject": n.subject, "status": n.status, "attempts": n.attempts, "error": n.error,
                       "to": [r for r in (n.recipients or []) if not r.startswith("cc:")], "cc": [r[3:] for r in (n.recipients or []) if r.startswith("cc:")],
                       "attachments": [a.get("filename") for a in (n.attachments or [])], "created_at": iso(n.created_at), "sent_at": iso(n.sent_at)} for n in rows]}

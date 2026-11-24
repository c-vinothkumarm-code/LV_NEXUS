"""Sends queued notifications with retry. Never reports delivery that did not happen."""
from __future__ import annotations

import logging

from sqlalchemy import select

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import JobStatus, NotificationLog, utcnow
from app.scheduler.engine import JobContext, JobResult

from .channels import ChatWebhookChannel, GmailChannel

log = logging.getLogger(__name__)


def build_channels(settings: Settings) -> dict:
    return {c.name: c for c in (ChatWebhookChannel(settings), GmailChannel(settings))}


def dispatch(ctx: JobContext, settings: Settings, channels: dict | None = None) -> JobResult:
    db = ctx.db
    channels = channels if channels is not None else build_channels(settings)
    pending = db.scalars(select(NotificationLog).where(NotificationLog.status == "queued").order_by(NotificationLog.id).limit(200)).all()
    sent = failed = waiting = 0
    failures = []
    unconfigured = set()
    from datetime import UTC, timedelta
    cutoff = utcnow() - timedelta(hours=settings.notify_queue_max_age_hours)
    expired = 0
    for n in pending:
        created = n.created_at.replace(tzinfo=UTC) if n.created_at and n.created_at.tzinfo is None else n.created_at
        if created and created < cutoff:
            # A report that waited longer than this (e.g. while the channel was not configured) is out of date:
            # it is kept for the record but never delivered late as if it were current.
            n.status, n.error = "expired", f"Not delivered: older than {settings.notify_queue_max_age_hours} h when it could be sent"
            expired += 1
            db.commit()
            continue
        channel = channels.get(n.channel)
        if channel is None or not channel.configured():
            unconfigured.add(n.channel)  # stays queued; it is delivered once the channel is configured
            waiting += 1
            continue
        n.attempts += 1
        try:
            if n.channel == "email" and (n.recipients or n.body_html or n.attachments):
                kw = {"attachments": n.attachments} if n.attachments else {}
                channel.send(n.subject, n.body or "", to=n.recipients or None, html=n.body_html, **kw)  # recipients / HTML / attachments
            else:
                channel.send(n.subject, n.body or "")
            n.status, n.sent_at, n.error = "sent", utcnow(), None
            sent += 1
        except Exception as exc:  # noqa: BLE001
            n.error = safe_error(exc)
            if n.attempts >= settings.notify_max_attempts:
                n.status = "failed"
                failed += 1
                failures.append({"provider": n.channel, "scope": f"notification {n.id}", "reason": f"Delivery failed after {n.attempts} attempts: {n.error}"})
            else:
                waiting += 1
        db.commit()
    for ch in sorted(unconfigured):
        miss = channels[ch].missing() if ch in channels and hasattr(channels[ch], "missing") else []
        hint = f" (missing: {', '.join(miss)})" if miss else " (set CHAT_WEBHOOK_URL)" if ch == "google_chat" else ""
        failures.append({"provider": ch, "scope": "*", "reason": f"{ch} channel is not configured{hint}; messages remain queued"})
    summary = {"sent": sent, "failed": failed, "still_queued": waiting, "expired": expired}
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if sent == 0 else JobStatus.PARTIAL
    return JobResult(status, len(pending), failed, summary, failures)

"""Rule-driven, de-duplicated security notifications through the existing email / Google Chat queue."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import NotificationKey, NotificationLog, NotificationRule


def notify(db: Session, event_type: str, key: str, subject: str, body: str, execution_id: int | None = None, *,
           html: str | None = None, recipients: list[str] | None = None, attachments: list[dict] | None = None,
           chat_body: str | None = None) -> bool:
    """Queue one message per configured channel unless the rule is disabled or this key was already sent.
    Returns True when queued. `key` identifies the alert (e.g. finding 42 overdue on 2026-11-17).
    `html`, `recipients` and `attachments` apply to the e-mail channel only; Google Chat gets `chat_body` (or `body`)."""
    rule = db.scalar(select(NotificationRule).where(NotificationRule.event_type == event_type))
    if rule is None or not rule.enabled:
        return False
    dedup = f"{event_type}:{key}"[:255]
    if db.scalar(select(NotificationKey.id).where(NotificationKey.key == dedup)):
        return False
    try:
        with db.begin_nested():
            db.add(NotificationKey(key=dedup))
    except IntegrityError:  # another worker queued it first
        return False
    for channel in [c.strip() for c in rule.channels.split(",") if c.strip()]:
        mail = channel == "email"
        db.add(NotificationLog(channel=channel, category=f"security_{event_type}"[:64], subject=subject[:255],
                               body=body if mail else (chat_body or body), execution_id=execution_id,
                               body_html=html if mail else None, recipients=(recipients or None) if mail else None,
                               attachments=attachments if mail else None))
    return True

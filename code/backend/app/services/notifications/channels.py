"""Delivery channels. A message is marked sent only after the provider accepted it."""
from __future__ import annotations

import base64
from email.message import EmailMessage

import httpx

from app.core.config import Settings

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


class ChatWebhookChannel:
    """Google Chat space webhook. The URL is a secret (Secret Manager / .env), never logged."""

    name = "google_chat"

    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.url, self.client = settings.chat_webhook_url, client or httpx.Client(timeout=15)

    def configured(self) -> bool:
        return bool(self.url)

    def send(self, subject: str, body: str) -> None:
        resp = self.client.post(self.url, json={"text": f"*{subject}*\n{body}"[:4000]})
        if resp.status_code >= 300:
            raise RuntimeError(f"Google Chat returned HTTP {resp.status_code}")


def google_credentials(settings: Settings, scopes: list[str]):
    """Service-account credentials for Google APIs: the key file named in GOOGLE_APPLICATION_CREDENTIALS (setting or
    environment), otherwise Application Default Credentials (workload identity in production)."""
    import os

    path = settings.google_application_credentials or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if path:
        from google.oauth2 import service_account
        if not os.path.isfile(path):
            raise RuntimeError(f"GOOGLE_APPLICATION_CREDENTIALS points to a file that does not exist: {os.path.basename(path)}")
        return service_account.Credentials.from_service_account_file(path, scopes=scopes)
    import google.auth
    creds, _ = google.auth.default(scopes=scopes)
    return creds


class GmailChannel:
    """E-mail. Transport `smtp` (default: Google Workspace / Microsoft 365 / any relay, STARTTLS, app password) or
    `gmail_api` (service account with domain-wide delegation for gmail.send, impersonating GMAIL_SENDER).
    A message is reported sent only after the server accepted it."""

    name = "email"

    def __init__(self, settings: Settings, service=None, smtp_factory=None):
        self.settings, self._service, self._smtp_factory = settings, service, smtp_factory

    def missing(self) -> list[str]:
        s = self.settings
        need = [("NOTIFY_EMAIL_ENABLED=true", s.notify_email_enabled), ("GMAIL_SENDER (From address)", s.gmail_sender),
                ("NOTIFY_EMAIL_TO", s.notify_email_to)]
        if s.email_transport == "smtp":
            need += [("SMTP_HOST", s.smtp_host), ("SMTP_USERNAME", s.smtp_username), ("SMTP_PASSWORD", s.smtp_password)]
        return [n for n, v in need if not v]

    def configured(self) -> bool:
        return not self.missing()

    def _gmail(self):
        if self._service is None:
            from googleapiclient.discovery import build

            creds = google_credentials(self.settings, GMAIL_SCOPES)
            if not hasattr(creds, "with_subject"):
                raise RuntimeError("Gmail API needs service-account credentials with domain-wide delegation")
            self._service = build("gmail", "v1", credentials=creds.with_subject(self.settings.gmail_sender), cache_discovery=False)
        return self._service

    def _message(self, subject: str, body: str, to: list[str] | None, html: str | None, attachments: list[dict] | None = None) -> EmailMessage:
        msg = EmailMessage()
        # recipients prefixed "cc:" go to Cc (used by the per-account monthly audit e-mail); the rest are To
        to_list = [r for r in (to or []) if not r.startswith("cc:")]
        cc_list = [r[3:] for r in (to or []) if r.startswith("cc:")]
        msg["To"], msg["From"], msg["Subject"] = ", ".join(to_list or self.settings.notify_email_to), self.settings.gmail_sender, subject
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)
        msg.set_content(body)
        if html:
            msg.add_alternative(html, subtype="html")
        for a in attachments or []:
            maintype, _, subtype = (a.get("content_type") or "text/csv").partition("/")
            data = a["text"].encode("utf-8-sig") if "text" in a else base64.b64decode(a.get("base64", ""))
            msg.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream", filename=a["filename"])
        return msg

    def send(self, subject: str, body: str, to: list[str] | None = None, html: str | None = None, attachments: list[dict] | None = None) -> None:
        msg = self._message(subject, body, to, html, attachments)
        if self.settings.email_transport == "gmail_api":
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            self._gmail().users().messages().send(userId="me", body={"raw": raw}).execute()
            return
        import smtplib
        import ssl

        s = self.settings
        factory = self._smtp_factory or (lambda: smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=30, context=ssl.create_default_context())
                                         if s.smtp_port == 465 else smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30))
        with factory() as smtp:
            if s.smtp_port != 465 and s.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            smtp.login(s.smtp_username, s.smtp_password)
            smtp.send_message(msg)

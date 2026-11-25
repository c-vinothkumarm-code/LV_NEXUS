"""Write today's Daily Governance Dashboard to governance-preview.html (and print the Chat summary). Sends nothing.

    python -m app.governance_preview
"""
from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings
from app.database.session import get_session_factory
from app.services.notifications import governance as gov


def main() -> None:
    with get_session_factory()() as db:
        subject, text, page, chat = gov.preview(db, get_settings())
    out = Path("governance-preview.html").resolve()
    out.write_text(page, encoding="utf-8")
    print(subject)
    print(f"E-mail preview written to {out} (open it in a browser).\n")
    print("Google Chat message:\n" + chat)


if __name__ == "__main__":
    main()

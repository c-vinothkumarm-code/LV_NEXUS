"""DEMO_MODE safety guards: never on production, never on the real database, clouds and notifications off."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def _settings(**kw):
    base = {"app_env": "development", "auth_mode": "dev", "demo_mode": True}
    base.update(kw)
    return Settings(_env_file=None, **base)


def test_demo_mode_refused_in_production():
    with pytest.raises(ValidationError, match="DEMO_MODE is not allowed"):
        _settings(app_env="production", auth_mode="google", database_url="sqlite:///./x-demo.db")


@pytest.mark.parametrize("url", ["sqlite:///./real.db", "mysql+pymysql://u:p@db/lvnexus"])
def test_demo_mode_needs_separate_demo_sqlite(url):
    with pytest.raises(ValidationError, match="separate demo database"):
        _settings(database_url=url)


def test_demo_mode_forces_clouds_and_notifications_off():
    s = _settings(
        database_url="sqlite:///./lvnexus-demo.db",
        aws_enabled=True, azure_enabled=True, gcp_enabled=True,
        notify_email_enabled=True, chat_webhook_url="https://example.invalid/hook", sheets_enabled=True,
    )
    assert not (s.aws_enabled or s.azure_enabled or s.gcp_enabled)
    assert not s.notify_email_enabled and s.chat_webhook_url is None and not s.sheets_enabled


def test_demo_mode_off_by_default():
    assert Settings(_env_file=None, app_env="development", auth_mode="dev").demo_mode is False

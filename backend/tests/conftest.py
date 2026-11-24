"""Test fixtures. Set TEST_DATABASE_URL to a PostgreSQL URL to run against PostgreSQL through the real
Alembic migration; without it the suite uses in-memory SQLite. MySQL URLs (mysql+pymysql://...) are supported the same way."""
from __future__ import annotations

import os

TEST_DB = os.environ.get("TEST_DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import Settings as _Settings  # noqa: E402 - importing reads no settings

# Hermetic tests: never use the developer's .env file or LV NEXUS variables left in the shell (DEMO_MODE, AWS_EXTERNAL_ID, ...).
_Settings.model_config["env_file"] = None
for _name, _field in _Settings.model_fields.items():
    _alias = _field.validation_alias
    for _env in {_name, *(getattr(_alias, "choices", None) or ([_alias] if isinstance(_alias, str) else []))}:
        os.environ.pop(str(_env).upper(), None)
os.environ.update(DATABASE_URL=TEST_DB, APP_ENV="test", AUTH_MODE="dev", DEMO_MODE="false", ACCESS_WORKFLOWS_ENABLED="true",
                  AWS_ENABLED="false", GCP_ENABLED="false", AZURE_ENABLED="false")

import pytest  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core.config import Settings, get_settings  # noqa: E402
from app.database import session as db_session  # noqa: E402
from app.database.seed import seed_reference_data  # noqa: E402
from app.models import Base  # noqa: E402

IS_POSTGRES = TEST_DB.startswith("postgresql")
IS_SERVER_DB = TEST_DB.startswith("mysql")


@pytest.fixture(scope="session")
def engine():
    if IS_POSTGRES:
        eng = create_engine(TEST_DB)
        with eng.begin() as c:
            c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    if IS_POSTGRES or IS_SERVER_DB:
        if not IS_POSTGRES:
            eng = create_engine(TEST_DB, **db_session.engine_options(TEST_DB))
            with eng.begin() as c:
                c.execute(text("SET FOREIGN_KEY_CHECKS=0"))
                for t in c.execute(text("SHOW TABLES")).scalars().all():
                    c.execute(text(f"DROP TABLE IF EXISTS `{t}`"))
                c.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        from alembic import command
        from alembic.config import Config

        command.upgrade(Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini")), "head")
    if not (IS_POSTGRES or IS_SERVER_DB):
        eng = create_engine(TEST_DB, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def session_factory(engine, monkeypatch):
    with engine.begin() as c:
        if IS_POSTGRES:
            names = ", ".join(t.name for t in Base.metadata.sorted_tables)
            c.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
        elif IS_SERVER_DB:  # TRUNCATE bypasses the append-only triggers
            c.execute(text("SET FOREIGN_KEY_CHECKS=0"))
            for t in Base.metadata.sorted_tables:
                c.execute(text(f"TRUNCATE TABLE `{t.name}`"))
            c.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        else:
            for t in reversed(Base.metadata.sorted_tables):
                c.execute(t.delete())
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(db_session, "get_session_factory", lambda: factory)
    with factory() as db:
        seed_reference_data(db)
    return factory


@pytest.fixture()
def db(session_factory):
    with session_factory() as s:
        yield s


@pytest.fixture()
def settings():
    return Settings(_env_file=None)


@pytest.fixture()
def client(session_factory, monkeypatch):
    from fastapi.testclient import TestClient

    import app.main as main
    import app.workers.jobs as jobs
    import app.workers.run as run

    monkeypatch.setattr(main, "get_session_factory", lambda: session_factory)
    monkeypatch.setattr(run, "get_session_factory", lambda: session_factory)
    monkeypatch.setattr(jobs, "get_session_factory", lambda: session_factory)
    application = main.create_app()

    def _get_db():
        with session_factory() as s:
            yield s

    application.dependency_overrides[db_session.get_db] = _get_db
    with TestClient(application) as c:
        c.app_ref = application
        yield c


def use_settings(client, **overrides) -> Settings:
    s = Settings(_env_file=None, **overrides)
    client.app_ref.dependency_overrides[get_settings] = lambda: s
    return s


@pytest.fixture(autouse=True)
def _no_real_rate_limit_waits(monkeypatch):
    """Provider pacing (e.g. one Azure Cost Management query per 10 s) is real in production; tests use fakes, so they
    run unpaced. The RateLimiter itself is covered directly in tests/unit/test_reliability.py."""
    from app.services import reliability
    monkeypatch.setattr(reliability, "RATE_LIMITS", {k: (1e6, 1e6) for k in reliability.RATE_LIMITS})
    monkeypatch.setattr(reliability, "_limiters", {})

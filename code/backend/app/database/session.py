from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def engine_options(url: str, kwargs: dict | None = None) -> dict:
    """Same transaction behaviour on every database: READ COMMITTED (MySQL defaults to REPEATABLE READ)."""
    kwargs = dict(kwargs or {})
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    elif url.startswith(("mysql", "mssql")):
        kwargs["isolation_level"] = "READ COMMITTED"
    return kwargs


@lru_cache
def get_engine():
    url = get_settings().database_url
    kwargs = {"pool_pre_ping": True, "pool_recycle": 1800}
    return create_engine(url, **engine_options(url, kwargs))


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()

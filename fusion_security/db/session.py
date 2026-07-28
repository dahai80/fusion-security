from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "~/.fusion-security/fusion_security.db"


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None
_async_engine = None
_AsyncSessionLocal = None


def init_db(db_path: str = DEFAULT_DB_PATH, echo: bool = False) -> None:
    global _engine, _SessionLocal

    path = Path(db_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    url = f"sqlite:///{path}"
    _engine = create_engine(
        url,
        echo=echo,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)

    from . import models  # noqa: F401 — ensure models registered

    Base.metadata.create_all(_engine)
    logger.info(f"数据库已初始化: {path}")


def init_async_db(db_path: str = DEFAULT_DB_PATH, echo: bool = False) -> None:
    global _async_engine, _AsyncSessionLocal

    path = Path(db_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    url = f"sqlite+aiosqlite:///{path}"
    _async_engine = create_async_engine(url, echo=echo)
    _AsyncSessionLocal = async_sessionmaker(_async_engine, expire_on_commit=False)

    from . import models  # noqa: F401

    logger.info(f"异步数据库已初始化: {path}")


def get_session() -> Session:
    if _SessionLocal is None:
        init_db()
    return _SessionLocal()


def get_async_session() -> AsyncSession:
    if _AsyncSessionLocal is None:
        init_async_db()
    return _AsyncSessionLocal()

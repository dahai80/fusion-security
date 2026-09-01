from __future__ import annotations

import logging
import threading
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
_init_lock = threading.Lock()
_async_init_lock = threading.Lock()


def init_db(db_path: str = DEFAULT_DB_PATH, echo: bool = False) -> None:
    global _engine, _SessionLocal

    with _init_lock:
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
        _migrate_schema(_engine)
        logger.info(f"数据库已初始化: {path}")


def _migrate_schema(engine) -> None:
    # create_all 只建缺失的表，不会给已存在的表追加新列。
    # 旧库升级时这里幂等补齐新增列，避免线上库缺列导致查询崩溃。
    _ensure_column(engine, "patches", "needs_review", "BOOLEAN NOT NULL DEFAULT 0")


def _ensure_column(engine, table: str, column: str, definition: str) -> None:
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
        if column in cols:
            return
        logger.info(f"[Migration] 补齐列 {table}.{column}")
        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.commit()


def init_async_db(db_path: str = DEFAULT_DB_PATH, echo: bool = False) -> None:
    global _async_engine, _AsyncSessionLocal

    with _async_init_lock:
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

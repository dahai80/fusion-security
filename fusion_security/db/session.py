from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

from sqlalchemy import URL, create_engine, event, make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "~/.fusion-security/fusion_security.db"
DEFAULT_DB_URL = ""
DB_URL_ENV = "FUSION_SECURITY_DB_URL"
DB_PATH_ENV = "FUSION_DB_PATH"

_ASYNC_DRIVER_MAP = {
    "sqlite": "sqlite+aiosqlite",
    "postgresql": "postgresql+asyncpg",
    "postgres": "postgresql+asyncpg",
    "mysql": "mysql+asyncmy",
    "mysql+pymysql": "mysql+asyncmy",
}


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None
_async_engine = None
_AsyncSessionLocal = None
_init_lock = threading.Lock()
_async_init_lock = threading.Lock()


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite") or url.startswith("sqlite+aiosqlite")


def _resolve_url(db_path: str | None, db_url: str | None) -> str:
    # Priority: explicit db_url > explicit db_path > FUSION_SECURITY_DB_URL > FUSION_DB_PATH > default SQLite file.
    # Explicit args override env vars so tests/single calls can isolate; env vars are for multi-node deployments.
    if db_url:
        return db_url
    if db_path:
        path = Path(db_path).expanduser()
        return f"sqlite:///{path}"
    env_url = os.environ.get(DB_URL_ENV, "").strip()
    if env_url:
        return env_url
    env_path = os.environ.get(DB_PATH_ENV, "").strip()
    if env_path:
        return f"sqlite:///{Path(env_path).expanduser()}"
    return f"sqlite:///{Path(DEFAULT_DB_PATH).expanduser()}"


def _to_async_url(url: str) -> str:
    if "+aiosqlite" in url or "+asyncpg" in url or "+asyncmy" in url:
        return url
    parsed = make_url(url)
    driver = parsed.drivername or ""
    base = driver.split("+")[0] if "+" in driver else driver
    async_driver = _ASYNC_DRIVER_MAP.get(driver) or _ASYNC_DRIVER_MAP.get(base)
    if not async_driver:
        logger.warning(f"[DB] cannot infer async driver, using as-is: {url}")
        return url
    # URL objects are immutable; use create to copy all fields and replace the drivername.
    new = URL.create(
        async_driver,
        username=parsed.username,
        password=parsed.password,
        host=parsed.host,
        port=parsed.port,
        database=parsed.database,
        query=parsed.query,
    )
    # str(url) masks the password as ***; the driver needs real credentials here, so use render_as_string.
    return new.render_as_string(hide_password=False)


def init_db(db_path: str | None = None, echo: bool = False, db_url: str | None = None) -> None:
    global _engine, _SessionLocal

    with _init_lock:
        url = _resolve_url(db_path, db_url)
        kwargs: dict = {"echo": echo}
        if _is_sqlite(url):
            # SQLite single file: StaticPool shares one connection (in-process concurrency safety relies on
            # the GIL + check_same_thread=False), WAL improves concurrent reads, and the parent directory
            # must be pre-created. Multi-node shared databases do not go through here.
            # P0-4: the DB file contains key_hash/source snippets, so on-disk permissions must be 0600.
            # umask takes effect before engine creation — the file created by create_all and its -wal/-shm
            # companions are all constrained; pre-existing files are tightened with an explicit chmod.
            path = Path(url.replace("sqlite:///", "").replace("sqlite+aiosqlite:///", ""))
            if path.parent and str(path.parent) not in ("", "."):
                path.parent.mkdir(parents=True, exist_ok=True)
            _old_umask = os.umask(0o077)
            try:
                if path.exists():
                    os.chmod(path, 0o600)
            finally:
                os.umask(_old_umask)
            kwargs["connect_args"] = {"check_same_thread": False}
            kwargs["poolclass"] = StaticPool

        _old_umask = os.umask(0o077) if _is_sqlite(url) else None
        try:
            _engine = create_engine(url, **kwargs)
        finally:
            if _old_umask is not None:
                os.umask(_old_umask)

        if _is_sqlite(url):

            @event.listens_for(_engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)

        from . import models  # noqa: F401 — ensure models registered

        Base.metadata.create_all(_engine)
        if _is_sqlite(url):
            _migrate_schema(_engine)
        else:
            _migrate_schema_portable(_engine)
        # S-P1-6: never expose passwords in logs; mask with hide_password.
        safe_url = make_url(url).render_as_string(hide_password=True)
        logger.info(f"database initialized: {safe_url}")


def _migrate_schema(engine) -> None:
    # create_all only creates missing tables; it never appends new columns to existing ones.
    # On upgrades of old databases, idempotently backfill new columns here to avoid query crashes
    # from missing columns in production. SQLite-only (PRAGMA).
    _ensure_column(engine, "patches", "needs_review", "BOOLEAN NOT NULL DEFAULT 0")
    # A-P0-2 / multi-tenant / distributed claiming: new columns on the scans table.
    _ensure_column(engine, "scans", "path", "VARCHAR(500) DEFAULT ''")
    _ensure_column(engine, "scans", "tenant_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column(engine, "scans", "claimed_by", "VARCHAR(64) DEFAULT ''")
    _ensure_column(engine, "scans", "heartbeat", "FLOAT DEFAULT 0.0")
    # Multi-tenant: new scan_id / tenant_id on the vulnerabilities table (indexes apply when create_all
    # creates the table; old databases get the columns backfilled here).
    _ensure_column(engine, "vulnerabilities", "scan_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column(engine, "vulnerabilities", "tenant_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column(engine, "api_keys", "expires_at", "DATETIME")
    # Feature 4: scheduled_scans table aligned with the ScanScheduler.ScheduledScan dataclass.
    _ensure_column(engine, "scheduled_scans", "project_path", "VARCHAR(500) DEFAULT ''")
    _ensure_column(engine, "scheduled_scans", "frequency", "VARCHAR(20) DEFAULT 'daily'")
    _ensure_column(engine, "scheduled_scans", "config_json", "TEXT DEFAULT ''")
    # Issue #32: multi-tenant isolation columns. Old databases lack tenant_id on projects/webhooks;
    # once backfilled, the fail-closed filter takes effect.
    _ensure_column(engine, "projects", "tenant_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column(engine, "webhooks", "tenant_id", "VARCHAR(16) DEFAULT ''")


def _ensure_column(engine, table: str, column: str, definition: str) -> None:
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
        if column in cols:
            return
        logger.info(f"[Migration] adding column {table}.{column}")
        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.commit()


def _migrate_schema_portable(engine) -> None:
    # Non-SQLite (PG/MySQL): use information_schema to detect column existence, ALTER ADD when missing.
    # Avoid running PRAGMA against shared databases (SQLite dialect; it raises a syntax error on PG).
    _ensure_column_portable(engine, "patches", "needs_review", "BOOLEAN NOT NULL DEFAULT FALSE")
    _ensure_column_portable(engine, "scans", "path", "VARCHAR(500) DEFAULT ''")
    _ensure_column_portable(engine, "scans", "tenant_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column_portable(engine, "scans", "claimed_by", "VARCHAR(64) DEFAULT ''")
    _ensure_column_portable(engine, "scans", "heartbeat", "FLOAT DEFAULT 0.0")
    _ensure_column_portable(engine, "vulnerabilities", "scan_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column_portable(engine, "vulnerabilities", "tenant_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column_portable(engine, "api_keys", "expires_at", "TIMESTAMP")
    _ensure_column_portable(engine, "scheduled_scans", "project_path", "VARCHAR(500) DEFAULT ''")
    _ensure_column_portable(engine, "scheduled_scans", "frequency", "VARCHAR(20) DEFAULT 'daily'")
    _ensure_column_portable(engine, "scheduled_scans", "config_json", "TEXT DEFAULT ''")
    _ensure_column_portable(engine, "projects", "tenant_id", "VARCHAR(16) DEFAULT ''")
    _ensure_column_portable(engine, "webhooks", "tenant_id", "VARCHAR(16) DEFAULT ''")
    # ID column widening: String(16) -> String(32). Scan.id="scan_"+hex12 (17), Project.id="proj_"+hex12 (17);
    # SQLite silently truncates, PG strictly validates and raises StringDataRightTruncation (POST /scans 500).
    # Old databases need an ALTER to widen.
    _widen_column_portable(engine, "scans", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "scans", "project_id", "VARCHAR(32)")
    _widen_column_portable(engine, "vulnerabilities", "scan_id", "VARCHAR(32)")
    _widen_column_portable(engine, "findings", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "findings", "scan_id", "VARCHAR(32)")
    _widen_column_portable(engine, "patches", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "patches", "scan_id", "VARCHAR(32)")
    _widen_column_portable(engine, "scan_cache", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "scan_cache", "project_id", "VARCHAR(32)")
    _widen_column_portable(engine, "scheduled_scans", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "scheduled_scans", "project_id", "VARCHAR(32)")
    _widen_column_portable(engine, "feedbacks", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "feedbacks", "scan_id", "VARCHAR(32)")
    _widen_column_portable(engine, "api_keys", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "webhooks", "id", "VARCHAR(32)")
    _widen_column_portable(engine, "projects", "id", "VARCHAR(32)")


def _widen_column_portable(engine, table: str, column: str, new_type: str) -> None:
    from sqlalchemy import inspect

    with engine.connect() as conn:
        insp = inspect(conn)
        cols = {c["name"]: c for c in insp.get_columns(table)}
        if column not in cols:
            return
        cur_type = str(cols[column].get("type", "")).upper()
        target = new_type.upper()
        cur_len = _varchar_len(cur_type)
        tgt_len = _varchar_len(target)
        if cur_len is None or tgt_len is None or cur_len >= tgt_len:
            return
        logger.info(f"[Migration] widening column {table}.{column}: {cur_type} -> {new_type}")
        conn.exec_driver_sql(f'ALTER TABLE "{table}" ALTER COLUMN {column} TYPE {new_type}')
        conn.commit()


def _varchar_len(type_str: str) -> int | None:
    import re

    m = re.search(r"VARCHAR\((\d+)\)", type_str)
    return int(m.group(1)) if m else None


def _ensure_column_portable(engine, table: str, column: str, definition: str) -> None:
    from sqlalchemy import inspect

    with engine.connect() as conn:
        insp = inspect(conn)
        if column in {c["name"] for c in insp.get_columns(table)}:
            return
        logger.info(f"[Migration] adding column {table}.{column} (portable)")
        conn.exec_driver_sql(f'ALTER TABLE "{table}" ADD COLUMN {column} {definition}')
        conn.commit()


def init_async_db(db_path: str | None = None, echo: bool = False, db_url: str | None = None) -> None:
    global _async_engine, _AsyncSessionLocal

    with _async_init_lock:
        sync_url = _resolve_url(db_path, db_url)
        url = _to_async_url(sync_url)
        kwargs: dict = {"echo": echo}
        if _is_sqlite(url):
            path = Path(url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", ""))
            if path.parent and str(path.parent) not in ("", "."):
                path.parent.mkdir(parents=True, exist_ok=True)
            # P0-4: tighten the async database file permissions to 0600 as well.
            _old_umask = os.umask(0o077)
            try:
                if path.exists():
                    os.chmod(path, 0o600)
            finally:
                os.umask(_old_umask)

        _old_umask = os.umask(0o077) if _is_sqlite(url) else None
        try:
            _async_engine = create_async_engine(url, **kwargs)
        finally:
            if _old_umask is not None:
                os.umask(_old_umask)
        _AsyncSessionLocal = async_sessionmaker(_async_engine, expire_on_commit=False)

        from . import models  # noqa: F401

        safe_url = make_url(url).render_as_string(hide_password=True)
        logger.info(f"async database initialized: {safe_url}")


def get_session() -> Session:
    if _SessionLocal is None:
        init_db()
    return _SessionLocal()


def get_async_session() -> AsyncSession:
    if _AsyncSessionLocal is None:
        init_async_db()
    return _AsyncSessionLocal()

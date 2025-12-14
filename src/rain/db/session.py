"""Database session management for RAIN SBOM."""

import logging
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from ..models.database import Base

logger = logging.getLogger(__name__)

# Global engine and session factory
_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_db_path() -> Path:
    """Get database file path."""
    # Store in ~/.local/share/rain/sboms.db
    db_dir = Path.home() / ".local" / "share" / "rain"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "sboms.db"


def get_engine() -> AsyncEngine:
    """Get or create database engine."""
    global _engine

    if _engine is None:
        db_path = get_db_path()
        db_url = f"sqlite+aiosqlite:///{db_path}"

        _engine = create_async_engine(
            db_url,
            echo=False,  # Set to True for SQL debugging
            poolclass=NullPool,  # SQLite doesn't need pooling
        )

        # Enable foreign keys for SQLite
        @event.listens_for(_engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        logger.info(f"Database: {db_path}")

    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create session factory."""
    global _async_session_factory

    if _async_session_factory is None:
        engine = get_engine()
        _async_session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    return _async_session_factory


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session (dependency injection).

    Usage with FastAPI:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_session)):
            ...
    """
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Initialize database (create tables)."""
    engine = get_engine()

    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database initialized")


async def close_db() -> None:
    """Close database connections."""
    global _engine, _async_session_factory

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None

    logger.info("Database closed")

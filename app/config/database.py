"""
config/database.py
──────────────────
Gestione connessione PostgreSQL async con SQLAlchemy.

Architettura multi-tenant:
  - schema "public" → dati globali (tenants, admin users)
  - schema "<slug>" → dati isolati per tenant

Driver: asyncpg
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

from app.config.settings import get_settings

settings = get_settings()


# ─────────────────────────────────────────────
# ENGINE GLOBALE (UNICO)
# ─────────────────────────────────────────────
engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    echo=settings.debug,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ─────────────────────────────────────────────
# BASE ORM
# ─────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────
# PUBLIC SESSION (schema globale)
# ─────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ─────────────────────────────────────────────
# TENANT SESSION (schema switching sicuro)
# ─────────────────────────────────────────────

@asynccontextmanager
async def get_tenant_session(schema: str) -> AsyncGenerator[AsyncSession, None]:
    """
    Usa lo stesso engine, cambia solo search_path.
    (CORRETTO per asyncpg)
    """

    async with AsyncSessionLocal() as session:
        try:
            # switch schema in modo sicuro
            await session.execute(
                text(f'SET search_path TO "{schema}"')
            )

            yield session

            await session.commit()

        except Exception:
            await session.rollback()
            raise

        finally:
            await session.close()

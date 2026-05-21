"""
alembic/env.py
───────────────
Configurazione Alembic per le migrazioni dello schema "public".

NOTA: Gestisce solo lo schema public (tabella tenants).
Le tabelle degli schema tenant sono create dinamicamente
da tenant_service.py al momento del provisioning.
"""
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Import necessari per l'autogenerazione delle migrazioni
from app.config.settings import get_settings
from app.config.database import Base
from app.models.tenant import Tenant  # noqa: F401

config = context.config
settings = get_settings()

# Sovrascrive la URL dall'env (non da alembic.ini)
config.set_main_option("sqlalchemy.url", settings.sync_database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        version_table_schema="public",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            version_table_schema="public",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

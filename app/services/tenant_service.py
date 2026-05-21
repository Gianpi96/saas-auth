"""
services/tenant_service.py  (Step 2: aggiornato)
──────────────────────────────────────────────────
Aggiunto: subdomain, plan, apply_plan_limits, tenant_id nelle tabelle tenant.
"""
import uuid
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant, PLAN_LIMITS
from app.schemas.tenant import TenantCreate


async def create_tenant(db: AsyncSession, data: TenantCreate) -> Tenant:
    safe_slug = data.slug.replace("-", "_")
    schema_name = f"tenant_{safe_slug}"

    # Calcola limiti dal piano scelto
    limits = PLAN_LIMITS[data.plan]

    tenant = Tenant(
        id=uuid.uuid4(),
        name=data.name,
        slug=data.slug,
        subdomain=data.subdomain,
        db_schema=schema_name,
        plan=data.plan,
        max_users=limits["max_users"],
        max_storage_gb=limits["max_storage_gb"],
        is_active=True,
    )
    db.add(tenant)
    await db.flush()

    tenant_id_str = str(tenant.id)

    # Crea schema PostgreSQL
    await db.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))

    # Crea tabella roles con tenant_id e indice composto
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS "{schema_name}".roles (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            permissions TEXT,
            ai_description TEXT,
            is_system BOOLEAN DEFAULT FALSE NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT uq_roles_tenant_name UNIQUE (tenant_id, name)
        )
    """))
    await db.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_roles_tenant_id_id
        ON "{schema_name}".roles (tenant_id, id)
    """))

    # Crea tabella users con tenant_id e indice composto
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS "{schema_name}".users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            email VARCHAR(255) NOT NULL,
            hashed_password VARCHAR(255) NOT NULL,
            full_name VARCHAR(255),
            is_active BOOLEAN DEFAULT TRUE NOT NULL,
            is_superuser BOOLEAN DEFAULT FALSE NOT NULL,
            role_id UUID REFERENCES "{schema_name}".roles(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            last_login TIMESTAMPTZ,
            CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email)
        )
    """))
    await db.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_users_tenant_id_id
        ON "{schema_name}".users (tenant_id, id)
    """))

    # Crea tabella policies con tenant_id e indice composto
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS "{schema_name}".policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            name VARCHAR(255) NOT NULL,
            role_id UUID NOT NULL REFERENCES "{schema_name}".roles(id) ON DELETE CASCADE,
            resource VARCHAR(100) NOT NULL,
            action VARCHAR(100) NOT NULL,
            effect VARCHAR(10) DEFAULT 'allow' NOT NULL,
            ai_description TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT uq_policies_tenant_role_res_act
                UNIQUE (tenant_id, role_id, resource, action)
        )
    """))
    await db.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_policies_tenant_id_id
        ON "{schema_name}".policies (tenant_id, id)
    """))

    # Crea tabella permissions (catalogo permessi del tenant)
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS "{schema_name}".permissions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            resource VARCHAR(100) NOT NULL,
            action VARCHAR(100) NOT NULL,
            codename VARCHAR(201) NOT NULL,
            description TEXT,
            ai_description TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT uq_permissions_tenant_resource_action
                UNIQUE (tenant_id, resource, action)
        )
    """))
    await db.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_permissions_tenant_id_id
        ON "{schema_name}".permissions (tenant_id, id)
    """))
    await db.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_permissions_codename
        ON "{schema_name}".permissions (tenant_id, codename)
    """))

    # Crea tabella role_permissions (giunzione many-to-many)
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS "{schema_name}".role_permissions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            role_id UUID NOT NULL
                REFERENCES "{schema_name}".roles(id) ON DELETE CASCADE,
            permission_id UUID NOT NULL
                REFERENCES "{schema_name}".permissions(id) ON DELETE CASCADE,
            granted_by VARCHAR(255),
            granted_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT uq_role_permission UNIQUE (role_id, permission_id)
        )
    """))
    await db.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_role_permissions_role_id
        ON "{schema_name}".role_permissions (role_id)
    """))
    await db.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_role_permissions_permission_id
        ON "{schema_name}".role_permissions (permission_id)
    """))

    # Ruoli di sistema con tenant_id popolato
    await db.execute(text(f"""
        INSERT INTO "{schema_name}".roles
            (tenant_id, name, description, permissions, is_system)
        VALUES
            ('{tenant_id_str}', 'admin',  'Amministratore del tenant', '*',       TRUE),
            ('{tenant_id_str}', 'viewer', 'Sola lettura',              'read:*',  TRUE)
        ON CONFLICT DO NOTHING
    """))

    await db.execute(text("SET search_path TO public"))
    return tenant


async def get_tenant_by_slug(db: AsyncSession, slug: str) -> Tenant | None:
    result = await db.execute(
        select(Tenant).where(Tenant.slug == slug, Tenant.is_active)
    )
    return result.scalar_one_or_none()


async def get_tenant_by_id(db: AsyncSession, tenant_id: uuid.UUID) -> Tenant | None:
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    return result.scalar_one_or_none()


async def get_tenant_by_subdomain(db: AsyncSession, subdomain: str) -> Tenant | None:
    result = await db.execute(
        select(Tenant).where(Tenant.subdomain == subdomain, Tenant.is_active)
    )
    return result.scalar_one_or_none()


async def update_tenant_plan(db: AsyncSession, tenant: Tenant, new_plan) -> Tenant:
    """Cambia il piano e aggiorna i limiti derivati."""
    tenant.plan = new_plan
    tenant.apply_plan_limits()
    await db.flush()
    await db.refresh(tenant)  # ricarica i campi server-side (updated_at) dal DB
    return tenant

"""
api/v1/endpoints/tenants.py  (Step 2: aggiornato)
───────────────────────────────────────────────────
Aggiunto: subdomain, plan, endpoint PATCH per upgrade piano.
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.database import get_db
from app.schemas.tenant import (
    TenantCreate,
    TenantRead,
    TenantReadInternal,
    TenantUpdate,
)
from app.services.tenant_service import (
    create_tenant,
    get_tenant_by_slug,
    get_tenant_by_id,
    update_tenant_plan,
)

router = APIRouter(prefix="/tenants", tags=["Tenants"])


@router.post(
    "/",
    response_model=TenantReadInternal,
    status_code=status.HTTP_201_CREATED,
    summary="Crea un nuovo tenant",
)
async def create_new_tenant(
    payload: TenantCreate,
    db: AsyncSession = Depends(get_db),
) -> TenantReadInternal:
    try:
        tenant = await create_tenant(db, payload)
        return TenantReadInternal.model_validate(tenant)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Errore durante la creazione del tenant: {exc}"
        )


@router.get(
    "/{slug}",
    response_model=TenantRead,
    summary="Recupera un tenant per slug",
)
async def get_tenant(slug: str, db: AsyncSession = Depends(get_db)) -> TenantRead:
    tenant = await get_tenant_by_slug(db, slug)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{slug}' non trovato")
    return TenantRead.model_validate(tenant)


@router.patch(
    "/{tenant_id}/plan",
    response_model=TenantReadInternal,
    summary="Aggiorna il piano del tenant (upgrade/downgrade)",
    description="""
Cambia il piano di abbonamento e aggiorna automaticamente i limiti:
- **free → pro**: max_users 5→50, max_storage_gb 1→20
- **pro → enterprise**: max_users 50→9999, max_storage_gb 20→500
""",
)
async def change_plan(
    tenant_id: uuid.UUID,
    payload: TenantUpdate,
    db: AsyncSession = Depends(get_db),
) -> TenantReadInternal:
    tenant = await get_tenant_by_id(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant non trovato")

    if payload.plan is not None:
        tenant = await update_tenant_plan(db, tenant, payload.plan)
    if payload.is_active is not None:
        tenant.is_active = payload.is_active
        await db.flush()
        await db.refresh(tenant)  # ricarica updated_at e altri campi server-side

    return TenantReadInternal.model_validate(tenant)

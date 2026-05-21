"""
api/v1/endpoints/roles.py  (Step 2: aggiornato)
────────────────────────────────────────────────
Aggiunto: tenant_id in tutti gli INSERT e le query.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text

from app.config.database import get_tenant_session
from app.schemas.user import PolicyCreate, PolicyRead, RoleCreate, RoleRead, TokenPayload
from app.services.groq_service import generate_policy_description, generate_role_description
from app.services.rbac import get_current_user, require_role

router = APIRouter(prefix="/roles", tags=["Ruoli & Policy RBAC"])


@router.post("/", response_model=RoleRead, status_code=status.HTTP_201_CREATED,
             summary="Crea un ruolo custom nel tenant")
async def create_role(
    payload: RoleCreate,
    current_user: TokenPayload = Depends(require_role("admin")),
) -> RoleRead:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id

    ai_desc: Optional[str] = None
    if payload.permissions:
        ai_desc = await generate_role_description(payload.name, payload.permissions)

    async with get_tenant_session(schema) as db:
        role_id = uuid.uuid4()
        await db.execute(
            text(f"""
                INSERT INTO "{schema}".roles
                    (id, tenant_id, name, description, permissions, ai_description, is_system)
                VALUES
                    (:id, :tid, :name, :desc, :perms, :ai_desc, FALSE)
            """),
            {"id": str(role_id), "tid": tenant_id, "name": payload.name,
             "desc": payload.description, "perms": payload.permissions, "ai_desc": ai_desc},
        )
        result = await db.execute(
            text(f'SELECT * FROM "{schema}".roles WHERE id = :id'), {"id": str(role_id)}
        )
        row = result.mappings().one()
        return RoleRead(**dict(row))


@router.get("/", response_model=list[RoleRead], summary="Lista tutti i ruoli del tenant")
async def list_roles(current_user: TokenPayload = Depends(get_current_user)) -> list[RoleRead]:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id
    async with get_tenant_session(schema) as db:
        result = await db.execute(
            text(f'SELECT * FROM "{schema}".roles WHERE tenant_id = :tid ORDER BY name'),
            {"tid": tenant_id},
        )
        return [RoleRead(**dict(row)) for row in result.mappings().all()]


@router.get("/{role_id}", response_model=RoleRead, summary="Dettaglio di un ruolo")
async def get_role(
    role_id: uuid.UUID,
    current_user: TokenPayload = Depends(get_current_user),
) -> RoleRead:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id
    async with get_tenant_session(schema) as db:
        result = await db.execute(
            text(f'SELECT * FROM "{schema}".roles WHERE tenant_id = :tid AND id = :id'),
            {"tid": tenant_id, "id": str(role_id)},
        )
        row = result.mappings().one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Ruolo non trovato")
        return RoleRead(**dict(row))


@router.post("/{role_id}/policies", response_model=PolicyRead,
             status_code=status.HTTP_201_CREATED, summary="Crea una policy RBAC per un ruolo")
async def create_policy(
    role_id: uuid.UUID,
    payload: PolicyCreate,
    current_user: TokenPayload = Depends(require_role("admin")),
) -> PolicyRead:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id

    if payload.role_id != role_id:
        raise HTTPException(status_code=400, detail="role_id nel body non corrisponde all'URL")

    async with get_tenant_session(schema) as db:
        role_result = await db.execute(
            text(f'SELECT name FROM "{schema}".roles WHERE tenant_id = :tid AND id = :id'),
            {"tid": tenant_id, "id": str(role_id)},
        )
        role_row = role_result.one_or_none()
        if not role_row:
            raise HTTPException(status_code=404, detail="Ruolo non trovato")

        ai_desc = await generate_policy_description(
            role_name=role_row[0], resource=payload.resource,
            action=payload.action, effect=payload.effect, policy_name=payload.name,
        )
        policy_id = uuid.uuid4()
        await db.execute(
            text(f"""
                INSERT INTO "{schema}".policies
                    (id, tenant_id, name, role_id, resource, action, effect, ai_description)
                VALUES
                    (:id, :tid, :name, :role_id, :resource, :action, :effect, :ai_desc)
            """),
            {"id": str(policy_id), "tid": tenant_id, "name": payload.name,
             "role_id": str(role_id), "resource": payload.resource,
             "action": payload.action, "effect": payload.effect, "ai_desc": ai_desc},
        )
        result = await db.execute(
            text(f'SELECT * FROM "{schema}".policies WHERE id = :id'), {"id": str(policy_id)}
        )
        row = result.mappings().one()
        return PolicyRead(**dict(row))


@router.get("/{role_id}/policies", response_model=list[PolicyRead], summary="Lista policy di un ruolo")
async def list_policies(
    role_id: uuid.UUID,
    current_user: TokenPayload = Depends(get_current_user),
) -> list[PolicyRead]:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id
    async with get_tenant_session(schema) as db:
        result = await db.execute(
            text(f"""
                SELECT * FROM "{schema}".policies
                WHERE tenant_id = :tid AND role_id = :role_id
                ORDER BY resource, action
            """),
            {"tid": tenant_id, "role_id": str(role_id)},
        )
        return [PolicyRead(**dict(row)) for row in result.mappings().all()]

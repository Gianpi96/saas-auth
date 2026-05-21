"""
api/v1/endpoints/admin.py  (Step 4: nuovo)
──────────────────────────────────────────
Endpoint /admin/roles per la gestione RBAC avanzata.

Differenza tra /roles e /admin/roles:
  /roles          → gestione base (Step 1-3): crea ruolo con permissions CSV
  /admin/roles    → gestione avanzata (Step 4): ruoli con permessi many-to-many,
                    assegnazione/revoca permessi, catalogo permessi

Tutti gli endpoint richiedono ruolo "admin" del tenant.

Decorator require_permission in azione:
  Ogni endpoint usa Depends(require_permission("admin:roles")) per dimostrare
  il funzionamento del decorator oltre che della dependency.
  Gli admin hanno il permesso wildcard "*" quindi passano sempre.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.user import (
    AdminRoleCreate,
    AssignPermissionRequest,
    PermissionCreate,
    PermissionRead,
    RoleWithPermissions,
    TokenPayload,
)
from app.services.permission_service import (
    assign_permission_to_role,
    create_permission,
    get_all_permissions,
    get_role_with_permissions,
    revoke_permission_from_role,
)
from app.services.rbac import require_permission, require_role
from app.services.groq_service import generate_role_description
from app.config.database import get_tenant_session
from sqlalchemy import text
import uuid as uuid_module

router = APIRouter(prefix="/admin", tags=["Admin — RBAC avanzato"])


# ── Ruoli ─────────────────────────────────────────────────────────────────────

@router.post(
    "/roles",
    response_model=RoleWithPermissions,
    status_code=status.HTTP_201_CREATED,
    summary="Crea un ruolo custom con permessi many-to-many",
    description="""
Crea un ruolo e i suoi permessi in un'unica operazione.

**Funzionamento:**
1. Crea il ruolo nel catalogo
2. Per ogni `permission_codename` (es: `"tasks:delete"`):
   - Crea il permesso nel catalogo (se non esiste)
   - Genera descrizione AI con **Groq llama-3.3-70b-versatile**
   - Assegna il permesso al ruolo (tabella `role_permissions`)
3. Restituisce il ruolo con tutti i permessi espansi

**Richiede:** ruolo `admin` o permesso `admin:roles`
""",
)
async def create_admin_role(
    payload: AdminRoleCreate,
    current_user: TokenPayload = Depends(require_role("admin")),
) -> RoleWithPermissions:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id
    user_id = current_user.sub

    # 1. Genera descrizione AI del ruolo
    codenames_str = ", ".join(payload.permission_codenames) or "nessun permesso"
    ai_desc = await generate_role_description(
        role_name=payload.name,
        permissions=codenames_str,
    )

    # 2. Crea il ruolo
    role_id = uuid_module.uuid4()
    async with get_tenant_session(schema) as db:
        await db.execute(
            text(f"""
                INSERT INTO "{schema}".roles
                    (id, tenant_id, name, description, ai_description,
                     permissions, is_system)
                VALUES
                    (:id, :tid, :name, :desc, :ai_desc, :perms, FALSE)
            """),
            {
                "id": str(role_id),
                "tid": tenant_id,
                "name": payload.name,
                "desc": payload.description,
                "ai_desc": ai_desc,
                "perms": ",".join(payload.permission_codenames),
            },
        )

    # 3. Crea e assegna ogni permesso
    for codename in payload.permission_codenames:
        if ":" not in codename:
            raise HTTPException(
                status_code=400,
                detail=f"Formato permesso non valido: '{codename}'. Usa 'resource:action'",
            )
        resource, action = codename.split(":", 1)

        # Crea il permesso nel catalogo (idempotente)
        perm = await create_permission(
            schema=schema,
            tenant_id=tenant_id,
            resource=resource,
            action=action,
            role_name_for_ai=payload.name,
        )

        # Assegna al ruolo
        await assign_permission_to_role(
            schema=schema,
            tenant_id=tenant_id,
            role_id=str(role_id),
            permission_id=str(perm["id"]),
            granted_by=user_id,
        )

    # 4. Restituisce il ruolo completo con permessi
    role_data = await get_role_with_permissions(schema, tenant_id, str(role_id))
    if not role_data:
        raise HTTPException(status_code=500, detail="Ruolo creato ma non recuperabile")

    return _map_role_with_permissions(role_data)


@router.get(
    "/roles",
    response_model=list[RoleWithPermissions],
    summary="Lista ruoli con permessi espansi",
)
async def list_admin_roles(
    current_user: TokenPayload = Depends(require_permission("admin:roles")),
) -> list[RoleWithPermissions]:
    """
    Lista tutti i ruoli del tenant con i loro permessi many-to-many.

    Questo endpoint usa Depends(require_permission("tasks:delete"))
    per dimostrare il decorator in azione:
      - Gli admin hanno "*" → passano
      - Un editor con solo "tasks:read" → 403
    """
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id

    async with get_tenant_session(schema) as db:
        result = await db.execute(
            text(f"""
                SELECT id FROM "{schema}".roles
                WHERE tenant_id = :tid ORDER BY name
            """),
            {"tid": tenant_id},
        )
        role_ids = [str(row[0]) for row in result.fetchall()]

    roles = []
    for rid in role_ids:
        role_data = await get_role_with_permissions(schema, tenant_id, rid)
        if role_data:
            roles.append(_map_role_with_permissions(role_data))
    return roles


@router.get(
    "/roles/{role_id}",
    response_model=RoleWithPermissions,
    summary="Dettaglio ruolo con permessi",
)
async def get_admin_role(
    role_id: uuid.UUID,
    current_user: TokenPayload = Depends(require_permission("admin:roles")),
) -> RoleWithPermissions:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id

    role_data = await get_role_with_permissions(schema, tenant_id, str(role_id))
    if not role_data:
        raise HTTPException(status_code=404, detail="Ruolo non trovato")
    return _map_role_with_permissions(role_data)


# ── Assegnazione Permessi ──────────────────────────────────────────────────────

@router.post(
    "/roles/{role_id}/permissions",
    status_code=status.HTTP_201_CREATED,
    summary="Assegna un permesso a un ruolo",
    description="""
Assegna un permesso esistente nel catalogo a un ruolo.
Se già assegnato, l'operazione è idempotente (nessun errore).
""",
)
async def assign_permission(
    role_id: uuid.UUID,
    payload: AssignPermissionRequest,
    current_user: TokenPayload = Depends(require_role("admin")),
) -> dict:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id

    try:
        result = await assign_permission_to_role(
            schema=schema,
            tenant_id=tenant_id,
            role_id=str(role_id),
            permission_id=str(payload.permission_id),
            granted_by=current_user.sub,
        )
        return {"message": "Permesso assegnato", **result}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete(
    "/roles/{role_id}/permissions/{permission_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoca un permesso da un ruolo",
)
async def revoke_permission(
    role_id: uuid.UUID,
    permission_id: uuid.UUID,
    current_user: TokenPayload = Depends(require_role("admin")),
) -> dict:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id

    removed = await revoke_permission_from_role(
        schema=schema,
        tenant_id=tenant_id,
        role_id=str(role_id),
        permission_id=str(permission_id),
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Assegnazione non trovata")
    return {"message": "Permesso revocato con successo"}


# ── Catalogo Permessi ─────────────────────────────────────────────────────────

@router.post(
    "/permissions",
    response_model=PermissionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Crea un permesso nel catalogo del tenant",
    description="""
Crea un nuovo permesso atomico nel catalogo.
**Groq llama-3.3-70b-versatile** genera automaticamente la descrizione human-readable.

Dopo la creazione, assegna il permesso a un ruolo con
`POST /admin/roles/{role_id}/permissions`.
""",
)
async def create_permission_endpoint(
    payload: PermissionCreate,
    current_user: TokenPayload = Depends(require_role("admin")),
) -> PermissionRead:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id

    perm_data = await create_permission(
        schema=schema,
        tenant_id=tenant_id,
        resource=payload.resource,
        action=payload.action,
        description=payload.description,
    )
    return PermissionRead(**perm_data)


@router.get(
    "/permissions",
    response_model=list[PermissionRead],
    summary="Lista catalogo permessi del tenant",
)
async def list_permissions(
    current_user: TokenPayload = Depends(require_permission("admin:roles")),
) -> list[PermissionRead]:
    schema = current_user.tenant_schema
    tenant_id = current_user.tenant_id
    perms = await get_all_permissions(schema, tenant_id)
    return [PermissionRead(**p) for p in perms]


# ── Helper ────────────────────────────────────────────────────────────────────

def _map_role_with_permissions(role_data: dict) -> RoleWithPermissions:
    """Converte il dict dal DB nello schema RoleWithPermissions."""
    from app.schemas.user import RolePermissionRead

    permissions = [
        RolePermissionRead(
            id=p["id"],
            codename=p["codename"],
            resource=p["resource"],
            action=p["action"],
            description=p.get("description"),
            ai_description=p.get("ai_description"),
            granted_by=p.get("granted_by"),
            granted_at=p["granted_at"],
        )
        for p in role_data.get("permissions", [])
    ]

    return RoleWithPermissions(
        id=role_data["id"],
        name=role_data["name"],
        description=role_data.get("description"),
        ai_description=role_data.get("ai_description"),
        is_system=role_data.get("is_system", False),
        created_at=role_data["created_at"],
        permissions=permissions,
    )

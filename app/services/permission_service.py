"""
services/permission_service.py  (Step 4: nuovo)
────────────────────────────────────────────────
Logica di business per Permission e RolePermission.

Responsabilità:
  - Creare permessi nel catalogo del tenant
  - Assegnare/revocare permessi a un ruolo
  - Caricare i permessi di un ruolo (per il JWT e per i check runtime)
  - Chiamare Groq per la descrizione AI

Perché carichiamo i permessi dal DB al login e li mettiamo nel JWT?
  Il JWT contiene già i permessi come lista di stringhe ("tasks:delete", ...).
  Questo permette ai check RBAC di funzionare SENZA query al DB su ogni
  request — il token è autosufficiente per 15 minuti.
  Al refresh, i permessi vengono ricaricati dal DB → aggiornamenti hanno
  effetto massimo entro 15 minuti (scadenza access token).
"""
import uuid
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.database import get_tenant_session
from app.services.groq_service import generate_permission_description


async def create_permission(
    schema: str,
    tenant_id: str,
    resource: str,
    action: str,
    description: Optional[str] = None,
    role_name_for_ai: Optional[str] = None,
) -> dict:
    """
    Crea un nuovo permesso nel catalogo del tenant.
    Genera automaticamente la descrizione AI con Groq llama-3.1-70b-versatile.

    Returns: dizionario con i dati del permesso creato.
    """
    codename = f"{resource}:{action}"

    # Genera descrizione AI
    ai_desc = await generate_permission_description(
        resource=resource,
        action=action,
        codename=codename,
        role_name=role_name_for_ai,
    )

    perm_id = uuid.uuid4()

    async with get_tenant_session(schema) as db:
        await db.execute(
            text(f"""
                INSERT INTO "{schema}".permissions
                    (id, tenant_id, resource, action, codename, description, ai_description)
                VALUES
                    (:id, :tid, :resource, :action, :codename, :desc, :ai_desc)
                ON CONFLICT ON CONSTRAINT uq_permissions_tenant_resource_action
                DO UPDATE SET
                    description   = EXCLUDED.description,
                    ai_description = EXCLUDED.ai_description
                RETURNING id, resource, action, codename, description, ai_description, created_at
            """),
            {
                "id": str(perm_id),
                "tid": tenant_id,
                "resource": resource,
                "action": action,
                "codename": codename,
                "desc": description,
                "ai_desc": ai_desc,
            },
        )
        result = await db.execute(
            text(f"""
                SELECT id, tenant_id, resource, action, codename,
                       description, ai_description, created_at
                FROM "{schema}".permissions
                WHERE tenant_id = :tid AND resource = :res AND action = :act
            """),
            {"tid": tenant_id, "res": resource, "act": action},
        )
        row = result.mappings().one()
        return dict(row)


async def assign_permission_to_role(
    schema: str,
    tenant_id: str,
    role_id: str,
    permission_id: str,
    granted_by: str,
) -> dict:
    """
    Assegna un permesso a un ruolo (inserisce in role_permissions).
    Se già assegnato, non fa nulla (idempotente).
    """
    async with get_tenant_session(schema) as db:
        # Verifica che ruolo e permesso appartengano al tenant
        role_check = await db.execute(
            text(f'SELECT id FROM "{schema}".roles WHERE id = :rid AND tenant_id = :tid'),
            {"rid": role_id, "tid": tenant_id},
        )
        if not role_check.scalar_one_or_none():
            raise ValueError(f"Ruolo {role_id} non trovato nel tenant")

        perm_check = await db.execute(
            text(f'SELECT id, codename FROM "{schema}".permissions WHERE id = :pid AND tenant_id = :tid'),
            {"pid": permission_id, "tid": tenant_id},
        )
        perm_row = perm_check.one_or_none()
        if not perm_row:
            raise ValueError(f"Permesso {permission_id} non trovato nel tenant")

        rp_id = uuid.uuid4()
        await db.execute(
            text(f"""
                INSERT INTO "{schema}".role_permissions
                    (id, tenant_id, role_id, permission_id, granted_by)
                VALUES
                    (:id, :tid, :role_id, :perm_id, :granted_by)
                ON CONFLICT ON CONSTRAINT uq_role_permission DO NOTHING
            """),
            {
                "id": str(rp_id),
                "tid": tenant_id,
                "role_id": role_id,
                "perm_id": permission_id,
                "granted_by": granted_by,
            },
        )
        return {
            "role_id": role_id,
            "permission_id": permission_id,
            "codename": perm_row[1],
            "granted_by": granted_by,
        }


async def revoke_permission_from_role(
    schema: str,
    tenant_id: str,
    role_id: str,
    permission_id: str,
) -> bool:
    """Revoca un permesso da un ruolo. Restituisce True se rimosso."""
    async with get_tenant_session(schema) as db:
        result = await db.execute(
            text(f"""
                DELETE FROM "{schema}".role_permissions
                WHERE tenant_id = :tid AND role_id = :rid AND permission_id = :pid
                RETURNING id
            """),
            {"tid": tenant_id, "rid": role_id, "pid": permission_id},
        )
        return result.scalar_one_or_none() is not None


async def get_role_permissions(
    schema: str,
    tenant_id: str,
    role_id: str,
) -> list[str]:
    """
    Carica tutti i codename dei permessi di un ruolo.
    Usato al login per costruire il JWT con i permessi aggiornati.

    Returns: lista di codename ["tasks:read", "tasks:write", ...]
    """
    async with get_tenant_session(schema) as db:
        result = await db.execute(
            text(f"""
                SELECT p.codename
                FROM "{schema}".permissions p
                JOIN "{schema}".role_permissions rp ON rp.permission_id = p.id
                WHERE rp.tenant_id = :tid AND rp.role_id = :rid
                ORDER BY p.codename
            """),
            {"tid": tenant_id, "rid": role_id},
        )
        return [row[0] for row in result.fetchall()]


async def get_all_permissions(schema: str, tenant_id: str) -> list[dict]:
    """Lista tutti i permessi del catalogo del tenant."""
    async with get_tenant_session(schema) as db:
        result = await db.execute(
            text(f"""
                SELECT id, tenant_id, resource, action, codename,
                       description, ai_description, created_at
                FROM "{schema}".permissions
                WHERE tenant_id = :tid
                ORDER BY resource, action
            """),
            {"tid": tenant_id},
        )
        return [dict(row) for row in result.mappings().all()]


async def get_role_with_permissions(
    schema: str,
    tenant_id: str,
    role_id: str,
) -> Optional[dict]:
    """
    Carica un ruolo con tutti i suoi permessi espansi.
    Usato per la risposta dell'endpoint GET /admin/roles/{role_id}.
    """
    async with get_tenant_session(schema) as db:
        # Carica il ruolo
        role_result = await db.execute(
            text(f"""
                SELECT id, tenant_id, name, description, ai_description,
                       is_system, created_at
                FROM "{schema}".roles
                WHERE id = :rid AND tenant_id = :tid
            """),
            {"rid": role_id, "tid": tenant_id},
        )
        role_row = role_result.mappings().one_or_none()
        if not role_row:
            return None

        role_data = dict(role_row)

        # Carica i permessi associati
        perms_result = await db.execute(
            text(f"""
                SELECT p.id, p.codename, p.resource, p.action,
                       p.description, p.ai_description,
                       rp.granted_by, rp.granted_at
                FROM "{schema}".permissions p
                JOIN "{schema}".role_permissions rp ON rp.permission_id = p.id
                WHERE rp.role_id = :rid AND rp.tenant_id = :tid
                ORDER BY p.codename
            """),
            {"rid": role_id, "tid": tenant_id},
        )
        role_data["permissions"] = [dict(row) for row in perms_result.mappings().all()]
        return role_data

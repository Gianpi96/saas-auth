"""
services/auth_service.py  (Step 2: aggiornato)
────────────────────────────────────────────────
Aggiunto: tenant_id viene ora scritto su ogni INSERT utente.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.database import get_tenant_session
from app.schemas.user import (
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserRead,
    RefreshRequest,
)
from app.services.jwt_service import create_access_token
from app.services.password_service import hash_password, verify_password
from app.services.tenant_service import get_tenant_by_slug
from app.services.refresh_token_service import (
    create_refresh_token,
    rotate_refresh_token,
    revoke_all_user_tokens,
)
from app.config.settings import get_settings

settings = get_settings()


async def register_user(
    db: AsyncSession,
    tenant_slug: str,
    user_data: UserCreate,
) -> UserRead:
    tenant = await get_tenant_by_slug(db, tenant_slug)
    if not tenant:
        raise ValueError(f"Tenant '{tenant_slug}' non trovato o non attivo")

    schema = tenant.db_schema
    tenant_id_str = str(tenant.id)

    async with get_tenant_session(schema) as tenant_db:
        # Controlla email duplicata (vincolo include tenant_id)
        existing = await tenant_db.execute(
            text(f"""
                SELECT id FROM "{schema}".users
                WHERE tenant_id = :tid AND email = :email
            """),
            {"tid": tenant_id_str, "email": user_data.email},
        )
        if existing.scalar_one_or_none():
            raise ValueError(
                f"Email '{user_data.email}' già registrata in questo tenant"
            )

        if user_data.role_id:
            role_exists = await tenant_db.execute(
                text(f"""
                    SELECT id FROM "{schema}".roles
                    WHERE tenant_id = :tid AND id = :rid
                """),
                {"tid": tenant_id_str, "rid": str(user_data.role_id)},
            )
            if not role_exists.scalar_one_or_none():
                raise ValueError(
                    f"Ruolo {user_data.role_id} non trovato in questo tenant"
                )

        user_id = uuid.uuid4()
        await tenant_db.execute(
            text(f"""
                INSERT INTO "{schema}".users
                    (id, tenant_id, email, hashed_password, full_name, role_id)
                VALUES
                    (:id, :tid, :email, :pwd, :full_name, :role_id)
            """),
            {
                "id": str(user_id),
                "tid": tenant_id_str,
                "email": user_data.email,
                "pwd": hash_password(user_data.password),
                "full_name": user_data.full_name,
                "role_id": str(user_data.role_id) if user_data.role_id else None,
            },
        )
        return await _fetch_user_read(tenant_db, schema, user_id)


async def login_user(
    db: AsyncSession,
    tenant_slug: str,
    credentials: LoginRequest,
) -> TokenResponse:
    tenant = await get_tenant_by_slug(db, tenant_slug)
    if not tenant:
        raise ValueError("Credenziali non valide")

    schema = tenant.db_schema
    tenant_id_str = str(tenant.id)

    async with get_tenant_session(schema) as tenant_db:
        result = await tenant_db.execute(
            text(f"""
                SELECT u.id, u.email, u.hashed_password, u.is_active,
                       u.full_name, u.is_superuser,
                       r.name as role_name, r.id as role_id_val
                FROM "{schema}".users u
                LEFT JOIN "{schema}".roles r ON r.id = u.role_id
                WHERE u.tenant_id = :tid AND u.email = :email
            """),
            {"tid": tenant_id_str, "email": credentials.email},
        )
        row = result.mappings().one_or_none()

        if not row or not verify_password(credentials.password, row["hashed_password"]):
            raise ValueError("Credenziali non valide")

        if not row["is_active"]:
            raise ValueError("Account disabilitato")

        # Carica i permessi dalla tabella role_permissions (many-to-many)
        # invece della stringa CSV legacy — così task:delete assegnato dopo
        # il login precedente compare nel nuovo JWT immediatamente
        permissions: list[str] = []
        if row["role_id_val"]:
            perm_result = await tenant_db.execute(
                text(f"""
                    SELECT p.codename
                    FROM "{schema}".permissions p
                    JOIN "{schema}".role_permissions rp ON rp.permission_id = p.id
                    WHERE rp.role_id = :rid AND rp.tenant_id = :tid
                    ORDER BY p.codename
                """),
                {"rid": str(row["role_id_val"]), "tid": tenant_id_str},
            )
            permissions = [r[0] for r in perm_result.fetchall()]

        # Fallback: se il ruolo ha "*" (admin) e non ha righe in role_permissions,
        # usa la colonna permissions legacy per non rompere i ruoli di sistema
        if not permissions and row["role_id_val"]:
            legacy_result = await tenant_db.execute(
                text(f'SELECT permissions FROM "{schema}".roles WHERE id = :rid'),
                {"rid": str(row["role_id_val"])},
            )
            legacy_row = legacy_result.one_or_none()
            if legacy_row and legacy_row[0]:
                permissions = [p.strip() for p in legacy_row[0].split(",") if p.strip()]

        access_token, access_expires = create_access_token(
            user_id=str(row["id"]),
            tenant_id=tenant_id_str,
            tenant_schema=schema,
            role=row["role_name"],
            permissions=permissions,
        )

        await tenant_db.execute(
            text(f"""
                UPDATE "{schema}".users SET last_login = NOW()
                WHERE tenant_id = :tid AND id = :uid
            """),
            {"tid": tenant_id_str, "uid": str(row["id"])},
        )

        # Crea refresh token (Step 3): family_id=None → nuovo login = nuova family
        refresh_raw = await create_refresh_token(
            db=db,
            user_id=str(row["id"]),
            tenant_id=tenant_id_str,
            tenant_schema=schema,
            family_id=None,  # nuovo login → nuova sessione → nuova family
            parent_token_hash=None,
        )

        user_read = await _fetch_user_read(tenant_db, schema, row["id"])
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_raw,
            token_type="bearer",
            expires_in=settings.jwt_access_token_expire_minutes * 60,
            refresh_expires_in=settings.jwt_refresh_token_expire_days * 24 * 3600,
            user=user_read,
        )


async def _fetch_user_read(tenant_db, schema: str, user_id) -> UserRead:
    from app.schemas.user import RoleRead

    result = await tenant_db.execute(
        text(f"""
            SELECT u.id, u.email, u.full_name, u.is_active, u.is_superuser,
                   u.created_at, u.last_login,
                   r.id as role_id, r.name as role_name, r.description as role_desc,
                   r.permissions as role_perms, r.ai_description as role_ai_desc,
                   r.is_system as role_is_system, r.created_at as role_created_at
            FROM "{schema}".users u
            LEFT JOIN "{schema}".roles r ON r.id = u.role_id
            WHERE u.id = :uid
        """),
        {"uid": str(user_id)},
    )
    row = result.mappings().one()
    role = None
    if row["role_id"]:
        role = RoleRead(
            id=row["role_id"],
            name=row["role_name"],
            description=row["role_desc"],
            permissions=row["role_perms"],
            ai_description=row["role_ai_desc"],
            is_system=row["role_is_system"],
            created_at=row["role_created_at"],
        )
    return UserRead(
        id=row["id"],
        email=row["email"],
        full_name=row["full_name"],
        is_active=row["is_active"],
        is_superuser=row["is_superuser"],
        role=role,
        created_at=row["created_at"],
        last_login=row["last_login"],
    )


async def refresh_tokens(
    db: AsyncSession,
    raw_refresh_token: str,
) -> TokenResponse:
    """
    Endpoint logico per il refresh token rotation.

    Flusso:
      1. Valida il refresh token (hash lookup nel DB)
      2. Se già usato → REPLAY ATTACK → invalida tutta la family → 401
      3. Se scaduto → 401
      4. Se valido → revoca il vecchio, genera access + refresh nuovi
      5. Ritorna la nuova coppia di token

    Il chiamante deve aggiornare ENTRAMBI i token (access + refresh)
    perché il vecchio refresh token è ora revocato.
    """
    try:
        old_rt, new_refresh_raw = await rotate_refresh_token(db, raw_refresh_token)
    except ValueError as exc:
        code = str(exc)
        if code == "REPLAY_ATTACK":
            raise ValueError(
                "REPLAY_ATTACK: token già utilizzato. "
                "Possibile furto di sessione. Tutti i token sono stati invalidati. "
                "Effettua nuovamente il login."
            )
        elif code == "TOKEN_EXPIRED":
            raise ValueError(
                "Il refresh token è scaduto. Effettua nuovamente il login."
            )
        else:
            raise ValueError("Refresh token non valido. Effettua nuovamente il login.")

    # Genera nuovo access token con le stesse informazioni del vecchio
    access_token, access_expires = create_access_token(
        user_id=old_rt.user_id,
        tenant_id=old_rt.tenant_id,
        tenant_schema=old_rt.tenant_schema,
    )
    # Nota: role e permissions non sono nel refresh token per sicurezza.
    # Verranno riletti dal DB al prossimo accesso a un endpoint protetto
    # che richiede permessi specifici. Per ora il nuovo access token
    # avrà role=None — nel prossimo step aggiungeremo il lookup dal DB.

    from app.config.settings import get_settings

    s = get_settings()

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_raw,
        token_type="bearer",
        expires_in=s.jwt_access_token_expire_minutes * 60,
        refresh_expires_in=s.jwt_refresh_token_expire_days * 24 * 3600,
        user=None,  # non serve ripetere i dati utente al refresh
    )


async def logout_user(
    db: AsyncSession,
    user_id: str,
    raw_refresh_token: str | None = None,
) -> dict:
    """
    Logout: revoca il refresh token presentato (o tutti i token dell'utente).

    Se raw_refresh_token è fornito → revoca solo quella sessione.
    Se non fornito → logout globale (revoca tutte le sessioni attive).
    """
    if raw_refresh_token:
        import hashlib

        token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
        from sqlalchemy import update as sa_update
        from app.models.refresh_token import RefreshToken

        await db.execute(
            sa_update(RefreshToken)
            .where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
            )
            .values(is_revoked=True, revoked_reason="logout")
        )
        return {"message": "Sessione corrente terminata"}
    else:
        count = await revoke_all_user_tokens(db, user_id, reason="logout")
        return {"message": f"Logout globale: {count} sessioni terminate"}

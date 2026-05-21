"""
services/refresh_token_service.py  (Step 3)
────────────────────────────────────────────
Logica completa per refresh token rotation con family invalidation.

Flusso normale (nessun attacco):
  1. Login  → crea family_id, genera token A, salva hash(A) nel DB
  2. Refresh con A → revoca A (reason='rotated'), genera B con stesso family_id
  3. Refresh con B → revoca B, genera C ...

Flusso replay attack (token già usato ripresentato):
  1. Attaccante ruba token A (già usato, is_revoked=True)
  2. Presenta A al /auth/refresh
  3. Sistema trova hash(A): is_revoked=True → REPLAY ATTACK rilevato
  4. Invalida TUTTA la family (tutti i token con lo stesso family_id)
  5. L'utente legittimo al prossimo refresh ottiene 401 e deve rifare login
  6. L'attaccante non ottiene nulla

Perché SHA-256 e non salvare il token in chiaro?
  Se il DB viene esfiltrato (SQL injection, backup leak, insider threat),
  l'attaccante non ha token pronti all'uso. Deve invertire SHA-256
  su stringhe random di 32 byte → computazionalmente impossibile.
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import get_settings
from app.models.refresh_token import RefreshToken

settings = get_settings()

# Lunghezza del token grezzo in byte → 32 byte = 256 bit di entropia
# url_safe base64 → stringa di ~43 caratteri
_TOKEN_BYTES = 32


def _hash_token(raw_token: str) -> str:
    """SHA-256 del token grezzo. Restituisce hex string di 64 caratteri."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def generate_raw_token() -> str:
    """Genera un token crittograficamente sicuro (256 bit di entropia)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


async def create_refresh_token(
    db: AsyncSession,
    user_id: str,
    tenant_id: str,
    tenant_schema: str,
    family_id: Optional[uuid.UUID] = None,
    parent_token_hash: Optional[str] = None,
) -> str:
    """
    Crea un nuovo refresh token, lo salva nel DB e restituisce il token grezzo.

    Args:
        family_id         : None per il primo token (login), UUID esistente per rotazione
        parent_token_hash : hash del token che ha richiesto questo (None per login)

    Returns:
        Il token grezzo (da inviare al client). Non viene mai salvato in DB.
    """
    raw_token = generate_raw_token()
    token_hash = _hash_token(raw_token)

    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.jwt_refresh_token_expire_days
    )

    rt = RefreshToken(
        id=uuid.uuid4(),
        token_hash=token_hash,
        family_id=family_id or uuid.uuid4(),  # nuovo UUID per il primo login
        user_id=user_id,
        tenant_id=tenant_id,
        tenant_schema=tenant_schema,
        parent_token_hash=parent_token_hash,
        is_revoked=False,
        expires_at=expires_at,
    )
    db.add(rt)
    await db.flush()
    return raw_token


async def rotate_refresh_token(
    db: AsyncSession,
    raw_token: str,
) -> tuple[RefreshToken, str]:
    """
    Cuore del sistema: valida il token presentato e ne genera uno nuovo.

    Returns:
        (vecchio_record, nuovo_token_grezzo)

    Raises:
        ValueError con codice specifico per ogni caso di errore:
          - "TOKEN_NOT_FOUND"   : token sconosciuto
          - "TOKEN_EXPIRED"     : scaduto (non revocato)
          - "REPLAY_ATTACK"     : token già usato → family invalidata
    """
    token_hash = _hash_token(raw_token)

    # ── 1. Cerca il token nel DB ───────────────────────────────────────────
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    rt = result.scalar_one_or_none()

    if rt is None:
        raise ValueError("TOKEN_NOT_FOUND")

    # ── 2. Già revocato → REPLAY ATTACK ───────────────────────────────────
    if rt.is_revoked:
        # Invalida TUTTA la family immediatamente
        await _invalidate_family(db, rt.family_id, reason="replay_attack")
        # Commit esplicito prima di sollevare l'eccezione: senza di esso
        # get_db farebbe rollback sull'eccezione, annullando la family invalidation.
        await db.commit()
        raise ValueError("REPLAY_ATTACK")

    # ── 3. Scaduto (ma non revocato) ──────────────────────────────────────
    if rt.is_expired:
        # Revoca ordinata: il token era legittimo ma è scaduto
        await _revoke_single(db, rt, reason="expired")
        raise ValueError("TOKEN_EXPIRED")

    # ── 4. Token valido: revoca il vecchio e crea il nuovo ────────────────
    await _revoke_single(db, rt, reason="rotated")
    rt.used_at = datetime.now(timezone.utc)

    new_raw_token = await create_refresh_token(
        db=db,
        user_id=rt.user_id,
        tenant_id=rt.tenant_id,
        tenant_schema=rt.tenant_schema,
        family_id=rt.family_id,          # stessa family → stessa sessione
        parent_token_hash=token_hash,    # catena di rotazione
    )

    return rt, new_raw_token


async def revoke_all_user_tokens(
    db: AsyncSession,
    user_id: str,
    reason: str = "logout",
) -> int:
    """
    Revoca TUTTI i token attivi di un utente (logout globale).
    Utile anche per: cambio password, account compromesso, admin action.

    Returns:
        Numero di token revocati.
    """
    result = await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked.is_(False),
        )
        .values(is_revoked=True, revoked_reason=reason)
        .returning(RefreshToken.id)
    )
    revoked = result.fetchall()
    return len(revoked)


async def _revoke_single(
    db: AsyncSession, rt: RefreshToken, reason: str
) -> None:
    """Revoca un singolo token con il motivo specificato."""
    rt.is_revoked = True
    rt.revoked_reason = reason
    await db.flush()


async def _invalidate_family(
    db: AsyncSession,
    family_id: uuid.UUID,
    reason: str = "replay_attack",
) -> int:
    """
    Invalida TUTTI i token della family (inclusi quelli non ancora usati).

    Questo è il meccanismo di sicurezza centrale:
    se un token rubato viene presentato, l'intera sessione viene distrutta,
    forzando sia l'attaccante che il legittimo proprietario a rifare login.
    """
    result = await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.family_id == family_id,
            RefreshToken.is_revoked.is_(False),
        )
        .values(is_revoked=True, revoked_reason=reason)
        .returning(RefreshToken.id)
    )
    invalidated = result.fetchall()
    return len(invalidated)


async def cleanup_expired_tokens(db: AsyncSession) -> int:
    """
    Elimina i token scaduti dal DB. Da chiamare periodicamente
    (es: task schedulato ogni notte) per evitare crescita infinita della tabella.

    Returns:
        Numero di token eliminati.
    """
    from sqlalchemy import delete
    result = await db.execute(
        delete(RefreshToken).where(
            RefreshToken.expires_at < datetime.now(timezone.utc)
        ).returning(RefreshToken.id)
    )
    deleted = result.fetchall()
    return len(deleted)

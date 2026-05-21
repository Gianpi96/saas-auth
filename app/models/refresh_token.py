"""
models/refresh_token.py  — Schema PUBLIC  (Step 3)
────────────────────────────────────────────────────
Tabella RefreshToken nello schema public.

Perché nello schema public e non in quello del tenant?
  Il refresh token è un artefatto di sessione/sicurezza, non un dato
  di business del tenant. Viverà centralizzato per:
    - query veloci senza dover sapere lo schema del tenant
    - invalidazione globale (family invalidation) in un'unica tabella
    - future implementazioni di session management cross-tenant

Concetti chiave:
  token_hash   : SHA-256 del token. Non salviamo il token in chiaro
                 per difesa in profondità: se il DB viene compromesso,
                 l'attaccante non ha token pronti all'uso.

  family_id    : UUID condiviso tra tutti i refresh token di una stessa
                 "sessione di login". Quando rileviamo un replay attack
                 (token già usato presentato di nuovo), invalidiamo
                 TUTTA la family → tutti i token di quella sessione
                 diventano inutilizzabili. L'utente deve rifare login.

  is_revoked   : flag esplicito. Un token può essere revocato anche
                 prima della scadenza (logout, replay attack, admin).

  parent_token_hash : hash del token che ha generato questo.
                      Permette di ricostruire l'albero di rotazione.
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.config.database import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        # Lookup principale: trovare un token dal suo hash
        Index("ix_refresh_tokens_token_hash", "token_hash", unique=True),
        # Invalidazione family: trovare tutti i token di una sessione
        Index("ix_refresh_tokens_family_id", "family_id"),
        # Pulizia per utente: trovare tutti i token di un utente
        Index("ix_refresh_tokens_user_id", "user_id"),
        {"schema": "public"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Hash SHA-256 del token grezzo (mai salvare token in chiaro)
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="SHA-256 hex del refresh token. Univoco."
    )

    # Identifica la "famiglia" (sessione di login)
    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False,
        comment="UUID condiviso tra tutti i token di una sessione. Usato per family invalidation."
    )

    # Riferimento all'utente (UUID come stringa, cross-schema)
    user_id: Mapped[str] = mapped_column(
        String(36), nullable=False,
        comment="UUID dell'utente proprietario del token."
    )

    # Riferimento al tenant
    tenant_id: Mapped[str] = mapped_column(
        String(36), nullable=False,
        comment="UUID del tenant dell'utente."
    )
    tenant_schema: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="Schema PostgreSQL del tenant (per evitare lookup al momento del refresh)."
    )

    # Catena di rotazione: hash del token padre
    parent_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
        comment="Hash del token che ha generato questo. None = primo token della family."
    )

    # Stato
    is_revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="True se il token è stato revocato (usato, logout, o replay attack)."
    )
    revoked_reason: Mapped[str | None] = mapped_column(
        String(50), nullable=True,
        comment="Motivo revoca: 'rotated' | 'logout' | 'replay_attack' | 'admin'"
    )

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        comment="Scadenza assoluta del token."
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Quando è stato usato per generare un nuovo token."
    )

    @property
    def is_expired(self) -> bool:
        from datetime import timezone
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """True solo se non revocato E non scaduto."""
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        return (
            f"<RefreshToken(user={self.user_id!r}, "
            f"family={str(self.family_id)[:8]}..., "
            f"revoked={self.is_revoked})>"
        )

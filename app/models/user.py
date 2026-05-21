"""
models/user.py  — Schema TENANT  (Step 2: aggiornato)
───────────────────────────────────────────────────────
Aggiunto rispetto allo step 1:
  - tenant_id  : UUID del tenant proprietario del record
  - Indici composti (tenant_id, id) su tutti i modelli

Perché tenant_id se già siamo in uno schema separato?
  Doppia difesa. Lo schema PostgreSQL garantisce isolamento fisico,
  ma tenant_id consente:
    1. Query cross-schema future (analytics, admin panel)
    2. Audit log: ogni record sa a chi appartiene senza JOIN sugli schema
    3. Backup/restore selettivo per tenant
    4. Shard migration: spostare un tenant su un altro DB senza perdere contesto
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.config.database import Base


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (
        # Indice composto: ricerche per tenant + id sono O(log n) invece di full scan
        Index("ix_roles_tenant_id_id", "tenant_id", "id"),
        # Unicità del nome ruolo DENTRO il tenant (non globalmente)
        UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # ── NUOVO: tenant_id come colonna esplicita ───────────────────────────────
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID del tenant proprietario. Ridondante con lo schema PG, ma utile per audit e cross-schema query."
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    permissions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    users: Mapped[list["User"]] = relationship("User", back_populates="role")

    def __repr__(self) -> str:
        return f"<Role(name={self.name!r}, tenant={self.tenant_id!r})>"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Indice composto primario: ogni lookup di un utente passa per tenant_id+id
        Index("ix_users_tenant_id_id", "tenant_id", "id"),
        # Email univoca DENTRO il tenant (la stessa email può esistere in tenant diversi)
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # ── NUOVO ────────────────────────────────────────────────────────────────
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    role_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="SET NULL"),
        nullable=True,
    )
    role: Mapped[Optional["Role"]] = relationship("Role", back_populates="users")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<User(email={self.email!r}, tenant={self.tenant_id!r})>"


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        Index("ix_policies_tenant_id_id", "tenant_id", "id"),
        # Una policy è univoca per (tenant, role, resource, action)
        UniqueConstraint(
            "tenant_id", "role_id", "resource", "action",
            name="uq_policies_tenant_role_resource_action"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # ── NUOVO ────────────────────────────────────────────────────────────────
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    effect: Mapped[str] = mapped_column(String(10), nullable=False, default="allow")
    ai_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    role: Mapped["Role"] = relationship("Role")

    def __repr__(self) -> str:
        return f"<Policy(tenant={self.tenant_id!r}, {self.action}:{self.resource})>"

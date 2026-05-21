"""
models/permission.py  — Schema TENANT  (Step 4)
────────────────────────────────────────────────
NOTA ARCHITETTURALE:
  Questi modelli ORM NON hanno ForeignKey perché vivono negli schemi tenant
  (tenant_acme_corp, tenant_beta_industries, ecc.) che vengono creati
  dinamicamente da tenant_service.py via DDL SQL raw.

  Base.metadata.create_all() gira solo sullo schema "public" al boot.
  Le FK reali (role_permissions.role_id → roles.id) esistono nel DDL
  dentro tenant_service.py — non qui.

  Se mettessimo FK qui, SQLAlchemy cercherebbe la tabella "roles" nello
  schema public durante create_all → NoReferencedTableError.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.config.database import Base


class Permission(Base):
    """
    Permesso atomico nel formato "resource:action".
    Vive nello schema del tenant, creato via DDL in tenant_service.py.
    """

    __tablename__ = "permissions"
    __table_args__ = (
        Index("ix_permissions_tenant_id_id", "tenant_id", "id"),
        UniqueConstraint(
            "tenant_id",
            "resource",
            "action",
            name="uq_permissions_tenant_resource_action",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    codename: Mapped[str] = mapped_column(String(201), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<Permission({self.codename!r})>"


class RolePermission(Base):
    """
    Tabella di giunzione Role ↔ Permission (many-to-many).
    Vive nello schema del tenant. Nessuna FK a livello ORM per il motivo
    spiegato nel docstring del modulo.
    """

    __tablename__ = "role_permissions"
    __table_args__ = (
        Index("ix_role_permissions_role_id", "role_id"),
        Index("ix_role_permissions_permission_id", "permission_id"),
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    # UUID senza ForeignKey ORM — la FK reale è nel DDL di tenant_service.py
    role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    granted_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<RolePermission(role={self.role_id!r}, perm={self.permission_id!r})>"

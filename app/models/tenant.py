"""
models/tenant.py  — Schema PUBLIC  (Step 2: aggiornato)
─────────────────────────────────────────────────────────
Aggiunto rispetto allo step 1:
  - subdomain : sottodominio univoco (es. "acme" → acme.myapp.com)
  - plan      : piano di abbonamento (free / pro / enterprise)
  - max_users / max_storage_gb: limiti derivati dal piano
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.config.database import Base


class TenantPlan(str, PyEnum):
    """
    Piani disponibili. str+PyEnum = serializzazione JSON automatica.
    Pydantic lo legge come stringa senza adattatori custom.
    """
    FREE       = "free"
    PRO        = "pro"
    ENTERPRISE = "enterprise"


# Limiti per piano — centralizzati qui, non sparsi nel codice
PLAN_LIMITS: dict[TenantPlan, dict] = {
    TenantPlan.FREE:       {"max_users": 5,    "max_storage_gb": 1},
    TenantPlan.PRO:        {"max_users": 50,   "max_storage_gb": 20},
    TenantPlan.ENTERPRISE: {"max_users": 9999, "max_storage_gb": 500},
}


class Tenant(Base):
    """
    Rappresenta un'organizzazione/cliente nel sistema multi-tenant.

    Tre identificatori distinti con scopi diversi:
      slug      → header HTTP (X-Tenant-Slug: acme-corp)
      subdomain → routing DNS (acme.myapp.com)
      db_schema → schema PostgreSQL (tenant_acme_corp)
    """
    __tablename__ = "tenants"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    slug: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    subdomain: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    db_schema: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    # Piano abbonamento
    plan: Mapped[TenantPlan] = mapped_column(
        Enum(
            TenantPlan,
            name="tenant_plan_enum",
            schema="public",
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        default=TenantPlan.FREE,
    )

    # Limiti derivati dal piano (denormalizzati per query veloci senza JOIN)
    max_users: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    max_storage_gb: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def apply_plan_limits(self) -> None:
        """Sincronizza i limiti con il piano corrente. Chiamare dopo ogni cambio piano."""
        limits = PLAN_LIMITS[self.plan]
        self.max_users      = limits["max_users"]
        self.max_storage_gb = limits["max_storage_gb"]

    def __repr__(self) -> str:
        return f"<Tenant(slug={self.slug!r}, plan={self.plan!r})>"

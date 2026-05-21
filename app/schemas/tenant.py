"""
schemas/tenant.py  (Step 2: aggiornato)
────────────────────────────────────────
Aggiunto: subdomain, plan, max_users, max_storage_gb.
"""
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.models.tenant import TenantPlan


class TenantCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, examples=["Acme Corp"])
    slug: str = Field(
        ..., min_length=2, max_length=100,
        pattern=r"^[a-z0-9\-]+$",
        examples=["acme-corp"],
    )
    subdomain: str = Field(
        ..., min_length=2, max_length=100,
        pattern=r"^[a-z0-9\-]+$",
        examples=["acme"],
        description="Sottodominio DNS (solo lowercase, numeri, trattini).",
    )
    plan: TenantPlan = Field(default=TenantPlan.FREE, examples=["free"])

    @field_validator("slug", "subdomain")
    @classmethod
    def no_reserved_words(cls, v: str) -> str:
        reserved = {"public", "admin", "api", "www", "mail", "app", "pg_catalog"}
        if v in reserved:
            raise ValueError(f"'{v}' è un valore riservato dal sistema")
        return v


class TenantRead(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    subdomain: str
    plan: TenantPlan
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantReadInternal(TenantRead):
    """Versione estesa per uso admin/interno."""
    db_schema: str
    max_users: int
    max_storage_gb: int
    updated_at: datetime


class TenantUpdate(BaseModel):
    """Aggiornamento piano (upgrade/downgrade)."""
    plan: Optional[TenantPlan] = None
    is_active: Optional[bool] = None

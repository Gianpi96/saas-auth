"""
schemas/user.py
────────────────
Schema per User, Role, Policy e token JWT.
"""
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# ── Role Schemas ──────────────────────────────────────────────────────────────

class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, examples=["editor"])
    description: Optional[str] = Field(None, examples=["Può modificare contenuti"])
    permissions: Optional[str] = Field(
        None,
        examples=["read:documents,write:documents"],
        description="Permessi separati da virgola nel formato azione:risorsa",
    )


class RoleRead(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    permissions: Optional[str]
    ai_description: Optional[str]  # generato da Groq
    is_system: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── User Schemas ──────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, examples=["P@ssword123"])
    full_name: Optional[str] = Field(None, examples=["Mario Rossi"])
    role_id: Optional[uuid.UUID] = None


class UserRead(BaseModel):
    id: uuid.UUID
    email: str
    full_name: Optional[str]
    is_active: bool
    is_superuser: bool
    role: Optional[RoleRead]
    created_at: datetime
    last_login: Optional[datetime]

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role_id: Optional[uuid.UUID] = None
    is_active: Optional[bool] = None


# ── Auth Schemas ──────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """
    Risposta al login e al refresh.

    Step 3: aggiunto refresh_token e refresh_expires_in.
    Il client deve:
      1. Salvare access_token in memoria (mai localStorage per XSS)
      2. Salvare refresh_token in cookie HttpOnly (mai localStorage)
      3. Quando access_token scade (401), chiamare POST /auth/refresh
    """
    access_token: str
    refresh_token: str                    # token opaco (non JWT)
    token_type: str = "bearer"
    expires_in: int                       # secondi alla scadenza access_token
    refresh_expires_in: int               # secondi alla scadenza refresh_token
    user: Optional[UserRead] = None       # None al refresh (dati già in possesso del client)


class RefreshRequest(BaseModel):
    """Body per POST /auth/refresh."""
    refresh_token: str = Field(..., description="Il refresh token ottenuto al login")


class LogoutRequest(BaseModel):
    """Body per POST /auth/logout."""
    refresh_token: str = Field(..., description="Il refresh token da revocare")


class TokenPayload(BaseModel):
    """
    Struttura interna del payload JWT (dopo decodifica).
    Non viene mai esposta via API.
    """
    sub: str          # user_id (UUID come stringa)
    tenant_id: str    # tenant UUID
    tenant_schema: str  # es: "tenant_acme"
    role: Optional[str] = None
    permissions: Optional[list[str]] = None
    exp: int          # timestamp di scadenza


# ── Policy Schemas ────────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name: str = Field(..., examples=["Accesso lettura documenti per editor"])
    role_id: uuid.UUID
    resource: str = Field(..., examples=["documents"])
    action: str = Field(..., examples=["read"])
    effect: str = Field(default="allow", pattern=r"^(allow|deny)$")


class PolicyRead(BaseModel):
    id: uuid.UUID
    name: str
    role_id: uuid.UUID
    resource: str
    action: str
    effect: str
    ai_description: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Permission Schemas (Step 4) ───────────────────────────────────────────────

class PermissionCreate(BaseModel):
    resource: str = Field(..., examples=["tasks"], description="Risorsa protetta")
    action: str = Field(..., examples=["delete"], description="Azione (read/write/delete/*)")
    description: Optional[str] = Field(None, examples=["Elimina task completati"])


class PermissionRead(BaseModel):
    id: uuid.UUID
    resource: str
    action: str
    codename: str          # "resource:action" — formato usato nel JWT
    description: Optional[str]
    ai_description: Optional[str]  # generato da Groq llama-3.1-70b-versatile
    created_at: datetime

    model_config = {"from_attributes": True}


class AssignPermissionRequest(BaseModel):
    permission_id: uuid.UUID = Field(..., description="UUID del permesso da assegnare")


class RolePermissionRead(BaseModel):
    """Permesso con metadati di assegnazione (quando, da chi)."""
    id: uuid.UUID
    codename: str
    resource: str
    action: str
    description: Optional[str]
    ai_description: Optional[str]
    granted_by: Optional[str]
    granted_at: datetime

    model_config = {"from_attributes": True}


class RoleWithPermissions(BaseModel):
    """Ruolo completo con lista permessi espansi."""
    id: uuid.UUID
    name: str
    description: Optional[str]
    ai_description: Optional[str]
    is_system: bool
    created_at: datetime
    permissions: list[RolePermissionRead] = []

    model_config = {"from_attributes": True}


# ── Admin Role Schemas ────────────────────────────────────────────────────────

class AdminRoleCreate(BaseModel):
    """
    Schema per POST /admin/roles — creazione ruolo con permessi in un colpo solo.
    Permette di specificare i permessi come codename ("tasks:delete")
    invece di UUID, per comodità.
    """
    name: str = Field(..., min_length=1, max_length=100, examples=["editor"])
    description: Optional[str] = Field(None, examples=["Può modificare ma non eliminare"])
    # Lista di codename permessi da creare/assegnare automaticamente
    permission_codenames: list[str] = Field(
        default=[],
        examples=[["tasks:read", "tasks:write", "reports:read"]],
        description="Lista di 'resource:action' da creare e assegnare al ruolo",
    )

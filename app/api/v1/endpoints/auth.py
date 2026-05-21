"""
api/v1/endpoints/auth.py  (Step 3: aggiornato)
────────────────────────────────────────────────
Aggiunto rispetto allo step 2:
  POST /auth/refresh  → refresh token rotation
  POST /auth/logout   → revoca sessione corrente o globale
"""
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.database import get_db
from app.schemas.user import (
    LoginRequest, LogoutRequest, RefreshRequest,
    TokenResponse, UserCreate, UserRead, TokenPayload,
)
from app.services.auth_service import (
    login_user, logout_user, refresh_tokens, register_user,
)
from app.services.rbac import get_current_user

router = APIRouter(prefix="/auth", tags=["Autenticazione"])


def _require_tenant_slug(x_tenant_slug: str = Header(..., alias="X-Tenant-Slug")):
    if not x_tenant_slug or len(x_tenant_slug) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Header X-Tenant-Slug obbligatorio",
        )
    return x_tenant_slug


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Registra un nuovo utente nel tenant",
)
async def register(
    user_data: UserCreate,
    tenant_slug: str = Depends(_require_tenant_slug),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    try:
        return await register_user(db, tenant_slug, user_data)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login — restituisce access_token (15 min) + refresh_token (7 giorni)",
    description="""
Autentica l'utente e restituisce la coppia di token.

**Header richiesto:** `X-Tenant-Slug: nome-del-tenant`

### Token restituiti
| Token | Tipo | Durata | Dove salvarlo |
|-------|------|--------|---------------|
| `access_token` | JWT firmato | 15 minuti | Memoria JS (mai localStorage) |
| `refresh_token` | Token opaco | 7 giorni | Cookie HttpOnly (mai localStorage) |

### Perché due token?
- **access_token** breve: se rubato, scade in 15 minuti
- **refresh_token** lungo: permette di ottenere nuovi access token senza riloginare
""",
)
async def login(
    credentials: LoginRequest,
    tenant_slug: str = Depends(_require_tenant_slug),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        return await login_user(db, tenant_slug, credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh token rotation — invalida il vecchio, emette coppia nuova",
    description="""
Scambia un refresh token valido con una nuova coppia access + refresh token.

### Comportamento
- Il refresh token presentato viene **immediatamente revocato**
- Viene generata una nuova coppia di token
- Il client deve aggiornare **entrambi** i token salvati

### Replay Attack Detection
Se viene presentato un refresh token **già usato**:
1. Il sistema rileva il riuso (token già revocato nel DB)
2. **Tutta la family di token** (= sessione di login) viene invalidata
3. L'utente deve rifare il login
4. Questo protegge anche l'utente legittimo se il token era stato rubato

### Risposta
`user` sarà `null` (il client ha già i dati utente dall'ultimo login/refresh).
""",
)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        return await refresh_tokens(db, body.refresh_token)
    except ValueError as exc:
        error_msg = str(exc)
        if "REPLAY_ATTACK" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error_msg,
                headers={"X-Security-Event": "replay-attack-detected"},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg,
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post(
    "/logout",
    summary="Logout — revoca il refresh token (o tutti i token dell'utente)",
    description="""
Revoca il refresh token presentato nel body.

Se `refresh_token` è fornito → revoca solo la sessione corrente.
Se omesso → **logout globale**: revoca tutte le sessioni attive dell'utente.

L'access token corrente rimane tecnicamente valido fino alla sua scadenza
(15 minuti). Per sicurezza critica usa il logout globale che invalida
tutte le sessioni: anche gli access token non possono essere rinnovati.
""",
)
async def logout(
    body: LogoutRequest,
    current_user: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await logout_user(
        db=db,
        user_id=current_user.sub,
        raw_refresh_token=body.refresh_token,
    )


@router.get(
    "/me",
    response_model=TokenPayload,
    summary="Profilo utente corrente dal JWT",
)
async def get_me(
    current_user: TokenPayload = Depends(get_current_user),
) -> TokenPayload:
    return current_user

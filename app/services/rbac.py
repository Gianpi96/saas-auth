"""
services/rbac.py  (Step 4: aggiornato)
────────────────────────────────────────
Aggiunto rispetto allo step precedente:
  - require_permission() ora funziona anche come decorator Python puro
    (oltre che come Depends() FastAPI)
  - _has_permission() invariata (wildcard matching)
  - Aggiunto require_any_permission() per OR tra permessi

Differenza Depends() vs decorator:
  Depends(require_permission("tasks:delete"))
    → dependency FastAPI: integrata con Swagger, errori 403 automatici,
      il token viene estratto dall'header Authorization

  @require_permission("tasks:delete")  ← NON USARE su endpoint FastAPI
    → il decorator puro funziona solo su funzioni normali/async,
      NON su endpoint FastAPI (che usano Depends per l'iniezione).
      Lo includiamo per compatibilità con test e logica non-HTTP.

In FastAPI USARE SEMPRE la forma Depends():
    @router.delete("/tasks/{id}")
    async def delete_task(
        current_user: TokenPayload = Depends(require_permission("tasks:delete"))
    ):
        ...
"""
import functools
import logging
from typing import Callable

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.schemas.user import TokenPayload
from app.services.jwt_service import decode_token

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> TokenPayload:
    """
    Dependency base: estrae e valida il JWT dall'header Authorization.
    Solleva 401 se il token è assente, malformato o scaduto.
    """
    try:
        payload = decode_token(credentials.credentials)
        return payload
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_permission(required_permission: str):
    """
    Factory usabile in due modi:

    1. Come Depends() FastAPI (uso raccomandato negli endpoint):
       async def endpoint(user = Depends(require_permission("tasks:delete"))):

    2. Come decorator su funzioni NON-endpoint (utility, test):
       @require_permission("tasks:delete")
       async def my_function(current_user: TokenPayload): ...

    La logica di matching supporta wildcard:
      "*"           → tutto
      "tasks:*"     → qualsiasi azione su tasks
      "*:read"      → lettura su qualsiasi risorsa
      "tasks:delete"→ esatto
    """
    async def _dependency(
        current_user: TokenPayload = Depends(get_current_user),
    ) -> TokenPayload:
        permissions = current_user.permissions or []
        if _has_permission(permissions, required_permission):
            return current_user
        logger.warning(
            f"Accesso negato: user={current_user.sub!r} "
            f"richiede={required_permission!r} "
            f"ha={permissions!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Permesso '{required_permission}' richiesto. "
                f"Il tuo ruolo '{current_user.role}' non ha questo permesso."
            ),
        )

    # Decorator puro per funzioni NON-endpoint
    def _decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def _wrapper(current_user: TokenPayload, *args, **kwargs):
            permissions = current_user.permissions or []
            if not _has_permission(permissions, required_permission):
                raise PermissionError(
                    f"Permesso '{required_permission}' richiesto, "
                    f"ruolo '{current_user.role}' non autorizzato."
                )
            return await func(current_user, *args, **kwargs)
        return _wrapper

    # Trick: la factory restituisce una callable che FastAPI accetta come Depends
    # MA che può anche essere usata come decorator
    _dependency._decorator = _decorator
    return _dependency


def require_role(*allowed_roles: str):
    """
    Factory: verifica che l'utente abbia uno dei ruoli specificati.

    Uso: Depends(require_role("admin", "superadmin"))
    """
    async def _check(
        current_user: TokenPayload = Depends(get_current_user),
    ) -> TokenPayload:
        if current_user.role in allowed_roles:
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Ruolo richiesto: uno tra {list(allowed_roles)}. Il tuo ruolo è '{current_user.role}'.",
        )
    return _check


def require_any_permission(*permissions: str):
    """
    OR tra permessi: l'utente deve averne ALMENO UNO.

    Uso: Depends(require_any_permission("tasks:write", "tasks:*", "*"))
    """
    async def _check(
        current_user: TokenPayload = Depends(get_current_user),
    ) -> TokenPayload:
        user_perms = current_user.permissions or []
        for perm in permissions:
            if _has_permission(user_perms, perm):
                return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Almeno uno di questi permessi richiesto: {list(permissions)}",
        )
    return _check


def _has_permission(user_permissions: list[str], required: str) -> bool:
    """
    Matching permessi con wildcard a due livelli (resource e action).

    Tabella di verità:
      user_perm   required        result
      "*"         qualsiasi       True   (wildcard globale)
      "tasks:*"   "tasks:delete"  True   (wildcard sull'action)
      "*:read"    "tasks:read"    True   (wildcard sulla resource)
      "tasks:read""tasks:read"    True   (match esatto)
      "tasks:read""tasks:write"   False
      "tasks:read""reports:read"  False
    """
    for perm in user_permissions:
        if perm == "*":
            return True

        if ":" in perm and ":" in required:
            perm_resource, perm_action = perm.split(":", 1)
            req_resource, req_action = required.split(":", 1)

            resource_match = perm_resource == req_resource or perm_resource == "*"
            action_match   = perm_action   == req_action   or perm_action   == "*"

            if resource_match and action_match:
                return True
        elif perm == required:
            return True

    return False

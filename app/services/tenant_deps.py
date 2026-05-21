"""
services/tenant_deps.py
────────────────────────
Dependency FastAPI per ottenere il tenant corrente negli endpoint.

Differenza tra Middleware e Dependency:
  TenantMiddleware  → risolve il tenant per TUTTI i path (inclusi middleware)
  get_current_tenant → usato negli endpoint che RICHIEDONO un tenant valido

Uso negli endpoint:
    @router.get("/something")
    async def my_endpoint(
        tenant: Tenant = Depends(get_current_tenant),
    ):
        # tenant è garantito non-None e attivo
        ...

Varianti disponibili:
  get_current_tenant          → richiede tenant (401 se assente)
  get_current_tenant_optional → restituisce None se assente (endpoint pubblici)
  require_plan                → factory che verifica il piano minimo
"""
from typing import Optional

from fastapi import Depends, HTTPException, Request, status

from app.models.tenant import Tenant, TenantPlan


def get_current_tenant(request: Request) -> Tenant:
    """
    Dependency standard: restituisce il tenant corrente.

    Legge da request.state.tenant popolato da TenantMiddleware.
    Solleva 401 se nessun tenant è stato identificato.

    Perché 401 e non 404?
      404 rivelerebbe che il tenant non esiste.
      401 è più generico e non espone informazioni sull'esistenza del tenant.
    """
    tenant: Optional[Tenant] = getattr(request.state, "tenant", None)

    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Tenant non identificato. "
                "Fornire l'header X-Tenant-ID (UUID) o X-Tenant-Slug (slug)."
            ),
            headers={"WWW-Authenticate": 'Bearer realm="tenant"'},
        )

    return tenant


def get_current_tenant_optional(request: Request) -> Optional[Tenant]:
    """
    Dependency opzionale: restituisce il tenant o None.
    Utile per endpoint misti (pubblici + autenticati).
    """
    return getattr(request.state, "tenant", None)


def require_plan(*allowed_plans: TenantPlan):
    """
    Factory di Dependency: verifica che il tenant abbia il piano richiesto.

    Uso:
        @router.post("/advanced-feature")
        async def advanced(
            tenant: Tenant = Depends(require_plan(TenantPlan.PRO, TenantPlan.ENTERPRISE))
        ):
            ...

    Gerarchia piani: FREE < PRO < ENTERPRISE
    """
    plan_hierarchy = {
        TenantPlan.FREE: 0,
        TenantPlan.PRO: 1,
        TenantPlan.ENTERPRISE: 2,
    }
    min_level = min(plan_hierarchy[p] for p in allowed_plans)

    def _check(tenant: Tenant = Depends(get_current_tenant)) -> Tenant:
        current_level = plan_hierarchy.get(tenant.plan, -1)
        if current_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Funzionalità disponibile per i piani: "
                    f"{', '.join(p.value for p in allowed_plans)}. "
                    f"Il tuo piano attuale è '{tenant.plan.value}'. "
                    f"Effettua l'upgrade per accedere."
                ),
            )
        return tenant

    return _check


def check_user_limit(tenant: Tenant) -> None:
    """
    Utility (non Dependency): verifica che il tenant non abbia raggiunto
    il limite utenti del suo piano.

    Chiamata da auth_service prima di creare un nuovo utente.
    Solleva HTTPException 402 se il limite è raggiunto.
    """
    # Nota: il conteggio utenti effettivo viene passato dall'esterno
    # per evitare una query aggiuntiva (chi chiama già ha il conteggio)
    pass  # implementazione completa in step 3 con feature flags


def get_tenant_info(request: Request) -> dict:
    """
    Dependency utile per i log e il debug: restituisce un dizionario
    con le info base del tenant senza l'oggetto ORM completo.
    """
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        return {"tenant_id": None, "tenant_schema": None, "plan": None}
    return {
        "tenant_id": str(tenant.id),
        "tenant_schema": tenant.db_schema,
        "plan": tenant.plan.value,
        "slug": tenant.slug,
    }

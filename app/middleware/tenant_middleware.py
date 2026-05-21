"""
middleware/tenant_middleware.py
────────────────────────────────
TenantMiddleware: identifica il tenant ad ogni request e lo inietta
in request.state.tenant prima che qualsiasi endpoint venga eseguito.

Strategia di risoluzione (in ordine di priorità):
  1. Header X-Tenant-ID   → UUID diretto del tenant (uso interno/API)
  2. Header X-Tenant-Slug → slug human-readable (uso da frontend/client)
  3. Subdomain            → acme.myapp.com  (futuro: routing DNS)

Perché un Middleware e non solo una Dependency?
  La Dependency (get_current_tenant) è più comoda negli endpoint,
  ma il Middleware garantisce che request.state.tenant sia disponibile
  ANCHE nei middleware successivi, nei logger, e in qualsiasi punto
  della chain ASGI — non solo negli endpoint FastAPI.
  I due meccanismi coesistono e si completano.

Endpoint esclusi dalla risoluzione del tenant (BYPASS_PATHS):
  - /health   → monitoring, non appartiene a nessun tenant
  - /docs     → Swagger UI
  - /redoc    → ReDoc
  - /openapi  → schema OpenAPI
  - /api/v1/tenants → gestione tenant (non richiede tenant attivo)
"""
import logging
from typing import Optional

from fastapi import Request, Response
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.config.database import AsyncSessionLocal
from app.models.tenant import Tenant

logger = logging.getLogger(__name__)

# Path che non richiedono un tenant valido
BYPASS_PATHS = {
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
}
BYPASS_PREFIXES = (
    "/api/v1/tenants",  # gestione tenant
)


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Middleware ASGI che risolve il tenant per ogni request.

    Dopo l'esecuzione, request.state ha questi attributi:
      - tenant         : oggetto Tenant ORM (o None se bypass/non trovato)
      - tenant_id      : UUID come stringa (o None)
      - tenant_schema  : nome schema PostgreSQL (o None)

    Gli endpoint usano la Dependency get_current_tenant() che
    legge da request.state e solleva 401/404 se necessario.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        # ── Reset state per ogni request ──────────────────────────────────
        request.state.tenant        = None
        request.state.tenant_id     = None
        request.state.tenant_schema = None

        # ── Bypass per path di sistema ────────────────────────────────────
        path = request.url.path
        if path in BYPASS_PATHS or path.startswith(BYPASS_PREFIXES):
            return await call_next(request)

        # ── Risolvi tenant dagli header ───────────────────────────────────
        tenant = await self._resolve_tenant(request)

        if tenant:
            request.state.tenant        = tenant
            request.state.tenant_id     = str(tenant.id)
            request.state.tenant_schema = tenant.db_schema
            logger.debug(
                f"Tenant risolto: {tenant.slug!r} "
                f"(schema={tenant.db_schema!r}, plan={tenant.plan!r})"
            )
        else:
            # Non logghiamo errore qui: alcuni endpoint pubblici non richiedono tenant.
            # Sarà get_current_tenant() a sollevare 401 se l'endpoint lo richiede.
            logger.debug(f"Nessun tenant risolto per {request.method} {path}")

        return await call_next(request)

    async def _resolve_tenant(self, request: Request) -> Optional[Tenant]:
        """
        Cerca il tenant nel DB in base agli header della request.
        Restituisce None se non trovato o non attivo.
        """
        tenant_id_header = request.headers.get("X-Tenant-ID")
        tenant_slug_header = request.headers.get("X-Tenant-Slug")

        if not tenant_id_header and not tenant_slug_header:
            return None

        async with AsyncSessionLocal() as db:
            try:
                if tenant_id_header:
                    # Ricerca per UUID — più veloce (PK lookup)
                    import uuid as uuid_module
                    try:
                        tid = uuid_module.UUID(tenant_id_header)
                    except ValueError:
                        logger.warning(f"X-Tenant-ID non è un UUID valido: {tenant_id_header!r}")
                        return None

                    result = await db.execute(
                        select(Tenant).where(
                            Tenant.id == tid,
                            Tenant.is_active == True,
                        )
                    )
                else:
                    # Ricerca per slug — usa l'indice su slug
                    result = await db.execute(
                        select(Tenant).where(
                            Tenant.slug == tenant_slug_header,
                            Tenant.is_active == True,
                        )
                    )

                return result.scalar_one_or_none()

            except Exception as exc:
                logger.exception(f"Errore nella risoluzione del tenant: {exc}")
                return None

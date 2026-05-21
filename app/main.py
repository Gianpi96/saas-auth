"""
main.py  (Step 2: aggiornato)
──────────────────────────────
Aggiunto:
  - TenantMiddleware registrato PRIMA del logging middleware
  - Versione aggiornata a 0.2.0
"""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.config.database import engine, Base
from app.config.settings import get_settings
from app.middleware.tenant_middleware import TenantMiddleware
from app.models import tenant as tenant_models  # noqa: F401
from app.models import refresh_token as refresh_token_models  # noqa: F401
from app.models import permission as permission_models  # noqa: F401

settings = get_settings()

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Avvio applicazione (Step 2 — Tenant Isolation)...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("✅ Tabelle schema public verificate/create")
    yield
    logger.info("🛑 Spegnimento applicazione...")
    await engine.dispose()
    logger.info("✅ Connection pool chiuso")


app = FastAPI(
    title="SaaS Auth — Multi-Tenant Backend",
    description="""
## Step 2: Tenant Isolation completo

### Novità rispetto allo Step 1
- **Modello Tenant** arricchito: `subdomain`, `plan` (free/pro/enterprise), limiti derivati
- **TenantMiddleware**: risolve il tenant da `X-Tenant-ID` o `X-Tenant-Slug` e lo inietta in `request.state`
- **Dependency `get_current_tenant`**: usabile con `Depends()` in qualsiasi endpoint
- **`tenant_id`** aggiunto come colonna su `users`, `roles`, `policies` con indici composti `(tenant_id, id)`
- **`require_plan()`**: dependency factory per bloccare feature per piano

### Flusso tipico
1. `POST /api/v1/tenants/` — Crea tenant (ora con subdomain e plan)
2. `POST /api/v1/auth/register` (header: `X-Tenant-Slug`) — Registra utente
3. `POST /api/v1/auth/login` — Ottieni JWT
4. Tutti gli endpoint protetti leggono il tenant da `request.state` iniettato dal middleware
""",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Ordine middleware: IMPORTANTE ──────────────────────────────────────────────
# I middleware vengono applicati in ordine INVERSO di registrazione.
# L'ultimo aggiunto è il primo ad essere eseguito sulla request.
# Quindi: CORS → TenantMiddleware → endpoint
app.add_middleware(CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# TenantMiddleware: risolve il tenant e lo mette in request.state
# Deve girare DOPO CORS (che deve essere il primo a rispondere agli OPTIONS)
app.add_middleware(TenantMiddleware)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    tenant_info = getattr(request.state, "tenant_schema", "-")
    logger.info(
        f"{request.method} {request.url.path} "
        f"[tenant={tenant_info}] → {response.status_code} ({duration_ms:.1f}ms)"
    )
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    tb = traceback.format_exc()
    logger.exception(f"Eccezione non gestita su {request.url.path}:\n{tb}")
    detail = tb if settings.debug else "Errore interno del server"
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": detail},
    )


app.include_router(api_router)


@app.get("/health", tags=["Monitoring"])
async def health_check():
    return {"status": "healthy", "version": "0.2.0", "environment": settings.app_env}


@app.get("/", include_in_schema=False)
async def root():
    return {"message": "SaaS Auth API v0.2.0 — /docs per la documentazione"}

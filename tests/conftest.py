"""
tests/conftest.py
──────────────────
Fixture condivise per tutti i test di integrazione.

ARCHITETTURA DEI TEST:
  Usiamo un database PostgreSQL reale (non SQLite, non mock) perché:
    - Il codice usa funzionalità PostgreSQL-specifiche (UUID, schema separati,
      gen_random_uuid(), search_path)
    - SQLite non supporta schemi separati → test falsi
    - I mock non testano la query reale → bug nascosti

DATABASE DI TEST:
  Variabile d'ambiente TEST_DATABASE_URL (default: saas_auth_test).
  Il DB di test viene creato/distrutto per ogni sessione di test.

ISOLAMENTO:
  Ogni test_function ottiene un tenant con slug univoco (uuid random)
  → zero interferenza tra test paralleli o sequenziali.

FIXTURE HIERARCHY:
  event_loop (session)
      └── db_engine (session)
              └── setup_db (session) → crea schema public
                      └── tenant (function) → crea tenant isolato
                              └── registered_user (function)
                                      └── auth_tokens (function)
                                              └── authenticated_client (function)
"""
import asyncio
import os
import uuid
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from sqlalchemy import text

# Override PRIMA di importare l'app (le settings usano lru_cache)
TEST_DB_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:1234@localhost:5432/saas_auth_test",
)
os.environ["DATABASE_URL"] = TEST_DB_URL
os.environ["SYNC_DATABASE_URL"] = TEST_DB_URL.replace("+asyncpg", "+psycopg2")
os.environ["JWT_SECRET_KEY"] = "test-secret-key-non-usare-in-produzione-32bytes!!"
os.environ["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["JWT_REFRESH_TOKEN_EXPIRE_DAYS"] = "7"
os.environ["GROQ_API_KEY"] = "test-groq-key-not-used-in-integration-tests"
os.environ["DEBUG"] = "false"  # meno rumore nei log durante i test

# ── Patch database module con NullPool PRIMA che app.main venga importato ──────
#
# NullPool crea una nuova connessione per ogni operazione e la chiude subito.
# Questo evita il RuntimeError "Future attached to a different loop" di asyncpg,
# che si verifica quando il connection pool tenta di riusare connessioni create
# su un event loop diverso da quello corrente del test.
import app.config.database as _db_module  # noqa: E402

_test_engine = create_async_engine(TEST_DB_URL, poolclass=NullPool, echo=False)
_test_session_factory = async_sessionmaker(
    bind=_test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)
_db_module.engine = _test_engine
_db_module.AsyncSessionLocal = _test_session_factory

# Import DOPO aver settato le env vars e patchato il database module
from app.main import app  # noqa: E402
from app.config.database import Base  # noqa: E402


# ── Event Loop ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop():
    """
    Event loop condiviso per tutta la sessione di test.
    Necessario perché le fixture session-scoped devono girare sullo stesso loop.
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Engine e DB setup ─────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session")
async def db_engine():
    """
    Restituisce il NullPool engine già patchato sull'app.
    Session-scoped: un solo engine per tutta la suite di test.
    """
    yield _test_engine
    await _test_engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def setup_db(db_engine):
    """
    Crea le tabelle dello schema public all'inizio della sessione,
    le elimina alla fine.

    Questo fixture gira UNA SOLA VOLTA per tutta la suite.
    """
    # Import modelli per registrarli su Base.metadata
    from app.models import tenant as _  # noqa
    from app.models import refresh_token as __  # noqa
    from app.models import permission as ___  # noqa

    async with db_engine.begin() as conn:
        # DO block compatibile con tutte le versioni di PostgreSQL (< 12 non supporta
        # CREATE TYPE IF NOT EXISTS)
        await conn.execute(text(
            "DO $$ BEGIN "
            "IF NOT EXISTS ("
            "  SELECT 1 FROM pg_type t"
            "  JOIN pg_namespace n ON n.oid = t.typnamespace"
            "  WHERE t.typname = 'tenant_plan_enum' AND n.nspname = 'public'"
            ") THEN "
            "CREATE TYPE public.tenant_plan_enum AS ENUM ('free', 'pro', 'enterprise'); "
            "END IF; END $$"
        ))
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Teardown: pulisce tutto dopo la sessione
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ── Session DB (per-test) ─────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db_session(setup_db, db_engine) -> AsyncGenerator[AsyncSession, None]:
    """
    Sessione DB pulita per ogni test.
    NON usa transazioni rollback perché i test creano schemi PostgreSQL
    separati (DDL implicito COMMIT) → usiamo cleanup esplicito nel tenant fixture.
    """
    session_factory = async_sessionmaker(
        bind=db_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


# ── HTTP Client ───────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client(setup_db) -> AsyncGenerator[AsyncClient, None]:
    """
    Client HTTP che chiama l'app FastAPI direttamente in memoria (no rete).
    ASGITransport bypassa il network stack → test veloci e deterministici.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


# ── Tenant fixture ────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def tenant(client: AsyncClient) -> dict:
    """
    Crea un tenant reale nel DB di test con slug univoco.

    Ogni test ottiene un tenant isolato → nessuna interferenza.
    UUID nel slug garantisce unicità anche con test paralleli.

    Returns: dizionario con i dati del tenant (id, slug, db_schema, ...)
    """
    unique_suffix = uuid.uuid4().hex[:8]  # es: "a3f7b2c1"
    slug = f"test-tenant-{unique_suffix}"
    subdomain = f"test{unique_suffix}"

    response = await client.post("/api/v1/tenants/", json={
        "name": f"Test Tenant {unique_suffix}",
        "slug": slug,
        "subdomain": subdomain,
        "plan": "pro",
    })
    assert response.status_code == 201, f"Creazione tenant fallita: {response.text}"
    return response.json()


# ── User fixture ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def registered_user(client: AsyncClient, tenant: dict) -> dict:
    """
    Registra un utente nel tenant creato dalla fixture tenant.

    Returns: dizionario con i dati dell'utente + credenziali + tenant info.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    email = f"testuser-{unique_suffix}@example.com"
    password = "TestPass123!"

    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Test User",
            "role_id": None,
        },
        headers={"X-Tenant-Slug": tenant["slug"]},
    )
    assert response.status_code == 201, f"Registrazione fallita: {response.text}"

    return {
        **response.json(),
        "password": password,           # salviamo per il login
        "email": email,
        "tenant_slug": tenant["slug"],
        "tenant_id": tenant["id"],
        "tenant_schema": tenant["db_schema"],
    }


# ── Auth tokens fixture ───────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def auth_tokens(client: AsyncClient, registered_user: dict) -> dict:
    """
    Esegue il login e restituisce access_token + refresh_token.

    Returns: {
        "access_token": "...",
        "refresh_token": "...",
        "user": {...},
        "tenant_slug": "...",
    }
    """
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        },
        headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
    )
    assert response.status_code == 200, f"Login fallito: {response.text}"

    data = response.json()
    return {
        **data,
        "tenant_slug": registered_user["tenant_slug"],
        "tenant_id": registered_user["tenant_id"],
        "email": registered_user["email"],
        "password": registered_user["password"],
    }


# ── Authenticated client fixture ──────────────────────────────────────────────

@pytest_asyncio.fixture
async def authenticated_client(client: AsyncClient, auth_tokens: dict):
    """
    Client HTTP con header Authorization già impostato.

    Uso negli endpoint protetti:
        response = await authenticated_client.get("/api/v1/auth/me")
        # → 200, nessun bisogno di passare il token manualmente

    Returns: (client, auth_tokens) — il client con Bearer token + i token grezzi
    """
    client.headers.update({
        "Authorization": f"Bearer {auth_tokens['access_token']}",
        "X-Tenant-Slug": auth_tokens["tenant_slug"],
    })
    return client, auth_tokens


# ── Admin user fixture ────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def admin_user(client: AsyncClient, tenant: dict, db_session: AsyncSession) -> dict:
    """
    Crea un utente e gli assegna il ruolo admin tramite SQL diretto.
    Usato per testare endpoint che richiedono admin:roles o require_role("admin").
    """
    from sqlalchemy import text

    unique_suffix = uuid.uuid4().hex[:8]
    email = f"admin-{unique_suffix}@example.com"
    password = "AdminPass123!"

    # Registra utente
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": "Admin User", "role_id": None},
        headers={"X-Tenant-Slug": tenant["slug"]},
    )
    assert response.status_code == 201

    schema = tenant["db_schema"]
    tid = tenant["id"]

    # Trova UUID ruolo admin
    result = await db_session.execute(
        text(f'SELECT id FROM "{schema}".roles WHERE name = \'admin\' AND tenant_id = :tid'),
        {"tid": tid},
    )
    admin_role_id = result.scalar_one()

    # Assegna ruolo admin
    await db_session.execute(
        text(f'UPDATE "{schema}".users SET role_id = :rid WHERE email = :email'),
        {"rid": str(admin_role_id), "email": email},
    )
    await db_session.commit()

    # Login per ottenere token con ruolo admin
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers={"X-Tenant-Slug": tenant["slug"]},
    )
    assert login_resp.status_code == 200
    data = login_resp.json()

    return {
        **data,
        "email": email,
        "password": password,
        "tenant_slug": tenant["slug"],
        "tenant_id": tid,
        "tenant_schema": schema,
    }

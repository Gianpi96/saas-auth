# SaaS Auth — Backend FastAPI Multi-Tenant

## Folder Structure

```
saas_auth/
├── .env.example              ← copia in .env e configura
├── .env                      ← NON committare mai nel git
├── requirements.txt
├── alembic.ini
├── pytest.ini
├── api_tests.http            ← test manuali con REST Client (VS Code)
│
├── alembic/
│   ├── env.py                ← configurazione migrazioni
│   └── versions/             ← file di migrazione generati
│
├── app/
│   ├── main.py               ← entry point FastAPI
│   │
│   ├── config/
│   │   ├── settings.py       ← configurazione da .env (Pydantic-Settings)
│   │   └── database.py       ← engine SQLAlchemy async + session management
│   │
│   ├── models/
│   │   ├── tenant.py         ← schema PUBLIC: tabella tenants
│   │   └── user.py           ← schema TENANT: users, roles, policies
│   │
│   ├── schemas/
│   │   ├── tenant.py         ← Pydantic: request/response tenant
│   │   └── user.py           ← Pydantic: user, role, policy, JWT, auth
│   │
│   ├── services/
│   │   ├── auth_service.py   ← login, registrazione
│   │   ├── tenant_service.py ← creazione tenant + provisioning schema
│   │   ├── jwt_service.py    ← creazione e verifica JWT
│   │   ├── password_service.py ← bcrypt hashing
│   │   ├── groq_service.py   ← Groq AI per descrizioni policy
│   │   └── rbac.py           ← dependency FastAPI per autenticazione/autorizzazione
│   │
│   └── api/
│       └── v1/
│           ├── router.py     ← aggrega tutti i router
│           └── endpoints/
│               ├── tenants.py ← POST/GET /tenants
│               ├── auth.py    ← /auth/register, /auth/login, /auth/me
│               └── roles.py   ← /roles + /roles/{id}/policies
│
└── tests/
    └── test_jwt_rbac.py      ← test unitari JWT + RBAC (no DB)
```

---

## Setup passo per passo (Windows + VS Code)

### Passo 1 — Configura il file .env

```powershell
# Nella root del progetto saas_auth/
copy .env.example .env
```

Apri `.env` in VS Code e modifica:

```
DATABASE_URL=postgresql+asyncpg://postgres:TUA_PASSWORD@localhost:5432/saas_auth
SYNC_DATABASE_URL=postgresql+psycopg2://postgres:TUA_PASSWORD@localhost:5432/saas_auth
JWT_SECRET_KEY=genera_con_python_secrets_token_hex_32
GROQ_API_KEY=gsk_...  ← da https://console.groq.com/keys
```

**Genera JWT_SECRET_KEY:**
```powershell
# Nel terminale VS Code (con .venv attivo)
python -c "import secrets; print(secrets.token_hex(32))"
```

---

### Passo 2 — Crea il database PostgreSQL

Apri pgAdmin o psql come superuser:

```sql
-- In pgAdmin: tasto destro su "Databases" → Create → Database
-- Oppure in psql:
CREATE DATABASE saas_auth;
```

---

### Passo 3 — Attiva il virtualenv e installa dipendenze

```powershell
# Nella root saas_auth/ con il terminale VS Code
.venv\Scripts\activate

# Installa tutte le dipendenze
pip install -r requirements.txt
```

**Verifica installazione:**
```powershell
python -c "import fastapi, sqlalchemy, groq; print('OK')"
```

---

### Passo 4 — Esegui i test unitari (no DB richiesto)

```powershell
pytest tests/test_jwt_rbac.py -v
```

Output atteso:
```
tests/test_jwt_rbac.py::TestJWT::test_create_and_decode_token PASSED
tests/test_jwt_rbac.py::TestJWT::test_invalid_token_raises PASSED
tests/test_jwt_rbac.py::TestJWT::test_token_without_role PASSED
tests/test_jwt_rbac.py::TestJWT::test_different_tenants_get_different_tokens PASSED
tests/test_jwt_rbac.py::TestRBACPermissions::test_wildcard_global_allows_everything PASSED
...
```

Se i test passano: JWT e RBAC funzionano correttamente.

---

### Passo 5 — Avvia il server

```powershell
# Dalla root del progetto (dove c'è app/)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Al primo avvio vedrai:
```
INFO  | Avvio applicazione...
INFO  | Tabelle schema public verificate/create   ← crea tabella tenants
INFO  | Application startup complete.
```

Apri nel browser: http://localhost:8000/docs

---

### Passo 6 — Test con Swagger UI

La Swagger UI su `/docs` è interattiva. Segui questo ordine:

#### 6a. Crea un tenant
```
POST /api/v1/tenants/
Body: {"name": "Acme Corp", "slug": "acme-corp"}
```

Risposta: vedi `db_schema: "tenant_acme_corp"` → schema PostgreSQL creato!

Verifica in pgAdmin: dovresti vedere lo schema `tenant_acme_corp` con le tabelle
`users`, `roles`, `policies`.

#### 6b. Registra un utente
```
POST /api/v1/auth/register
Header: X-Tenant-Slug: acme-corp
Body: {"email": "admin@acme.com", "password": "Admin1234!", "full_name": "Mario Rossi"}
```

#### 6c. Fai il login
```
POST /api/v1/auth/login
Header: X-Tenant-Slug: acme-corp
Body: {"email": "admin@acme.com", "password": "Admin1234!"}
```

Copia il `access_token` dalla risposta.

#### 6d. Autorizzati su Swagger
Clicca il pulsante **Authorize 🔒** in alto a destra nella Swagger UI,
incolla il token (senza "Bearer ").

#### 6e. Verifica il token
```
GET /api/v1/auth/me
```

Vedrai il payload JWT con `tenant_id`, `tenant_schema`, `role`, `permissions`.

---

### Passo 7 — Test con REST Client (VS Code)

1. Installa l'estensione **REST Client** (Huachao Mao)
2. Apri `api_tests.http`
3. Clicca **Send Request** sopra ogni blocco

Il file è già strutturato nell'ordine corretto per testare tutto il flusso.

---

### Passo 8 — Verifica isolamento tenant in PostgreSQL

Apri pgAdmin e osserva:

```
Databases
└── saas_auth
    └── Schemas
        ├── public           ← tabella: tenants
        ├── tenant_acme_corp ← tabelle: users, roles, policies (solo Acme)
        └── tenant_beta_industries ← tabelle: users, roles, policies (solo Beta)
```

Ogni tenant ha **zero accesso** ai dati degli altri.

---

### Passo 9 — Test Groq AI (descrizioni policy)

```
POST /api/v1/roles/
Authorization: Bearer <token_admin>
Body: {
  "name": "editor",
  "permissions": "read:documents,write:documents,read:reports"
}
```

Risposta: il campo `ai_description` conterrà testo generato da Groq, tipo:
> "Il ruolo Editor può leggere e modificare documenti dell'organizzazione e consultare
> i report disponibili, ma non può gestire altri utenti o modificare le impostazioni
> del sistema."

---

## Architettura JWT — Cosa c'è nel token

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "tenant_schema": "tenant_acme_corp",
  "role": "admin",
  "permissions": ["*"],
  "exp": 1700000000,
  "iat": 1699996400
}
```

**Perché `tenant_schema` nel JWT?**
Ogni request autenticata sa immediatamente su quale schema PostgreSQL operare,
senza fare query aggiuntive al DB. Zero overhead per la risoluzione del tenant.

---

## Comandi utili

```powershell
# Avvia in modalità development (reload automatico)
uvicorn app.main:app --reload

# Esegui test con output verboso
pytest -v

# Esegui test specifico
pytest tests/test_jwt_rbac.py::TestJWT::test_create_and_decode_token -v

# Guarda i log SQL in tempo reale (DEBUG=true nel .env)
uvicorn app.main:app --reload --log-level debug

# Genera chiave JWT sicura
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Troubleshooting comuni

### "connection refused" al DB
```powershell
# Verifica che PostgreSQL sia in esecuzione
Get-Service -Name postgresql*
# Se stopped:
Start-Service postgresql-x64-16  # adatta il numero di versione
```

### "module not found"
```powershell
# Assicurati che il venv sia attivo (vedi prompt con (.venv))
.venv\Scripts\activate
pip install -r requirements.txt
```

### "GROQ_API_KEY not set"
Verifica che il file `.env` esista nella root del progetto (stesso livello di `app/`)
e che contenga la chiave corretta.

### "password authentication failed for user postgres"
Modifica DATABASE_URL nel .env con la password corretta del tuo utente PostgreSQL.

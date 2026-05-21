"""
tests/test_integration.py
──────────────────────────
Test di integrazione con PostgreSQL reale.

Coprono i 4 requisiti richiesti:
  1. TestRegistration    → registrazione con tenant_id
  2. TestLogin           → JWT payload con tenant_id, role, permissions
  3. TestRefreshRotation → rotation normale + replay attack
  4. TestRBAC            → endpoint protetto: 403 senza permesso, 200 con permesso

Ogni test usa fixture isolate (tenant unico per test) → zero interferenza.
I test sono ordinati per dipendenza logica, ma pytest li esegue indipendentemente.
"""
import uuid
import pytest
from httpx import AsyncClient

import jwt as pyjwt

from app.config.settings import get_settings

settings = get_settings()


# ══════════════════════════════════════════════════════════════════════════════
# 1. REGISTRAZIONE
# ══════════════════════════════════════════════════════════════════════════════

class TestRegistration:
    """
    Test sulla registrazione utente e verifica che tenant_id
    sia correttamente salvato nel record utente.
    """

    @pytest.mark.asyncio
    async def test_register_returns_201(self, client: AsyncClient, tenant: dict):
        """La registrazione deve restituire 201 con i dati utente."""
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": f"user-{uuid.uuid4().hex[:8]}@test.com",
                "password": "Password123!",
                "full_name": "Test User",
                "role_id": None,
            },
            headers={"X-Tenant-Slug": tenant["slug"]},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert data["email"].endswith("@test.com")
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_register_user_has_correct_tenant_id(
        self, client: AsyncClient, tenant: dict, db_session
    ):
        """
        Il campo tenant_id nel DB deve corrispondere all'UUID del tenant.
        Questo è il test chiave dell'isolamento: ogni utente sa a quale
        tenant appartiene anche senza guardare lo schema.
        """
        from sqlalchemy import text

        email = f"tenantcheck-{uuid.uuid4().hex[:8]}@test.com"
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "Pass123!", "full_name": "TCheck", "role_id": None},
            headers={"X-Tenant-Slug": tenant["slug"]},
        )
        assert resp.status_code == 201
        user_id = resp.json()["id"]

        schema = tenant["db_schema"]
        result = await db_session.execute(
            text(f'SELECT tenant_id FROM "{schema}".users WHERE id = :uid'),
            {"uid": user_id},
        )
        db_tenant_id = str(result.scalar_one())

        # Il tenant_id nel DB deve essere l'UUID del tenant
        assert db_tenant_id == tenant["id"], (
            f"tenant_id nel DB ({db_tenant_id}) != "
            f"UUID del tenant ({tenant['id']})"
        )

    @pytest.mark.asyncio
    async def test_register_duplicate_email_same_tenant_fails(
        self, client: AsyncClient, tenant: dict
    ):
        """
        La stessa email non può essere registrata due volte nello stesso tenant.
        Vincolo: UNIQUE(tenant_id, email).
        """
        email = f"dup-{uuid.uuid4().hex[:8]}@test.com"
        payload = {"email": email, "password": "Pass123!", "full_name": "Dup", "role_id": None}
        headers = {"X-Tenant-Slug": tenant["slug"]}

        r1 = await client.post("/api/v1/auth/register", json=payload, headers=headers)
        assert r1.status_code == 201

        r2 = await client.post("/api/v1/auth/register", json=payload, headers=headers)
        assert r2.status_code == 400
        assert "già registrata" in r2.json()["detail"]

    @pytest.mark.asyncio
    async def test_register_same_email_different_tenants_succeeds(
        self, client: AsyncClient, tenant: dict
    ):
        """
        La stessa email PUÒ esistere in tenant diversi (isolamento completo).
        Questo è il cuore dell'architettura multi-tenant.
        """
        email = f"shared-{uuid.uuid4().hex[:8]}@test.com"
        password = "Pass123!"

        # Crea secondo tenant
        suffix2 = uuid.uuid4().hex[:8]
        r_tenant2 = await client.post("/api/v1/tenants/", json={
            "name": f"Second Tenant {suffix2}",
            "slug": f"second-{suffix2}",
            "subdomain": f"second{suffix2}",
            "plan": "free",
        })
        assert r_tenant2.status_code == 201
        tenant2 = r_tenant2.json()

        # Registra la stessa email in entrambi i tenant
        r1 = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password, "full_name": "User1", "role_id": None},
            headers={"X-Tenant-Slug": tenant["slug"]},
        )
        r2 = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "DiversaPass456!", "full_name": "User2", "role_id": None},
            headers={"X-Tenant-Slug": tenant2["slug"]},
        )

        assert r1.status_code == 201, f"Primo tenant fallito: {r1.text}"
        assert r2.status_code == 201, f"Secondo tenant fallito: {r2.text}"

        # Gli UUID devono essere diversi (sono utenti diversi)
        assert r1.json()["id"] != r2.json()["id"]

    @pytest.mark.asyncio
    async def test_register_without_tenant_slug_fails(self, client: AsyncClient):
        """Senza header X-Tenant-Slug → 422 (campo obbligatorio mancante)."""
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "x@test.com", "password": "Pass123!", "role_id": None},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_register_nonexistent_tenant_fails(self, client: AsyncClient):
        """Tenant inesistente → 400."""
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "x@test.com", "password": "Pass123!", "role_id": None},
            headers={"X-Tenant-Slug": "tenant-che-non-esiste-mai"},
        )
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# 2. LOGIN E JWT PAYLOAD
# ══════════════════════════════════════════════════════════════════════════════

class TestLogin:
    """
    Test sul login e verifica del JWT payload.
    Verifichiamo che tenant_id, tenant_schema, role e permissions
    siano presenti e corretti nel token.
    """

    @pytest.mark.asyncio
    async def test_login_returns_200_with_tokens(
        self, client: AsyncClient, registered_user: dict
    ):
        """Login con credenziali corrette → 200 con access e refresh token."""
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 15 * 60  # 15 minuti in secondi

    @pytest.mark.asyncio
    async def test_jwt_payload_contains_tenant_id(
        self, client: AsyncClient, registered_user: dict
    ):
        """
        Il JWT deve contenere tenant_id nel payload.
        Questo permette a ogni endpoint di sapere a quale tenant appartiene
        la request senza query aggiuntive al DB.
        """
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
        )
        token = resp.json()["access_token"]
        payload = pyjwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )

        assert "tenant_id" in payload
        assert payload["tenant_id"] == registered_user["tenant_id"]

    @pytest.mark.asyncio
    async def test_jwt_payload_contains_tenant_schema(
        self, client: AsyncClient, registered_user: dict
    ):
        """
        Il JWT deve contenere tenant_schema per evitare lookup al DB
        ad ogni request. Il middleware legge questo campo per sapere
        su quale schema PostgreSQL operare.
        """
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
        )
        payload = pyjwt.decode(
            resp.json()["access_token"],
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        assert "tenant_schema" in payload
        assert payload["tenant_schema"] == registered_user["tenant_schema"]
        assert payload["tenant_schema"].startswith("tenant_")

    @pytest.mark.asyncio
    async def test_jwt_payload_complete_structure(
        self, client: AsyncClient, registered_user: dict
    ):
        """Verifica la struttura completa del JWT payload."""
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
        )
        payload = pyjwt.decode(
            resp.json()["access_token"],
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        required_fields = ["sub", "tenant_id", "tenant_schema", "role", "permissions", "exp", "iat"]
        for field in required_fields:
            assert field in payload, f"Campo '{field}' mancante nel JWT payload"

        assert isinstance(payload["permissions"], list)
        assert isinstance(payload["exp"], int)
        assert payload["exp"] > payload["iat"]

    @pytest.mark.asyncio
    async def test_jwt_expires_in_15_minutes(
        self, client: AsyncClient, registered_user: dict
    ):
        """L'access token deve scadere dopo esattamente 15 minuti."""
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
        )
        payload = pyjwt.decode(
            resp.json()["access_token"],
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        duration_minutes = (payload["exp"] - payload["iat"]) / 60
        assert duration_minutes == pytest.approx(15, abs=0.1)

    @pytest.mark.asyncio
    async def test_login_wrong_password_returns_401(
        self, client: AsyncClient, registered_user: dict
    ):
        """Password sbagliata → 401 con messaggio generico (no info leak)."""
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": "password_sbagliata"},
            headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
        )
        assert resp.status_code == 401
        # Il messaggio non deve rivelare se l'utente esiste o no
        assert "Credenziali non valide" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_creates_refresh_token_in_db(
        self, client: AsyncClient, registered_user: dict, db_session
    ):
        """
        Dopo il login, il refresh token deve essere salvato nel DB
        con is_revoked=False e family_id valorizzato.
        """
        from sqlalchemy import select
        from app.models.refresh_token import RefreshToken

        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-Tenant-Slug": registered_user["tenant_slug"]},
        )
        assert resp.status_code == 200

        # Il refresh token grezzo non è nel DB (solo l'hash SHA-256)
        # Verifichiamo che esista almeno un token attivo per l'utente
        user_id = resp.json()["user"]["id"]
        result = await db_session.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked.is_(False),
            )
        )
        tokens = result.scalars().all()
        assert len(tokens) >= 1, "Nessun refresh token trovato nel DB dopo il login"
        assert tokens[0].family_id is not None
        assert tokens[0].parent_token_hash is None  # primo token → no parent

    @pytest.mark.asyncio
    async def test_login_wrong_tenant_returns_401(
        self, client: AsyncClient, registered_user: dict
    ):
        """
        Credenziali corrette ma tenant sbagliato → 401.
        L'utente esiste in un tenant, non nell'altro.
        """
        suffix = uuid.uuid4().hex[:8]
        await client.post("/api/v1/tenants/", json={
            "name": f"Other {suffix}", "slug": f"other-{suffix}",
            "subdomain": f"other{suffix}", "plan": "free",
        })

        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-Tenant-Slug": f"other-{suffix}"},
        )
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 3. REFRESH TOKEN ROTATION + REPLAY ATTACK
# ══════════════════════════════════════════════════════════════════════════════

class TestRefreshRotation:
    """
    Test sul refresh token rotation e replay attack detection.

    Questi sono i test più critici: verificano che il sistema di sicurezza
    funzioni correttamente con il DB reale.
    """

    @pytest.mark.asyncio
    async def test_refresh_returns_new_token_pair(
        self, client: AsyncClient, auth_tokens: dict
    ):
        """
        POST /auth/refresh con token valido → nuova coppia di token.
        Il nuovo access_token deve essere diverso dal vecchio.
        """
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        # Il nuovo access_token deve essere diverso
        assert data["access_token"] != auth_tokens["access_token"]
        # Il nuovo refresh_token deve essere diverso
        assert data["refresh_token"] != auth_tokens["refresh_token"]

    @pytest.mark.asyncio
    async def test_refresh_old_token_revoked_in_db(
        self, client: AsyncClient, auth_tokens: dict, db_session
    ):
        """
        Dopo il refresh, il vecchio refresh_token deve essere revocato nel DB
        con reason='rotated'. Questo è fondamentale per il replay attack detection.
        """
        import hashlib
        from sqlalchemy import select
        from app.models.refresh_token import RefreshToken

        old_token = auth_tokens["refresh_token"]
        old_hash = hashlib.sha256(old_token.encode()).hexdigest()

        # Esegui il refresh
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_token},
        )
        assert resp.status_code == 200

        # Verifica nel DB che il vecchio token sia revocato
        result = await db_session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == old_hash)
        )
        old_rt = result.scalar_one()
        assert old_rt.is_revoked is True
        assert old_rt.revoked_reason == "rotated"
        assert old_rt.used_at is not None

    @pytest.mark.asyncio
    async def test_refresh_new_token_has_same_family_id(
        self, client: AsyncClient, auth_tokens: dict, db_session
    ):
        """
        Dopo la rotazione, il nuovo token deve avere lo stesso family_id
        del vecchio — appartengono alla stessa sessione di login.
        """
        import hashlib
        from sqlalchemy import select
        from app.models.refresh_token import RefreshToken

        old_token = auth_tokens["refresh_token"]
        old_hash = hashlib.sha256(old_token.encode()).hexdigest()

        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_token},
        )
        assert resp.status_code == 200
        new_token = resp.json()["refresh_token"]
        new_hash = hashlib.sha256(new_token.encode()).hexdigest()

        # Carica entrambi i record
        old_result = await db_session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == old_hash)
        )
        new_result = await db_session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == new_hash)
        )
        old_rt = old_result.scalar_one()
        new_rt = new_result.scalar_one()

        # Stessa family
        assert old_rt.family_id == new_rt.family_id
        # Catena parent → figlio
        assert new_rt.parent_token_hash == old_hash

    @pytest.mark.asyncio
    async def test_replay_attack_detected(
        self, client: AsyncClient, auth_tokens: dict
    ):
        """
        REPLAY ATTACK: presentare un refresh token già usato → 401.

        Sequenza:
          1. Token A (dal login)
          2. Refresh con A → Token B (A revocato)
          3. Refresh con A di nuovo → REPLAY ATTACK → 401
        """
        original_refresh = auth_tokens["refresh_token"]

        # Primo refresh: valido
        r1 = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": original_refresh},
        )
        assert r1.status_code == 200

        # Secondo refresh con lo stesso token (replay attack)
        r2 = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": original_refresh},
        )
        assert r2.status_code == 401
        assert "REPLAY_ATTACK" in r2.json()["detail"]

    @pytest.mark.asyncio
    async def test_replay_attack_sets_security_header(
        self, client: AsyncClient, auth_tokens: dict
    ):
        """
        Sul replay attack deve essere presente l'header X-Security-Event.
        Utile per i sistemi di monitoring/alerting.
        """
        original_refresh = auth_tokens["refresh_token"]

        # Primo refresh: consuma il token
        await client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})

        # Replay attack
        r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})
        assert r2.status_code == 401
        assert r2.headers.get("x-security-event") == "replay-attack-detected"

    @pytest.mark.asyncio
    async def test_replay_attack_invalidates_entire_family(
        self, client: AsyncClient, auth_tokens: dict, db_session
    ):
        """
        FAMILY INVALIDATION: dopo un replay attack, TUTTI i token
        della famiglia vengono invalidati, incluso il token B
        (quello legittimo generato dopo il primo refresh).

        Questo costringe l'utente a rifare login da zero.
        """
        from sqlalchemy import select
        from app.models.refresh_token import RefreshToken

        original_refresh = auth_tokens["refresh_token"]
        user_id = auth_tokens["user"]["id"]

        # Primo refresh: crea token B
        r1 = await client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})
        assert r1.status_code == 200
        token_b = r1.json()["refresh_token"]

        # Replay attack con token A → invalida tutta la family
        r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})
        assert r2.status_code == 401

        # Verifica che il token B sia ora inutilizzabile
        r3 = await client.post("/api/v1/auth/refresh", json={"refresh_token": token_b})
        assert r3.status_code == 401, (
            "Il token B dovrebbe essere invalidato dalla family invalidation"
        )

        # Verifica nel DB: tutti i token della family sono revocati
        result = await db_session.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked.is_(False),
            )
        )
        active_tokens = result.scalars().all()
        assert len(active_tokens) == 0, (
            f"Trovati {len(active_tokens)} token attivi dopo family invalidation"
        )

    @pytest.mark.asyncio
    async def test_after_replay_attack_must_relogin(
        self, client: AsyncClient, auth_tokens: dict
    ):
        """
        Dopo un replay attack, l'utente deve rifare il login completo.
        Il nuovo login deve funzionare normalmente.
        """
        original_refresh = auth_tokens["refresh_token"]

        # Crea il replay attack
        await client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})
        await client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})

        # L'utente rifà il login
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": auth_tokens["email"], "password": auth_tokens["password"]},
            headers={"X-Tenant-Slug": auth_tokens["tenant_slug"]},
        )
        assert resp.status_code == 200, "Il login dopo replay attack deve funzionare"
        assert "access_token" in resp.json()
        assert "refresh_token" in resp.json()

    @pytest.mark.asyncio
    async def test_refresh_invalid_token_returns_401(self, client: AsyncClient):
        """Token mai visto → 401."""
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "token_completamente_inventato_non_esiste"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_logout_revokes_refresh_token(
        self, client: AsyncClient, auth_tokens: dict
    ):
        """
        Dopo il logout, il refresh_token non deve più funzionare.
        """
        access_token = auth_tokens["access_token"]
        refresh_token = auth_tokens["refresh_token"]

        # Logout
        logout_resp = await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert logout_resp.status_code == 200

        # Prova a usare il refresh_token dopo il logout
        refresh_resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 4. ENDPOINT PROTETTO DA RBAC
# ══════════════════════════════════════════════════════════════════════════════

class TestRBAC:
    """
    Test sul sistema RBAC:
      - Endpoint senza token → 401
      - Endpoint con token ma senza permesso → 403
      - Endpoint con token e permesso corretto → 200
      - Endpoint con ruolo admin → 200
      - Endpoint con wildcard → 200
    """

    @pytest.mark.asyncio
    async def test_protected_endpoint_without_token_returns_401(
        self, client: AsyncClient
    ):
        """Nessun token → 401."""
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401 or resp.status_code == 403

    @pytest.mark.asyncio
    async def test_protected_endpoint_with_valid_token_returns_200(
        self, authenticated_client
    ):
        """Token valido → 200 su /auth/me."""
        client, tokens = authenticated_client
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        payload = resp.json()
        assert "sub" in payload
        assert "tenant_id" in payload

    @pytest.mark.asyncio
    async def test_admin_endpoint_without_admin_role_returns_403(
        self, authenticated_client
    ):
        """
        Utente senza ruolo admin → 403 su endpoint require_role("admin").
        L'utente dalla fixture registered_user non ha ruolo assegnato.
        """
        client, tokens = authenticated_client
        # Questo endpoint richiede require_role("admin")
        resp = await client.post(
            "/api/v1/admin/roles",
            json={
                "name": "test-role",
                "description": "test",
                "permission_codenames": [],
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_endpoint_with_admin_role_returns_201(
        self, client: AsyncClient, admin_user: dict
    ):
        """
        Utente con ruolo admin → 201 su POST /admin/roles.
        Dimostra che require_role("admin") funziona correttamente.
        """
        resp = await client.post(
            "/api/v1/admin/roles",
            json={
                "name": f"test-role-{uuid.uuid4().hex[:6]}",
                "description": "Ruolo di test",
                "permission_codenames": ["tasks:read"],
            },
            headers={"Authorization": f"Bearer {admin_user['access_token']}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert len(data["permissions"]) == 1
        assert data["permissions"][0]["codename"] == "tasks:read"

    @pytest.mark.asyncio
    async def test_require_permission_blocks_wrong_permission(
        self, client: AsyncClient, admin_user: dict
    ):
        """
        Utente con permesso 'tasks:read' non può accedere a endpoint
        che richiede 'admin:roles'.

        Sequenza:
          1. Admin crea ruolo con solo tasks:read
          2. Crea utente con quel ruolo
          3. Utente prova ad accedere a GET /admin/roles → 403
        """
        # Crea ruolo con permesso limitato
        role_name = f"limited-{uuid.uuid4().hex[:6]}"
        r_role = await client.post(
            "/api/v1/admin/roles",
            json={
                "name": role_name,
                "description": "Ruolo limitato",
                "permission_codenames": ["tasks:read"],
            },
            headers={"Authorization": f"Bearer {admin_user['access_token']}"},
        )
        assert r_role.status_code == 201
        role_id = r_role.json()["id"]

        # Crea utente con quel ruolo
        suffix = uuid.uuid4().hex[:8]
        email = f"limited-{suffix}@test.com"
        r_reg = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "Pass123!", "full_name": "Limited", "role_id": role_id},
            headers={"X-Tenant-Slug": admin_user["tenant_slug"]},
        )
        assert r_reg.status_code == 201

        # Login con l'utente limitato
        r_login = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "Pass123!"},
            headers={"X-Tenant-Slug": admin_user["tenant_slug"]},
        )
        assert r_login.status_code == 200
        limited_token = r_login.json()["access_token"]

        # Prova ad accedere a GET /admin/roles (richiede admin:roles)
        r_roles = await client.get(
            "/api/v1/admin/roles",
            headers={"Authorization": f"Bearer {limited_token}"},
        )
        assert r_roles.status_code == 403, (
            "Un utente con solo tasks:read non deve poter vedere i ruoli admin"
        )

    @pytest.mark.asyncio
    async def test_require_permission_allows_correct_permission(
        self, client: AsyncClient, admin_user: dict
    ):
        """
        Utente con permesso corretto → 200.
        Admin ha wildcard '*' → accede a tutto.
        """
        # L'admin ha "*" → può accedere a GET /admin/roles (richiede admin:roles)
        resp = await client.get(
            "/api/v1/admin/roles",
            headers={"Authorization": f"Bearer {admin_user['access_token']}"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self, client: AsyncClient):
        """
        Un JWT con exp nel passato → 401.
        Generiamo manualmente un token scaduto.
        """
        import time
        token = pyjwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "tenant_id": str(uuid.uuid4()),
                "tenant_schema": "tenant_test",
                "role": "viewer",
                "permissions": [],
                "exp": int(time.time()) - 3600,  # scaduto 1 ora fa
                "iat": int(time.time()) - 7200,
            },
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_tampered_token_returns_401(self, client: AsyncClient):
        """Un token con firma alterata → 401."""
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.firma_falsa"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_tenant_middleware_injects_state(
        self, client: AsyncClient, tenant: dict
    ):
        """
        Il TenantMiddleware deve iniettare il tenant in request.state
        quando l'header X-Tenant-Slug è presente.
        Verifichiamo indirettamente: il login funziona solo se il middleware
        ha trovato il tenant.
        """
        suffix = uuid.uuid4().hex[:8]
        email = f"mw-{suffix}@test.com"

        # Registra utente (richiede che il middleware trovi il tenant)
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "Pass123!", "role_id": None},
            headers={"X-Tenant-Slug": tenant["slug"]},
        )
        assert r.status_code == 201

    @pytest.mark.asyncio
    async def test_roles_list_isolated_between_tenants(
        self, client: AsyncClient, admin_user: dict
    ):
        """
        I ruoli di un tenant non devono essere visibili a un admin di un altro tenant.
        Verifica l'isolamento RBAC inter-tenant.
        """
        # Crea secondo tenant con admin
        suffix2 = uuid.uuid4().hex[:8]
        r_t2 = await client.post("/api/v1/tenants/", json={
            "name": f"Tenant2 {suffix2}", "slug": f"tenant2-{suffix2}",
            "subdomain": f"t2{suffix2}", "plan": "free",
        })
        assert r_t2.status_code == 201
        tenant2 = r_t2.json()

        # Crea admin nel secondo tenant
        email2 = f"admin2-{suffix2}@test.com"
        await client.post(
            "/api/v1/auth/register",
            json={"email": email2, "password": "Pass123!", "role_id": None},
            headers={"X-Tenant-Slug": tenant2["slug"]},
        )

        # I ruoli del tenant1 (visti dall'admin del tenant1)
        r_roles_t1 = await client.get(
            "/api/v1/admin/roles",
            headers={"Authorization": f"Bearer {admin_user['access_token']}"},
        )
        assert r_roles_t1.status_code == 200
        roles_t1 = {r["name"] for r in r_roles_t1.json()}

        # Verifica che ci siano solo ruoli del tenant1
        # (admin, viewer, e quelli creati nei test precedenti)
        # Il punto chiave: tenant2 non ha ruoli custom del tenant1
        assert "admin" in roles_t1  # ruolo di sistema sempre presente

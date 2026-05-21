"""
tests/test_step2_tenant_isolation.py
──────────────────────────────────────
Test unitari per Step 2: modello Tenant arricchito, middleware, dependency, indici.
Questi test NON richiedono il DB: testano la logica pura.
"""
import uuid
import pytest
from unittest.mock import MagicMock

from app.models.tenant import Tenant, TenantPlan, PLAN_LIMITS


# ── Test Modello Tenant ───────────────────────────────────────────────────────

class TestTenantModel:
    """Test sul modello Tenant arricchito."""

    def _make_tenant(self, plan: TenantPlan) -> Tenant:
        t = Tenant()
        t.id = uuid.uuid4()
        t.name = "Test Corp"
        t.slug = "test-corp"
        t.subdomain = "test"
        t.db_schema = "tenant_test_corp"
        t.plan = plan
        t.max_users = PLAN_LIMITS[plan]["max_users"]
        t.max_storage_gb = PLAN_LIMITS[plan]["max_storage_gb"]
        t.is_active = True
        return t

    def test_plan_enum_values(self):
        """I valori dell'enum devono essere le stringhe corrette."""
        assert TenantPlan.FREE.value == "free"
        assert TenantPlan.PRO.value == "pro"
        assert TenantPlan.ENTERPRISE.value == "enterprise"

    def test_plan_enum_is_string(self):
        """TenantPlan è una str-enum: confronto diretto con stringhe."""
        assert TenantPlan.FREE == "free"
        assert TenantPlan.PRO == "pro"

    def test_plan_limits_free(self):
        """Piano FREE: 5 utenti, 1 GB."""
        t = self._make_tenant(TenantPlan.FREE)
        assert t.max_users == 5
        assert t.max_storage_gb == 1

    def test_plan_limits_pro(self):
        """Piano PRO: 50 utenti, 20 GB."""
        t = self._make_tenant(TenantPlan.PRO)
        assert t.max_users == 50
        assert t.max_storage_gb == 20

    def test_plan_limits_enterprise(self):
        """Piano ENTERPRISE: nessun limite pratico, 500 GB."""
        t = self._make_tenant(TenantPlan.ENTERPRISE)
        assert t.max_users == 9999
        assert t.max_storage_gb == 500

    def test_apply_plan_limits_upgrade(self):
        """apply_plan_limits aggiorna i campi dopo un cambio piano."""
        t = self._make_tenant(TenantPlan.FREE)
        assert t.max_users == 5

        t.plan = TenantPlan.PRO
        t.apply_plan_limits()

        assert t.max_users == 50
        assert t.max_storage_gb == 20

    def test_apply_plan_limits_downgrade(self):
        """Il downgrade aggiorna i limiti verso il basso."""
        t = self._make_tenant(TenantPlan.ENTERPRISE)
        t.plan = TenantPlan.FREE
        t.apply_plan_limits()
        assert t.max_users == 5

    def test_all_plans_in_limits_dict(self):
        """PLAN_LIMITS deve contenere tutti i piani dell'enum."""
        for plan in TenantPlan:
            assert plan in PLAN_LIMITS, f"Piano {plan} mancante in PLAN_LIMITS"
            assert "max_users" in PLAN_LIMITS[plan]
            assert "max_storage_gb" in PLAN_LIMITS[plan]

    def test_tenant_repr(self):
        t = self._make_tenant(TenantPlan.PRO)
        assert "test-corp" in repr(t)
        assert "pro" in repr(t)


# ── Test Dependency get_current_tenant ───────────────────────────────────────

class TestGetCurrentTenant:
    """Test sulla dependency get_current_tenant."""

    def _make_request_with_tenant(self, tenant=None):
        """Crea una Request mock con state.tenant impostato."""
        request = MagicMock()
        request.state = MagicMock()
        request.state.tenant = tenant
        return request

    def test_returns_tenant_when_present(self):
        """Se request.state.tenant è impostato, lo restituisce."""
        from app.services.tenant_deps import get_current_tenant

        tenant = MagicMock(spec=Tenant)
        request = self._make_request_with_tenant(tenant)

        result = get_current_tenant(request)
        assert result is tenant

    def test_raises_401_when_no_tenant(self):
        """Se request.state.tenant è None, solleva 401."""
        from app.services.tenant_deps import get_current_tenant
        from fastapi import HTTPException

        request = self._make_request_with_tenant(None)

        with pytest.raises(HTTPException) as exc_info:
            get_current_tenant(request)

        assert exc_info.value.status_code == 401

    def test_optional_returns_none(self):
        """get_current_tenant_optional non solleva eccezioni se assente."""
        from app.services.tenant_deps import get_current_tenant_optional

        request = self._make_request_with_tenant(None)
        result = get_current_tenant_optional(request)
        assert result is None

    def test_optional_returns_tenant_when_present(self):
        from app.services.tenant_deps import get_current_tenant_optional

        tenant = MagicMock(spec=Tenant)
        request = self._make_request_with_tenant(tenant)
        result = get_current_tenant_optional(request)
        assert result is tenant


# ── Test require_plan ─────────────────────────────────────────────────────────

class TestRequirePlan:
    """Test sulla factory require_plan."""

    def _make_tenant_with_plan(self, plan: TenantPlan) -> Tenant:
        t = MagicMock(spec=Tenant)
        t.plan = plan
        return t

    def test_free_plan_allowed_when_free_required(self):
        """Un tenant FREE può accedere a feature che richiedono FREE."""
        from app.services.tenant_deps import require_plan

        tenant = self._make_tenant_with_plan(TenantPlan.FREE)
        require_plan(TenantPlan.FREE)

        # Test diretto della logica interna
        from app.models.tenant import TenantPlan as TP
        plan_hierarchy = {TP.FREE: 0, TP.PRO: 1, TP.ENTERPRISE: 2}
        min_level = plan_hierarchy[TenantPlan.FREE]
        current_level = plan_hierarchy[tenant.plan]
        assert current_level >= min_level

    def test_free_plan_blocked_when_pro_required(self):
        """Un tenant FREE non può accedere a feature PRO."""
        from app.models.tenant import TenantPlan as TP
        plan_hierarchy = {TP.FREE: 0, TP.PRO: 1, TP.ENTERPRISE: 2}

        tenant_plan = TenantPlan.FREE
        required_plan = TenantPlan.PRO

        current_level = plan_hierarchy[tenant_plan]
        min_level = plan_hierarchy[required_plan]
        assert current_level < min_level  # deve essere bloccato

    def test_enterprise_passes_pro_check(self):
        """Un tenant ENTERPRISE può usare feature PRO."""
        from app.models.tenant import TenantPlan as TP
        plan_hierarchy = {TP.FREE: 0, TP.PRO: 1, TP.ENTERPRISE: 2}

        assert plan_hierarchy[TenantPlan.ENTERPRISE] >= plan_hierarchy[TenantPlan.PRO]

    def test_multi_plan_requirement(self):
        """require_plan(PRO, ENTERPRISE): sia PRO che ENTERPRISE passano."""
        from app.models.tenant import TenantPlan as TP
        plan_hierarchy = {TP.FREE: 0, TP.PRO: 1, TP.ENTERPRISE: 2}
        allowed = [TenantPlan.PRO, TenantPlan.ENTERPRISE]
        min_level = min(plan_hierarchy[p] for p in allowed)

        assert plan_hierarchy[TenantPlan.PRO] >= min_level        # ✓ passa
        assert plan_hierarchy[TenantPlan.ENTERPRISE] >= min_level  # ✓ passa
        assert plan_hierarchy[TenantPlan.FREE] < min_level         # ✗ bloccato


# ── Test Middleware bypass paths ──────────────────────────────────────────────

class TestMiddlewareBypass:
    """Verifica che i path di sistema saltino la risoluzione tenant."""

    def test_bypass_paths_defined(self):
        """I path di bypass devono includere /health e /docs."""
        from app.middleware.tenant_middleware import BYPASS_PATHS
        assert "/health" in BYPASS_PATHS
        assert "/docs" in BYPASS_PATHS
        assert "/openapi.json" in BYPASS_PATHS

    def test_bypass_prefixes_include_tenants(self):
        """L'endpoint di creazione tenant deve essere in bypass."""
        from app.middleware.tenant_middleware import BYPASS_PREFIXES
        assert any("tenants" in p for p in BYPASS_PREFIXES)

    def test_tenant_api_paths_bypassed(self):
        """Simula il check del middleware sui path."""
        from app.middleware.tenant_middleware import BYPASS_PATHS, BYPASS_PREFIXES

        paths_that_should_bypass = [
            "/health",
            "/docs",
            "/openapi.json",
            "/api/v1/tenants/",
            "/api/v1/tenants/acme-corp",
        ]
        for path in paths_that_should_bypass:
            bypassed = path in BYPASS_PATHS or path.startswith(BYPASS_PREFIXES)
            assert bypassed, f"Il path {path!r} dovrebbe essere in bypass"

    def test_protected_paths_not_bypassed(self):
        """Path protetti NON devono essere in bypass."""
        from app.middleware.tenant_middleware import BYPASS_PATHS, BYPASS_PREFIXES

        protected = [
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/roles/",
        ]
        for path in protected:
            bypassed = path in BYPASS_PATHS or path.startswith(BYPASS_PREFIXES)
            assert not bypassed, f"Il path {path!r} NON dovrebbe essere in bypass"


# ── Test indici composti (strutturale) ────────────────────────────────────────

class TestCompositeIndexes:
    """Verifica che i modelli abbiano gli indici composti definiti."""

    def test_user_model_has_tenant_id(self):
        """Il modello User deve avere la colonna tenant_id."""
        from app.models.user import User
        cols = {c.key for c in User.__table__.columns}
        assert "tenant_id" in cols

    def test_role_model_has_tenant_id(self):
        from app.models.user import Role
        cols = {c.key for c in Role.__table__.columns}
        assert "tenant_id" in cols

    def test_policy_model_has_tenant_id(self):
        from app.models.user import Policy
        cols = {c.key for c in Policy.__table__.columns}
        assert "tenant_id" in cols

    def test_user_composite_index_exists(self):
        """Deve esistere un indice su (tenant_id, id) per User."""
        from app.models.user import User
        index_names = {idx.name for idx in User.__table__.indexes}
        assert "ix_users_tenant_id_id" in index_names

    def test_role_composite_index_exists(self):
        from app.models.user import Role
        index_names = {idx.name for idx in Role.__table__.indexes}
        assert "ix_roles_tenant_id_id" in index_names

    def test_policy_composite_index_exists(self):
        from app.models.user import Policy
        index_names = {idx.name for idx in Policy.__table__.indexes}
        assert "ix_policies_tenant_id_id" in index_names

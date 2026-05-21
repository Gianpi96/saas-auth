"""
tests/test_step4_rbac.py
─────────────────────────
Test unitari per Step 4: RBAC avanzato con permessi many-to-many.

Struttura:
  TestPermissionMatching    → logica wildcard _has_permission()
  TestRequirePermission     → decorator e dependency behavior
  TestRequireAnyPermission  → OR tra permessi
  TestPermissionCodename    → formato "resource:action"
  TestRoleHierarchy         → admin > editor > viewer
  TestGroqDescriptions      → fallback quando Groq non è disponibile
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from app.services.rbac import _has_permission, require_permission, require_any_permission
from app.schemas.user import TokenPayload


# ── Helper ────────────────────────────────────────────────────────────────────

def make_token(
    permissions: list[str] = None,
    role: str = "viewer",
    user_id: str = "user-123",
    tenant_id: str = "tenant-456",
    tenant_schema: str = "tenant_acme_corp",
) -> TokenPayload:
    return TokenPayload(
        sub=user_id,
        tenant_id=tenant_id,
        tenant_schema=tenant_schema,
        role=role,
        permissions=permissions or [],
        exp=9999999999,
    )


# ── Test _has_permission (matching wildcard) ──────────────────────────────────

class TestPermissionMatching:
    """Test esaustivo sulla logica di matching con wildcard."""

    # ── Wildcard globale "*" ──────────────────────────────────────────────────
    def test_global_wildcard_allows_anything(self):
        assert _has_permission(["*"], "tasks:read") is True
        assert _has_permission(["*"], "tasks:delete") is True
        assert _has_permission(["*"], "reports:write") is True
        assert _has_permission(["*"], "admin:roles") is True

    def test_global_wildcard_alone_is_enough(self):
        """Basta "*" nella lista, il resto non conta."""
        assert _has_permission(["tasks:read", "*", "reports:write"], "users:delete") is True

    # ── Wildcard sull'azione "resource:*" ────────────────────────────────────
    def test_resource_wildcard_allows_any_action(self):
        assert _has_permission(["tasks:*"], "tasks:read") is True
        assert _has_permission(["tasks:*"], "tasks:write") is True
        assert _has_permission(["tasks:*"], "tasks:delete") is True

    def test_resource_wildcard_blocks_other_resources(self):
        assert _has_permission(["tasks:*"], "reports:read") is False
        assert _has_permission(["tasks:*"], "users:delete") is False

    # ── Wildcard sulla risorsa "*:action" ────────────────────────────────────
    def test_action_wildcard_allows_any_resource(self):
        assert _has_permission(["*:read"], "tasks:read") is True
        assert _has_permission(["*:read"], "reports:read") is True
        assert _has_permission(["*:read"], "users:read") is True

    def test_action_wildcard_blocks_other_actions(self):
        assert _has_permission(["*:read"], "tasks:write") is False
        assert _has_permission(["*:read"], "tasks:delete") is False

    # ── Match esatto ─────────────────────────────────────────────────────────
    def test_exact_match(self):
        assert _has_permission(["tasks:read"], "tasks:read") is True
        assert _has_permission(["tasks:delete"], "tasks:delete") is True

    def test_exact_mismatch_action(self):
        assert _has_permission(["tasks:read"], "tasks:write") is False
        assert _has_permission(["tasks:read"], "tasks:delete") is False

    def test_exact_mismatch_resource(self):
        assert _has_permission(["tasks:read"], "reports:read") is False
        assert _has_permission(["tasks:read"], "users:read") is False

    # ── Lista di permessi ─────────────────────────────────────────────────────
    def test_multiple_permissions_any_matches(self):
        perms = ["tasks:read", "reports:read", "tasks:write"]
        assert _has_permission(perms, "tasks:read") is True
        assert _has_permission(perms, "reports:read") is True
        assert _has_permission(perms, "tasks:write") is True

    def test_multiple_permissions_none_matches(self):
        perms = ["tasks:read", "reports:read"]
        assert _has_permission(perms, "tasks:delete") is False
        assert _has_permission(perms, "users:write") is False

    def test_empty_permissions_deny_all(self):
        assert _has_permission([], "tasks:read") is False
        assert _has_permission([], "*") is False

    # ── Casi edge ─────────────────────────────────────────────────────────────
    def test_admin_star_permission(self):
        """Il ruolo admin ha "*" → accede a tutto."""
        admin_perms = ["*"]
        assert _has_permission(admin_perms, "tasks:delete") is True
        assert _has_permission(admin_perms, "admin:roles") is True
        assert _has_permission(admin_perms, "anything:whatever") is True

    def test_viewer_read_only(self):
        """Il viewer ha solo "read:*" → può leggere, non scrivere."""
        viewer_perms = ["*:read"]
        assert _has_permission(viewer_perms, "tasks:read") is True
        assert _has_permission(viewer_perms, "reports:read") is True
        assert _has_permission(viewer_perms, "tasks:write") is False
        assert _has_permission(viewer_perms, "tasks:delete") is False

    def test_editor_specific_permissions(self):
        """L'editor ha permessi specifici."""
        editor_perms = ["tasks:read", "tasks:write", "reports:read"]
        assert _has_permission(editor_perms, "tasks:read") is True
        assert _has_permission(editor_perms, "tasks:write") is True
        assert _has_permission(editor_perms, "reports:read") is True
        assert _has_permission(editor_perms, "tasks:delete") is False
        assert _has_permission(editor_perms, "reports:write") is False
        assert _has_permission(editor_perms, "users:read") is False


# ── Test require_permission come Dependency ───────────────────────────────────

class TestRequirePermission:
    """Test del comportamento di require_permission come Depends()."""

    @pytest.mark.asyncio
    async def test_passes_with_exact_permission(self):
        """Utente con il permesso esatto → passa."""
        token = make_token(permissions=["tasks:delete"])
        dependency = require_permission("tasks:delete")
        result = await dependency(current_user=token)
        assert result is token

    @pytest.mark.asyncio
    async def test_passes_with_wildcard_permission(self):
        """Utente con wildcard globale → passa su qualsiasi permesso."""
        token = make_token(permissions=["*"], role="admin")
        dependency = require_permission("tasks:delete")
        result = await dependency(current_user=token)
        assert result is token

    @pytest.mark.asyncio
    async def test_passes_with_resource_wildcard(self):
        """Utente con 'tasks:*' → passa su 'tasks:delete'."""
        token = make_token(permissions=["tasks:*"])
        dependency = require_permission("tasks:delete")
        result = await dependency(current_user=token)
        assert result is token

    @pytest.mark.asyncio
    async def test_blocks_without_permission(self):
        """Utente senza il permesso → 403."""
        token = make_token(permissions=["tasks:read"])
        dependency = require_permission("tasks:delete")
        with pytest.raises(HTTPException) as exc_info:
            await dependency(current_user=token)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_403_message_contains_permission_name(self):
        """Il messaggio 403 deve specificare quale permesso manca."""
        token = make_token(permissions=[])
        dependency = require_permission("tasks:delete")
        with pytest.raises(HTTPException) as exc_info:
            await dependency(current_user=token)
        assert "tasks:delete" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_403_message_contains_role(self):
        """Il messaggio 403 deve citare il ruolo dell'utente."""
        token = make_token(permissions=["tasks:read"], role="viewer")
        dependency = require_permission("tasks:delete")
        with pytest.raises(HTTPException) as exc_info:
            await dependency(current_user=token)
        assert "viewer" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_empty_permissions_blocked(self):
        """Utente senza permessi → bloccato su qualsiasi risorsa."""
        token = make_token(permissions=[])
        for perm in ["tasks:read", "reports:write", "users:delete"]:
            dependency = require_permission(perm)
            with pytest.raises(HTTPException) as exc_info:
                await dependency(current_user=token)
            assert exc_info.value.status_code == 403


# ── Test require_any_permission ───────────────────────────────────────────────

class TestRequireAnyPermission:
    """OR tra permessi: basta averne uno."""

    @pytest.mark.asyncio
    async def test_passes_with_first_permission(self):
        token = make_token(permissions=["tasks:write"])
        dep = require_any_permission("tasks:write", "tasks:*", "*")
        result = await dep(current_user=token)
        assert result is token

    @pytest.mark.asyncio
    async def test_passes_with_any_of_the_permissions(self):
        token = make_token(permissions=["reports:read"])
        dep = require_any_permission("tasks:write", "reports:read")
        result = await dep(current_user=token)
        assert result is token

    @pytest.mark.asyncio
    async def test_blocks_when_none_match(self):
        token = make_token(permissions=["tasks:read"])
        dep = require_any_permission("tasks:delete", "reports:write")
        with pytest.raises(HTTPException) as exc_info:
            await dep(current_user=token)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_wildcard_passes_any_or(self):
        token = make_token(permissions=["*"], role="admin")
        dep = require_any_permission("tasks:delete", "reports:write")
        result = await dep(current_user=token)
        assert result is token


# ── Test Codename Format ──────────────────────────────────────────────────────

class TestPermissionCodename:
    """Verifica il formato resource:action e la sua coerenza."""

    def test_codename_format(self):
        """Il codename deve essere 'resource:action'."""
        cases = [
            ("tasks", "read", "tasks:read"),
            ("tasks", "delete", "tasks:delete"),
            ("reports", "*", "reports:*"),
            ("*", "*", "*:*"),
            ("admin", "roles", "admin:roles"),
        ]
        for resource, action, expected in cases:
            assert f"{resource}:{action}" == expected

    def test_wildcard_codename_matches_all_actions(self):
        """'tasks:*' deve matchare qualsiasi azione su tasks."""
        required_perms = ["tasks:read", "tasks:write", "tasks:delete", "tasks:archive"]
        for required in required_perms:
            assert _has_permission(["tasks:*"], required) is True

    def test_specific_codename_does_not_match_wildcard(self):
        """
        'tasks:read' NON deve matchare 'tasks:*'.
        L'utente ha un permesso specifico, non il wildcard.
        Il check è: 'l'utente ha ALMENO questo permesso?'
        """
        # L'utente ha "tasks:read"
        # Il requisito è "tasks:*" (wildcard — significa 'qualsiasi azione su tasks')
        # L'utente NON soddisfa il requisito wildcard
        assert _has_permission(["tasks:read"], "tasks:*") is False


# ── Test Role Hierarchy ───────────────────────────────────────────────────────

class TestRoleHierarchy:
    """
    Simula i tre ruoli tipici di un SaaS e verifica l'accesso corretto.

    Admin    → ["*"]
    Editor   → ["tasks:read", "tasks:write", "reports:read"]
    Viewer   → ["*:read"] o ["tasks:read", "reports:read"]
    """

    ADMIN_PERMS  = ["*"]
    EDITOR_PERMS = ["tasks:read", "tasks:write", "reports:read"]
    VIEWER_PERMS = ["*:read"]

    @pytest.mark.asyncio
    async def test_admin_can_delete_tasks(self):
        token = make_token(permissions=self.ADMIN_PERMS, role="admin")
        dep = require_permission("tasks:delete")
        result = await dep(current_user=token)
        assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_editor_can_write_tasks(self):
        token = make_token(permissions=self.EDITOR_PERMS, role="editor")
        dep = require_permission("tasks:write")
        result = await dep(current_user=token)
        assert result.role == "editor"

    @pytest.mark.asyncio
    async def test_editor_cannot_delete_tasks(self):
        """L'editor non ha il permesso di eliminare — 403."""
        token = make_token(permissions=self.EDITOR_PERMS, role="editor")
        dep = require_permission("tasks:delete")
        with pytest.raises(HTTPException) as exc_info:
            await dep(current_user=token)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_can_read_anything(self):
        """Il viewer con '*:read' può leggere qualsiasi risorsa."""
        token = make_token(permissions=self.VIEWER_PERMS, role="viewer")
        for resource in ["tasks", "reports", "users", "documents"]:
            dep = require_permission(f"{resource}:read")
            result = await dep(current_user=token)
            assert result is token

    @pytest.mark.asyncio
    async def test_viewer_cannot_write(self):
        """Il viewer non può scrivere — 403."""
        token = make_token(permissions=self.VIEWER_PERMS, role="viewer")
        dep = require_permission("tasks:write")
        with pytest.raises(HTTPException) as exc_info:
            await dep(current_user=token)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_manage_roles(self):
        """Solo l'admin può gestire i ruoli."""
        admin = make_token(permissions=self.ADMIN_PERMS, role="admin")
        editor = make_token(permissions=self.EDITOR_PERMS, role="editor")
        viewer = make_token(permissions=self.VIEWER_PERMS, role="viewer")

        dep = require_permission("admin:roles")

        # Admin passa
        result = await dep(current_user=admin)
        assert result is admin

        # Editor e viewer bloccati
        for token in [editor, viewer]:
            with pytest.raises(HTTPException) as exc_info:
                await dep(current_user=token)
            assert exc_info.value.status_code == 403


# ── Test Groq Fallback ────────────────────────────────────────────────────────

class TestGroqDescriptions:
    """Verifica che il fallback funzioni quando Groq non è disponibile."""

    @pytest.mark.asyncio
    async def test_permission_description_fallback(self):
        """Se Groq fallisce, deve restituire una descrizione di fallback."""
        from app.services.groq_service import generate_permission_description

        with patch("app.services.groq_service.get_groq_client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=Exception("API non disponibile")
            )
            mock_client.return_value = mock_instance

            result = await generate_permission_description(
                resource="tasks",
                action="delete",
                codename="tasks:delete",
            )

        # Il fallback deve essere una stringa non vuota
        assert isinstance(result, str)
        assert len(result) > 0
        # Deve contenere info sul permesso
        assert "tasks" in result.lower() or "delete" in result.lower()

    @pytest.mark.asyncio
    async def test_role_description_fallback(self):
        """Fallback per la descrizione del ruolo."""
        from app.services.groq_service import generate_role_description

        with patch("app.services.groq_service.get_groq_client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=Exception("Timeout")
            )
            mock_client.return_value = mock_instance

            result = await generate_role_description(
                role_name="editor",
                permissions="tasks:read,tasks:write",
            )

        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_groq_uses_70b_model_for_permissions(self):
        """Verifica che usiamo llama-3.3-70b-versatile per i permessi."""
        from app.services.groq_service import generate_permission_description

        with patch("app.services.groq_service.get_groq_client") as mock_client:
            mock_instance = MagicMock()
            mock_response = MagicMock()
            mock_response.choices[0].message.content = "Descrizione test"
            mock_instance.chat.completions.create = AsyncMock(
                return_value=mock_response
            )
            mock_client.return_value = mock_instance

            await generate_permission_description(
                resource="tasks",
                action="delete",
                codename="tasks:delete",
            )

            call_kwargs = mock_instance.chat.completions.create.call_args.kwargs
            assert call_kwargs["model"] == "llama-3.3-70b-versatile"

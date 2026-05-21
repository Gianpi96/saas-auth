"""
tests/test_jwt_rbac.py
───────────────────────
Test unitari per JWT service e logica RBAC.

Questi test NON richiedono il DB: testano la logica pura.
Eseguibili immediatamente dopo l'installazione delle dipendenze.
"""
import pytest
from datetime import datetime, timezone

from app.services.jwt_service import create_access_token, decode_token
from app.services.rbac import _has_permission


# ── JWT Tests ─────────────────────────────────────────────────────────────────

class TestJWT:
    """Test sulla creazione e verifica dei token JWT."""

    def test_create_and_decode_token(self):
        """Il token creato deve essere decodificabile con i dati corretti."""
        token, expires = create_access_token(
            user_id="user-123",
            tenant_id="tenant-456",
            tenant_schema="tenant_acme",
            role="admin",
            permissions=["read:documents", "write:documents"],
        )

        assert token  # il token non è vuoto
        assert isinstance(expires, int)
        assert expires > datetime.now(timezone.utc).timestamp()  # non è scaduto

        payload = decode_token(token)
        assert payload.sub == "user-123"
        assert payload.tenant_id == "tenant-456"
        assert payload.tenant_schema == "tenant_acme"
        assert payload.role == "admin"
        assert "read:documents" in payload.permissions

    def test_invalid_token_raises(self):
        """Un token manipolato deve sollevare ValueError."""
        with pytest.raises(ValueError, match="Token non valido"):
            decode_token("questo.non.e.un.jwt.valido")

    def test_token_without_role(self):
        """Il token funziona anche senza ruolo (utente senza ruolo assegnato)."""
        token, _ = create_access_token(
            user_id="user-789",
            tenant_id="tenant-abc",
            tenant_schema="tenant_test",
        )
        payload = decode_token(token)
        assert payload.role is None
        assert payload.permissions == []

    def test_different_tenants_get_different_tokens(self):
        """Due tenant diversi devono avere token diversi."""
        token_a, _ = create_access_token("u1", "tenant-a", "tenant_a", "admin")
        token_b, _ = create_access_token("u1", "tenant-b", "tenant_b", "admin")
        assert token_a != token_b


# ── RBAC Permission Tests ─────────────────────────────────────────────────────

class TestRBACPermissions:
    """Test sulla logica di matching dei permessi."""

    def test_wildcard_global_allows_everything(self):
        """Il permesso '*' deve consentire qualsiasi azione su qualsiasi risorsa."""
        assert _has_permission(["*"], "read:documents") is True
        assert _has_permission(["*"], "delete:users") is True
        assert _has_permission(["*"], "write:anything") is True

    def test_read_wildcard_allows_any_read(self):
        """'read:*' deve consentire lettura su qualsiasi risorsa."""
        assert _has_permission(["read:*"], "read:documents") is True
        assert _has_permission(["read:*"], "read:reports") is True
        assert _has_permission(["read:*"], "write:documents") is False  # no!

    def test_specific_permission_exact_match(self):
        """Un permesso specifico deve matchare solo esattamente."""
        assert _has_permission(["read:documents"], "read:documents") is True
        assert _has_permission(["read:documents"], "read:users") is False
        assert _has_permission(["read:documents"], "write:documents") is False

    def test_multiple_permissions(self):
        """Lista di permessi: basta che uno faccia match."""
        perms = ["read:documents", "write:reports"]
        assert _has_permission(perms, "read:documents") is True
        assert _has_permission(perms, "write:reports") is True
        assert _has_permission(perms, "delete:documents") is False

    def test_empty_permissions(self):
        """Nessun permesso → nessun accesso."""
        assert _has_permission([], "read:anything") is False

    def test_deny_pattern_not_overrides_allow(self):
        """
        La logica _has_permission verifica solo 'allow'.
        Il deny è gestito a livello di policy nel DB, non qui.
        """
        # Con solo "read:*" non si ha accesso a write
        assert _has_permission(["read:*"], "write:documents") is False

    def test_wildcard_action(self):
        """'*:documents' dovrebbe permettere qualsiasi azione su documents."""
        assert _has_permission(["*:documents"], "read:documents") is True
        assert _has_permission(["*:documents"], "write:documents") is True
        assert _has_permission(["*:documents"], "read:users") is False


# ── Password Tests ─────────────────────────────────────────────────────────────

class TestPasswordHashing:
    """Test su hashing e verifica password."""

    def test_hash_is_different_from_plain(self):
        from app.services.password_service import hash_password
        pwd = "MySecurePass123!"
        hashed = hash_password(pwd)
        assert hashed != pwd
        assert len(hashed) > 20  # bcrypt hash è lungo

    def test_verify_correct_password(self):
        from app.services.password_service import hash_password, verify_password
        pwd = "MySecurePass123!"
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed) is True

    def test_reject_wrong_password(self):
        from app.services.password_service import hash_password, verify_password
        hashed = hash_password("correct_password")
        assert verify_password("wrong_password", hashed) is False

    def test_same_password_different_hashes(self):
        """bcrypt genera salt random: stesso input → hash diversi."""
        from app.services.password_service import hash_password
        pwd = "same_password"
        hash1 = hash_password(pwd)
        hash2 = hash_password(pwd)
        assert hash1 != hash2  # salt diverso!

"""
tests/test_step3_refresh_tokens.py
────────────────────────────────────
Test unitari per Step 3: refresh token rotation e replay attack detection.

Questi test NON richiedono il DB: usano mock per simulare le sessioni.
Testano la logica pura di sicurezza — la parte più critica del sistema.

Struttura:
  TestTokenHashing       → SHA-256, entropia, unicità
  TestRefreshTokenModel  → proprietà is_valid, is_expired
  TestRotationLogic      → flusso normale di rotazione
  TestReplayAttack       → rilevamento e family invalidation
  TestLogoutFlow         → revoca singola e globale
  TestAccessTokenExpiry  → scadenza 15 minuti
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.refresh_token import RefreshToken
from app.services.refresh_token_service import (
    _hash_token,
    generate_raw_token,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_refresh_token(
    is_revoked: bool = False,
    expires_delta: timedelta = timedelta(days=7),
    family_id: uuid.UUID = None,
    user_id: str = "user-123",
    tenant_id: str = "tenant-456",
    tenant_schema: str = "tenant_acme_corp",
    token_hash: str = "abc123",
    parent_token_hash: str = None,
    revoked_reason: str = None,
) -> RefreshToken:
    """Costruisce un RefreshToken mock con valori controllati."""
    rt = RefreshToken()
    rt.id = uuid.uuid4()
    rt.token_hash = token_hash
    rt.family_id = family_id or uuid.uuid4()
    rt.user_id = user_id
    rt.tenant_id = tenant_id
    rt.tenant_schema = tenant_schema
    rt.parent_token_hash = parent_token_hash
    rt.is_revoked = is_revoked
    rt.revoked_reason = revoked_reason
    rt.created_at = datetime.now(timezone.utc)
    rt.expires_at = datetime.now(timezone.utc) + expires_delta
    rt.used_at = None
    return rt


# ── Test Hashing ──────────────────────────────────────────────────────────────


class TestTokenHashing:
    """SHA-256 e generazione token sicuri."""

    def test_hash_is_sha256(self):
        """L'hash deve essere SHA-256: 64 caratteri hex."""
        token = "mio_token_segreto"
        result = _hash_token(token)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_is_deterministic(self):
        """Stesso input → stesso output (necessario per il lookup nel DB)."""
        token = "token_fisso"
        assert _hash_token(token) == _hash_token(token)

    def test_different_tokens_different_hashes(self):
        """Token diversi → hash diversi (nessuna collisione su input simili)."""
        assert _hash_token("token_a") != _hash_token("token_b")
        assert _hash_token("token_1") != _hash_token("token_2")

    def test_hash_matches_stdlib_sha256(self):
        """Verifica che usiamo proprio SHA-256 e non un altro algoritmo."""
        raw = "verifica_algoritmo"
        expected = hashlib.sha256(raw.encode()).hexdigest()
        assert _hash_token(raw) == expected

    def test_generate_raw_token_is_random(self):
        """Ogni token generato deve essere diverso (entropia da secrets)."""
        tokens = {generate_raw_token() for _ in range(100)}
        assert len(tokens) == 100  # zero collisioni su 100 generazioni

    def test_generate_raw_token_length(self):
        """32 byte urlsafe base64 → almeno 43 caratteri."""
        token = generate_raw_token()
        assert len(token) >= 43

    def test_generate_raw_token_url_safe(self):
        """Il token non deve contenere caratteri non URL-safe."""
        for _ in range(50):
            token = generate_raw_token()
            assert "+" not in token
            assert "/" not in token
            assert "=" not in token or token.count("=") <= 2


# ── Test Modello RefreshToken ─────────────────────────────────────────────────


class TestRefreshTokenModel:
    """Proprietà is_valid e is_expired del modello."""

    def test_valid_token_is_valid(self):
        """Token non revocato e non scaduto → is_valid=True."""
        rt = make_refresh_token(is_revoked=False, expires_delta=timedelta(days=7))
        assert rt.is_valid is True
        assert rt.is_expired is False

    def test_revoked_token_is_invalid(self):
        """Token revocato → is_valid=False anche se non scaduto."""
        rt = make_refresh_token(is_revoked=True, expires_delta=timedelta(days=7))
        assert rt.is_valid is False

    def test_expired_token_is_invalid(self):
        """Token scaduto → is_valid=False anche se non revocato."""
        rt = make_refresh_token(is_revoked=False, expires_delta=timedelta(seconds=-1))
        assert rt.is_expired is True
        assert rt.is_valid is False

    def test_revoked_and_expired_is_invalid(self):
        """Entrambe le condizioni → is_valid=False."""
        rt = make_refresh_token(is_revoked=True, expires_delta=timedelta(seconds=-1))
        assert rt.is_valid is False

    def test_expires_at_boundary(self):
        """Token che scade esattamente ora → considerato scaduto."""
        rt = make_refresh_token(expires_delta=timedelta(seconds=-1))
        assert rt.is_expired is True

    def test_fresh_token_not_expired(self):
        """Token creato con scadenza futura → non scaduto."""
        rt = make_refresh_token(expires_delta=timedelta(hours=1))
        assert rt.is_expired is False


# ── Test Flusso di Rotazione ──────────────────────────────────────────────────


class TestRotationLogic:
    """Flusso normale: token valido → revocato → nuovo emesso."""

    @pytest.mark.asyncio
    async def test_rotate_valid_token_revokes_old(self):
        """
        Quando presentiamo un token valido, il vecchio deve essere revocato
        con reason='rotated' e deve essere emesso un nuovo token.
        """
        from app.services.refresh_token_service import rotate_refresh_token

        raw_token = "token_valido_grezzo"
        token_hash = _hash_token(raw_token)
        family_id = uuid.uuid4()

        existing_rt = make_refresh_token(
            is_revoked=False,
            token_hash=token_hash,
            family_id=family_id,
        )

        db = AsyncMock()

        # Mock: SELECT trova il token
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_rt
        db.execute = AsyncMock(return_value=mock_result)
        db.add = MagicMock()
        db.flush = AsyncMock()

        # Intercetta create_refresh_token per non fare DB reale
        with patch(
            "app.services.refresh_token_service.create_refresh_token",
            new_callable=AsyncMock,
            return_value="nuovo_token_grezzo",
        ) as mock_create:
            old_rt, new_raw = await rotate_refresh_token(db, raw_token)

        # Il vecchio token deve essere revocato
        assert existing_rt.is_revoked is True
        assert existing_rt.revoked_reason == "rotated"
        assert existing_rt.used_at is not None

        # Il nuovo token deve essere stato creato con la stessa family
        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs["family_id"] == family_id
        assert call_kwargs["parent_token_hash"] == token_hash

        assert new_raw == "nuovo_token_grezzo"

    @pytest.mark.asyncio
    async def test_rotate_preserves_family_id(self):
        """
        La family_id deve propagarsi: tutti i token di una sessione
        condividono lo stesso family_id per permettere la family invalidation.
        """
        from app.services.refresh_token_service import rotate_refresh_token

        family_id = uuid.uuid4()
        raw_token = "token_con_family"
        token_hash = _hash_token(raw_token)

        rt = make_refresh_token(
            token_hash=token_hash,
            family_id=family_id,
            is_revoked=False,
        )

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = rt
        db.execute = AsyncMock(return_value=mock_result)
        db.flush = AsyncMock()

        with patch(
            "app.services.refresh_token_service.create_refresh_token",
            new_callable=AsyncMock,
            return_value="nuovo",
        ) as mock_create:
            await rotate_refresh_token(db, raw_token)

        # La family_id deve essere la stessa del token padre
        assert mock_create.call_args.kwargs["family_id"] == family_id

    @pytest.mark.asyncio
    async def test_rotate_expired_token_raises(self):
        """Un token scaduto (ma non revocato) deve restituire TOKEN_EXPIRED."""
        from app.services.refresh_token_service import rotate_refresh_token

        raw_token = "token_scaduto"
        rt = make_refresh_token(
            token_hash=_hash_token(raw_token),
            is_revoked=False,
            expires_delta=timedelta(seconds=-100),  # già scaduto
        )

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = rt
        db.execute = AsyncMock(return_value=mock_result)
        db.flush = AsyncMock()

        with pytest.raises(ValueError, match="TOKEN_EXPIRED"):
            await rotate_refresh_token(db, raw_token)

    @pytest.mark.asyncio
    async def test_rotate_unknown_token_raises(self):
        """Un token mai visto deve restituire TOKEN_NOT_FOUND."""
        from app.services.refresh_token_service import rotate_refresh_token

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # non trovato nel DB
        db.execute = AsyncMock(return_value=mock_result)

        with pytest.raises(ValueError, match="TOKEN_NOT_FOUND"):
            await rotate_refresh_token(db, "token_inesistente")


# ── Test Replay Attack ────────────────────────────────────────────────────────


class TestReplayAttack:
    """
    Il cuore della sicurezza: rilevamento e risposta al replay attack.

    Scenario: un attaccante ruba un refresh token già usato e tenta di usarlo.
    Il sistema deve:
      1. Rilevare che il token è già stato revocato (is_revoked=True)
      2. Invalidare TUTTA la family (tutti i token della sessione)
      3. Restituire REPLAY_ATTACK
    """

    @pytest.mark.asyncio
    async def test_replay_attack_detected_on_revoked_token(self):
        """
        Se presentiamo un token già revocato → ValueError("REPLAY_ATTACK").
        """
        from app.services.refresh_token_service import rotate_refresh_token

        raw_token = "token_gia_usato"
        rt = make_refresh_token(
            token_hash=_hash_token(raw_token),
            is_revoked=True,  # già revocato = replay attack
            revoked_reason="rotated",
        )

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = rt
        db.execute = AsyncMock(return_value=mock_result)
        db.flush = AsyncMock()

        with patch(
            "app.services.refresh_token_service._invalidate_family",
            new_callable=AsyncMock,
        ) as mock_invalidate:
            with pytest.raises(ValueError, match="REPLAY_ATTACK"):
                await rotate_refresh_token(db, raw_token)

            # La family DEVE essere stata invalidata
            mock_invalidate.assert_called_once_with(
                db, rt.family_id, reason="replay_attack"
            )

    @pytest.mark.asyncio
    async def test_replay_attack_invalidates_entire_family(self):
        """
        La family invalidation deve colpire TUTTI i token con lo stesso
        family_id, non solo quello presentato.

        Questo protegge l'utente legittimo: i suoi token futuri
        diventano inutilizzabili → deve rifare login.
        """
        from app.services.refresh_token_service import _invalidate_family

        family_id = uuid.uuid4()
        db = AsyncMock()

        # Simula il risultato dell'UPDATE con RETURNING
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            ("id1",),
            ("id2",),
            ("id3",),
        ]  # 3 token invalidati
        db.execute = AsyncMock(return_value=mock_result)

        count = await _invalidate_family(db, family_id, reason="replay_attack")

        # Deve aver invalidato 3 token
        assert count == 3

        # Verifica che la query sia stata eseguita
        assert db.execute.called

    def test_replay_attack_scenario_explained(self):
        """
        Test documentale: spiega la sequenza di eventi di un replay attack.
        Non testa codice ma serve come documentazione eseguibile.
        """
        # Timeline:
        # T=0: utente fa login → token A (family_id=X, is_revoked=False)
        # T=1: utente usa A → sistema emette B (A revocato con reason='rotated')
        # T=2: attaccante ruba A (già revocato)
        # T=3: attaccante presenta A → sistema vede is_revoked=True → REPLAY ATTACK
        # T=4: sistema invalida tutta la family X → B diventa revocato
        # T=5: utente legittimo presenta B → TOKEN_NOT_FOUND o REPLAY_ATTACK → deve riloginare
        # T=6: attaccante non ottiene nulla

        token_a = make_refresh_token(
            is_revoked=True,
            revoked_reason="rotated",
        )
        token_b = make_refresh_token(
            is_revoked=False,
            family_id=token_a.family_id,  # stessa family
            parent_token_hash=token_a.token_hash,
        )

        # Precondizioni prima del replay attack
        assert token_a.is_revoked is True  # A già usato
        assert token_b.is_revoked is False  # B ancora valido
        assert token_a.family_id == token_b.family_id  # stessa sessione

        # Dopo la family invalidation:
        token_b.is_revoked = True  # simuliamo l'UPDATE
        token_b.revoked_reason = "replay_attack"

        assert token_b.is_valid is False  # B ora non è più usabile


# ── Test Logout ───────────────────────────────────────────────────────────────


class TestLogoutFlow:
    """Revoca token al logout."""

    @pytest.mark.asyncio
    async def test_revoke_all_user_tokens(self):
        """revoke_all_user_tokens deve aggiornare tutti i token non revocati."""
        from app.services.refresh_token_service import revoke_all_user_tokens

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [("id1",), ("id2",)]
        db.execute = AsyncMock(return_value=mock_result)

        count = await revoke_all_user_tokens(db, "user-123", reason="logout")
        assert count == 2
        assert db.execute.called

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens(self):
        """cleanup_expired_tokens elimina i token scaduti."""
        from app.services.refresh_token_service import cleanup_expired_tokens

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [("id1",), ("id2",), ("id3",)]
        db.execute = AsyncMock(return_value=mock_result)

        count = await cleanup_expired_tokens(db)
        assert count == 3


# ── Test Access Token 15 minuti ───────────────────────────────────────────────


class TestAccessTokenExpiry:
    """Verifica che l'access token abbia scadenza di 15 minuti."""

    def test_access_token_expires_in_15_minutes(self):
        """
        Il JWT deve scadere esattamente dopo jwt_access_token_expire_minutes.
        """
        from app.services.jwt_service import create_access_token
        import jwt as pyjwt
        from app.config.settings import get_settings

        settings = get_settings()

        token, expires_ts = create_access_token(
            user_id="u1",
            tenant_id="t1",
            tenant_schema="tenant_test",
        )

        payload = pyjwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        issued_at = payload["iat"]
        expired_at = payload["exp"]
        duration_minutes = (expired_at - issued_at) / 60

        assert duration_minutes == pytest.approx(
            settings.jwt_access_token_expire_minutes, abs=0.1
        )

    def test_access_token_shorter_than_refresh(self):
        """
        L'access token deve scadere PRIMA del refresh token.
        Questa è la garanzia fondamentale del sistema dual-token.
        """
        from app.config.settings import get_settings

        settings = get_settings()

        access_minutes = settings.jwt_access_token_expire_minutes
        refresh_minutes = settings.jwt_refresh_token_expire_days * 24 * 60

        assert access_minutes < refresh_minutes, (
            f"access ({access_minutes}min) deve essere < refresh ({refresh_minutes}min)"
        )

    def test_refresh_token_duration_7_days(self):
        """Il refresh token deve durare 7 giorni."""
        from app.config.settings import get_settings

        settings = get_settings()
        assert settings.jwt_refresh_token_expire_days == 7

    def test_access_token_duration_15_minutes(self):
        """L'access token deve durare 15 minuti."""
        from app.config.settings import get_settings

        settings = get_settings()
        assert settings.jwt_access_token_expire_minutes == 15


# ── Test Chain di Rotazione ───────────────────────────────────────────────────


class TestTokenChain:
    """
    Verifica la catena parent_token_hash che permette di ricostruire
    l'albero di rotazione per audit e forensics.
    """

    def test_first_token_has_no_parent(self):
        """Il primo token di una sessione (login) non ha parent."""
        rt = make_refresh_token(parent_token_hash=None)
        assert rt.parent_token_hash is None

    def test_rotated_token_has_parent(self):
        """Un token generato dalla rotazione deve avere il parent hash."""
        parent_hash = _hash_token("token_padre")
        rt = make_refresh_token(parent_token_hash=parent_hash)
        assert rt.parent_token_hash == parent_hash

    def test_chain_reconstruction(self):
        """
        La catena parent → figlio permette di ricostruire la sequenza di rotazioni.
        Utile per audit: 'chi ha generato questo token?'
        """
        family_id = uuid.uuid4()

        # Token A: primo della famiglia (login)
        token_a_raw = generate_raw_token()
        token_a_hash = _hash_token(token_a_raw)
        rt_a = make_refresh_token(
            token_hash=token_a_hash,
            family_id=family_id,
            parent_token_hash=None,  # primo token
        )

        # Token B: generato dalla rotazione di A
        token_b_raw = generate_raw_token()
        token_b_hash = _hash_token(token_b_raw)
        rt_b = make_refresh_token(
            token_hash=token_b_hash,
            family_id=family_id,
            parent_token_hash=token_a_hash,  # B è figlio di A
        )

        # Verifica catena
        assert rt_b.parent_token_hash == rt_a.token_hash
        assert rt_a.family_id == rt_b.family_id
        assert rt_a.parent_token_hash is None  # A è la radice

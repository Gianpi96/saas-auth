"""
services/jwt_service.py
────────────────────────
Gestisce la creazione e verifica dei JWT con PyJWT.

Sostituisce python-jose (abbandonato, usa datetime.utcnow() deprecato
in Python 3.12+ e schedulato per rimozione in 3.14+) con PyJWT,
attivamente mantenuto e compatibile con Python 3.14.

Il payload include:
  - sub          : user_id
  - tenant_id    : UUID del tenant
  - tenant_schema: schema PostgreSQL del tenant (per le query)
  - role         : nome del ruolo dell'utente
  - permissions  : lista di permessi ["read:documents", "write:reports"]
  - exp          : scadenza (Unix timestamp, gestito da PyJWT)
  - iat          : issued at
"""
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # PyJWT
from jwt.exceptions import InvalidTokenError

from app.config.settings import get_settings
from app.schemas.user import TokenPayload

settings = get_settings()


def create_access_token(
    user_id: str,
    tenant_id: str,
    tenant_schema: str,
    role: Optional[str] = None,
    permissions: Optional[list[str]] = None,
) -> tuple[str, int]:
    """
    Crea un JWT firmato con HMAC-SHA256.

    Returns:
        (token_string, expire_unix_timestamp)
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "tenant_schema": tenant_schema,
        "role": role,
        "permissions": permissions or [],
        "exp": expire,   # PyJWT accetta datetime timezone-aware direttamente
        "iat": now,
        "jti": str(_uuid.uuid4()),  # garantisce unicità anche se emesso nello stesso secondo
    }

    token: str = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token, int(expire.timestamp())


def decode_token(token: str) -> TokenPayload:
    """
    Decodifica e valida un JWT.
    Lancia ValueError se il token è invalido, scaduto o malformato.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return TokenPayload(**payload)
    except InvalidTokenError as exc:
        raise ValueError(f"Token non valido: {exc}") from exc

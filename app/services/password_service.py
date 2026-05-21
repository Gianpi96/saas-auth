"""
services/password_service.py
─────────────────────────────
Hashing e verifica password con bcrypt diretto (senza passlib).

Perché non più passlib?
  passlib 1.7.4 è unmaintained dal 2020 e non riconosce bcrypt >= 4.x.
  Durante l'init tenta un "wrap bug detection" con una password da 200 byte
  che bcrypt 4+ rifiuta con ValueError. Usiamo bcrypt direttamente.

bcrypt genera automaticamente un salt random a 16 byte per ogni hash,
quindi lo stesso input produce output sempre diverso (salt è embedded
nell'hash stesso: "$2b$12$<salt><hash>").
"""
import bcrypt


def hash_password(plain_password: str) -> str:
    """
    Restituisce l'hash bcrypt della password.

    rounds=12: ogni incremento di 1 raddoppia il tempo di calcolo.
    12 è il valore consigliato per il 2024 (≈ 300ms su hardware moderno).
    """
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")  # salviamo come stringa nel DB


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Confronta la password in chiaro con il suo hash bcrypt.
    bcrypt.checkpw usa confronto constant-time internamente.
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )

"""
services/groq_service.py
─────────────────────────
Integrazione con Groq API per generare descrizioni in linguaggio naturale.

Caso d'uso principale:
  - L'admin crea una policy tecnica (role=editor, resource=documents, action=write)
  - Groq genera una spiegazione comprensibile:
    "Gli utenti con ruolo Editor possono creare e modificare documenti,
     ma non eliminarli o gestire altri utenti."

Perché Groq?
  Groq ha latenza estremamente bassa (< 1 secondo per risposte brevi)
  grazie al chip LPU (Language Processing Unit), ideale per use-case
  in-request dove la latenza conta.
"""
from typing import Optional

from groq import AsyncGroq

from app.config.settings import get_settings

settings = get_settings()

# Client Groq asincrono (riutilizzato tra le richieste)
_groq_client: AsyncGroq | None = None


def get_groq_client() -> AsyncGroq:
    """Singleton: crea il client solo alla prima chiamata."""
    global _groq_client
    if _groq_client is None:
        _groq_client = AsyncGroq(api_key=settings.groq_api_key)
    return _groq_client


async def generate_policy_description(
    role_name: str,
    resource: str,
    action: str,
    effect: str,
    policy_name: str,
    language: str = "italiano",
) -> str:
    """
    Genera una descrizione in linguaggio naturale di una policy RBAC.

    Args:
        role_name   : nome del ruolo (es: "editor")
        resource    : risorsa protetta (es: "documents")
        action      : azione permessa/negata (es: "write", "*")
        effect      : "allow" o "deny"
        policy_name : nome della policy
        language    : lingua della descrizione (default: italiano)

    Returns:
        Stringa con la descrizione in linguaggio naturale.
    """
    effect_it = "consentita" if effect == "allow" else "NEGATA"
    action_desc = "qualsiasi operazione" if action == "*" else f"l'operazione '{action}'"

    prompt = f"""Sei un esperto di sicurezza informatica. Descrivi questa policy RBAC in {language}
in modo chiaro e comprensibile per un utente non tecnico. Massimo 3 frasi. Niente bullet points.

Policy: {policy_name}
Ruolo: {role_name}
Risorsa: {resource}
Azione: {action_desc}
Effetto: {effect_it}

Descrivi concretamente cosa può o non può fare un utente con questo ruolo."""

    client = get_groq_client()

    try:
        response = await client.chat.completions.create(
            model="llama-3.1-8b-instant",  # modello veloce e gratuito su Groq
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.3,  # bassa creatività = risposte più precise e consistenti
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        # In caso di errore Groq, non blocchiamo l'operazione principale
        # Logghiamo e restituiamo una descrizione di fallback
        import logging
        logging.getLogger(__name__).warning(f"Groq API error: {exc}")
        return f"Policy '{policy_name}': {action_desc} su '{resource}' è {effect_it} per il ruolo '{role_name}'."


async def generate_role_description(
    role_name: str,
    permissions: str,
    language: str = "italiano",
) -> str:
    """
    Genera una descrizione del ruolo basata sui suoi permessi.

    Args:
        role_name   : nome del ruolo
        permissions : stringa permessi separata da virgola
        language    : lingua output
    """
    prompt = f"""Sei un esperto di sicurezza informatica. Descrivi questo ruolo applicativo
in {language} in modo chiaro per un utente non tecnico. Massimo 2 frasi.

Ruolo: {role_name}
Permessi: {permissions or "nessun permesso specifico"}

Spiega concretamente cosa può fare chi ha questo ruolo."""

    client = get_groq_client()

    try:
        response = await client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(f"Groq API error: {exc}")
        return f"Ruolo '{role_name}' con permessi: {permissions or 'nessuno'}."


async def generate_permission_description(
    resource: str,
    action: str,
    codename: str,
    role_name: Optional[str] = None,
    language: str = "italiano",
) -> str:
    """
    Genera una descrizione human-readable di un permesso atomico.
    Usa llama-3.1-70b-versatile per descrizioni più ricche e precise.

    Esempio output:
      "Consente di eliminare definitivamente i task dal sistema.
       Questa operazione non può essere annullata."
    """
    role_ctx = f" nel contesto del ruolo '{role_name}'" if role_name else ""
    action_map = {
        "read": "leggere/visualizzare",
        "write": "creare e modificare",
        "create": "creare nuovi",
        "update": "modificare",
        "delete": "eliminare",
        "*": "eseguire qualsiasi operazione su",
    }
    action_desc = action_map.get(action, f"eseguire '{action}' su")

    prompt = f"""Sei un esperto di sicurezza informatica e UX writing.
Descrivi questo permesso applicativo{role_ctx} in {language} per un utente non tecnico.
Scrivi esattamente 1-2 frasi. Sii specifico sulle conseguenze pratiche.

Permesso: {codename}
Risorsa: {resource}
Azione: {action_desc} {resource}

Esempi di buone descrizioni:
- "Consente di visualizzare i task assegnati al proprio team, ma non di modificarli."
- "Permette di eliminare definitivamente i report. Questa azione non può essere annullata."

Scrivi la descrizione (solo il testo, niente prefissi):"""

    client = get_groq_client()
    try:
        response = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=120,
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(f"Groq API error (permission desc): {exc}")
        return f"Consente di {action_desc} '{resource}'."

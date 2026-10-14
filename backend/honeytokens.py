"""
Honeytoken Vault Manager for Aegis-SOC
Generates, stores, and monitors decoy credentials, API keys, and tracking URLs.
"""

import uuid
from backend.database import get_db, get_honeytokens, record_honeytoken_hit

def create_honeytoken(name, token_type, description="Custom Honeytoken"):
    conn = get_db()
    cursor = conn.cursor()
    token_id = f"ht-{uuid.uuid4().hex[:8]}"

    if token_type.upper() == "API KEY":
        token_value = f"AKIA{uuid.uuid4().hex[:16].upper()}_DECOY"
    elif token_type.upper() == "CREDENTIALS":
        token_value = f"user_{uuid.uuid4().hex[:4]}:Pass#{uuid.uuid4().hex[:6]}"
    else:
        token_value = f"/decoy-url-vault-{uuid.uuid4().hex[:6]}"

    created_at = conn.execute("SELECT datetime('now')").fetchone()[0]

    cursor.execute('''
        INSERT INTO honeytokens (token_id, name, type, token_value, status, created_at)
        VALUES (?, ?, ?, ?, 'ACTIVE', ?)
    ''', (token_id, name, token_type, token_value, created_at))

    conn.commit()
    conn.close()
    return {
        "token_id": token_id,
        "name": name,
        "type": token_type,
        "token_value": token_value,
        "created_at": created_at
    }

def fetch_all_honeytokens():
    return get_honeytokens()


def tokens_used_in(text, token_type):
    """Honeytokens of this type (e.g. 'API Key', 'Credentials') whose value appears in text."""
    return [t for t in get_honeytokens() if t["type"] == token_type and t["token_value"] and t["token_value"] in text]

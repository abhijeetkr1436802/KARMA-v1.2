"""
Decoy State Manager for Aegis-SOC
Manages dynamic enable/disable states for Honeypots, Open Ports, and API Traps.
"""

from typing import Dict, Any
from backend.config import PORT_SSH_HONEYPOT, PORT_WEB_HONEYPOT, DECOY_PORTS

# Default Decoy Registry
DECOYS: Dict[str, Dict[str, Any]] = {
    "ssh_2222": {
        "id": "ssh_2222",
        "name": "SSH Honeypot Server",
        "type": "Protocol Honeypot",
        "port": PORT_SSH_HONEYPOT,
        "enabled": True,
        "description": "Traps SSH brute-force attempts and command probes"
    },
    "web_8080": {
        "id": "web_8080",
        "name": "Corporate Admin Portal Decoy",
        "type": "Web Honeypot",
        "port": PORT_WEB_HONEYPOT,
        "enabled": True,
        "description": "Fake web authentication portal trapping SQLi & credential harvest attempts"
    },
    "port_21": {
        "id": "port_21",
        "name": "FTP Service Decoy",
        "type": "Open Port",
        "port": 21,
        "enabled": True,
        "description": "Read-only FTP archive with directory navigation and active/passive downloads"
    },
    "port_23": {
        "id": "port_23",
        "name": "Telnet Remote Decoy",
        "type": "Open Port",
        "port": 23,
        "enabled": True,
        "description": "Traps legacy Telnet port enumeration and brute-force probes"
    },
    "port_3389": {
        "id": "port_3389",
        "name": "RDP Remote Desktop Decoy",
        "type": "Open Port",
        "port": 3389,
        "enabled": True,
        "description": "Listens for Remote Desktop Protocol connection attempts"
    },
    "api_auth_keys": {
        "id": "api_auth_keys",
        "name": "Decoy API Credentials Trap",
        "type": "API Endpoint",
        "port": PORT_WEB_HONEYPOT,
        "enabled": True,
        "description": "Fake REST endpoint `/api/v1/auth/keys` trapping unauthorized API key theft"
    },
    "api_db_export": {
        "id": "api_db_export",
        "name": "Decoy Database Export Trap",
        "type": "API Endpoint",
        "port": PORT_WEB_HONEYPOT,
        "enabled": True,
        "description": "Fake endpoint `/api/v1/admin/db_export` capturing data exfiltration attempts"
    }
}

import threading
import json
from backend.database import get_db
from backend.config import PORT_API

_lock = threading.RLock()
_initialized = False


def initialize_decoys():
    global _initialized
    with _lock:
        conn = get_db()
        try:
            for row in conn.execute("SELECT config FROM decoy_config"):
                decoy = json.loads(row[0])
                DECOYS[decoy["id"]] = decoy
            _initialized = True
        finally:
            conn.close()


def _save(decoy):
    if not _initialized:
        return
    conn = get_db()
    try:
        conn.execute("INSERT OR REPLACE INTO decoy_config VALUES (?, ?)", (decoy["id"], json.dumps(decoy)))
        conn.commit()
    finally:
        conn.close()


def get_all_decoys():
    with _lock:
        return [dict(d) for d in DECOYS.values()]


def is_decoy_enabled(decoy_id):
    with _lock:
        return bool(DECOYS.get(decoy_id, {}).get("enabled", False))


def is_port_enabled(port):
    with _lock:
        return any(d["port"] == port and d["enabled"] for d in DECOYS.values())


def toggle_decoy(decoy_id, enabled=None):
    with _lock:
        if decoy_id not in DECOYS:
            raise ValueError("Decoy not found")
        d = dict(DECOYS[decoy_id])
        d["enabled"] = not d["enabled"] if enabled is None else enabled
        _save(d)
        DECOYS[decoy_id] = d
        return {"status": "SUCCESS", "decoy": dict(d)}


def add_custom_decoy(name, port, service_type, description=""):
    with _lock:
        if not 1 <= port <= 65535 or port == PORT_API or any(d["port"] == port for d in DECOYS.values()):
            raise ValueError("Port must be available, unique, and between 1 and 65535")
        if len(DECOYS) >= 32:
            raise ValueError("Maximum of 32 decoys reached")
        d = {"id": f"custom_port_{port}", "name": name, "port": port,
             "type": service_type, "description": description, "enabled": True}
        _save(d)
        DECOYS[d["id"]] = d
        return dict(d)

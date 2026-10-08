"""
K.A.R.M.A SQLite Database Engine & Geolocation Mapping Layer
Manages threat logs, attacker IP profiles, MITRE ATT&CK statistics, and honeytoken tracking.
"""

import sqlite3
import json
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from backend import config
from backend.config import MAX_EVENTS
from backend.config import DB_PATH, DEFAULT_HONEYTOKENS

LAB_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"))


def get_geo_info(ip):
    """Explicit lab override only for LAN/loopback, not all non-global addresses."""
    try:
        address = ipaddress.ip_address(ip)
        address = getattr(address, "ipv4_mapped", None) or address
        local = any(address in network for network in LAB_NETWORKS)
    except ValueError:
        local = False
    if local and config.LAB_LOCATION_ENABLED:
        return {"country": config.LAB_COUNTRY, "city": config.LAB_CITY,
                "lat": config.LAB_LAT, "lng": config.LAB_LNG, "flag": "🌐",
                "geo_source": "configured_lab", "geo_label": "Configured lab location"}
    return {"country": "Private network" if local else "Unknown", "city": "Unknown",
            "lat": None, "lng": None, "flag": "🌐", "geo_source": "unknown",
            "geo_label": "Location unavailable"}


def with_location(row, ip_column="attacker_ip"):
    # Apply current configuration at read time to include historical LAN events.
    # Stored coordinates from earlier versions must not masquerade as measured geo.
    result = dict(row)
    result.update(get_geo_info(result[ip_column]))
    return result


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    return conn

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = get_db()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attacker_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                decoy_service TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                payload TEXT,
                mitre_id TEXT,
                mitre_name TEXT,
                mitre_tactic TEXT,
                risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                country TEXT,
                city TEXT,
                lat REAL,
                lng REAL,
                flag TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attackers (
                ip TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                total_attempts INTEGER DEFAULT 1,
                max_risk_score INTEGER DEFAULT 0,
                status TEXT DEFAULT 'MONITORING',
                services_targeted TEXT,
                country TEXT,
                city TEXT,
                lat REAL,
                lng REAL,
                flag TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeytokens (
                token_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                token_value TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL,
                hit_count INTEGER DEFAULT 0,
                last_hit_ip TEXT,
                last_hit_time TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine_list (
                ip TEXT PRIMARY KEY,
                quarantined_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT DEFAULT 'ACTIVE'
            )
        ''')

        cursor.execute('SELECT COUNT(*) FROM honeytokens')
        if cursor.fetchone()[0] == 0:
            now = datetime.now(timezone.utc).isoformat()
            for ht in DEFAULT_HONEYTOKENS:
                cursor.execute('''
                    INSERT INTO honeytokens (token_id, name, type, token_value, status, created_at)
                    VALUES (?, ?, ?, ?, 'ACTIVE', ?)
                ''', (ht['token_id'], ht['name'], ht['type'], ht['token_value'], now))

        # Migrate columns individually so partially upgraded databases recover safely.
        for table in ("attack_logs", "attackers"):
            existing = {r[1] for r in cursor.execute(f"PRAGMA table_info({table})")}
            for name, kind in (("country", "TEXT"), ("city", "TEXT"), ("lat", "REAL"), ("lng", "REAL"), ("flag", "TEXT"), ("geo_source", "TEXT"), ("geo_label", "TEXT")):
                if name not in existing:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}")
        if "quarantined" not in {r[1] for r in cursor.execute("PRAGMA table_info(attack_logs)")}:
            cursor.execute("ALTER TABLE attack_logs ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_ip ON attack_logs(attacker_ip, id)")
        cursor.execute("CREATE TABLE IF NOT EXISTS decoy_config (id TEXT PRIMARY KEY, config TEXT NOT NULL)")
        cursor.execute("CREATE TABLE IF NOT EXISTS runtime_settings (id TEXT PRIMARY KEY, value TEXT NOT NULL)")
        cursor.execute('''CREATE TABLE IF NOT EXISTS document_tokens (
            token_hash TEXT PRIMARY KEY, filename TEXT NOT NULL, source_ip TEXT NOT NULL,
            session_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)''')
        conn.commit()
    finally:
        conn.close()


def log_attack_event(attacker_ip, port, decoy_service, attack_type, payload, mitre_id, mitre_name, mitre_tactic, risk_score, severity):
    conn = get_db()
    try:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        attacker_ip = str(ipaddress.ip_address(attacker_ip))
        payload = str(payload or "")[:8192]
        geo = get_geo_info(attacker_ip)
        cursor.execute("BEGIN IMMEDIATE")

        cursor.execute('''
            INSERT INTO attack_logs (timestamp, attacker_ip, port, decoy_service, attack_type, payload, mitre_id, mitre_name, mitre_tactic, risk_score, severity, country, city, lat, lng, flag, geo_source, geo_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now, attacker_ip, port, decoy_service, attack_type, payload, mitre_id, mitre_name, mitre_tactic, risk_score, severity, geo['country'], geo['city'], geo['lat'], geo['lng'], geo['flag'], geo['geo_source'], geo['geo_label']))

        log_id = cursor.lastrowid
        cursor.execute('SELECT total_attempts, max_risk_score, services_targeted FROM attackers WHERE ip = ?', (attacker_ip,))
        row = cursor.fetchone()

        if row:
            attempts = row['total_attempts'] + 1
            max_score = max(row['max_risk_score'], risk_score)
            try:
                services = set(json.loads(row['services_targeted'] or "[]"))
            except Exception:
                services = set()
            services.add(decoy_service)
            services_str = json.dumps(list(services))

            cursor.execute('''
                UPDATE attackers
                SET last_seen = ?, total_attempts = ?, max_risk_score = ?, services_targeted = ?
                WHERE ip = ?
            ''', (now, attempts, max_score, services_str, attacker_ip))
        else:
            services_str = json.dumps([decoy_service])
            cursor.execute('''
                INSERT INTO attackers (ip, first_seen, last_seen, total_attempts, max_risk_score, status, services_targeted, country, city, lat, lng, flag)
                VALUES (?, ?, ?, 1, ?, 'MONITORING', ?, ?, ?, ?, ?, ?)
            ''', (attacker_ip, now, now, risk_score, services_str, geo['country'], geo['city'], geo['lat'], geo['lng'], geo['flag']))

        cursor.execute('UPDATE attackers SET country=?, city=?, lat=?, lng=?, flag=?, geo_source=?, geo_label=? WHERE ip=?',
                       (geo['country'], geo['city'], geo['lat'], geo['lng'], geo['flag'], geo['geo_source'], geo['geo_label'], attacker_ip))
        if log_id % 100 == 0:
            cursor.execute("DELETE FROM attack_logs WHERE id <= ?", (log_id - MAX_EVENTS,))
            cursor.execute("DELETE FROM attackers WHERE ip NOT IN (SELECT DISTINCT attacker_ip FROM attack_logs) AND ip NOT IN (SELECT ip FROM quarantine_list)")
        conn.commit()
        return log_id
    finally:
        conn.close()


def get_total_attack_count():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM attack_logs')
        count = cursor.fetchone()[0]
        return count
    finally:
        conn.close()


def get_recent_logs(limit=1000):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attack_logs ORDER BY id DESC LIMIT ?', (max(1, min(int(limit), 1000)),))
        rows = [with_location(r) for r in cursor.fetchall()]
        return rows
    finally:
        conn.close()


def get_attackers_list(limit=1000, offset=0):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attackers ORDER BY max_risk_score DESC, total_attempts DESC LIMIT ? OFFSET ?', (max(1, min(int(limit), 1000)), max(0, int(offset))))
        rows = [with_location(r, "ip") for r in cursor.fetchall()]
        return rows
    finally:
        conn.close()


def get_mitre_stats():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT mitre_id, mitre_name, mitre_tactic, COUNT(*) as hit_count, MAX(risk_score) as max_score
            FROM attack_logs
            WHERE mitre_id IS NOT NULL AND mitre_id != ''
            GROUP BY mitre_id, mitre_name, mitre_tactic
            ORDER BY hit_count DESC
        ''')
        rows = [dict(r) for r in cursor.fetchall()]
        return rows
    finally:
        conn.close()


def get_honeytokens():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM honeytokens ORDER BY hit_count DESC')
        rows = [dict(r) for r in cursor.fetchall()]
        return rows
    finally:
        conn.close()


def record_honeytoken_hit(token_id, ip_address):
    conn = get_db()
    try:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute('''
            UPDATE honeytokens
            SET hit_count = hit_count + 1, last_hit_ip = ?, last_hit_time = ?
            WHERE token_id = ? OR token_value = ?
        ''', (ip_address, now, token_id, token_id))
        conn.commit()
    finally:
        conn.close()


def add_to_quarantine(ip, reason, risk_score):
    conn = get_db()
    try:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute('''
            INSERT OR REPLACE INTO quarantine_list (ip, quarantined_at, reason, risk_score, status)
            VALUES (?, ?, ?, ?, 'ACTIVE')
        ''', (ip, now, reason, risk_score))
        cursor.execute("UPDATE attackers SET status = 'QUARANTINED' WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        conn.close()


def remove_from_quarantine(ip):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM quarantine_list WHERE ip = ?", (ip,))
        cursor.execute("UPDATE attackers SET status = 'MONITORING' WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        conn.close()


def get_quarantine_list():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM quarantine_list ORDER BY quarantined_at DESC')
        rows = [dict(r) for r in cursor.fetchall()]
        return rows
    finally:
        conn.close()


def clear_all_data():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM attack_logs')
        cursor.execute('DELETE FROM attackers')
        cursor.execute('DELETE FROM quarantine_list')
        cursor.execute('DELETE FROM document_tokens')
        cursor.execute('UPDATE honeytokens SET hit_count = 0, last_hit_ip = NULL, last_hit_time = NULL')
        conn.commit()
    finally:
        conn.close()


def is_quarantined(ip):
    conn = get_db()
    try:
        return conn.execute("SELECT 1 FROM quarantine_list WHERE ip=? AND status='ACTIVE'", (ip,)).fetchone() is not None
    finally:
        conn.close()


def get_event(log_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM attack_logs WHERE id=?", (log_id,)).fetchone()
        return with_location(row) if row else None
    finally:
        conn.close()


def get_attempt_count(ip):
    conn = get_db()
    try:
        row = conn.execute("SELECT total_attempts FROM attackers WHERE ip=?", (ip,)).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def mark_event_quarantine(log_id, quarantined):
    conn = get_db()
    try:
        conn.execute("UPDATE attack_logs SET quarantined=? WHERE id=?", (int(quarantined), log_id))
        conn.commit()
    finally:
        conn.close()

"""
Active Defense & Autonomous Quarantine Manager for Aegis-SOC
Maintains the block list enforced by KARMA sensors; optionally mirrored to the OS firewall (backend/firewall.py).
"""

from backend.config import QUARANTINE_SCORE_THRESHOLD
from backend import config, firewall
from backend.database import add_to_quarantine, remove_from_quarantine, get_quarantine_list

class ActiveDefenseManager:
    def __init__(self):
        self.auto_quarantine_enabled = config.ENGAGEMENT_MODE == 'contain'

    def load_mode(self):
        from backend.database import get_db
        import json
        conn = get_db()
        try:
            row = conn.execute("SELECT value FROM runtime_settings WHERE id='engagement_mode'").fetchone()
            mode = json.loads(row[0]) if row else config.ENGAGEMENT_MODE
            self.auto_quarantine_enabled = mode != 'observe'
        finally:
            conn.close()

    def set_mode(self, mode):
        from backend.database import get_db
        import json
        if mode not in ('observe', 'contain'):
            raise ValueError('Invalid engagement mode')
        conn = get_db()
        try:
            conn.execute("INSERT OR REPLACE INTO runtime_settings(id,value) VALUES('engagement_mode',?)", (json.dumps(mode),))
            conn.commit()
            self.auto_quarantine_enabled = mode == 'contain'
        finally:
            conn.close()

    def process_event(self, attacker_ip, risk_score, mitre_name):
        if not self.auto_quarantine_enabled:
            return False, "Auto-quarantine disabled"

        if risk_score >= QUARANTINE_SCORE_THRESHOLD:
            reason = f"High Risk Score ({risk_score}/100) triggered by {mitre_name}"
            add_to_quarantine(attacker_ip, reason, risk_score)
            firewall.block(attacker_ip)
            return True, f"IP {attacker_ip} automatically quarantined!"

        return False, "Score below threshold"

    def manual_quarantine(self, ip, reason="Manual Admin Containment Action"):
        add_to_quarantine(ip, reason, 100)
        firewall.block(ip)
        return True, f"IP {ip} manually quarantined."

    def enforce_ip_quarantine(self, ip, reason="Honeytoken Trap Containment"):
        add_to_quarantine(ip, reason, 95)
        firewall.block(ip)
        return True, f"IP {ip} quarantined."

    def manual_unblock(self, ip):
        remove_from_quarantine(ip)
        firewall.unblock(ip)
        return True, f"IP {ip} removed from quarantine."

    def get_status(self):
        quarantined = get_quarantine_list()
        return {
            "auto_quarantine_active": self.auto_quarantine_enabled,
            "threshold": QUARANTINE_SCORE_THRESHOLD,
            "quarantined_count": len(quarantined),
            "quarantined_ips": quarantined
        }

active_defense_engine = ActiveDefenseManager()

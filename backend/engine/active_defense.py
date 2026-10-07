"""
Active Defense & Autonomous Quarantine Manager for Aegis-SOC
Maintains the block list enforced by KARMA sensors. No OS firewall changes.
"""

from backend.config import QUARANTINE_SCORE_THRESHOLD
from backend.database import add_to_quarantine, remove_from_quarantine, get_quarantine_list

class ActiveDefenseManager:
    def __init__(self):
        self.auto_quarantine_enabled = True

    def process_event(self, attacker_ip, risk_score, mitre_name):
        if not self.auto_quarantine_enabled:
            return False, "Auto-quarantine disabled"

        if risk_score >= QUARANTINE_SCORE_THRESHOLD:
            reason = f"High Risk Score ({risk_score}/100) triggered by {mitre_name}"
            add_to_quarantine(attacker_ip, reason, risk_score)
            return True, f"IP {attacker_ip} automatically quarantined!"

        return False, "Score below threshold"

    def manual_quarantine(self, ip, reason="Manual Admin Containment Action"):
        add_to_quarantine(ip, reason, 100)
        return True, f"IP {ip} manually quarantined."

    def enforce_ip_quarantine(self, ip, reason="Honeytoken Trap Containment"):
        add_to_quarantine(ip, reason, 95)
        return True, f"IP {ip} quarantined."

    def manual_unblock(self, ip):
        remove_from_quarantine(ip)
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

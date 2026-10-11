"""
Dynamic Risk Calculation Engine for Aegis-SOC
Computes real-time threat scores (0 - 100) per event and cumulative attacker risk rating.
"""

from backend.config import QUARANTINE_SCORE_THRESHOLD


def calculate_event_risk(base_risk, attempt_count=1):
    # Repetition raises severity, but only an intrinsically high-risk event
    # (exploit, honeytoken, command execution) can reach the quarantine threshold.
    # Scans, page views and logins alone never lock an attacker out.
    freq_boost = min(30, max(0, attempt_count - 1) * 5)
    final_score = max(0, min(100, base_risk + freq_boost))
    if base_risk < QUARANTINE_SCORE_THRESHOLD:
        final_score = min(final_score, QUARANTINE_SCORE_THRESHOLD - 1)

    if final_score >= 85:
        severity = "CRITICAL"
    elif final_score >= 70:
        severity = "HIGH"
    elif final_score >= 45:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return final_score, severity

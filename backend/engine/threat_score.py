"""
Dynamic Risk Calculation Engine for Aegis-SOC
Computes real-time threat scores (0 - 100) per event and cumulative attacker risk rating.
"""

def calculate_event_risk(base_risk, attempt_count=1, repeats=0):
    # Dynamic multiplier based on frequency
    freq_boost = min(30, max(0, attempt_count - 1) * 5)
    final_score = max(0, min(100, base_risk + freq_boost))

    if final_score >= 85:
        severity = "CRITICAL"
    elif final_score >= 70:
        severity = "HIGH"
    elif final_score >= 45:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return final_score, severity

def generate_single_event_ai_report(event):
    """
    Generates a dedicated, highly detailed AI Forensic Report for a SINGLE specific attack event log.
    Includes exact executed hacker commands, IP location, MITRE ATT&CK mapping, intent breakdown, and SOC remediation.
    """
    if not event:
        return {}

    ip = event.get("attacker_ip", "0.0.0.0")
    service = event.get("decoy_service", "UNKNOWN")
    port = event.get("port", "N/A")
    payload = event.get("payload", "No raw payload recorded")
    attack_type = event.get("attack_type", "Network Attack")
    mitre_id = event.get("mitre_id", "T1046")
    mitre_name = event.get("mitre_name", "Network Service Discovery")
    mitre_tactic = event.get("mitre_tactic", "Reconnaissance")
    risk_score = event.get("risk_score", 50)
    severity = event.get("severity", "MEDIUM")
    timestamp = event.get("timestamp", "N/A")

    from backend.database import get_geo_info
    geo = get_geo_info(ip)

    payload_lower = payload.lower()

    # Dynamic Intent & Detailed Forensic Summary Analysis
    if service == 'DOCUMENT_DECOY':
        intent = 'Decoy document interaction'
        summary = (f"Recorded observation: {attack_type}. Source connection: {ip}. "
                   'A file read does not establish a completed download. An acknowledgement does not '
                   'establish local file opening, code execution, device identity or a backdoor.')
        remediations = ['Review the document session and original source IP in the event payload.',
                        'Correlate this observation with SSH telemetry before drawing conclusions.']
    elif "cat /etc/passwd" in payload_lower or "cat /etc/shadow" in payload_lower:
        intent = "Credential Harvesting & Password Database Leak Attempt"
        summary = (f"CRITICAL FORENSIC INCIDENT: The adversary at {ip} connected to decoy service '{service}' "
                   f"on Port {port} and executed an OS credential extraction payload: '{payload}'. "
                   f"The attacker attempted to read Linux account password hashes to compromise system access.")
        remediations = [
            f"Block IP {ip} at boundary firewall and quarantine network interface.",
            "Audit all Linux system account credentials for weak or default passwords.",
            "Ensure SSH root logins are disabled (`PermitRootLogin no` in /etc/ssh/sshd_config)."
        ]
    elif any(cmd in payload_lower for cmd in ["whoami", "id", "uname", "hostname", "pwd"]):
        intent = "System & Privilege Discovery Reconnaissance"
        summary = (f"HIGH SEVERITY INCIDENT: Attacker from {ip} reached decoy service '{service}' (Port {port}) "
                   f"and executed post-exploitation discovery commands: '{payload}'. "
                   f"The adversary was attempting to map active user privileges and system OS release parameters.")
        remediations = [
            f"Isolate IP address {ip} via K.A.R.M.A Active Defense Quarantine.",
            "Audit SSH and Telnet session logs for unauthorized concurrent logins.",
            "Enforce strict Multi-Factor Authentication (MFA) across all administrative management portals."
        ]
    elif "user" in payload_lower or "pass" in payload_lower or "login" in payload_lower:
        intent = "Interactive Authentication Brute-Force & Credential Probing"
        summary = (f"MEDIUM-HIGH SEVERITY: Attacker from {ip} attempted authentication brute-forcing against "
                   f"decoy service '{service}' on Port {port} with input payload: '{payload}'. "
                   f"The attempt was trapped by K.A.R.M.A deception listeners before gaining internal network access.")
        remediations = [
            "Apply automated IP rate limiting and Fail2Ban rules on public authentication services.",
            "Rotate any exposed user passwords that match dictionary attack patterns."
        ]
    elif any(sqli in payload_lower for sqli in ["select", "or 1=1", "' or", "union", "drop table", "insert"]):
        intent = "Web Application Vulnerability Exploitation (SQL Injection / OWASP Top 10)"
        summary = (f"HIGH SEVERITY WEB ATTACK: Attacker from {ip} submitted malicious SQL Injection exploit vectors "
                   f"against Web Decoy '{service}' on Port {port}: '{payload}'. "
                   f"The attack intended to bypass web login forms or exfiltrate database records.")
        remediations = [
            "Deploy Web Application Firewall (WAF) SQLi inspection rules.",
            "Ensure parameterised database queries (Prepared Statements) are enforced across production APIs."
        ]
    elif "api" in payload_lower or "token" in payload_lower or "honeytoken" in payload_lower or "key" in payload_lower:
        intent = "Targeted Honeytoken API Credential Exfiltration"
        summary = (f"CRITICAL HONEYTOKEN BREACH ALERT: Attacker from {ip} accessed decoy API honeytoken endpoint "
                   f"'{service}' (Port {port}): '{payload}'. "
                   f"This confirms active targeted reconnaissance or credential harvesting using decoy keys.")
        remediations = [
            f"Immediately quarantine IP {ip} across all cloud API gateways.",
            "Revoke compromised API token keys and audit IAM policy attachments."
        ]
    else:
        intent = "Network Service Probing & Scanner Fingerprinting"
        summary = (f"SERVICE RECONNAISSANCE: Attacker from {ip} probed decoy listener '{service}' "
                   f"on Port {port} with payload/interaction: '{payload}'. "
                   f"Behavior matches automated network port scanning tools (Nmap / Masscan / ZMap).")
        remediations = [
            f"Maintain continuous perimeter monitoring for IP {ip}.",
            "Ensure unrequired management ports remain closed or restricted to VPN ranges."
        ]

    return {
        "event_id": event.get("id"),
        "timestamp": timestamp,
        "attacker_ip": ip,
        "country": geo.get("country", "Unknown"),
        "city": geo.get("city", "Unknown"),
        "geo_source": geo.get('geo_source', 'unknown'),
        "geo_label": geo.get('geo_label', 'Location unavailable'),
        "flag": geo.get("flag", "🌐"),
        "lat": geo.get("lat"),
        "lng": geo.get("lng"),
        "decoy_service": service,
        "port": port,
        "attack_type": attack_type,
        "executed_payload": payload,
        "mitre_id": mitre_id,
        "mitre_name": mitre_name,
        "mitre_tactic": mitre_tactic,
        "risk_score": risk_score,
        "severity": severity,
        "intent_classification": intent,
        "forensic_summary": summary,
        "recommendations": remediations,
        "action_taken": f"Event recorded. Check sensor block status separately; no host firewall isolation."
    }

def generate_ai_threat_summary(attacker_ip, logs, attacker_profile):
    if not logs:
        return {
            "summary": "No telemetry recorded for this IP address yet.",
            "intent": "UNKNOWN",
            "threat_level": "LOW",
            "recommendations": ["Maintain standard perimeter monitoring."]
        }

    total_events = len(logs)
    services_hit = list(set(l['decoy_service'] for l in logs))
    mitre_ids = list(set(l['mitre_id'] for l in logs if l['mitre_id']))
    max_risk = max((l['risk_score'] for l in logs), default=0)

    # Classify Intent
    if services_hit == ['DOCUMENT_DECOY']:
        intent = 'Decoy document interactions'
        summary = (f'{total_events} document interaction observations recorded for {attacker_ip}. '
                   'Review the event payloads to distinguish file reads from submitted acknowledgements. '
                   'These observations do not establish a backdoor or computer compromise.')
        threat_level = 'MEDIUM' if max_risk >= 40 else 'LOW'
        remediations = ['Correlate document session identifiers with SSH events.']
    elif "T1078" in mitre_ids or "HONEYTOKEN" in services_hit:
        intent = "Targeted Credential Exploitation / Exfiltration"
        summary = (f"CRITICAL INCIDENT: Attacker from {attacker_ip} triggered a high-value Honeytoken (Decoy Credential/URL). "
                   f"This indicates active lateral movement or post-reconnaissance access attempt using decoy tokens.")
        threat_level = "CRITICAL"
        remediations = [
            "Immediately isolate associated host network interface.",
            "Revoke compromised credential signatures & rotate active session keys.",
            "Check the KARMA sensor block list; no host firewall isolation is performed."
        ]
    elif "T1059" in mitre_ids:
        intent = "Arbitrary Command Execution / Interactive Shell Compromise"
        summary = (f"HIGH SEVERITY: Attacker connected to SSH Decoy and attempted interactive shell commands. "
                   f"Captured commands include reconnaissance tools (whoami, id, cat /etc/passwd).")
        threat_level = "CRITICAL" if max_risk >= 85 else "HIGH"
        remediations = [
            "Block IP address at gateway firewall / IPTables.",
            "Audit internal Linux user accounts for unauthorized key additions.",
            "Enforce strict multi-factor authentication (MFA)."
        ]
    elif "T1190" in mitre_ids:
        intent = "Web Application Vulnerability Exploitation (OWASP Top 10)"
        summary = (f"HIGH SEVERITY: Attacker launched SQL Injection / Web Application exploit payloads against Web Admin Decoy. "
                   f"Pattern demonstrates automated web vulnerability scanner or targeted exploit script.")
        threat_level = "HIGH"
        remediations = [
            "Deploy Web Application Firewall (WAF) filtering rules.",
            f"Block IP {attacker_ip} across public web endpoints.",
            "Inspect web access logs for secondary payloads."
        ]
    elif "T1110" in mitre_ids:
        intent = "Automated Brute-Force Authentication Attack"
        summary = (f"MEDIUM-HIGH SEVERITY: Attacker launched repeated authentication attempts against decoy authentication interfaces. "
                   f"Recorded {total_events} failed login attempts across services: {', '.join(services_hit)}.")
        threat_level = "HIGH" if total_events > 10 else "MEDIUM"
        remediations = [
            "Enable Fail2Ban / IP rate limiting on public SSH and Login portals.",
            "Disallow password-based SSH logins in favor of SSH keys."
        ]
    else:
        intent = "Reconnaissance & Network Port Probing"
        summary = (f"LOW-MEDIUM SEVERITY: Attacker probed decoy network services ({', '.join(services_hit)}). "
                   f"Consistent with automated network port scanners (e.g., Nmap, Masscan).")
        threat_level = "MEDIUM" if max_risk >= 50 else "LOW"
        remediations = [
            "Filter unused external inbound ports at boundary router.",
            "Monitor IP for escalation or payload execution attempts."
        ]

    # Dynamic AI Executive Synthesis Report
    report = {
        "attacker_ip": attacker_ip,
        "threat_level": threat_level,
        "max_risk_score": max_risk,
        "total_events": total_events,
        "intent_classification": intent,
        "summary": summary,
        "targeted_services": services_hit,
        "mitre_techniques": mitre_ids,
        "recommendations": remediations,
        "ai_verdict": f"Aegis AI recommends immediate {'QUARANTINE' if threat_level in ['CRITICAL', 'HIGH'] else 'CONTINUOUS MONITORING'} for IP {attacker_ip}."
    }

    return report

"""
MITRE ATT&CK Framework Mapping Engine for Aegis-SOC
Automatically categorizes decoy hits and telemetry payloads into standardized MITRE techniques.
"""

MITRE_MAPPING_RULES = [
    {
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts (Honeytoken)",
        "mitre_tactic": "Initial Access",
        "keywords": ["honeytoken", "token_hit", "AKIAIOSFODNN7EXAMPLE", "secret-vault-admin"],
        "service": ["HONEYTOKEN"],
        "base_risk": 95,
        "severity": "CRITICAL"
    },
    {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",
        "keywords": ["select", "union", "drop table", "OR 1=1", "exec", "system(", "<script>", "../../", "/etc/passwd"],
        "service": ["WEB_HONEYPOT"],
        "base_risk": 85,
        "severity": "HIGH"
    },
    {
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "mitre_tactic": "Credential Access",
        "keywords": ["ssh_login_failed", "brute_force", "admin/password", "root/root"],
        "service": ["SSH_HONEYPOT", "WEB_HONEYPOT"],
        "base_risk": 70,
        "severity": "HIGH"
    },
    {
        "mitre_id": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "mitre_tactic": "Execution",
        "keywords": ["whoami", "id", "uname", "wget", "curl", "chmod", "cat /etc", "nc -e", "bash -i", "command_execution"],
        "service": ["SSH_HONEYPOT", "RAW_DECOY"],
        "base_risk": 90,
        "severity": "CRITICAL"
    },
    {
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "keywords": ["port_scan", "connect_probe", "syn_scan"],
        "service": ["RAW_DECOY", "PORT_SCANNER", "SSH_HONEYPOT"],
        "base_risk": 45,
        "severity": "MEDIUM"
    },
    {
        "mitre_id": "T1595",
        "mitre_name": "Active Scanning",
        "mitre_tactic": "Reconnaissance",
        "keywords": ["directory_traversal", "fuzzing", "/.env", "/wp-login.php", "/phpmyadmin"],
        "service": ["WEB_HONEYPOT"],
        "base_risk": 55,
        "severity": "MEDIUM"
    }
]

def map_payload_to_mitre(decoy_service, attack_type, payload=""):
    payload_lower = (payload or "").lower()
    attack_type_lower = (attack_type or "").lower()
    combined_text = f"{attack_type_lower} {payload_lower}"

    for rule in MITRE_MAPPING_RULES:
        # Check service match
        if decoy_service in rule["service"] or "ALL" in rule["service"]:
            # Check keyword match
            for kw in rule["keywords"]:
                import re
                if re.search(r"(?<!\w)" + re.escape(kw.lower()) + r"(?!\w)", combined_text):
                    return {
                        "mitre_id": rule["mitre_id"],
                        "mitre_name": rule["mitre_name"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "risk_score": rule["base_risk"],
                        "severity": rule["severity"]
                    }

    # Default Fallback mapping
    if "executed command" in payload_lower:
        # Harmless commands (ls, cd, pwd) inside the fake shell: execution, but not quarantine-worthy.
        return {
            "mitre_id": "T1059",
            "mitre_name": "Command and Scripting Interpreter",
            "mitre_tactic": "Execution",
            "risk_score": 60,
            "severity": "MEDIUM"
        }
    if "ssh" in decoy_service.lower():
        return {
            "mitre_id": "T1110",
            "mitre_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "risk_score": 65,
            "severity": "MEDIUM"
        }
    elif "web" in decoy_service.lower():
        return {
            "mitre_id": "T1595",
            "mitre_name": "Active Scanning",
            "mitre_tactic": "Reconnaissance",
            "risk_score": 50,
            "severity": "MEDIUM"
        }
    else:
        return {
            "mitre_id": "T1046",
            "mitre_name": "Network Service Discovery",
            "mitre_tactic": "Discovery",
            "risk_score": 40,
            "severity": "LOW"
        }

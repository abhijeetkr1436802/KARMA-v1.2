/*
 * MITRE ATT&CK Catalog & Heatmap Renderer for Enterprise Cloud SIEM
 */

const MITRE_CATALOG = [
    { id: "T1110", name: "Brute Force", tactic: "Credential Access", desc: "Decoy SSH & Web auth brute-force attempts" },
    { id: "T1190", name: "Exploit Public Application", tactic: "Initial Access", desc: "SQL Injection, XSS & OWASP payloads" },
    { id: "T1059", name: "Command & Script Interpreter", tactic: "Execution", desc: "Shell commands trapped in SSH decoy" },
    { id: "T1046", name: "Network Service Discovery", tactic: "Discovery", desc: "Decoy port scans (FTP, Telnet, RDP)" },
    { id: "T1078", name: "Valid Accounts (Honeytoken)", tactic: "Initial Access", desc: "Leaked AWS keys & backdoor URLs" },
    { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance", desc: "Web directory fuzzing & probes" },
    { id: "T1005", name: "Data from Local System", tactic: "Collection", desc: "Files downloaded from the FTP/SFTP decoys" }
];

function renderMitreGrid(stats) {
    const container = document.getElementById("mitreGrid");
    if (!container) return;

    const statsMap = {};
    (stats || []).forEach(s => {
        statsMap[s.mitre_id] = s.hit_count;
    });

    // Techniques seen in the logs but missing from the catalog still get a card.
    const known = new Set(MITRE_CATALOG.map(i => i.id));
    const extra = (stats || []).filter(s => !known.has(s.mitre_id))
        .map(s => ({ id: s.mitre_id, name: s.mitre_name || s.mitre_id, tactic: s.mitre_tactic || "", desc: "Observed by KARMA sensors" }));
    container.innerHTML = MITRE_CATALOG.concat(extra).map(item => {
        const count = statsMap[item.id] || 0;
        const isTriggered = count > 0;

        return `
            <div class="mitre-item-card ${isTriggered ? 'active-hit' : ''}">
                <div class="mitre-code">${escapeHTML(item.id)}</div>
                <div class="mitre-name">${escapeHTML(item.name)}</div>
                <div class="mitre-tactic">${escapeHTML(item.tactic)}</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${escapeHTML(item.desc)}</div>
                <div class="mitre-hits">${isTriggered ? `⚡ ${count} Hits Logged` : '0 Hits'}</div>
            </div>
        `;
    }).join('');
}

// Same-origin API requests carry a CSRF header; authentication stays in an HttpOnly cookie.
const nativeFetch = window.fetch.bind(window);
window.fetch = async function (input, options = {}) {
    const url = new URL(typeof input === 'string' ? input : input.url, window.location.href);
    if (url.origin !== window.location.origin) return nativeFetch(input, options);
    const headers = new Headers(options.headers || {});
    headers.set('X-Karma-Request', '1');
    const response = await nativeFetch(input, { ...options, headers });
    if (response.status === 401) window.location.assign('/login');
    if (!response.ok) {
        const data = await response.clone().json().catch(() => ({}));
        throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status})`);
    }
    return response;
};

/*
 * Enterprise Cloud SIEM Main Application Logic
 * Integrates Leaflet Attacker Origin World Map, Light/Dark Theme Switcher,
 * Collapsible Sidebar, and Telemetry Dispatcher.
 */

let leafMap = null;
let mapMarkersLayer = null;
let threatsMap = null;
let threatsMarkersLayer = null;
let mapBounds = null;

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById('timeFilterSelect')?.addEventListener('change', fetchDashboardData);
    for (const id of ['btnLaunchTester', 'btnLaunchSim']) {
        const button = document.getElementById(id);
        if (button) { button.disabled = true; button.title = 'Use the local desktop testing tools'; }
    }
    initTheme();
    if (typeof Chart !== "undefined") initSiemCharts();
    if (typeof L !== "undefined") initLeafletMap();
    fetchDashboardData();
    setupEventListeners();
    initWebSocketConnection();
});

// THEME SWITCHER LOGIC (Light / Dark Mode)
function initTheme() {
    const savedTheme = localStorage.getItem('siem_theme') || 'dark';
    setTheme(savedTheme);
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('siem_theme', theme);

    // Synchronize Chart.js colors with Clay Theme
    if (typeof getChartColors === 'function') {
        const c = getChartColors();
        if (typeof timeSeriesChartInstance !== 'undefined' && timeSeriesChartInstance && timeSeriesChartInstance.options.scales) {
            timeSeriesChartInstance.options.scales.x.ticks.color = c.textColor;
            timeSeriesChartInstance.options.scales.x.grid.color = c.gridColor;
            timeSeriesChartInstance.options.scales.y.ticks.color = c.textColor;
            timeSeriesChartInstance.options.scales.y.grid.color = c.gridColor;
            timeSeriesChartInstance.update();
        }
        if (typeof productsBarChartInstance !== 'undefined' && productsBarChartInstance && productsBarChartInstance.options.scales) {
            productsBarChartInstance.options.scales.x.ticks.color = c.textColor;
            productsBarChartInstance.options.scales.y.ticks.color = c.textColor;
            productsBarChartInstance.options.scales.y.grid.color = c.gridColor;
            productsBarChartInstance.update();
        }
        if (typeof logTypesDoughnutChartInstance !== 'undefined' && logTypesDoughnutChartInstance) {
            logTypesDoughnutChartInstance.data.datasets[0].borderColor = theme === 'dark' ? '#172033' : '#f9fbfe';
            if (logTypesDoughnutChartInstance.options.plugins && logTypesDoughnutChartInstance.options.plugins.legend) {
                logTypesDoughnutChartInstance.options.plugins.legend.labels.color = c.textColor;
            }
            logTypesDoughnutChartInstance.update();
        }
        if (typeof eventActionsHorizontalChartInstance !== 'undefined' && eventActionsHorizontalChartInstance && eventActionsHorizontalChartInstance.options.scales) {
            eventActionsHorizontalChartInstance.options.scales.x.ticks.color = c.textColor;
            eventActionsHorizontalChartInstance.options.scales.x.grid.color = c.gridColor;
            eventActionsHorizontalChartInstance.options.scales.y.ticks.color = c.textColor;
            eventActionsHorizontalChartInstance.update();
        }
    }
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = current === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
}

// ATTACKER ORIGIN WORLD MAP INITIALIZATION (Leaflet.js)
function initLeafletMap() {
    const container1 = document.getElementById('attackerWorldMap');
    if (container1) {
        leafMap = L.map('attackerWorldMap', { zoomControl: true, attributionControl: true }).setView([20, 0], 2);
        mapMarkersLayer = L.layerGroup().addTo(leafMap);
    }

    const container2 = document.getElementById('threatsWorldMap');
    if (container2) {
        threatsMap = L.map('threatsWorldMap', { zoomControl: true, attributionControl: true }).setView([20, 0], 2);
        threatsMarkersLayer = L.layerGroup().addTo(threatsMap);
    }

    for (const m of [leafMap, threatsMap]) if (m) addBasemap(m);
}

// Basemaps tried in order: Esri satellite imagery with place labels, then OpenStreetMap.
const BASEMAPS = [
    {
        url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
        labels: 'https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}',
        maxZoom: 18,
        attribution: 'Imagery &copy; <a href="https://www.esri.com/">Esri</a>, Maxar, Earthstar Geographics &amp; the GIS User Community'
    },
    {
        url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
        maxZoom: 19,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }
];

function addBasemap(map, i = 0) {
    const base = BASEMAPS[i];
    if (!base) {
        map.getContainer().classList.add('map-offline');  // every source failed: say so instead of a grey box
        return;
    }
    const options = { maxZoom: base.maxZoom, referrerPolicy: 'strict-origin-when-cross-origin', attribution: base.attribution };
    const layers = [L.tileLayer(base.url, options)];
    if (base.labels) layers.push(L.tileLayer(base.labels, { ...options, attribution: '' }));
    let loaded = 0, failed = 0;
    layers[0].on('tileload', () => { loaded++; map.getContainer().classList.remove('map-offline'); });
    layers[0].on('tileerror', () => {
        // ponytail: falls back after 4 failures with nothing loaded; a flaky link may still mix in grey tiles
        if (++failed === 4 && !loaded) {
            layers.forEach(l => map.removeLayer(l));
            addBasemap(map, i + 1);
        }
    });
    map.setMaxZoom(base.maxZoom);
    layers.forEach(l => l.addTo(map));
}

// Zoom each map onto the attackers once, when it is visible (a map in a hidden tab has no size yet).
function fitMap(map) {
    if (!map || !mapBounds || map._karmaFitted || !map.getSize().x) return;
    map.fitBounds(mapBounds.pad(0.5), { maxZoom: 12 });
    map._karmaFitted = true;
}

function updateMapMarkers(attackers) {
    if (mapMarkersLayer) mapMarkersLayer.clearLayers();
    if (threatsMarkersLayer) threatsMarkersLayer.clearLayers();

    attackers = attackers || [];
    const mapped = attackers.filter(a => Number.isFinite(a.lat) && Number.isFinite(a.lng) && Math.abs(a.lat) <= 90 && Math.abs(a.lng) <= 180);
    const labCount = mapped.filter(a => a.geo_source === 'configured_lab').length;
    const summary = attackers.length
        ? `${mapped.length} of ${attackers.length} loaded profiles mapped. ${labCount} use a configured lab location; ${attackers.length - mapped.length} have no location. Lab markers do not represent measured attacker locations.`
        : 'Awaiting events. Private LAN events use the configured lab location.';
    for (const id of ['attackerMapStatus', 'threatsMapStatus']) {
        const element = document.getElementById(id);
        if (element) element.textContent = summary;
    }

    mapped.forEach(a => {
        const lat = a.lat;
        const lng = a.lng;
        const flag = a.flag || "🌐";
        const country = a.country || "Unknown Origin";
        const score = a.max_risk_score ?? 50;

        const circleColor = score >= 75 ? '#ef4444' : (score >= 50 ? '#f59e0b' : '#3b82f6');

        const popupHTML = `
            <div style="font-family: sans-serif; padding: 4px;">
                <h4 style="margin: 0 0 4px 0; font-size: 13px;">${escapeHTML(flag)} ${escapeHTML(a.city || 'Unknown')}, ${escapeHTML(country)}</h4>
                <p style="margin: 0 0 6px; font-size: 12px;"><b>${escapeHTML(a.geo_label || 'Location unavailable')}</b></p>
                <p style="margin: 0; font-size: 11px; color: #64748b;"><b>IP:</b> <code style="color: #0070f3;">${a.ip}</code></p>
                <p style="margin: 2px 0; font-size: 11px; color: #64748b;"><b>Attempts:</b> ${a.total_attempts} | <b>Risk Score:</b> <strong style="color:${circleColor}">${score}/100</strong></p>
                <p style="margin: 4px 0 0 0;"><button onclick="inspectAIReport('${a.ip}')" style="background:#0070f3; color:#fff; border:none; padding:3px 8px; border-radius:4px; font-size:10px; cursor:pointer;">Rule-based Report</button></p>
            </div>
        `;

        if (leafMap && mapMarkersLayer) {
            const marker1 = L.circleMarker([lat, lng], {
                radius: 8 + Math.min(10, a.total_attempts),
                fillColor: circleColor,
                color: '#ffffff',
                weight: 2,
                opacity: 0.9,
                fillOpacity: 0.7
            });
            marker1.bindPopup(popupHTML);
            marker1.bindTooltip(`${escapeHTML(a.city || 'Unknown')} — ${escapeHTML(a.geo_label || 'Location unavailable')}`);
            mapMarkersLayer.addLayer(marker1);
        }

        if (threatsMap && threatsMarkersLayer) {
            const marker2 = L.circleMarker([lat, lng], {
                radius: 8 + Math.min(10, a.total_attempts),
                fillColor: circleColor,
                color: '#ffffff',
                weight: 2,
                opacity: 0.9,
                fillOpacity: 0.7
            });
            marker2.bindPopup(popupHTML);
            marker2.bindTooltip(`${escapeHTML(a.city || 'Unknown')} — ${escapeHTML(a.geo_label || 'Location unavailable')}`);
            threatsMarkersLayer.addLayer(marker2);
        }
    });

    if (mapped.length && !mapBounds) {
        mapBounds = L.latLngBounds(mapped.map(a => [a.lat, a.lng]));
        fitMap(leafMap);
        fitMap(threatsMap);
    }
}

let dashboardRefreshTimer = null;
function initWebSocketConnection() {
    new TelemetryWebSocket((event) => {
        prependTelemetryRow(event);
        if (event.decoy_service === 'DOCUMENT_DECOY') showDocumentAlert(event);
        if (!dashboardRefreshTimer) dashboardRefreshTimer = setTimeout(() => { dashboardRefreshTimer = null; fetchDashboardData(); }, 1000);
    }, (connected) => {
        if (connected) fetchDashboardData();
    });
}

async function fetchDashboardData() {
    try {
        const [statusRes, logsRes, attackersRes, mitreRes, honeytokensRes, documentsRes] = await Promise.all([
            fetch("/api/status"),
            fetch(`/api/logs?limit=${document.getElementById("timeFilterSelect")?.value || 50}`),
            fetch("/api/attackers"),
            fetch("/api/mitre"),
            fetch("/api/honeytokens"),
            fetch('/api/document-events')
        ]);

        const status = await statusRes.json();
        const logs = await logsRes.json();
        const attackers = await attackersRes.json();
        const mitre = await mitreRes.json();
        const honeytokens = await honeytokensRes.json();
        renderDocumentEvents(await documentsRes.json());
        const modeSelect = document.getElementById('engagementMode');
        if (modeSelect && document.activeElement !== modeSelect) modeSelect.value = status.engagement_mode;

        // Update Stat Counters
        document.getElementById("statTotalAttacks").innerText = status.metrics.total_attacks_logged;
        document.getElementById("statAuditEvents").innerText = status.metrics.web_events;
        document.getElementById("statEndpointEvents").innerText = status.metrics.network_events;
        document.getElementById("statQuarantined").innerText = status.metrics.quarantined_ips;

        // Render Tables & SIEM Charts
        renderTelemetryTable(logs);
        updateSiemCharts(logs);
        renderMitreGrid(mitre);
        renderAttackersTable(attackers);
        renderHoneytokenList(honeytokens);

        // Fetch Decoys
        fetchDecoys();

        // Update World Map Markers
        updateMapMarkers(attackers);

    } catch (err) {
        console.error("[Aegis Cloud SIEM] Fetch error:", err);
    }
}

function documentEventText(event) {
    let details = {};
    try { details = JSON.parse(event.payload || '{}'); } catch (_) { /* Retain event label if older payload differs. */ }
    return `${event.attack_type}: ${details.file || 'document'} · Source ${event.attacker_ip} · Original session IP ${details.original_source_ip || 'unknown'}`;
}

function showDocumentAlert(event) {
    const alert = document.getElementById('documentAlert');
    const text = document.getElementById('documentAlertText');
    if (alert && text) {
        text.textContent = documentEventText(event);
        alert.hidden = false;
    }
}

function renderDocumentEvents(events) {
    const container = document.getElementById('documentEvents');
    if (!container) return;
    container.innerHTML = events.length ? events.map(event => `<p style="font-size:12px">${escapeHTML(event.timestamp)} · ${escapeHTML(documentEventText(event))}</p>`).join('')
        : '<p style="font-size:12px">No document interactions recorded yet.</p>';
}

async function setEngagementMode(mode) {
    const status = document.getElementById('engagementStatus');
    try {
        await fetch('/api/engagement', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mode})});
        status.textContent = `${mode === 'observe' ? 'Observation enabled: automatic quarantine disabled.' : 'Containment enabled: high-risk sessions are blocked.'} Existing IP blocks remain active.`;
    } catch (error) {
        status.textContent = `Could not change mode: ${error.message}`;
        fetchDashboardData();
    }
}

async function fetchDecoys() {
    try {
        const res = await fetch("/api/decoys");
        if (!res.ok) {
            console.warn("Decoys endpoint returned error:", res.status);
            return;
        }
        const decoys = await res.json();
        if (Array.isArray(decoys)) {
            renderDecoyList(decoys);
        }
    } catch (err) {
        console.error("Error fetching decoys:", err);
    }
}

function renderDecoyList(decoys) {
    const container = document.getElementById("decoyListContainer");
    if (!container) return;

    if (!Array.isArray(decoys) || decoys.length === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); font-size: 12px; padding: 20px;">No decoys configured.</div>`;
        return;
    }

    container.innerHTML = decoys.map(d => {
        const isEnabled = d.status === 'ACTIVE';
        const statusBadge = isEnabled
            ? `<span class="decoy-badge active" style="background: rgba(16, 185, 129, 0.15); color: #10b981; padding: 3px 8px; border-radius: 6px; font-weight: 700; font-size: 11px;">🟢 ACTIVE & LISTENING</span>`
            : `<span class="decoy-badge disabled" style="background: rgba(239, 68, 68, 0.15); color: #ef4444; padding: 3px 8px; border-radius: 6px; font-weight: 700; font-size: 11px;">${escapeHTML(d.status || "STOPPED")}</span>`;

        return `
            <div class="decoy-card">
                <div class="decoy-card-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div>
                        <div class="decoy-name" style="font-weight: 700; font-size: 14px; color: var(--text-primary);">${escapeHTML(d.name)}</div>
                        <div style="font-size: 11px; color: var(--accent-blue); font-family: monospace; margin-top: 2px;">
                            ${escapeHTML(d.type)} ${d.port ? `• Port ${d.port}` : ''}
                        </div>
                    </div>
                    ${statusBadge}
                </div>
                <div class="decoy-desc" style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.4;">${escapeHTML(d.error || d.description || '')}</div>
                <div class="decoy-card-footer" style="font-size: 11px; color: var(--text-muted); border-top: 1px solid var(--border-subtle); padding-top: 8px; display: flex; justify-content: space-between;">
                    <span>Decoy ID: <code>${escapeHTML(d.id)}</code></span><button class="btn btn-sm" onclick="toggleDecoyStatus('${d.id}', ${!d.enabled})">${d.enabled ? "Disable" : "Enable"}</button>
                    <span>Port State: <strong style="color: ${isEnabled ? '#10b981' : '#ef4444'};">${escapeHTML(d.status || "STOPPED")}</strong></span>
                </div>
            </div>
        `;
    }).join('');
}

async function toggleDecoyStatus(decoyId, enabled) {
    try {
        await fetch("/api/decoys/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: decoyId, enabled: enabled })
        });
        fetchDecoys();
    } catch (err) {
        console.error("Error toggling decoy:", err);
    }
}

function renderTelemetryTable(logs) {
    const tbody = document.getElementById("telemetryTableBody");
    if (!tbody) return;

    if (!logs || logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-cell">Awaiting SIEM log telemetry...</td></tr>`;
        return;
    }

    tbody.innerHTML = logs.map(l => createTelemetryRowHTML(l)).join('');
}

function prependTelemetryRow(l) {
    const tbody = document.getElementById("telemetryTableBody");
    if (!tbody) return;

    if (tbody.children.length === 1 && tbody.children[0].cells.length === 1) {
        tbody.innerHTML = "";
    }

    const tr = document.createElement("tr");
    tr.innerHTML = createTelemetryRowHTML(l, true);
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.children.length > 100) tbody.lastElementChild.remove();

    tr.style.background = "rgba(0, 112, 243, 0.1)";
    setTimeout(() => { tr.style.background = "transparent"; }, 1500);
}

function createTelemetryRowHTML(l, innerOnly = false) {
    const timestampStr = l.timestamp ? l.timestamp.replace("T", " ").substring(0, 19) : "N/A";
    const payloadSnippet = l.payload ? (l.payload.length > 32 ? l.payload.substring(0, 32) + "..." : l.payload) : "-";
    const flag = l.flag || "🌐";
    const country = l.country || "Unknown";

    const content = `
        <td class="font-mono" style="color: var(--text-muted); font-size: 11px;">${timestampStr}</td>
        <td><span style="margin-right: 4px;">${escapeHTML(flag)}</span> ${escapeHTML(country)}${l.geo_source === 'configured_lab' ? '<br><small>Configured lab location</small>' : ''}</td>
        <td class="font-mono" style="color: var(--accent-blue); font-weight: 600;">${l.attacker_ip}</td>
        <td><span class="widget-tag">${escapeHTML(l.decoy_service)}</span></td>
        <td class="font-mono" style="font-size: 11px;">${escapeHTML(payloadSnippet)}</td>
        <td><span class="font-mono" style="color: var(--accent-amber); font-weight: bold;">${escapeHTML(l.mitre_id || '—')}</span> ${escapeHTML(l.mitre_name || '')}</td>
        <td><span class="sev-badge sev-${l.severity}">${l.severity}</span></td>
        <td>
            <button class="btn btn-sm btn-primary" style="font-size: 11px; font-weight: 600; padding: 2px 8px;" onclick="inspectEventAIReport(${l.id})">⚡ Rule-based Report</button>
        </td>
    `;
    return innerOnly ? content : `<tr>${content}</tr>`;
}

function renderAttackersTable(attackers) {
    const tbody = document.getElementById("attackersTableBody");
    if (!tbody) return;

    if (!attackers || attackers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No adversary profiles recorded.</td></tr>`;
        return;
    }

    tbody.innerHTML = attackers.map(a => {
        const isQuarantined = a.status === 'QUARANTINED';
        const statusBadge = isQuarantined
            ? `<span class="sev-badge sev-CRITICAL">SENSOR BLOCKED</span>`
            : `<span class="sev-badge sev-LOW">MONITORING</span>`;

        const actionBtn = isQuarantined
            ? `<button class="btn btn-sm btn-secondary" onclick="toggleIPBlock('${a.ip}', 'UNBLOCK')">Unblock</button>`
            : `<button class="btn btn-sm btn-secondary" onclick="toggleIPBlock('${a.ip}', 'BLOCK')">Block on sensors</button>`;

        const flag = a.flag || "🌐";
        const country = a.country || "Unknown";

        return `
            <tr>
                <td class="font-mono" style="color: var(--accent-blue); font-weight: 600;">${a.ip}</td>
                <td>${escapeHTML(flag)} ${escapeHTML(country)}${a.geo_source === 'configured_lab' ? `<br><small>${escapeHTML(a.city)} · Configured lab location</small>` : ''}</td>
                <td class="font-mono" style="font-size: 11px; color: var(--text-muted);">${(a.last_seen || '').replace('T', ' ').substring(0, 16)}</td>
                <td class="font-mono" style="text-align: center;">${a.total_attempts}</td>
                <td class="font-mono" style="color: ${a.max_risk_score >= 75 ? '#ef4444' : '#10b981'}; font-weight: bold;">${a.max_risk_score} / 100</td>
                <td>${statusBadge}</td>
                <td>
                    <div style="display: flex; gap: 4px;">
                        <button class="btn btn-sm btn-primary" onclick="inspectAIReport('${a.ip}')">Inspect</button>
                        ${actionBtn}
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

function renderHoneytokenList(tokens) {
    const container = document.getElementById("honeytokenList");
    if (!container) return;

    if (!tokens || tokens.length === 0) {
        container.innerHTML = `<div class="empty-cell">No honeytokens configured.</div>`;
        return;
    }

    container.innerHTML = tokens.map(t => {
        const isHit = t.hit_count > 0;
        return `
            <div class="ht-card">
                <div style="display: flex; justify-content: space-between;">
                    <span class="ht-name">${escapeHTML(t.name)}</span>
                    <span class="ht-type">${escapeHTML(t.type)}</span>
                </div>
                <div class="ht-val">${escapeHTML(t.token_value)}</div>
                <div class="ht-status ${isHit ? 'hit' : ''}">
                    ${isHit ? `🚨 TRIGGERED (${t.hit_count} Hits)` : '🟢 ACTIVE'}
                </div>
            </div>
        `;
    }).join('');
}

async function inspectEventAIReport(logId) {
    const modal = document.getElementById("aiReportModal");
    const content = document.getElementById("modalReportContent");

    content.innerHTML = `<p style="text-align:center; color: var(--text-secondary); padding: 20px;">Generating rule-based forensic Report for Event <b>#${logId}</b>...</p>`;
    modal.classList.add("open");

    try {
        const res = await fetch(`/api/ai-report/event/${logId}`);
        if (!res.ok) throw new Error("Failed to load event forensic report");
        const data = await res.json();

        content.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0,112,243,0.08); padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; border: 1px solid rgba(0,112,243,0.2);">
                <div>
                    <span style="font-size: 11px; color: var(--accent-blue); font-weight: bold; text-transform: uppercase;">INCIDENT EVENT #${data.event_id || logId}</span>
                    <div style="font-size: 15px; font-weight: 800; color: var(--text-primary); margin-top: 2px;">
                        ${escapeHTML(data.intent_classification)}
                    </div>
                </div>
                <span class="sev-badge sev-${data.severity}" style="font-size: 12px; padding: 4px 10px;">${data.severity} (${data.risk_score}/100)</span>
            </div>

            <!-- INCIDENT METADATA GRID -->
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 16px; font-size: 12px;">
                <div style="background: var(--bg-subtle); padding: 10px; border-radius: 6px;">
                    <div style="color: var(--text-muted); font-size: 11px;">ATTACKER IP / ORIGIN</div>
                    <div style="font-weight: 700; color: var(--accent-blue); margin-top: 2px;">
                        <span style="margin-right: 4px;">${data.flag || '🌐'}</span> ${escapeHTML(data.attacker_ip)}
                    </div>
                    <div style="font-size: 10px; color: var(--text-secondary); margin-top: 2px;">${escapeHTML(data.city || '')}, ${escapeHTML(data.country || 'Local Network')} · ${escapeHTML(data.geo_label || 'Location unavailable')}</div>
                </div>

                <div style="background: var(--bg-subtle); padding: 10px; border-radius: 6px;">
                    <div style="color: var(--text-muted); font-size: 11px;">TARGET DECOY SERVICE</div>
                    <div style="font-weight: 700; color: var(--text-primary); margin-top: 2px;">
                        <span class="widget-tag">${escapeHTML(data.decoy_service)}</span>
                    </div>
                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">Port ${data.port}</div>
                </div>

                <div style="background: var(--bg-subtle); padding: 10px; border-radius: 6px;">
                    <div style="color: var(--text-muted); font-size: 11px;">MITRE ATT&CK TTP</div>
                    <div style="font-weight: 700; color: var(--accent-amber); margin-top: 2px;">
                        ${data.mitre_id}
                    </div>
                    <div style="font-size: 10px; color: var(--text-secondary); margin-top: 2px;">${escapeHTML(data.mitre_name || '')}</div>
                </div>

                <div style="background: var(--bg-subtle); padding: 10px; border-radius: 6px;">
                    <div style="color: var(--text-muted); font-size: 11px;">TIMESTAMP</div>
                    <div style="font-weight: 600; color: var(--text-primary); margin-top: 2px; font-family: monospace;">
                        ${(data.timestamp || '').replace('T', ' ').substring(0, 19)}
                    </div>
                </div>
            </div>

            <!-- EXECUTED PAYLOAD / HACKER COMMAND -->
            <div style="margin-bottom: 16px;">
                <p style="font-weight: 700; font-size: 12px; color: var(--text-primary); margin-bottom: 6px;">💻 Captured Executed Hacker Command / Payload:</p>
                <div style="background: #020617; border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; padding: 12px 14px; border-radius: 6px; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 140px; overflow-y: auto;">${escapeHTML(data.executed_payload)}</div>
            </div>

            <!-- FORENSIC SUMMARY ANALYSIS -->
            <div style="background: var(--bg-subtle); padding: 14px; border-left: 4px solid var(--accent-blue); border-radius: 6px; margin-bottom: 16px;">
                <p style="font-weight: 700; font-size: 12px; color: var(--text-primary); margin-bottom: 4px;">🔍 AI Executive Forensic Analysis:</p>
                <p style="color: var(--text-secondary); font-size: 12px; line-height: 1.5; margin: 0;">${escapeHTML(data.forensic_summary)}</p>
            </div>

            <!-- RECOMMENDED SOC ACTION PLAN -->
            <div style="margin-bottom: 12px;">
                <p style="font-weight: 700; font-size: 12px; color: var(--text-primary); margin-bottom: 6px;">🛡️ Recommended SOC Remediation Action Plan:</p>
                <ul style="padding-left: 20px; color: var(--text-secondary); font-size: 12px; margin: 0; line-height: 1.6;">
                    ${(data.recommendations || []).map(r => `<li>${escapeHTML(r)}</li>`).join('')}
                </ul>
            </div>

            <div style="font-size: 11px; color: var(--accent-green); border-top: 1px solid var(--border-subtle); padding-top: 10px; margin-top: 14px; text-align: right; font-weight: 600;">
                ⚡ ${escapeHTML(data.action_taken || 'Event recorded & isolated by K.A.R.M.A Active Defense Engine')}
            </div>
        `;
    } catch (err) {
        content.innerHTML = `<p style="color: var(--accent-red); padding: 20px; text-align: center;">Error generating forensic report: ${escapeHTML(err.message)}</p>`;
    }
}

async function inspectAIReport(ip) {
    const modal = document.getElementById("aiReportModal");
    const content = document.getElementById("modalReportContent");

    content.innerHTML = `<p style="text-align:center; color: var(--text-secondary);">Generating rule-based threat report for <b>${ip}</b>...</p>`;
    modal.classList.add("open");

    try {
        const res = await fetch(`/api/ai-report/${ip}`);
        const data = await res.json();

        content.innerHTML = `
            <div style="margin-bottom: 16px;">
                <p><b>Attacker IP:</b> <span class="font-mono" style="color: var(--accent-blue);">${escapeHTML(data.attacker_ip)}</span> | <b>Risk Score:</b> <span class="sev-badge sev-${data.threat_level}">${data.max_risk_score} / 100</span></p>
                <p style="margin-top: 4px;"><b>Intent Classification:</b> <span style="color: var(--accent-amber); font-weight: 600;">${escapeHTML(data.intent_classification)}</span></p>
            </div>

            <div style="background: var(--bg-subtle); padding: 14px; border-left: 3px solid var(--accent-blue); border-radius: 6px; margin-bottom: 16px;">
                <p><strong>Executive Summary:</strong></p>
                <p style="color: var(--text-secondary); margin-top: 4px;">${escapeHTML(data.summary)}</p>
            </div>

            <div style="margin-bottom: 16px;">
                <p><strong>Mapped MITRE TTPs:</strong></p>
                <p style="margin-top: 4px;">${(data.mitre_techniques || []).map(t => `<span class="widget-tag" style="margin-right: 4px; font-family: var(--font-mono);">${t}</span>`).join('')}</p>
            </div>

            <div>
                <p><strong>Recommended Action Plan:</strong></p>
                <ul style="padding-left: 20px; color: var(--text-secondary); margin-top: 4px;">
                    ${(data.recommendations || []).map(r => `<li style="margin-bottom: 4px;">${escapeHTML(r)}</li>`).join('')}
                </ul>
            </div>
        `;
    } catch (err) {
        content.innerHTML = `<p style="color: var(--accent-red);">Error generating report: ${escapeHTML(err.message)}</p>`;
    }
}

async function toggleIPBlock(ip, action) {
    try {
        await fetch("/api/quarantine/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, action: action, reason: "Manual SIEM Admin Action" })
        });
        fetchDashboardData();
    } catch (err) {
        alert("Error toggling status: " + err.message);
    }
}

function setupEventListeners() {
    // Theme Switcher Toggle
    const themeBtn = document.getElementById("themeToggle");
    if (themeBtn) {
        themeBtn.addEventListener("click", toggleTheme);
    }

    // Sidebar Collapse / Mobile Toggle
    const sidebarToggle = document.getElementById("sidebarToggle");
    const sidebar = document.getElementById("siemSidebar");
    const overlay = document.getElementById("sidebarOverlay");

    function closeMobileSidebar() {
        if (sidebar) {
            sidebar.classList.remove("mobile-open");
            sidebar.classList.remove("open");
        }
        if (overlay) overlay.classList.remove("active");
    }

    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener("click", () => {
            if (window.innerWidth <= 768) {
                sidebar.classList.toggle("mobile-open");
                if (overlay) overlay.classList.toggle("active");
            } else {
                sidebar.classList.toggle("collapsed");
            }
            setTimeout(() => {
                if (leafMap) leafMap.invalidateSize();
                if (threatsMap) threatsMap.invalidateSize();
            }, 300);
        });
    }

    if (overlay) {
        overlay.addEventListener("click", closeMobileSidebar);
    }

    // Brand Logo Button Click -> Return to Home Dashboard
    const brandLogoBtn = document.getElementById("brandLogoBtn");
    if (brandLogoBtn) {
        brandLogoBtn.addEventListener("click", () => {
            const summaryTab = document.querySelector(".siem-sidebar .nav-item[data-tab='summary']");
            if (summaryTab) summaryTab.click();
            closeMobileSidebar();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    // Sidebar Navigation Tab Switching
    const navItems = document.querySelectorAll(".siem-sidebar .nav-item[data-tab]");
    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const tabName = item.getAttribute("data-tab");

            navItems.forEach(n => n.classList.remove("active"));
            item.classList.add("active");

            const tabContents = document.querySelectorAll(".tab-content");
            tabContents.forEach(tc => tc.classList.remove("active"));

            // Convert e.g. "tool-password" -> "tabToolPassword" or "summary" -> "tabSummary"
            const camelTab = tabName.split('-').map(part => part.charAt(0).toUpperCase() + part.slice(1)).join('');
            const targetId = "tab" + camelTab;
            const targetTab = document.getElementById(targetId);

            if (targetTab) {
                targetTab.classList.add("active");
            } else {
                // Default to summary tab
                document.getElementById("tabSummary").classList.add("active");
            }

            closeMobileSidebar();

            setTimeout(() => {
                if (leafMap) leafMap.invalidateSize();
                if (threatsMap) threatsMap.invalidateSize();
                fitMap(leafMap);
                fitMap(threatsMap);
            }, 200);
        });
    });

    // Tester / Attacker Suite Button
    const btnTester = document.getElementById("btnLaunchTester");
    if (btnTester) {
        btnTester.addEventListener("click", async () => {
            try {
                btnTester.innerText = "⏳ Opening Tester GUI...";
                btnTester.disabled = true;
                const res = await fetch("/api/tester/launch", { method: "POST" });
                const data = await res.json();
                console.log("[Tester Suite]", data);
            } catch (err) {
                console.error("Error launching Tester GUI:", err);
            } finally {
                setTimeout(() => {
                    btnTester.innerText = "🧪 Tester / Attacker";
                    btnTester.disabled = false;
                }, 1500);
            }
        });
    }

    // Simulator Button
    const btnSim = document.getElementById("btnLaunchSim");
    if (btnSim) {
        btnSim.addEventListener("click", async () => {
            btnSim.disabled = true;
            btnSim.innerText = "⏳ Running...";
            try {
                await fetch("/api/simulator/launch", { method: "POST" });
                setTimeout(() => {
                    btnSim.disabled = false;
                    btnSim.innerText = "⚡ Run Attack Simulator";
                    fetchDashboardData();
                }, 3000);
            } catch (e) {
                btnSim.disabled = false;
                btnSim.innerText = "⚡ Run Attack Simulator";
            }
        });
    }

    // Reset System Data Button
    const btnReset = document.getElementById("btnResetData");
    if (btnReset) {
        btnReset.addEventListener("click", async () => {
            if (confirm("Reset all SIEM telemetry data and clear live charts?")) {
                await fetch("/api/reset", { method: "POST" });
                if (typeof resetCharts === "function") resetCharts();
                fetchDashboardData();
            }
        });
    }

    // Create Token Button
    const btnCreateToken = document.getElementById("btnCreateToken");
    if (btnCreateToken) {
        btnCreateToken.addEventListener("click", async () => {
            const name = prompt("Enter Honeytoken Name:", "Decoy Production Key");
            if (name) {
                await fetch("/api/honeytokens/create", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ name: name, type: "API Key" })
                });
                fetchDashboardData();
            }
        });
    }

    // Academic Topbar Badge Click -> Switch to About Tab
    const academicBtn = document.getElementById("academicBadgeBtn");
    if (academicBtn) {
        academicBtn.addEventListener("click", () => {
            const aboutNavItem = document.querySelector(".siem-sidebar .nav-item[data-tab='about']");
            if (aboutNavItem) {
                aboutNavItem.click();
            }
        });
    }

    // Add Custom Decoy Form Handler
    const formDecoy = document.getElementById("formAddCustomDecoy");
    if (formDecoy) {
        formDecoy.addEventListener("submit", async (e) => {
            e.preventDefault();
            const name = document.getElementById("customDecoyName").value;
            const port = parseInt(document.getElementById("customDecoyPort").value, 10);
            const type = document.getElementById("customDecoyType").value;

            try {
                await fetch("/api/decoys/add", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ name: name, port: port, service_type: type })
                });
                formDecoy.reset();
                fetchDecoys();
            } catch (err) {
                alert("Error adding custom decoy: " + err.message);
            }
        });
    }

    // Modal Close Buttons (Rule-based Report Modal)
    const btnCloseModal = document.getElementById("btnCloseModal");
    const btnModalClose2 = document.getElementById("btnModalClose2");
    const modal = document.getElementById("aiReportModal");

    if (btnCloseModal) btnCloseModal.addEventListener("click", () => modal.classList.remove("open"));
    if (btnModalClose2) btnModalClose2.addEventListener("click", () => modal.classList.remove("open"));

    // Modal Close Buttons (CSV View Modal)
    const btnCsvClose = document.getElementById("btnCsvModalClose");
    const btnCsvClose2 = document.getElementById("btnCsvModalClose2");
    const csvModal = document.getElementById("csvViewModal");

    if (btnCsvClose) btnCsvClose.addEventListener("click", () => csvModal.classList.remove("open"));
    if (btnCsvClose2) btnCsvClose2.addEventListener("click", () => csvModal.classList.remove("open"));

    // Initial CSV logs fetch
    fetchCsvLogsList();
}

async function fetchCsvLogsList() {
    const tbody = document.getElementById("csvLogsTableBody");
    if (!tbody) return;

    try {
        const res = await fetch("/api/logs/csv/list");
        const files = await res.json();

        if (!Array.isArray(files) || files.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">No CSV audit log files generated yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = files.map(f => {
            const sizeKb = (f.size_bytes / 1024).toFixed(1) + " KB";
            return `
                <tr>
                    <td class="font-mono" style="color: var(--accent-blue); font-weight: 600;">${escapeHTML(f.filename)}</td>
                    <td class="font-mono" style="font-size: 11px; color: var(--text-muted);">${f.created_time}</td>
                    <td class="font-mono" style="font-size: 11px;">${sizeKb}</td>
                    <td class="font-mono" style="text-align: center; font-weight: bold; color: var(--accent-green);">${f.row_count ?? "—"} events</td>
                    <td>
                        <div style="display: flex; gap: 4px;">
                            <button class="btn btn-sm btn-primary" onclick="viewCsvLog('${f.filename}')">👁️ View</button>
                            <button class="btn btn-sm btn-secondary" onclick="downloadCsvLog('${f.filename}')">⬇️ Download</button>
                            <button class="btn btn-sm btn-secondary" style="color: var(--accent-red); border-color: rgba(239,68,68,0.3);" onclick="deleteCsvLog('${f.filename}')">🗑️ Delete</button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-cell" style="color: var(--accent-red);">Error loading CSV log files: ${escapeHTML(err.message)}</td></tr>`;
    }
}

async function viewCsvLog(filename) {
    const modal = document.getElementById("csvViewModal");
    const title = document.getElementById("csvModalTitle");
    const content = document.getElementById("modalCsvContent");

    if (!modal || !content) return;

    title.innerText = `📄 Preview Audit Log: ${filename}`;
    content.innerHTML = `<p style="text-align:center; padding: 20px; color: var(--text-secondary);">Loading CSV log contents...</p>`;
    modal.classList.add("open");

    try {
        const res = await fetch(`/api/logs/csv/view/${filename}`);
        if (!res.ok) throw new Error("Failed to load CSV file");
        const data = await res.json();

        if (!data.rows || data.rows.length === 0) {
            content.innerHTML = `<p style="text-align:center; padding: 20px; color: var(--text-muted);">This CSV file is currently empty (0 event rows).</p>`;
            return;
        }

        const headers = Object.keys(data.rows[0]);
        const headerHTML = headers.map(h => `<th style="font-size: 11px;">${escapeHTML(h)}</th>`).join('');
        const rowsHTML = data.rows.map(r => {
            return `<tr>${headers.map(h => `<td class="font-mono" style="font-size: 11px;">${escapeHTML(r[h] || '')}</td>`).join('')}</tr>`;
        }).join('');

        content.innerHTML = `
            <div style="margin-bottom: 10px; font-size: 12px; color: var(--text-secondary);">
                Total Recorded Session Events: <strong style="color: var(--accent-blue);">${data.total_rows}</strong>
            </div>
            <div class="table-container" style="max-height: 55vh; overflow-y: auto;">
                <table class="siem-table">
                    <thead><tr>${headerHTML}</tr></thead>
                    <tbody>${rowsHTML}</tbody>
                </table>
            </div>
        `;
    } catch (err) {
        content.innerHTML = `<p style="color: var(--accent-red); padding: 20px; text-align: center;">Error viewing CSV file: ${escapeHTML(err.message)}</p>`;
    }
}

function downloadCsvLog(filename) {
    window.open(`/api/logs/csv/download/${filename}`, '_blank');
}

async function deleteCsvLog(filename) {
    if (confirm(`Are you sure you want to delete '${filename}'?`)) {
        try {
            await fetch(`/api/logs/csv/delete/${filename}`, { method: "DELETE" });
            fetchCsvLogsList();
        } catch (err) {
            alert("Error deleting CSV file: " + err.message);
        }
    }
}

function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>'"]/g,
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}

// PHONE & E-MAIL ALERTS
async function loadAlertSettings() {
    const form = document.getElementById('alertForm');
    if (!form) return;
    const s = await (await fetch('/api/notify')).json();
    form.ntfy_topic.value = s.ntfy_topic;
    form.email_to.value = s.email_to;
    form.smtp_user.value = s.smtp_user;
    form.smtp_host.value = s.smtp_host;
    form.smtp_password.placeholder = s.has_password ? 'Saved (leave empty to keep)' : '16 characters';
    document.getElementById('alertQuiet').textContent = s.quiet_minutes;
    document.getElementById('alertStatus').textContent = 'Last alert: ' + s.last_result;
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('alertForm');
    if (!form) return;
    const status = document.getElementById('alertStatus');
    form.addEventListener('submit', async e => {
        e.preventDefault();
        try {
            await fetch('/api/notify', {method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(Object.fromEntries(new FormData(form)))});
            form.smtp_password.value = '';
            await loadAlertSettings();
            status.textContent = 'Saved. ' + status.textContent;
        } catch (err) { status.textContent = 'Not saved: ' + err.message; }
    });
    document.getElementById('alertTest').addEventListener('click', async () => {
        status.textContent = 'Sending test…';
        try { status.textContent = 'Test: ' + (await (await fetch('/api/notify/test', {method: 'POST'})).json()).result; }
        catch (err) { status.textContent = 'Test failed: ' + err.message; }
    });
    loadAlertSettings().catch(() => {});
});

// About tab animation: hold one still frame (decoy hit) for people who prefer reduced motion.
document.addEventListener('DOMContentLoaded', () => {
    if (!matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    document.querySelectorAll('.karma-how svg').forEach(svg => { svg.pauseAnimations(); svg.setCurrentTime(6.3); });
});

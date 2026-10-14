/*
 * K.A.R.M.A Cloud SIEM Analytics & Real-Time Multi-Plot Chart Handler
 * Real-Time Per-Second Line Plot with Auto-Compression & Interactive Zooming
 */

let timeSeriesChartInstance = null;
let productsBarChartInstance = null;
let logTypesDoughnutChartInstance = null;
let eventActionsHorizontalChartInstance = null;

// Zoom state for Time Series Line Plot
let linePlotZoomLimit = 15; // default visible ticks
let cachedSecondBuckets = {};

function getChartColors() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        textColor: isDark ? '#94a3b8' : '#475569',
        gridColor: isDark ? 'rgba(255, 255, 255, 0.06)' : 'rgba(166, 180, 204, 0.25)',
        blue: '#3b82f6',
        green: '#10b981',
        purple: isDark ? '#a855f7' : '#8b5cf6',
        amber: '#f59e0b',
        red: '#f43f5e',
        cyan: isDark ? '#22d3ee' : '#06b6d4'
    };
}

function initSiemCharts() {
    initTimeSeriesChart();
    initProductsBarChart();
    initLogTypesDoughnutChart();
    initEventActionsHorizontalChart();
}

// 1. Real-Time Per-Second Event Volume Trend Line Chart (with auto-skip & label clamping)
function initTimeSeriesChart() {
    const ctx = document.getElementById('timeSeriesChart');
    if (!ctx) return;
    const c = getChartColors();

    timeSeriesChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attack Event Count',
                data: [],
                borderColor: c.green,
                backgroundColor: 'rgba(16, 185, 129, 0.16)',
                borderWidth: 3,
                tension: 0.35,
                fill: true,
                pointRadius: 5,
                pointHoverRadius: 8,
                pointBackgroundColor: c.green,
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(23, 32, 51, 0.9)',
                    padding: 10,
                    cornerRadius: 10,
                    callbacks: {
                        title: function(items) {
                            return `Timestamp: ${items[0].label}`;
                        },
                        label: function(item) {
                            return ` Attacks: ${item.raw} events`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: c.textColor,
                        font: { size: 9, family: "'Plus Jakarta Sans', sans-serif", weight: '600' },
                        maxRotation: 0,
                        minRotation: 0,
                        autoSkip: true,
                        autoSkipPadding: 14
                    },
                    grid: { color: c.gridColor }
                },
                y: {
                    ticks: { color: c.textColor, font: { size: 10, family: "'Plus Jakarta Sans', sans-serif", weight: '600' }, stepSize: 1 },
                    grid: { color: c.gridColor },
                    beginAtZero: true
                }
            }
        }
    });
}

// 2. Products / Decoy Services Bar Chart
function initProductsBarChart() {
    const ctx = document.getElementById('productsBarChart');
    if (!ctx) return;
    const c = getChartColors();

    productsBarChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Event Hits',
                data: [],
                backgroundColor: [c.blue, c.purple, c.cyan, c.amber, c.red],
                borderRadius: 10,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { cornerRadius: 10 }
            },
            scales: {
                x: { ticks: { color: c.textColor, font: { size: 9, family: "'Plus Jakarta Sans', sans-serif", weight: '600' }, maxRotation: 0, autoSkip: true }, grid: { display: false } },
                y: { ticks: { color: c.textColor, font: { size: 10, family: "'Plus Jakarta Sans', sans-serif", weight: '600' }, stepSize: 1 }, grid: { color: c.gridColor }, beginAtZero: true }
            }
        }
    });
}

// 3. Log Types Volume Doughnut Chart
function initLogTypesDoughnutChart() {
    const ctx = document.getElementById('logTypesDoughnutChart');
    if (!ctx) return;
    const c = getChartColors();

    const doughnutValueLabels = {
        id: 'doughnutValueLabels',
        afterDatasetsDraw(chart) {
            const ctx2 = chart.ctx;
            chart.getDatasetMeta(0).data.forEach((arc, i) => {
                const value = chart.data.datasets[0].data[i];
                if (!value || !chart.getDataVisibility(i)) return;  // skip slices hidden via the legend
                const { x, y } = arc.getCenterPoint();
                ctx2.save();
                ctx2.font = "800 14px 'Plus Jakarta Sans', sans-serif";
                ctx2.textAlign = 'center';
                ctx2.textBaseline = 'middle';
                ctx2.lineWidth = 3;
                ctx2.strokeStyle = 'rgba(0,0,0,0.55)';
                ctx2.strokeText(value, x, y);
                ctx2.fillStyle = '#ffffff';
                ctx2.fillText(value, x, y);
                ctx2.restore();
            });
        }
    };
    logTypesDoughnutChartInstance = new Chart(ctx, {
        type: 'doughnut',
        plugins: [doughnutValueLabels],
        data: {
            labels: ['Critical (Honeytoken)', 'High (SQLi/XSS)', 'Medium (BruteForce)', 'Info (Scan Probe)'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [c.red, c.amber, c.blue, c.green],
                borderWidth: 3,
                borderColor: document.documentElement.getAttribute('data-theme') === 'dark' ? '#172033' : '#f9fbfe',
                borderRadius: 6,
                spacing: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                tooltip: { cornerRadius: 10 },
                legend: {
                    position: 'right',
                    labels: { color: c.textColor, font: { size: 10, family: "'Plus Jakarta Sans', sans-serif", weight: '600' }, usePointStyle: true, boxWidth: 8 }
                }
            }
        }
    });
}

// 4. Event Actions Horizontal Bar Chart
function initEventActionsHorizontalChart() {
    const ctx = document.getElementById('eventActionsHorizontalChart');
    if (!ctx) return;
    const c = getChartColors();

    eventActionsHorizontalChartInstance = new Chart(ctx, {
        type: 'bar',
        indexAxis: 'y',
        data: {
            labels: ['Quarantined', 'Alerted', 'Monitored', 'Blocked'],
            datasets: [{
                label: 'Count',
                data: [0, 0, 0, 0],
                backgroundColor: [c.red, c.amber, c.green, c.purple],
                borderRadius: 10,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { cornerRadius: 10 }
            },
            scales: {
                x: { ticks: { color: c.textColor, font: { size: 10, family: "'Plus Jakarta Sans', sans-serif", weight: '600' }, stepSize: 1 }, grid: { color: c.gridColor }, beginAtZero: true },
                y: { ticks: { color: c.textColor, font: { size: 10, family: "'Plus Jakarta Sans', sans-serif", weight: '600' } }, grid: { display: false } }
            }
        }
    });
}

// Zoom Controls for Line Plot (Zoom In, Zoom Out, Fit All)
function zoomTimeSeriesChart(action) {
    const timeKeys = Object.keys(cachedSecondBuckets).sort();
    if (timeKeys.length === 0) return;

    if (action === 'in') {
        linePlotZoomLimit = Math.max(5, Math.floor(linePlotZoomLimit / 1.6));
    } else if (action === 'out') {
        linePlotZoomLimit = Math.min(timeKeys.length, Math.ceil(linePlotZoomLimit * 1.6));
    } else if (action === 'reset') {
        linePlotZoomLimit = timeKeys.length;
    }

    renderTimeSeriesPlot();
}

function renderTimeSeriesPlot() {
    if (!timeSeriesChartInstance) return;

    const timeKeys = Object.keys(cachedSecondBuckets).sort();
    if (timeKeys.length === 0) {
        timeSeriesChartInstance.data.labels = [];
        timeSeriesChartInstance.data.datasets[0].data = [];
    } else {
        const sliceCount = Math.min(linePlotZoomLimit, timeKeys.length);
        const visibleKeys = timeKeys.slice(-sliceCount);

        timeSeriesChartInstance.data.labels = visibleKeys;
        timeSeriesChartInstance.data.datasets[0].data = visibleKeys.map(k => cachedSecondBuckets[k]);
    }
    timeSeriesChartInstance.update();
}

// Update Charts Real-Time from Telemetry Stream
function updateSiemCharts(logs) {
    if (!logs || logs.length === 0) {
        resetCharts();
        return;
    }

    // Update Severity & Service Breakdown
    let counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    let services = {};
    let actions = { Quarantined: 0, Alerted: 0, Monitored: 0, Blocked: 0 };
    cachedSecondBuckets = {};

    logs.forEach(l => {
        const sev = l.severity || 'LOW';
        if (counts[sev] !== undefined) counts[sev]++;

        const s = l.decoy_service || 'UNKNOWN';
        services[s] = (services[s] || 0) + 1;

        if (l.quarantined) {
            actions.Quarantined++;
            actions.Blocked++;
        } else if (sev === 'CRITICAL' || sev === 'HIGH') {
            actions.Alerted++;
        } else {
            actions.Monitored++;
        }

        // Group by Real Time Second (HH:MM:SS)
        if (l.timestamp) {
            let timeStr = "";
            if (l.timestamp.includes("T")) {
                timeStr = l.timestamp.split("T")[1].substring(0, 8);
            } else if (l.timestamp.includes(" ")) {
                timeStr = l.timestamp.split(" ")[1].substring(0, 8);
            } else {
                timeStr = l.timestamp.substring(0, 8);
            }
            if (timeStr) {
                cachedSecondBuckets[timeStr] = (cachedSecondBuckets[timeStr] || 0) + 1;
            }
        }
    });

    // 1. Update Doughnut Chart
    if (logTypesDoughnutChartInstance) {
        logTypesDoughnutChartInstance.data.datasets[0].data = [
            counts.CRITICAL,
            counts.HIGH,
            counts.MEDIUM,
            counts.LOW
        ];
        logTypesDoughnutChartInstance.update();
    }

    // 2. Update Products / Services Bar Chart
    if (productsBarChartInstance) {
        productsBarChartInstance.data.labels = Object.keys(services);
        productsBarChartInstance.data.datasets[0].data = Object.values(services);
        productsBarChartInstance.update();
    }

    // 3. Update Event Actions Horizontal Bar Chart
    if (eventActionsHorizontalChartInstance) {
        eventActionsHorizontalChartInstance.data.datasets[0].data = [
            actions.Quarantined,
            actions.Alerted,
            actions.Monitored,
            actions.Blocked
        ];
        eventActionsHorizontalChartInstance.update();
    }

    // 4. Update Line Plot with Zoom Clamping
    renderTimeSeriesPlot();
}

// Reset All Charts Back to Zero / Empty State
function resetCharts() {
    cachedSecondBuckets = {};
    linePlotZoomLimit = 15;

    if (timeSeriesChartInstance) {
        timeSeriesChartInstance.data.labels = [];
        timeSeriesChartInstance.data.datasets[0].data = [];
        timeSeriesChartInstance.update();
    }
    if (productsBarChartInstance) {
        productsBarChartInstance.data.labels = [];
        productsBarChartInstance.data.datasets[0].data = [];
        productsBarChartInstance.update();
    }
    if (logTypesDoughnutChartInstance) {
        logTypesDoughnutChartInstance.data.datasets[0].data = [0, 0, 0, 0];
        logTypesDoughnutChartInstance.update();
    }
    if (eventActionsHorizontalChartInstance) {
        eventActionsHorizontalChartInstance.data.datasets[0].data = [0, 0, 0, 0];
        eventActionsHorizontalChartInstance.update();
    }
}

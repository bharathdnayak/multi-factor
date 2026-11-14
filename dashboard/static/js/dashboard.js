/**
 * BEHAVIORAL DRIFT CONTINUOUS AUTHENTICATION SOC
 * Real-Time Streaming Client, Dual Chart.js Visualizer & Simulation Dispatcher
 * Department of ISE | Team 30 | Major Project
 */

// -----------------------------------------------------------------------------
// State & Configuration
// -----------------------------------------------------------------------------
const CONFIG = {
    MAX_CHART_POINTS: 30,
    RECONNECT_DELAY_MS: 2000,
    RISK_THRESHOLD: 0.55,
    ACUTE_THRESHOLD: 0.78
};

let ws = null;
let riskChart = null;
let biometricsChart = null;
let isBreachedState = false;

// -----------------------------------------------------------------------------
// DOM Elements
// -----------------------------------------------------------------------------
const el = {
    streamStatusText: document.getElementById('streamStatusText'),
    liveStreamBadge: document.getElementById('liveStreamBadge'),
    systemStateBadge: document.getElementById('systemStateBadge'),
    systemStateText: document.getElementById('systemStateText'),
    clockDisplay: document.getElementById('clockDisplay'),
    breachBanner: document.getElementById('breachBanner'),
    bannerOtpCode: document.getElementById('bannerOtpCode'),

    instantRiskVal: document.getElementById('instantRiskVal'),
    instantRiskBar: document.getElementById('instantRiskBar'),
    instantRiskTag: document.getElementById('instantRiskTag'),

    smoothedRiskVal: document.getElementById('smoothedRiskVal'),
    smoothedRiskBar: document.getElementById('smoothedRiskBar'),
    smoothedRiskTag: document.getElementById('smoothedRiskTag'),

    contextModeVal: document.getElementById('contextModeVal'),
    contextAppTag: document.getElementById('contextAppTag'),
    windowTitleVal: document.getElementById('windowTitleVal'),

    svddConfVal: document.getElementById('svddConfVal'),
    svddTag: document.getElementById('svddTag'),
    dwellVal: document.getElementById('dwellVal'),
    flightVal: document.getElementById('flightVal'),

    hwActiveApp: document.getElementById('hwActiveApp'),
    hwWindowTitle: document.getElementById('hwWindowTitle'),
    hwKeystrokeCount: document.getElementById('hwKeystrokeCount'),
    hwMouseEvents: document.getElementById('hwMouseEvents'),
    hwMouseVel: document.getElementById('hwMouseVel'),
    hwCpuLoad: document.getElementById('hwCpuLoad'),
    hwRamUsage: document.getElementById('hwRamUsage'),
    eventCounterBadge: document.getElementById('eventCounterBadge'),

    intruderPhotoImg: document.getElementById('intruderPhotoImg'),
    aiModelChip: document.getElementById('aiModelChip'),
    aiPersonaVal: document.getElementById('aiPersonaVal'),
    aiIntentVal: document.getElementById('aiIntentVal'),
    aiThreatPill: document.getElementById('aiThreatPill'),
    honeypotStatusBadge: document.getElementById('honeypotStatusBadge'),
    hpBrowserSearches: document.getElementById('hpBrowserSearches'),
    hpFilesAccessed: document.getElementById('hpFilesAccessed'),
    hpSandboxIntercepts: document.getElementById('hpSandboxIntercepts'),

    incidentLogFeed: document.getElementById('incidentLogFeed'),
    toastContainer: document.getElementById('toastContainer'),
    photoModal: document.getElementById('photoModal'),
    modalImg: document.getElementById('modalImg'),
    resetAuthModal: document.getElementById('resetAuthModal'),
    resetCredentialInput: document.getElementById('resetCredentialInput'),
    resetAuthError: document.getElementById('resetAuthError')
};

// -----------------------------------------------------------------------------
// Clock & Utilities
// -----------------------------------------------------------------------------
function updateClock() {
    const now = new Date();
    if (el.clockDisplay) {
        el.clockDisplay.textContent = now.toTimeString().split(' ')[0];
    }
}
setInterval(updateClock, 1000);
updateClock();

function showToast(message, type = 'info') {
    if (!el.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'critical' ? '🚨' : (type === 'success' ? '✅' : 'ℹ️');
    const iconSpan = document.createElement('span');
    iconSpan.textContent = icon;
    const msgSpan = document.createElement('span');
    msgSpan.textContent = ` ${String(message || '')}`;
    toast.appendChild(iconSpan);
    toast.appendChild(msgSpan);
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.4s ease';
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

// -----------------------------------------------------------------------------
// Charts Initialization (Chart.js)
// -----------------------------------------------------------------------------
function initCharts() {
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js not loaded. Visual canvas charts unavailable.');
        return;
    }

    const defaultFont = { family: "'JetBrains Mono', 'Consolas', monospace", size: 10 };
    const gridStyle = { color: 'rgba(255, 255, 255, 0.05)', borderColor: 'rgba(255, 255, 255, 0.1)' };

    // 1. Risk Trajectory Chart
    const ctxRisk = document.getElementById('riskTrajectoryChart').getContext('2d');
    riskChart = new Chart(ctxRisk, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Instant Risk',
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.12)',
                    borderWidth: 2,
                    pointRadius: 2,
                    tension: 0.35,
                    fill: false,
                    data: []
                },
                {
                    label: '30s Smoothed',
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.12)',
                    borderWidth: 2,
                    pointRadius: 2,
                    tension: 0.35,
                    fill: false,
                    data: []
                },
                {
                    label: 'Threshold',
                    borderColor: '#ef4444',
                    borderWidth: 1.5,
                    borderDash: [5, 4],
                    pointRadius: 0,
                    fill: false,
                    data: []
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            scales: {
                x: {
                    grid: gridStyle,
                    ticks: { color: '#64748b', font: defaultFont, maxTicksLimit: 8 }
                },
                y: {
                    min: 0.0,
                    max: 1.0,
                    grid: gridStyle,
                    ticks: { color: '#64748b', font: defaultFont, stepSize: 0.2 }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });

    // 2. Biometrics & Dynamics Chart
    const ctxBio = document.getElementById('biometricsChart').getContext('2d');
    biometricsChart = new Chart(ctxBio, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Dwell Time (s)',
                    borderColor: '#10b981',
                    borderWidth: 2,
                    pointRadius: 1,
                    tension: 0.3,
                    yAxisID: 'yTime',
                    data: []
                },
                {
                    label: 'Flight Time (s)',
                    borderColor: '#f59e0b',
                    borderWidth: 2,
                    pointRadius: 1,
                    tension: 0.3,
                    yAxisID: 'yTime',
                    data: []
                },
                {
                    label: 'Mouse Velocity',
                    borderColor: '#3b82f6',
                    borderWidth: 1.5,
                    pointRadius: 1,
                    tension: 0.3,
                    yAxisID: 'yVel',
                    data: []
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            scales: {
                x: {
                    grid: gridStyle,
                    ticks: { color: '#64748b', font: defaultFont, maxTicksLimit: 8 }
                },
                yTime: {
                    type: 'linear',
                    position: 'left',
                    min: 0.0,
                    max: 0.8,
                    grid: gridStyle,
                    ticks: { color: '#10b981', font: defaultFont, stepSize: 0.2 }
                },
                yVel: {
                    type: 'linear',
                    position: 'right',
                    min: 0,
                    max: 2000,
                    grid: { display: false },
                    ticks: { color: '#3b82f6', font: defaultFont, stepSize: 500 }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function appendChartData(timeStr, instantRisk, smoothedRisk, dwell, flight, mouseVel) {
    if (!riskChart || !biometricsChart) return;

    // Risk Chart
    riskChart.data.labels.push(timeStr);
    riskChart.data.datasets[0].data.push(instantRisk);
    riskChart.data.datasets[1].data.push(smoothedRisk);
    riskChart.data.datasets[2].data.push(CONFIG.RISK_THRESHOLD);

    if (riskChart.data.labels.length > CONFIG.MAX_CHART_POINTS) {
        riskChart.data.labels.shift();
        riskChart.data.datasets[0].data.shift();
        riskChart.data.datasets[1].data.shift();
        riskChart.data.datasets[2].data.shift();
    }
    riskChart.update('none');

    // Biometrics Chart
    biometricsChart.data.labels.push(timeStr);
    biometricsChart.data.datasets[0].data.push(dwell);
    biometricsChart.data.datasets[1].data.push(flight);
    biometricsChart.data.datasets[2].data.push(mouseVel);

    if (biometricsChart.data.labels.length > CONFIG.MAX_CHART_POINTS) {
        biometricsChart.data.labels.shift();
        biometricsChart.data.datasets[0].data.shift();
        biometricsChart.data.datasets[1].data.shift();
        biometricsChart.data.datasets[2].data.shift();
    }
    biometricsChart.update('none');
}

// -----------------------------------------------------------------------------
// Telemetry UI Updates
// -----------------------------------------------------------------------------
function updateTelemetryUI(d) {
    if (!d) return;

    const timeStr = new Date(d.timestamp * 1000).toTimeString().split(' ')[0];

    // 1. Instant Risk
    const instRisk = parseFloat(d.instant_risk) || 0.0;
    el.instantRiskVal.textContent = instRisk.toFixed(2);
    const instPercent = Math.min(100, Math.max(0, instRisk * 100));
    el.instantRiskBar.style.width = `${instPercent}%`;

    if (instRisk >= 0.75 || d.is_breached) {
        el.instantRiskVal.className = 'metric-value-huge text-crimson';
        el.instantRiskBar.className = 'risk-bar-fill fill-crimson';
        el.instantRiskTag.className = 'kpi-tag tag-danger';
        el.instantRiskTag.textContent = 'CRITICAL SPIKE';
    } else if (instRisk >= 0.40) {
        el.instantRiskVal.className = 'metric-value-huge text-amber';
        el.instantRiskBar.className = 'risk-bar-fill fill-amber';
        el.instantRiskTag.className = 'kpi-tag tag-warning';
        el.instantRiskTag.textContent = 'DRIFT ELEVATED';
    } else {
        el.instantRiskVal.className = 'metric-value-huge text-cyan';
        el.instantRiskBar.className = 'risk-bar-fill';
        el.instantRiskTag.className = 'kpi-tag';
        el.instantRiskTag.textContent = 'NOMINAL';
    }

    // 2. Smoothed Risk
    const smoothRisk = parseFloat(d.smoothed_risk) || 0.0;
    el.smoothedRiskVal.textContent = smoothRisk.toFixed(2);
    const smoothPercent = Math.min(100, Math.max(0, smoothRisk * 100));
    el.smoothedRiskBar.style.width = `${smoothPercent}%`;

    if (smoothRisk >= CONFIG.RISK_THRESHOLD || d.is_breached) {
        el.smoothedRiskVal.className = 'metric-value-huge text-crimson';
        el.smoothedRiskBar.className = 'risk-bar-fill fill-crimson';
        el.smoothedRiskTag.className = 'kpi-tag tag-danger';
        el.smoothedRiskTag.textContent = 'DRIFT BREACH';
    } else if (smoothRisk >= 0.40) {
        el.smoothedRiskVal.className = 'metric-value-huge text-amber';
        el.smoothedRiskBar.className = 'risk-bar-fill fill-amber';
        el.smoothedRiskTag.className = 'kpi-tag tag-warning';
        el.smoothedRiskTag.textContent = 'WARNING';
    } else {
        el.smoothedRiskVal.className = 'metric-value-huge text-violet';
        el.smoothedRiskBar.className = 'risk-bar-fill fill-violet';
        el.smoothedRiskTag.className = 'kpi-tag';
        el.smoothedRiskTag.textContent = 'NORMAL';
    }

    // 3. Cognitive Context
    el.contextModeVal.textContent = (d.interaction_mode || 'IDLE').replace(/_/g, ' ').toUpperCase();
    el.contextAppTag.textContent = d.active_app || 'None';
    el.windowTitleVal.textContent = d.active_window || 'Waiting for telemetry window';

    // 4. Biometrics (zero synthetic fallbacks when idle)
    const svddRaw = (d.svdd_confidence !== undefined && d.svdd_confidence !== null) ? parseFloat(d.svdd_confidence) : 1.0;
    const confVal = Math.round(svddRaw * 100);
    el.svddConfVal.textContent = `${confVal}%`;
    if (el.svddTag) {
        if (svddRaw < 0.45) {
            el.svddTag.className = 'kpi-tag tag-danger';
            el.svddTag.textContent = 'ANOMALY';
        } else if (svddRaw < 0.70) {
            el.svddTag.className = 'kpi-tag tag-warning';
            el.svddTag.textContent = 'DRIFT';
        } else {
            el.svddTag.className = 'kpi-tag tag-emerald';
            el.svddTag.textContent = 'MATCH';
        }
    }
    el.dwellVal.textContent = `${Math.round((d.dwell_mean || 0.0) * 1000)}ms`;
    el.flightVal.textContent = `${Math.round((d.flight_mean || 0.0) * 1000)}ms`;

    // 5. Station Hardware State & Data State Badge
    el.hwActiveApp.textContent = d.active_app || 'None';
    el.hwWindowTitle.textContent = d.active_window || 'Waiting for telemetry window';
    el.hwKeystrokeCount.textContent = d.keystroke_count ?? 0;
    el.hwMouseEvents.textContent = d.mouse_events ?? 0;
    el.hwMouseVel.textContent = `${Math.round(d.mouse_velocity || 0)} px/s`;
    el.hwCpuLoad.textContent = `${(d.cpu_usage || 0).toFixed(1)}%`;
    el.hwRamUsage.textContent = `${Math.round(d.ram_usage_mb || 0)} MB`;
    if (el.eventCounterBadge) {
        el.eventCounterBadge.textContent = `Events: ${d.event_count ?? 0}`;
    }

    updateStreamStateBadge(d.data_state, d.telemetry_age_seconds);

    // 6. Breach Status Banner & Header Pill
    if (d.is_breached || instRisk >= 0.78 || smoothRisk >= CONFIG.RISK_THRESHOLD) {
        setBreachState(true, d.otp_issued);
    } else {
        setBreachState(false, false);
    }

    // Append to charts only for fresh real or simulated telemetry frames (never duplicate heartbeats)
    if (d.append_chart !== false) {
        appendChartData(timeStr, instRisk, smoothRisk, d.dwell_mean || 0.0, d.flight_mean || 0.0, d.mouse_velocity || 0.0);
    }
}

function updateStreamStateBadge(dataState, ageSeconds) {
    if (!el.liveStreamBadge || !el.streamStatusText) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const state = (dataState || 'IDLE').toUpperCase();
    if (state === 'SIMULATED') {
        el.liveStreamBadge.className = 'status-pill tag-danger';
        el.streamStatusText.textContent = 'SIMULATION MODE ACTIVE';
    } else if (state === 'LIVE') {
        el.liveStreamBadge.className = 'status-pill status-nominal';
        el.streamStatusText.textContent = 'LIVE TELEMETRY: ACTIVE';
    } else if (state === 'STALE') {
        el.liveStreamBadge.className = 'status-pill tag-warning';
        const ageTxt = ageSeconds !== null && ageSeconds !== undefined ? ` (${Math.round(ageSeconds)}s)` : '';
        el.streamStatusText.textContent = `TELEMETRY STALE${ageTxt}`;
    } else {
        el.liveStreamBadge.className = 'status-pill tag-warning';
        el.streamStatusText.textContent = 'CONNECTED (IDLE)';
    }
}

function setBreachState(breached, otpIssued = false) {
    isBreachedState = breached;
    if (breached) {
        if (el.breachBanner) el.breachBanner.classList.remove('hidden');
        if (el.bannerOtpCode) el.bannerOtpCode.textContent = otpIssued ? 'ACTIVE (CHECK ALERT)' : 'DISPATCHED';
        if (el.systemStateBadge) {
            el.systemStateBadge.className = 'status-pill status-breach';
            el.systemStateText.textContent = '🚨 LOCKDOWN: HONEYPOT ACTIVE';
        }
        if (el.honeypotStatusBadge) {
            el.honeypotStatusBadge.textContent = 'DECEPTIVE SANDBOX ACTIVE';
            el.honeypotStatusBadge.className = 'sub-badge badge-warning text-crimson';
        }
    } else {
        if (el.breachBanner) el.breachBanner.classList.add('hidden');
        if (el.systemStateBadge) {
            el.systemStateBadge.className = 'status-pill status-secure';
            el.systemStateText.textContent = 'AUTHENTICATED: OWNER';
        }
        if (el.honeypotStatusBadge) {
            el.honeypotStatusBadge.textContent = 'ARMED & MONITORING';
            el.honeypotStatusBadge.className = 'sub-badge badge-warning';
        }
    }
}

// -----------------------------------------------------------------------------
// Incident Feed & Logging
// -----------------------------------------------------------------------------
function appendIncident(item) {
    if (!el.incidentLogFeed || !item) return;
    const entry = document.createElement('div');
    const lvl = (item.level || 'info').toLowerCase().replace(/[^a-z]/g, '') || 'info';
    entry.className = `log-entry log-${lvl}`;

    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = `[${item.time || 'NOW'}] `;

    const msgSpan = document.createElement('span');
    msgSpan.className = 'log-msg';
    msgSpan.textContent = String(item.message || '');

    entry.appendChild(timeSpan);
    entry.appendChild(msgSpan);
    el.incidentLogFeed.prepend(entry);

    // Keep log size bounded
    while (el.incidentLogFeed.children.length > 50) {
        el.incidentLogFeed.lastElementChild.remove();
    }
}

function clearIncidentLog() {
    if (el.incidentLogFeed) {
        el.incidentLogFeed.innerHTML = '<div class="log-entry log-info"><span class="log-time">[CLEARED]</span><span class="log-msg">Log cleared by operator.</span></div>';
    }
}

// -----------------------------------------------------------------------------
// WebSocket Client
// -----------------------------------------------------------------------------
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('WebSocket connected to SOC telemetry server.');
        if (el.liveStreamBadge) {
            el.liveStreamBadge.className = 'status-pill tag-warning';
            el.streamStatusText.textContent = 'CONNECTED (IDLE)';
        }
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'INITIAL_SNAPSHOT') {
                if (msg.history && Array.isArray(msg.history)) {
                    msg.history.forEach(item => updateTelemetryUI(item));
                }
                if (msg.incidents && Array.isArray(msg.incidents)) {
                    msg.incidents.slice().reverse().forEach(inc => appendIncident(inc));
                }
                updateTelemetryUI(msg.data);
            } else if (msg.type === 'TELEMETRY_UPDATE') {
                updateTelemetryUI(msg.data);
                if (msg.latest_alert) appendIncident(msg.latest_alert);
            } else if (msg.type === 'BREACH_ALERT') {
                updateTelemetryUI(msg.data);
                if (msg.latest_alert) appendIncident(msg.latest_alert);
                showToast(`Security Breach: Honeypot Activated! Risk: ${msg.data.instant_risk}`, 'critical');
                refreshForensics();
            } else if (msg.type === 'SYSTEM_RESET') {
                updateTelemetryUI(msg.data);
                if (msg.latest_alert) appendIncident(msg.latest_alert);
                showToast('System normalized. Baseline adaptation complete.', 'success');
                refreshForensics();
            } else if (msg.type === 'RESET_DENIED') {
                if (msg.latest_alert) appendIncident(msg.latest_alert);
                showToast(msg.message || 'Verification rejected: Invalid OTP or Recovery Key.', 'critical');
            }
        } catch (err) {
            console.error('Error handling WebSocket frame:', err);
        }
    };

    ws.onclose = () => {
        console.warn('WebSocket connection lost. Reconnecting in 2s...');
        if (el.liveStreamBadge) {
            el.liveStreamBadge.className = 'status-pill tag-danger';
            el.streamStatusText.textContent = 'STREAM DISCONNECTED (RETRYING)';
        }
        setTimeout(connectWebSocket, CONFIG.RECONNECT_DELAY_MS);
    };

    ws.onerror = (err) => {
        console.error('WebSocket encountered an error:', err);
        ws.close();
    };
}

// -----------------------------------------------------------------------------
// Forensics & Report REST Handlers
// -----------------------------------------------------------------------------
async function refreshForensics() {
    try {
        const res = await fetch('/api/forensics/latest');
        if (!res.ok) return;
        const data = await res.json();

        // Refresh stats
        if (data.stats) {
            if (el.hpBrowserSearches) el.hpBrowserSearches.textContent = (data.stats.browser_searches || []).length;
            if (el.hpFilesAccessed) el.hpFilesAccessed.textContent = (data.stats.files_accessed || []).length;
            if (el.hpSandboxIntercepts) el.hpSandboxIntercepts.textContent = (data.stats.sandbox_interceptions || []).length;
        }

        // Refresh photo timestamp
        if (data.latest_intruder && el.intruderPhotoImg) {
            el.intruderPhotoImg.src = `/api/forensics/intruder_photo?t=${Date.now()}`;
        }

        // Refresh AI Intel dynamically from backend IntruderIntentAnalyzer
        const ai = data.ai_analysis;
        if (ai) {
            if (el.aiModelChip) {
                const srcLabel = (ai.source || '').toUpperCase().includes('OLLAMA') ? `OLLAMA (${ai.model_name || 'LOCAL LLM'})` : (ai.source || 'HEURISTIC ENGINE').toUpperCase();
                el.aiModelChip.textContent = srcLabel;
            }
            if (el.aiPersonaVal) el.aiPersonaVal.textContent = ai.attacker_persona || 'Awaiting Intruder Event';
            if (el.aiIntentVal) el.aiIntentVal.textContent = ai.primary_intent || 'System monitoring baseline owner behavior.';
            if (el.aiThreatPill) {
                const lvl = (ai.threat_level || 'LOW').toUpperCase();
                const mitres = Array.isArray(ai.mitre_tactics) && ai.mitre_tactics.length > 0
                    ? ` (${ai.mitre_tactics.slice(0, 2).map(m => m.split(' ')[0]).join(' / ')})`
                    : '';
                el.aiThreatPill.textContent = `THREAT LEVEL: ${lvl}${mitres}`;
                if (lvl === 'CRITICAL' || lvl === 'HIGH') {
                    el.aiThreatPill.className = 'intel-threat-pill text-crimson';
                } else if (lvl === 'MEDIUM') {
                    el.aiThreatPill.className = 'intel-threat-pill text-amber';
                } else {
                    el.aiThreatPill.className = 'intel-threat-pill text-emerald';
                }
            }
        }
    } catch (err) {
        console.error('Error refreshing forensics:', err);
    }
}

async function generateFreshPdf() {
    showToast('Generating multi-page Forensic PDF with SHA-256 seal...', 'info');
    try {
        const res = await fetch('/api/forensics/generate_pdf', { method: 'POST' });
        if (!res.ok) throw new Error('PDF Generation failed');
        const data = await res.json();
        showToast(`Forensic PDF '${data.filename}' ready!`, 'success');
        refreshForensics();
        // Trigger download
        window.location.href = data.download_url;
    } catch (err) {
        showToast('Error generating PDF report.', 'critical');
    }
}

async function launchForensicsGui() {
    showToast('Launching Desktop Forensic Analyst Workbench...', 'info');
    try {
        const res = await fetch('/api/system/launch_forensics_gui', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            showToast('Desktop Forensic Dashboard opened!', 'success');
        } else {
            showToast(data.message || 'Failed to open Forensic Dashboard', 'critical');
        }
    } catch (err) {
        showToast(`Launch error: ${err.message}`, 'critical');
    }
}

async function launchHoneypotGui() {
    showToast('Launching Sandboxed Honeypot Desktop...', 'info');
    try {
        const res = await fetch('/api/system/launch_honeypot_gui', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            const otpNotice = data.recovery_otp ? ` (Recovery OTP: ${data.recovery_otp})` : '';
            showToast(`Honeypot Desktop window launched!${otpNotice}`, 'success');
        } else {
            showToast(data.message || 'Failed to open Honeypot Desktop', 'critical');
        }
    } catch (err) {
        showToast(`Launch error: ${err.message}`, 'critical');
    }
}

// -----------------------------------------------------------------------------
// Viva Demonstration & Anomaly Simulation Triggers
// -----------------------------------------------------------------------------
async function simulateAnomaly(type) {
    showToast(`Injecting simulated anomaly: ${type.replace(/_/g, ' ')}...`, 'info');
    try {
        const res = await fetch('/api/security/simulate_anomaly', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ anomaly_type: type, severity: 0.88 })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(`Simulated Breach: ${data.reason}`, 'critical');
            refreshForensics();
        }
    } catch (err) {
        showToast(`Simulation error: ${err.message}`, 'critical');
    }
}

async function triggerReset() {
    if (el.resetAuthModal) {
        if (el.resetCredentialInput) el.resetCredentialInput.value = '';
        if (el.resetAuthError) el.resetAuthError.textContent = '';
        el.resetAuthModal.classList.remove('hidden');
        if (el.resetCredentialInput) el.resetCredentialInput.focus();
    }
}

function closeResetModal() {
    if (el.resetAuthModal) {
        el.resetAuthModal.classList.add('hidden');
    }
}

async function submitResetVerification() {
    const cred = el.resetCredentialInput ? el.resetCredentialInput.value.trim() : '';
    if (!cred) {
        if (el.resetAuthError) el.resetAuthError.textContent = 'Enter the 6-digit Session OTP or Emergency Recovery Key.';
        return;
    }
    showToast('Verifying credential for baseline reset...', 'info');
    try {
        const res = await fetch('/api/security/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bypass_key: cred })
        });
        const data = await res.json();
        if (res.ok && data.status === 'success') {
            closeResetModal();
            showToast('Identity verified. System normalized.', 'success');
            refreshForensics();
        } else {
            const msg = data.message || 'Invalid credential. Reset denied.';
            if (el.resetAuthError) el.resetAuthError.textContent = msg;
            showToast(msg, 'critical');
        }
    } catch (err) {
        showToast(`Reset error: ${err.message}`, 'critical');
    }
}

// -----------------------------------------------------------------------------
// Photo Modal
// -----------------------------------------------------------------------------
function openPhotoModal() {
    if (el.photoModal && el.modalImg) {
        el.modalImg.src = `/api/forensics/intruder_photo?t=${Date.now()}`;
        el.photoModal.classList.remove('hidden');
    }
}

function closePhotoModal() {
    if (el.photoModal) {
        el.photoModal.classList.add('hidden');
    }
}

// -----------------------------------------------------------------------------
// Lifecycle Initialization
// -----------------------------------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
    initCharts();
    connectWebSocket();
    refreshForensics();
    setInterval(refreshForensics, 8000);
});

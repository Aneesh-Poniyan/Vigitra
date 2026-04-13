

// Vigitra Dashboard — Chart.js global config
if (typeof Chart !== 'undefined') {
  Chart.defaults.color = '#8892a4';
  Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;
}

let timelineChart = null;
let engineChart = null;

let seenAlertIds = new Set();
let timelineLabels = [];
let timelineTotalData = [];
let timelineBlockedData = [];
let prevTotal = 0;
let prevBlocked = 0;
let tickCount = 0;
let startTime = Date.now();
let lastTotal = 0;
let lastCheckTime = Date.now();

// Vigitra API Decoupling Hook
const API_KEY = document.querySelector('meta[name="api-key"]')?.content || '';
const apiHeaders = { 'X-Vigitra-Key': API_KEY, 'Content-Type': 'application/json' };


document.addEventListener('DOMContentLoaded', () => {
    initTimelineChart();
    initEngineChart();
    poll();
    setInterval(poll, 2000);

    setInterval(() => {
        const el = document.getElementById('uptime-val');
        if (!el) return;
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        el.textContent = `${h}:${m}:${s}`;
    }, 1000);
});


function initTimelineChart() {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    for (let i = 0; i < 30; i++) {
        timelineLabels.push('');
        timelineTotalData.push(0);
        timelineBlockedData.push(0);
    }

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timelineLabels,
            datasets: [
                {
                    label: 'Total Queries',
                    data: timelineTotalData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4
                },
                {
                    label: 'Threats Blocked',
                    data: timelineBlockedData,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { display: false },
                tooltip: {
                  backgroundColor: 'rgba(13,15,26,0.95)',
                  borderColor: 'rgba(0,212,255,0.3)',
                  borderWidth: 1,
                  titleFont: { family: 'JetBrains Mono', size: 11 },
                  bodyFont: { family: 'DM Sans', size: 12 },
                  padding: 12
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    suggestedMax: 10,
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#64748b', font: { size: 11 } }
                },
                x: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#64748b', font: { size: 10 }, maxRotation: 0 }
                }
            }
        }
    });
}

function initEngineChart() {
    const ctx = document.getElementById('engineChart').getContext('2d');
    engineChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['DGA Engine', 'Tunneling Engine', 'Blocklist Engine', 'Clean'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#f59e0b', '#8b5cf6', '#ef4444', 'rgba(16,185,129,0.3)'],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: { display: false },
                tooltip: {
                  backgroundColor: 'rgba(13,15,26,0.95)',
                  borderColor: 'rgba(0,212,255,0.3)',
                  borderWidth: 1,
                  titleFont: { family: 'JetBrains Mono', size: 11 },
                  bodyFont: { family: 'DM Sans', size: 12 },
                  padding: 12
                }
            }
        }
    });
}



// API Key retrieval function to ensure it's fresh
function getApiHeaders() {
    const key = document.querySelector('meta[name="api-key"]')?.content || 'vigitra_dev_key_x9f2';
    return { 'X-Vigitra-Key': key, 'Content-Type': 'application/json' };
}


async function poll() {
    try {
        const response = await fetch('/api/summary', { headers: getApiHeaders() });
        if (!response.ok) {
            console.error('Unified poll failed:', response.status);
            return;
        }
        
        const res = await response.json();
        if (!res.ok) {
            console.error('API Error:', res.error);
            return;
        }

        const data = res.data;
        const stats = data.stats;
        
        // 1. Update KPI Values
        animateValue('val-total', stats.total);
        animateValue('val-blocked', stats.blocked);
        animateValue('val-dga', stats.dga);
        animateValue('val-tunnel', stats.tunnel);
        
        const dbSizeEl = document.getElementById('val-db-size');
        if (dbSizeEl) dbSizeEl.textContent = stats.blocklist_size.toLocaleString();

        const now = Date.now();
        const elapsed = (now - lastCheckTime) / 60000;
        if (elapsed > 0.05 && lastTotal > 0) {
            const rate = Math.round((stats.total - lastTotal) / elapsed);
            const trendEl = document.getElementById('trend-total');
            if (trendEl) trendEl.textContent = `+${Math.max(0, rate)}/min`;
        }
        lastTotal = stats.total;
        lastCheckTime = now;

        const blockRate = stats.total > 0 ? ((stats.blocked / stats.total) * 100).toFixed(1) : '0.0';
        const blockEl = document.getElementById('trend-blocked');
        if (blockEl) blockEl.textContent = `${blockRate}% block rate`;

        // 2. Update Timeline Chart
        if (data.timeline && data.timeline.length > 0) {
            timelineLabels.length = 0;
            timelineTotalData.length = 0;
            timelineBlockedData.length = 0;
            data.timeline.forEach(d => {
                timelineLabels.push(d.t);
                timelineTotalData.push(d.total || 0);
                timelineBlockedData.push(d.blocked || 0);
            });
            timelineChart.options.scales.y.suggestedMax = Math.max(10, ...timelineTotalData) + 2;
            timelineChart.update('none'); // Optimization: update without animation if busy
        }

        // 3. Update Engine Chart (Doughnut)
        const safe = stats.total - stats.blocked;
        engineChart.data.datasets[0].data = [stats.dga, stats.tunnel, stats.blocklist_hits || 0, safe];
        engineChart.update('none');

        // 4. Update Tables and Badges
        document.getElementById('query-count-badge').textContent = `${stats.total.toLocaleString()} queries`;
        renderQueryTable(data.queries);
        renderClientTable(data.clients);

        // 5. Toasts / Alerts
        data.alerts.filter(a => !seenAlertIds.has(a.id)).forEach(a => {
            seenAlertIds.add(a.id);
            showToast(a);
        });

    } catch (e) {
        console.error('Poll error:', e);
    }
}



function renderQueryTable(rows) {
    const tbody = document.querySelector('#query-table tbody');
    tbody.innerHTML = '';
    
    const reversedRows = [...rows].reverse();
    
    reversedRows.forEach(r => {
        const tr = document.createElement('tr');
        if (r.blocked) tr.className = 'row-blocked';
        
        let engineBadge;
        switch (r.threat_type) {
            case 'DGA': engineBadge = '<span class="badge badge-dga">ML:DGA</span>'; break;
            case 'Tunneling': engineBadge = '<span class="badge badge-tunnel">ML:Tunnel</span>'; break;
            case 'Phishing': engineBadge = '<span class="badge badge-dga">ML:Phish</span>'; break;
            case 'Blocklist': engineBadge = '<span class="badge badge-bl">DB:Block</span>'; break;
            case 'Suspicious': engineBadge = '<span class="badge badge-amber">Suspicious</span>'; break;
            case 'SHADOWING': engineBadge = '<span class="badge badge-shadowing">BEH:Shadowing</span>'; break;
            case 'FAST_FLUX': engineBadge = '<span class="badge badge-flux">BEH:FastFlux</span>'; break;
            default: engineBadge = '<span class="badge badge-clean">Clean</span>';
        }
        
        const verdict = r.blocked
            ? '<span class="badge badge-block">BLOCKED</span>'
            : '<span class="badge badge-safe">PASS</span>';
        
        tr.innerHTML = `
            <td class="cell-time">${fmtTime(r.timestamp)}</td>
            <td class="cell-domain">${r.domain}</td>
            <td class="cell-ip">${r.client_ip}</td>
            <td>${verdict}</td>
            <td>${engineBadge}</td>
        `;
        tbody.appendChild(tr);
    });
    
    const wrap = document.querySelector('.log-table-wrap');
    if (wrap) {
        wrap.scrollTop = wrap.scrollHeight;
    }
}

function renderClientTable(clients) {
    const tbody = document.querySelector('#client-table tbody');
    tbody.innerHTML = '';
    clients.slice(0, 6).forEach(c => {
        const riskPct = c.total > 0 ? Math.min(100, Math.round((c.blocked / c.total) * 100)) : 0;
        const riskColor = riskPct > 30 ? '#ef4444' : riskPct > 10 ? '#f59e0b' : '#10b981';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="cell-ip">${c.client_ip}</td>
            <td>${c.total}</td>
            <td>${c.blocked}</td>
            <td><div class="risk-bar"><div class="risk-fill" style="width:${riskPct}%;background:${riskColor}"></div></div></td>
        `;
        tbody.appendChild(tr);
    });
}

function showToast(alert) {
    const container = document.getElementById('alert-container');
    while (container.children.length >= 3) container.firstChild.remove();
    
    const d = document.createElement('div');
    d.className = 'toast';
    d.innerHTML = `
        <div class="toast-head">
            <span class="toast-title">⚠ ${alert.threat_type} Detection</span>
            <span class="toast-time">${fmtTime(alert.timestamp)}</span>
        </div>
        <div class="toast-domain">${alert.domain}</div>
        <div class="toast-reason">${alert.client_ip} — ${alert.reason}</div>
    `;
    container.appendChild(d);
    setTimeout(() => {
        d.style.animation = 'toastOut 0.3s forwards';
        setTimeout(() => d.remove(), 300);
    }, 6000);
}



async function analyzeDomain() {
    const domain = document.getElementById('domain-input').value.trim();
    if (!domain) return;
    
    const loading = document.getElementById('analysis-loading');
    const results = document.getElementById('analysis-results');
    
    loading.style.display = 'flex';
    results.style.display = 'none';
    
    try {
        const res = await fetch('/api/analyze_domain', {
            method: 'POST',
            headers: getApiHeaders(),
            body: JSON.stringify({ domain })
        });
        if (!res.ok) {
            throw new Error(`Server error (${res.status})`);
        }
        const envelope = await res.json();
        if (!envelope.ok) throw new Error(envelope.error || 'Analysis failed');
        
        const data = envelope.data;
        
        const meta = document.getElementById('analysis-meta');
        let chips = '';
        
        const mlClass = (data.ml_verdict || '').includes('Malicious') ? 'danger' : 'safe';
        chips += `<span class="meta-chip ${mlClass}">ML: ${data.ml_verdict} (${data.ml_confidence.toFixed(1)} / 100)</span>`;
        
        const entClass = data.entropy > 3.5 ? 'warn' : 'info';
        chips += `<span class="meta-chip ${entClass}">Entropy: ${data.entropy}</span>`;
        
        if (data.in_blocklist) chips += `<span class="meta-chip danger">⚠ IN BLOCKLIST</span>`;
        else chips += `<span class="meta-chip safe">Not in blocklist</span>`;
        
        if (data.domain && data.domain.startsWith('xn--')) chips += `<span class="meta-chip danger">PUNYCODE (internationalized domain)</span>`;
        
        if (data.lookalike) chips += `<span class="meta-chip warn">Lookalike: ${data.lookalike}</span>`;
        
        meta.innerHTML = chips;
        
        document.getElementById('resp-gemini').textContent = data.ai_responses.Gemini;
        document.getElementById('resp-gpt').textContent = data.ai_responses.ChatGPT;
        document.getElementById('resp-claude').textContent = data.ai_responses.Claude;
        
        loading.style.display = 'none';
        results.style.display = 'block';
        
    } catch (err) {
        loading.innerHTML = `<span style="color:var(--red)">Analysis failed: ${err.message}</span>`;
        setTimeout(() => { loading.innerHTML = ''; loading.style.display = 'none'; }, 4000);
    }
}



function fmtTime(ts) {
    try {
        return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
        return ts;
    }
}

function animateValue(id, target) {
    const el = document.getElementById(id);
    const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
    if (current === target) return;
    
    const diff = target - current;
    const steps = 15;
    const increment = diff / steps;
    let step = 0;
    
    const timer = setInterval(() => {
        step++;
        const val = Math.round(current + (increment * step));
        el.textContent = val.toLocaleString();
        if (step >= steps) {
            el.textContent = target.toLocaleString();
            clearInterval(timer);
        }
    }, 30);
}

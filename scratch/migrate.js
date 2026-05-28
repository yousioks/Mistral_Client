const fs = require('fs');
const path = require('path');

const jsCode = `
// ══ State ══════════════════════════════════════════════════════════════════
let ws = null;
let token = null;
let serverBase = '';
let currentModel = 'deepseek-v4-pro';
let reconnectTimer = null;
let reconnectAttempts = 0;
let allIncidents = [];
let chartInstances = {};

window.analyzeLog = function(msgText) {
  const prompt = \`Проанализируй следующую строку логов с сервера. Скажи, нормальное ли это поведение или атака, и что она означает:\\n\\n\${msgText}\\n\\nУчти строгие правила: ничего не ломать, не отключать.\`;
  document.getElementById('ai-task').value = prompt;
  switchTab('ai');
  sendAITask();
};

window.analyzeContext = function(id) {
  const inc = allIncidents.find(i => i.id === id);
  if(!inc) return;
  const prompt = \`Проанализируй опасный участок логов. Тип атаки: \${inc.type}. Описание: \${inc.description}.\\n\\nКонтекст:\\n\${inc.contextBlock}\\n\\nЧто делает атакующий и какие меры предпринять? Ничего не отключай и не ломай.\`;
  document.getElementById('ai-task').value = prompt;
  switchTab('ai');
  sendAITask();
};

// ══ Login ══════════════════════════════════════════════════════════════════
async function doLogin() {
    const host = document.getElementById('inp-host').value.trim();
    const port = document.getElementById('inp-port').value.trim() || '8080';
    const username = document.getElementById('inp-user').value.trim();
    const password = document.getElementById('inp-pass').value;
    const errEl = document.getElementById('login-error');
    const statusEl = document.getElementById('login-status');
    const btn = document.getElementById('btn-login');

    if (!host) { errEl.textContent = 'Укажите IP/хост сервера'; return; }
    if (!username || !password) { errEl.textContent = 'Введите логин и пароль'; return; }

    errEl.textContent = '';
    btn.disabled = true;
    statusEl.textContent = 'Проверка соединения...';

    let base = '';
    let loginData = null;

    for (const proto of ['https', 'http']) {
        try {
            const url = \`\${proto}://\${host}:\${port}\`;
            statusEl.textContent = \`Подключение к \${url}...\`;
            const r = await fetch(\`\${url}/api/auth/login\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
                signal: AbortSignal.timeout(5000),
            });
            const data = await r.json();
            if (data.success) { base = url; loginData = data; break; }
            else { errEl.textContent = data.error || 'Неверный логин или пароль'; btn.disabled = false; statusEl.textContent = ''; return; }
        } catch (e) { }
    }

    if (!loginData) {
        errEl.textContent = 'Сервер недоступен. Проверьте IP и порт.';
        btn.disabled = false; statusEl.textContent = ''; return;
    }

    serverBase = base;
    token = loginData.token;
    statusEl.textContent = 'Авторизован. Подключение...';

    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    btn.disabled = false;

    fetch('/api/set-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: base, host, port, token }),
    }).catch(() => { });

    initCharts();
    connectWS(host, port);
    loadUsers();
    loadQuarantine();
}

function doLogout() {
    if (ws) { ws.close(); ws = null; }
    token = null; serverBase = '';
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('app').classList.add('hidden');
    document.getElementById('live-feed').innerHTML = '';
    document.getElementById('incidents-list').innerHTML = '';
    document.getElementById('logs-feed').innerHTML = '';
}

// ══ WebSocket ══════════════════════════════════════════════════════════════
function connectWS(host, port) {
    if (ws) { ws.close(); ws = null; }
    setConnStatus('connecting', 'Подключение...');

    const proto = serverBase.startsWith('https') ? 'wss' : 'ws';
    const url = \`\${proto}://\${host}:\${port}/ws\`;

    try { ws = new WebSocket(url); } catch (e) {
        setConnStatus('error', 'Ошибка WS'); scheduleReconnect(host, port); return;
    }

    ws.onopen = () => {
        reconnectAttempts = 0;
        setConnStatus('connecting', 'Авторизация...');
        ws.send(JSON.stringify({ event: 'auth', data: { token, nonce: Date.now().toString(36) + Math.random().toString(36).slice(2) } }));
    };

    ws.onmessage = (e) => {
        try { handleMessage(JSON.parse(e.data)); } catch (_) { }
    };

    ws.onclose = () => { setConnStatus('error', 'Отключён'); scheduleReconnect(host, port); };
    ws.onerror = () => { setConnStatus('error', 'Ошибка соединения'); };
}

function scheduleReconnect(host, port) {
    if (reconnectTimer) return;
    const delay = Math.min(2000 * Math.pow(1.5, reconnectAttempts), 30000);
    reconnectAttempts++;
    reconnectTimer = setTimeout(() => { reconnectTimer = null; if (token) connectWS(host, port); }, delay);
}

function setConnStatus(state, label) {
    const dot = document.getElementById('conn-dot');
    const lbl = document.getElementById('conn-label');
    dot.className = 'conn-dot ' + state;
    lbl.textContent = label;
}

// ══ Message Handler ════════════════════════════════════════════════════════
function handleMessage(msg) {
    switch (msg.event) {
        case 'auth_success':
            setConnStatus('connected', 'Подключён');
            if (msg.data?.model) { currentModel = msg.data.model; document.getElementById('model-badge').textContent = currentModel; }
            break;
        case 'auth_error': setConnStatus('error', 'Ошибка авторизации'); break;
        case 'stats': updateStats(msg.data); break;
        case 'incidents_list': 
            allIncidents = msg.data || []; 
            renderIncidents(allIncidents); 
            updateChartsFromIncidents(allIncidents);
            break;
        case 'incident_updated':
            const idx = allIncidents.findIndex(i => i.id === msg.data.id);
            if(idx !== -1) allIncidents[idx] = msg.data;
            renderIncidents(allIncidents);
            updateChartsFromIncidents(allIncidents);
            break;
        case 'logs_list': renderLogs(msg.data || []); break;
        case 'log': if (msg.data) addLiveEntry(msg.data); break;
        case 'incident':
            if (msg.data) {
                allIncidents.unshift(msg.data);
                if(allIncidents.length > 500) allIncidents.pop();
                renderIncidents(allIncidents);
                updateChartsFromIncidents(allIncidents);
                if (msg.data.severity === 'CRITICAL' || msg.data.severity === 'HIGH') {
                    showAlert(msg.data);
                }
            }
            break;
        case 'metrics':
            updateMetrics(msg.data);
            break;
        case 'quarantine_updated':
            renderQuarantine(msg.data || []);
            break;
        case 'model_changed':
            if (msg.data?.model) { currentModel = msg.data.model; document.getElementById('model-badge').textContent = currentModel; }
            break;
        case 'ai_result':
            document.getElementById('ai-output').textContent = msg.data?.result || '(нет ответа)';
            document.getElementById('btn-ai-send').disabled = false;
            break;
        case 'ai_error':
            document.getElementById('ai-output').textContent = '❌ Ошибка: ' + (msg.data?.error || 'unknown');
            document.getElementById('btn-ai-send').disabled = false;
            break;
        case 'bot_notify': if (msg.data) showAlert(msg.data); break;
    }
}

// ══ Charts Initialization ════════════════════════════════════════════════════
function initCharts() {
    Chart.defaults.color = '#8A99B5';
    Chart.defaults.font.family = "'Inter', sans-serif";

    // Risk Gauge
    const ctxRisk = document.getElementById('chart-risk').getContext('2d');
    chartInstances.risk = new Chart(ctxRisk, {
        type: 'doughnut',
        data: {
            labels: ['Risk', 'Safe'],
            datasets: [{ data: [10, 90], backgroundColor: ['#F44336', '#1E2532'], borderWidth: 0, borderRadius: 10 }]
        },
        options: {
            cutout: '85%', rotation: -125, circumference: 250,
            plugins: { tooltip: { enabled: false }, legend: { display: false } }
        }
    });

    // Threats by Type
    const ctxType = document.getElementById('chart-type').getContext('2d');
    chartInstances.type = new Chart(ctxType, {
        type: 'bar',
        data: {
            labels: ['Brute Force', 'SQLi', 'DDoS', 'Malware', 'XSS', 'Other'],
            datasets: [{
                label: 'Threats',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: ['#F44336', '#FF9800', '#4CAF50', '#2196F3', '#9C27B0', '#607D8B'],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { grid: { color: '#1E2532' }, beginAtZero: true },
                x: { grid: { display: false } }
            }
        }
    });

    // Network Activity
    const ctxNet = document.getElementById('chart-network').getContext('2d');
    chartInstances.net = new Chart(ctxNet, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                label: 'Connections',
                data: Array(20).fill(0),
                borderColor: '#4CAF50',
                backgroundColor: 'rgba(76, 175, 80, 0.1)',
                borderWidth: 2, tension: 0.4, fill: true, pointRadius: 0
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { display: false }, x: { display: false } }
        }
    });
}

function updateChartsFromIncidents(list) {
    let crit = 0, high = 0;
    const types = { 'Brute Force': 0, 'SQLi': 0, 'DDoS': 0, 'Malware': 0, 'XSS': 0, 'Other': 0 };
    list.forEach(i => {
        if (i.severity === 'CRITICAL') crit++;
        if (i.severity === 'HIGH') high++;
        const t = String(i.type).toLowerCase();
        if (t.includes('brute') || t.includes('login')) types['Brute Force']++;
        else if (t.includes('sql')) types['SQLi']++;
        else if (t.includes('ddos') || t.includes('flood')) types['DDoS']++;
        else types['Other']++;
    });

    const riskLevel = Math.min(100, crit * 10 + high * 5);
    document.getElementById('risk-value').textContent = riskLevel;
    document.getElementById('risk-label').textContent = riskLevel > 70 ? 'HIGH' : riskLevel > 40 ? 'MEDIUM' : 'LOW';
    document.getElementById('risk-label').style.color = riskLevel > 70 ? '#F44336' : riskLevel > 40 ? '#FF9800' : '#4CAF50';
    
    if (chartInstances.risk) {
        chartInstances.risk.data.datasets[0].data = [riskLevel, 100 - riskLevel];
        chartInstances.risk.data.datasets[0].backgroundColor[0] = riskLevel > 70 ? '#F44336' : riskLevel > 40 ? '#FF9800' : '#4CAF50';
        chartInstances.risk.update();
    }

    if (chartInstances.type) {
        chartInstances.type.data.datasets[0].data = Object.values(types);
        chartInstances.type.update();
    }
}

// ══ Stats ══════════════════════════════════════════════════════════════════
function updateStats(data) {
    if (!data?.incidents) return;
    document.getElementById('s-critical').textContent = data.incidents.critical || 0;
    document.getElementById('s-threats').textContent = (data.incidents.critical || 0) + (data.incidents.high || 0) + (data.incidents.medium || 0) + (data.incidents.low || 0);
    document.getElementById('s-vuln').textContent = data.cveLogs || 0;
}

// ══ Live Feed ══════════════════════════════════════════════════════════════
function addLiveEntry(entry) {
    const feed = document.getElementById('live-feed');
    const div = document.createElement('div');
    div.className = 'log-entry';
    const t = (entry.timestamp || '').slice(11, 19);
    div.innerHTML = \`<span class="log-time">\${t}</span><span class="log-level \${entry.level}">\${(entry.level || 'info').toUpperCase()}</span><span class="log-msg">\${esc(entry.message || '')}</span><span class="log-monitor">\${esc(entry.type || '')}</span>\`;
    feed.insertBefore(div, feed.firstChild);
    if (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

// ══ Incidents ══════════════════════════════════════════════════════════════
function renderIncidents(list) {
    const el = document.getElementById('incidents-list');
    el.innerHTML = '';
    list.forEach(i => {
        addIncidentCard(i, false, el);
    });
}

function updateIncidentStatus(id, selectEl) {
    const status = selectEl.value;
    fetch(\`\${serverBase}/api/incidents/\${id}\`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
    });
}

function updateIncidentSeverity(id, selectEl) {
    const severity = selectEl.value;
    fetch(\`\${serverBase}/api/incidents/\${id}\`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity })
    });
}

function addIncidentCard(inc, prepend, container) {
    if(!container) container = document.getElementById('incidents-list');
    const div = document.createElement('div');
    div.className = \`incident-card \${inc.severity||'LOW'}\`;
    
    let ctxHtml = '';
    if(inc.contextBlock) {
        ctxHtml = \`<div class="incident-ctx">\${esc(inc.contextBlock)}</div>\`;
    }

    const statuses = [
        {val: 'new', label: 'Новый'},
        {val: 'in_review', label: 'В рассмотрении'},
        {val: 'resolved', label: 'Решен'}
    ];
    let statusOpts = statuses.map(s => \`<option value="\${s.val}" \${inc.status===s.val?'selected':''}>\${s.label}</option>\`).join('');
    
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    let sevOpts = severities.map(s => \`<option value="\${s}" \${inc.severity===s?'selected':''}>\${s}</option>\`).join('');

    const controlsHtml = \`
        <div class="incident-controls">
            <select class="inc-select" onchange="updateIncidentStatus('\${inc.id}', this)">\${statusOpts}</select>
            <select class="inc-select" onchange="updateIncidentSeverity('\${inc.id}', this)">\${sevOpts}</select>
            <button class="btn-ai-inline" onclick="analyzeContext('\${inc.id}')">🧠 АНАЛИЗ ИИ</button>
        </div>
    \`;
    
    div.innerHTML = \`<span class="inc-sev \${inc.severity}">\${inc.severity}</span>
    <div class="inc-body">
        <div class="inc-type">\${esc(inc.type||'')}</div>
        <div class="inc-desc">\${esc(inc.description||'')}</div>
        \${ctxHtml}
        \${controlsHtml}
        <div class="inc-meta">\${esc(inc.monitor||'')} · \${(inc.timestamp||'').slice(0,19).replace('T',' ')}</div>
    </div>\`;
    
    if (prepend) container.insertBefore(div, container.firstChild);
    else container.appendChild(div);
}

// ══ Logs ══════════════════════════════════════════════════════════════════
function renderLogs(list) {
    const feed = document.getElementById('logs-feed');
    feed.innerHTML = '';
    list.forEach(entry => {
        const div = document.createElement('div');
        div.className = 'log-entry';
        const t = (entry.timestamp || '').slice(0, 19).replace('T', ' ');
        div.innerHTML = \`<span class="log-time">\${t}</span><span class="log-level \${entry.level}">\${(entry.level || 'info').toUpperCase()}</span><span class="log-msg">\${esc(entry.message || '')}</span>\`;
        feed.appendChild(div);
    });
}

function loadLogs() {
    const type = document.getElementById('log-type').value;
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ event: 'get_logs', data: { type, limit: 200 } }));
    }
}

// ══ Quarantine & Network ════════════════════════════════════════════════════
function loadQuarantine() {
    fetch(\`\${serverBase}/api/quarantine\`)
        .then(r => r.json())
        .then(data => renderQuarantine(data || []))
        .catch(console.error);
}

function renderQuarantine(list) {
    const tb = document.getElementById('quarantine-tbody');
    tb.innerHTML = '';
    list.forEach(q => {
        const tr = document.createElement('tr');
        tr.innerHTML = \`
            <td>\${esc(q.ip)}</td>
            <td>\${esc(q.reason || 'Manual')}</td>
            <td>\${esc(q.timestamp).slice(0,19).replace('T',' ')}</td>
            <td><button class="btn-sm" onclick="unquarantineIp('\${q.ip}')">УДАЛИТЬ</button></td>
        \`;
        tb.appendChild(tr);
    });
}

function quarantineIp(ip, reason) {
    fetch(\`\${serverBase}/api/quarantine\`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip, reason})
    });
}

function unquarantineIp(ip) {
    fetch(\`\${serverBase}/api/quarantine/\${ip}\`, {
        method: 'DELETE'
    });
}

// ══ Metrics (Auth & SSH) ════════════════════════════════════════════════════
function updateMetrics(data) {
    if (!data) return;
    
    // System metrics update
    if (data.cpu != null) {
        document.getElementById('sys-cpu').style.width = data.cpu + '%';
        document.getElementById('sys-cpu-val').textContent = data.cpu + '%';
    }
    if (data.ram) {
        document.getElementById('sys-ram').style.width = data.ram.percent + '%';
        document.getElementById('sys-ram-val').textContent = data.ram.percent + '%';
    }
    if (data.disk) {
        document.getElementById('sys-disk').style.width = data.disk.percent + '%';
        document.getElementById('sys-disk-val').textContent = data.disk.percent + '%';
    }
    if (data.connections != null && chartInstances.net) {
        const ds = chartInstances.net.data.datasets[0].data;
        ds.shift(); ds.push(data.connections);
        chartInstances.net.update();
    }

    // Auth Monitor
    if (data.ssh_sessions) {
        const tb = document.getElementById('ssh-tbody');
        tb.innerHTML = '';
        data.ssh_sessions.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = \`
                <td>\${esc(s.user)}</td>
                <td>\${esc(s.ip)}</td>
                <td>\${esc(s.time)}</td>
                <td><button class="btn-sm btn-danger" onclick="quarantineIp('\${s.ip}', 'Blocked from SSH table')">КАРАНТИН</button></td>
            \`;
            tb.appendChild(tr);
        });
    }
}

// ══ AI ════════════════════════════════════════════════════════════════════
function selectModel(model, btn) {
    currentModel = model;
    document.querySelectorAll('.model-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ event: 'switch_model', data: { model } }));
}

function sendAITask() {
    const task = document.getElementById('ai-task').value.trim();
    if (!task) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) { document.getElementById('ai-output').textContent = '❌ Нет соединения с сервером'; return; }
    document.getElementById('btn-ai-send').disabled = true;
    document.getElementById('ai-output').textContent = '⏳ Запрос отправлен, ожидаю ответ...';
    ws.send(JSON.stringify({ event: 'ai_task', data: { task, model: currentModel } }));
}

// ══ Users ══════════════════════════════════════════════════════════════════
async function loadUsers() {
    try {
        const r = await fetch(\`\${serverBase}/api/users\`);
        const users = await r.json();
        const el = document.getElementById('users-list');
        el.innerHTML = '';
        users.forEach(u => {
            const div = document.createElement('div');
            div.className = 'user-card';
            div.innerHTML = \`<div class="user-avatar">\${(u.username || '?')[0].toUpperCase()}</div><div class="user-info"><div class="name">\${esc(u.username)}</div><div class="role">\${esc(u.role || 'operator')}</div></div>\${u.chat_id ? '<span class="user-tg">TELEGRAM</span>' : ''}\`;
            el.appendChild(div);
        });
    } catch (e) { }
}

async function addUser() {
    const username = document.getElementById('nu-user').value.trim();
    const password = document.getElementById('nu-pass').value;
    const role = document.getElementById('nu-role').value;
    if (!username || !password) return;
    try {
        const r = await fetch(\`\${serverBase}/api/users\`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password, role }) });
        const data = await r.json();
        if (data.success) { document.getElementById('nu-user').value = ''; document.getElementById('nu-pass').value = ''; loadUsers(); }
        else alert(data.error || 'Ошибка');
    } catch (e) { alert('Ошибка соединения'); }
}

// ══ Alert Banner ══════════════════════════════════════════════════════════
function showAlert(data) {
    const banner = document.getElementById('alert-banner');
    const sev = data.severity || data.type || 'ALERT';
    banner.textContent = \`🚨 \${sev}: \${data.description || data.type || ''} — ТРЕБУЕТСЯ ВМЕШАТЕЛЬСТВО!\`;
    banner.style.display = 'block';
    setTimeout(() => { banner.style.display = 'none'; }, 8000);
}

// ══ Tabs ══════════════════════════════════════════════════════════════════
function switchTab(name) {
    document.querySelectorAll('.tab').forEach((t, i) => t.classList.toggle('active', ['dashboard', 'network', 'incidents', 'logs', 'ai', 'users'][i] === name));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.getElementById('panel-' + name).classList.add('active');
    if (name === 'logs') loadLogs();
    if (name === 'users') loadUsers();
    if (name === 'incidents' && ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ event: 'get_incidents' }));
}

// ══ Utils ══════════════════════════════════════════════════════════════════
function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

document.getElementById('inp-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
`;

const htmlCode = \`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>MISTRAL Defense Command</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #0B0E14;
            --bg-panel: #151A22;
            --border: #1E2532;
            --text: #E0E6ED;
            --muted: #8A99B5;
            --red: #F44336;
            --green: #4CAF50;
            --orange: #FF9800;
            --blue: #2196F3;
            --font-display: 'Inter', system-ui, sans-serif;
            --font-mono: 'Fira Code', monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: var(--bg); color: var(--text); font-family: var(--font-display); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

        /* Login */
        #login-screen { position: fixed; inset: 0; background: var(--bg); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        #login-screen.hidden { display: none; }
        .login-box { background: rgba(20,20,20,0.85); backdrop-filter: blur(16px); border: 1px solid rgba(255,255,255,0.05); border-radius: 16px; padding: 50px; width: 500px; display: flex; flex-direction: column; gap: 25px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); }
        .login-logo h1 { font-size: 60px; color: var(--red); text-align: center; font-weight: 800; }
        .login-logo p { text-align: center; color: var(--muted); letter-spacing: 4px; font-size: 14px; }
        .field-group { display: flex; flex-direction: column; gap: 8px; }
        .field-group label { font-size: 12px; color: var(--muted); font-weight: bold; letter-spacing: 1px; }
        .field-group input { background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1); padding: 14px; color: #fff; border-radius: 8px; outline: none; transition: 0.2s; }
        .field-group input:focus { border-color: var(--red); box-shadow: 0 0 15px rgba(244,67,54,0.2); }
        .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .btn-login { background: linear-gradient(135deg, var(--red) 0%, #8b0000 100%); color: #fff; border: none; padding: 16px; font-size: 20px; font-weight: bold; border-radius: 8px; cursor: pointer; letter-spacing: 2px; box-shadow: 0 8px 20px rgba(244,67,54,0.3); transition: 0.2s; }
        .btn-login:hover { transform: translateY(-2px); filter: brightness(1.1); box-shadow: 0 12px 25px rgba(244,67,54,0.5); }
        #login-error { color: var(--red); font-size: 14px; text-align: center; }
        #login-status { color: var(--muted); font-size: 12px; text-align: center; }

        /* Main App Header */
        #app { display: flex; flex-direction: column; height: 100vh; }
        #app.hidden { display: none; }
        header { background: var(--bg-panel); border-bottom: 1px solid var(--border); display: flex; align-items: center; padding: 0 24px; height: 60px; gap: 24px; }
        .header-logo { font-size: 20px; font-weight: 900; color: #fff; letter-spacing: 1px; display: flex; align-items: center; gap: 10px; }
        .header-logo span { color: var(--blue); }
        .tabs { display: flex; gap: 24px; height: 100%; align-items: center; flex: 1; }
        .tab { font-size: 13px; font-weight: 600; color: var(--muted); cursor: pointer; letter-spacing: 1px; text-transform: uppercase; height: 100%; display: flex; align-items: center; border-bottom: 2px solid transparent; transition: 0.2s; }
        .tab:hover { color: #fff; }
        .tab.active { color: #fff; border-bottom-color: var(--blue); }
        .header-right { display: flex; align-items: center; gap: 16px; margin-left: auto; }
        .conn-badge { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
        .conn-dot { width: 8px; height: 8px; border-radius: 50%; background: #555; }
        .conn-dot.connected { background: var(--green); box-shadow: 0 0 10px var(--green); }
        .conn-dot.error { background: var(--red); box-shadow: 0 0 10px var(--red); }
        .conn-dot.connecting { background: var(--orange); }
        .btn-logout { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold; }
        .btn-logout:hover { color: #fff; border-color: #fff; }

        /* Panels */
        .content { flex: 1; overflow: hidden; position: relative; padding: 24px; }
        .panel { display: none; height: 100%; overflow-y: auto; }
        .panel.active { display: block; }

        /* Dashboard Grid */
        .grid-dashboard { display: grid; grid-template-columns: 2fr 1fr 1fr; grid-template-rows: auto auto auto; gap: 24px; height: 100%; }
        .card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 12px; padding: 24px; display: flex; flex-direction: column; position: relative; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .card-title { font-size: 14px; font-weight: bold; color: #fff; margin-bottom: 16px; letter-spacing: 1px; display: flex; align-items: center; justify-content: space-between; }
        
        .gauge-container { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; position: relative; }
        .gauge-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -30%); text-align: center; }
        .gauge-text .val { font-size: 64px; font-weight: 800; color: var(--red); line-height: 1; text-shadow: 0 0 20px rgba(244,67,54,0.5); }
        .gauge-text .lbl { font-size: 16px; color: var(--muted); font-weight: bold; letter-spacing: 4px; }

        .stat-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; }
        .stat-box { background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 8px; padding: 20px; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .stat-box .val { font-size: 36px; font-weight: 800; color: #fff; margin-bottom: 8px; }
        .stat-box .lbl { font-size: 12px; color: var(--muted); text-transform: uppercase; font-weight: bold; display: flex; align-items: center; gap: 6px; }

        .chart-container { position: relative; flex: 1; min-height: 200px; }

        .progress-group { display: flex; flex-direction: column; gap: 12px; margin-top: auto; }
        .progress-item { display: flex; flex-direction: column; gap: 6px; }
        .progress-header { display: flex; justify-content: space-between; font-size: 12px; font-weight: bold; color: var(--muted); }
        .progress-bar { height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; }
        .progress-fill { height: 100%; border-radius: 3px; }

        /* Tables & Lists */
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 12px; }
        td { color: #fff; }
        .btn-sm { background: var(--bg); border: 1px solid var(--border); color: #fff; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold; }
        .btn-sm:hover { background: var(--border); }
        .btn-danger { background: rgba(244,67,54,0.1); border-color: var(--red); color: var(--red); }
        .btn-danger:hover { background: var(--red); color: #fff; }

        /* Incident Card */
        .incident-card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; display: flex; gap: 16px; border-left: 4px solid var(--muted); }
        .incident-card.CRITICAL { border-left-color: var(--red); box-shadow: 0 0 15px rgba(244,67,54,0.1); }
        .incident-card.HIGH { border-left-color: var(--orange); }
        .inc-sev { font-size: 12px; font-weight: bold; padding: 4px 8px; border-radius: 4px; height: fit-content; }
        .inc-sev.CRITICAL { background: rgba(244,67,54,0.2); color: var(--red); }
        .inc-sev.HIGH { background: rgba(255,152,0,0.2); color: var(--orange); }
        .inc-body { flex: 1; display: flex; flex-direction: column; gap: 8px; }
        .inc-type { font-weight: bold; font-size: 16px; color: #fff; }
        .inc-desc { color: var(--muted); font-size: 14px; }
        .inc-meta { font-size: 12px; color: #555; margin-top: 8px; }
        .incident-ctx { background: #000; padding: 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; color: #aaa; max-height: 150px; overflow-y: auto; }
        .incident-controls { display: flex; gap: 12px; margin-top: 8px; }
        .inc-select { background: rgba(0,0,0,0.3); border: 1px solid var(--border); color: #fff; padding: 6px 12px; border-radius: 4px; font-size: 12px; outline: none; }
        .btn-ai-inline { background: rgba(33,150,243,0.1); border: 1px solid var(--blue); color: var(--blue); padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; cursor: pointer; }
        .btn-ai-inline:hover { background: var(--blue); color: #fff; }

        /* Logs */
        .log-entry { font-family: var(--font-mono); font-size: 13px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; gap: 16px; }
        .log-time { color: #555; }
        .log-level { font-weight: bold; width: 60px; }
        .log-level.info { color: var(--blue); }
        .log-level.warn { color: var(--orange); }
        .log-level.error { color: var(--red); }
        .log-msg { color: #ccc; flex: 1; word-break: break-all; }
        
        /* Banner */
        #alert-banner { position: fixed; top: 0; left: 0; right: 0; background: var(--red); color: #fff; text-align: center; padding: 16px; font-weight: bold; font-size: 18px; z-index: 2000; display: none; }

        /* Forms */
        .ai-panel { display: flex; flex-direction: column; gap: 20px; height: 100%; }
        .ai-output { flex: 1; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; font-family: var(--font-mono); white-space: pre-wrap; overflow-y: auto; }
        .ai-input-row { display: flex; gap: 16px; }
        .ai-input-row textarea { flex: 1; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; color: #fff; font-family: var(--font-mono); resize: none; height: 80px; outline: none; }
        .ai-input-row textarea:focus { border-color: var(--blue); }
        .ai-input-row button { background: var(--blue); color: #fff; border: none; border-radius: 8px; padding: 0 32px; font-weight: bold; cursor: pointer; }

        .model-btn { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .model-btn.active { background: var(--blue); color: #fff; border-color: var(--blue); }
        .ai-models { display: flex; gap: 12px; }

        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
    </style>
</head>
<body>
    <div id="alert-banner"></div>

    <div id="login-screen">
        <div class="login-box">
            <div class="login-logo">
                <h1>MIST<span>RAL</span></h1>
                <p>ENTERPRISE SECURITY</p>
            </div>
            <div class="row2">
                <div class="field-group"><label>SERVER IP</label><input id="inp-host" type="text" placeholder="127.0.0.1"></div>
                <div class="field-group"><label>PORT</label><input id="inp-port" type="text" placeholder="8080" value="8080"></div>
            </div>
            <div class="field-group"><label>USERNAME</label><input id="inp-user" type="text" placeholder="admin"></div>
            <div class="field-group"><label>PASSWORD</label><input id="inp-pass" type="password" placeholder="••••••••"></div>
            <div id="login-error"></div>
            <button class="btn-login" id="btn-login" onclick="doLogin()">AUTHORIZE</button>
            <div id="login-status"></div>
        </div>
    </div>

    <div id="app" class="hidden">
        <header>
            <div class="header-logo">MIST<span>RAL</span></div>
            <div class="tabs">
                <div class="tab active" onclick="switchTab('dashboard')">Dashboard</div>
                <div class="tab" onclick="switchTab('network')">Network</div>
                <div class="tab" onclick="switchTab('incidents')">Incidents</div>
                <div class="tab" onclick="switchTab('logs')">Logs</div>
                <div class="tab" onclick="switchTab('ai')">AI Analysis</div>
                <div class="tab" onclick="switchTab('users')">Access</div>
            </div>
            <div class="header-right">
                <div class="conn-badge">
                    <div class="conn-dot" id="conn-dot"></div>
                    <span id="conn-label">Connecting...</span>
                </div>
                <div class="btn-logout" id="model-badge" style="border:none">DEEPSEEK V4 PRO</div>
                <button class="btn-logout" onclick="doLogout()">LOGOUT</button>
            </div>
        </header>

        <div class="content">
            <!-- DASHBOARD -->
            <div class="panel active" id="panel-dashboard">
                <div class="grid-dashboard">
                    <!-- Top Left: Huge Gauge -->
                    <div class="card" style="grid-column: 1; grid-row: 1;">
                        <div class="gauge-container">
                            <canvas id="chart-risk"></canvas>
                            <div class="gauge-text">
                                <div class="val" id="risk-value">0</div>
                                <div class="lbl" id="risk-label">SAFE</div>
                            </div>
                        </div>
                    </div>

                    <!-- Top Middle: Network Activity -->
                    <div class="card" style="grid-column: 2 / span 2; grid-row: 1;">
                        <div class="card-title">Network Activity</div>
                        <div class="chart-container"><canvas id="chart-network"></canvas></div>
                    </div>

                    <!-- Middle: Stats -->
                    <div class="stat-grid" style="grid-column: 1 / span 3; grid-row: 2;">
                        <div class="stat-box"><div class="val" id="s-threats">0</div><div class="lbl"><span style="color:var(--red)">▲</span> Active Threats</div></div>
                        <div class="stat-box"><div class="val" id="s-critical">0</div><div class="lbl"><span style="color:var(--orange)">■</span> Critical Alerts</div></div>
                        <div class="stat-box"><div class="val" id="s-vuln">0</div><div class="lbl"><span style="color:var(--blue)">●</span> System Vulnerabilities</div></div>
                    </div>

                    <!-- Bottom Left: Bar Chart -->
                    <div class="card" style="grid-column: 1 / span 2; grid-row: 3;">
                        <div class="card-title">Threats by Type</div>
                        <div class="chart-container" style="min-height:250px"><canvas id="chart-type"></canvas></div>
                    </div>

                    <!-- Bottom Right: System Health -->
                    <div class="card" style="grid-column: 3; grid-row: 3;">
                        <div class="card-title">System Health</div>
                        <div class="progress-group" style="margin-top:0">
                            <div class="progress-item"><div class="progress-header"><span>CPU Load</span><span id="sys-cpu-val">0%</span></div><div class="progress-bar"><div class="progress-fill" id="sys-cpu" style="width: 0%; background: var(--blue);"></div></div></div>
                            <div class="progress-item"><div class="progress-header"><span>Memory Usage</span><span id="sys-ram-val">0%</span></div><div class="progress-bar"><div class="progress-fill" id="sys-ram" style="width: 0%; background: var(--green);"></div></div></div>
                            <div class="progress-item"><div class="progress-header"><span>Storage</span><span id="sys-disk-val">0%</span></div><div class="progress-bar"><div class="progress-fill" id="sys-disk" style="width: 0%; background: var(--orange);"></div></div></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- NETWORK & QUARANTINE -->
            <div class="panel" id="panel-network">
                <div class="card" style="margin-bottom:24px">
                    <div class="card-title">SSH Connection Attempts</div>
                    <table>
                        <thead><tr><th>User</th><th>IP Address</th><th>Time</th><th>Action</th></tr></thead>
                        <tbody id="ssh-tbody"><tr><td colspan="4">No data</td></tr></tbody>
                    </table>
                </div>
                <div class="card">
                    <div class="card-title">Quarantined IPs</div>
                    <table>
                        <thead><tr><th>IP Address</th><th>Reason</th><th>Timestamp</th><th>Action</th></tr></thead>
                        <tbody id="quarantine-tbody"><tr><td colspan="4">No data</td></tr></tbody>
                    </table>
                </div>
            </div>

            <!-- INCIDENTS -->
            <div class="panel" id="panel-incidents">
                <div class="card" style="height:100%; display:flex; flex-direction:column;">
                    <div class="card-title">Security Incidents</div>
                    <div id="incidents-list" style="flex:1; overflow-y:auto; padding-right:8px;"></div>
                </div>
            </div>

            <!-- LOGS -->
            <div class="panel" id="panel-logs">
                <div class="card" style="height:100%; display:flex; flex-direction:column;">
                    <div class="card-title" style="display:flex; gap:16px;">
                        System Logs
                        <select id="log-type" onchange="loadLogs()" style="background:transparent; border:1px solid var(--border); color:#fff; border-radius:4px;">
                            <option value="server">Server</option>
                            <option value="bot">Bot</option>
                            <option value="cve">CVE</option>
                        </select>
                    </div>
                    <div id="logs-feed" style="flex:1; overflow-y:auto;"></div>
                </div>
            </div>

            <!-- AI -->
            <div class="panel" id="panel-ai">
                <div class="ai-panel">
                    <div class="ai-models">
                        <button class="model-btn active" onclick="selectModel('deepseek-v4-pro',this)">DEEPSEEK V4 PRO</button>
                        <button class="model-btn" onclick="selectModel('kimi-k2.6',this)">KIMI K2.6</button>
                        <button class="model-btn" onclick="selectModel('claude-sonnet-4.6',this)">CLAUDE SONNET 4.6</button>
                    </div>
                    <div class="ai-output" id="ai-output">AI System Ready.</div>
                    <div class="ai-input-row">
                        <textarea id="ai-task" placeholder="Describe a task or analyze an incident..."></textarea>
                        <button id="btn-ai-send" onclick="sendAITask()">ANALYZE</button>
                    </div>
                </div>
            </div>

            <!-- USERS -->
            <div class="panel" id="panel-users">
                <div class="card" style="margin-bottom:24px">
                    <div class="card-title">Add User</div>
                    <div style="display:flex; gap:16px; align-items:flex-end;">
                        <div class="field-group"><label>USERNAME</label><input id="nu-user" type="text"></div>
                        <div class="field-group"><label>PASSWORD</label><input id="nu-pass" type="password"></div>
                        <div class="field-group"><label>ROLE</label>
                            <select id="nu-role" style="background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.1); padding:14px; color:#fff; border-radius:8px;">
                                <option value="operator">Operator</option><option value="admin">Admin</option>
                            </select>
                        </div>
                        <button class="btn-sm" style="padding:16px 24px" onclick="addUser()">ADD</button>
                    </div>
                </div>
                <div class="card">
                    <div class="card-title">Active Users</div>
                    <div id="users-list" style="display:grid; gap:16px;"></div>
                </div>
            </div>
        </div>
    </div>
    <script>
\${jsCode}
    </script>
</body>
</html>\`;

fs.writeFileSync(path.join(__dirname, '../src/templates/index.html'), htmlCode);
console.log('Successfully generated index.html');

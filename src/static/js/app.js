// ══════════════════════════════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════════════════════════════
let ws = null, token = null, serverBase = '', currentModel = 'deepseek-v4-pro';
let reconnectTimer = null, reconnectAttempts = 0;
let allIncidents = [];
let chartRisk = null, chartNet = null, chartType = null;
let autoDefenseTriggered = false;
let threatCount = 0;
const $ = id => document.getElementById(id);
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
 
// ══════════════════════════════════════════════════════════════════════════════
// ANALYZE (from original)
// ══════════════════════════════════════════════════════════════════════════════
window.analyzeLog = function(msgText) {
    const prompt = `Проанализируй следующую строку логов с сервера. Скажи, нормальное ли это поведение или атака, и что она означает:\n\n${msgText}\n\nУчти строгие правила: ничего не ломать, не отключать.`;
    $('ai-task').value = prompt; switchTab('ai'); sendAITask();
};
window.analyzeContext = function(id) {
    const inc = allIncidents.find(i => i.id === id);
    if(!inc) return;
    const prompt = `Проанализируй опасный участок логов. Тип атаки: ${inc.type}. Описание: ${inc.description}.\n\nКонтекст:\n${inc.contextBlock}\n\nЧто делает атакующий и какие меры предпринять? Ничего не отключай и не ломай.`;
    $('ai-task').value = prompt; switchTab('ai'); sendAITask();
};
 
// ══════════════════════════════════════════════════════════════════════════════
// CHARTS
// ══════════════════════════════════════════════════════════════════════════════
function initCharts() {
    Chart.defaults.color = '#8899A6';
    Chart.defaults.font.family = "'Inter', sans-serif";
    chartRisk = new Chart($('chart-risk').getContext('2d'), {
        type: 'doughnut',
        data: { datasets: [{ data: [0,100], backgroundColor: ['#FF0000','#110000'], borderWidth: 0 }] },
        options: { cutout:'82%', rotation:-90, circumference:180, plugins:{tooltip:{enabled:false},legend:{display:false}} }
    });
    chartNet = new Chart($('chart-network').getContext('2d'), {
        type: 'line',
        data: { labels: Array(30).fill(''), datasets: [{ data: Array(30).fill(0), borderColor:'#FFFFFF', backgroundColor:'rgba(255,255,255,0.05)', borderWidth:1.5, tension:0.4, fill:true, pointRadius:0 }] },
        options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}}, scales:{y:{display:false},x:{display:false}} }
    });
    chartType = new Chart($('chart-type').getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Brute Force','SQLi','DDoS','Malware','XSS','Other'],
            datasets: [{ data:[0,0,0,0,0,0], backgroundColor:['#EF4444','#F59E0B','#22C55E','#3B82F6','#A855F7','#6B7280'], borderRadius:4, borderWidth:0 }]
        },
        options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}}, scales:{y:{grid:{color:'rgba(255,255,255,0.08)'},beginAtZero:true},x:{grid:{display:false}}} }
    });
}

function updateChartsFromIncidents(list) {
    let crit=0, high=0, med=0, low=0;
    const types = [0,0,0,0,0,0];
    list.forEach(i => {
        const sev = String(i.severity||'').toUpperCase();
        if(sev==='CRITICAL') crit++;
        else if(sev==='HIGH') high++;
        else if(sev==='MEDIUM') med++;
        else low++;
        const t = String(i.type||'').toLowerCase();
        if(t.includes('brute')||t.includes('login')||t.includes('auth')) types[0]++;
        else if(t.includes('sql')||t.includes('inject')) types[1]++;
        else if(t.includes('ddos')||t.includes('flood')) types[2]++;
        else if(t.includes('malware')||t.includes('virus')) types[3]++;
        else if(t.includes('xss')||t.includes('script')) types[4]++;
        else types[5]++;
    });
    // Risk level
    const risk = Math.min(100, crit*12 + high*6 + med*2);
    $('risk-value').textContent = risk;
    const col = risk>70?'#EF4444':risk>40?'#F59E0B':'#22C55E';
    const lbl = risk>70?'HIGH':risk>40?'MEDIUM':'SAFE';
    $('risk-value').style.color=col; $('risk-label').style.color=col; $('risk-label').textContent=lbl;
    if(chartRisk){chartRisk.data.datasets[0].data=[risk,100-risk]; chartRisk.data.datasets[0].backgroundColor[0]=col; chartRisk.update();}
    // chartType update removed
    // Risk level table
    $('rl-crit').textContent=crit; $('rl-high').textContent=high; $('rl-med').textContent=med; $('rl-low').textContent=low;
    // Recent alerts (last 8 critical/high)
    const recent = list.filter(i=> {
        const s = String(i.severity||'').toUpperCase();
        return s==='CRITICAL' || s==='HIGH';
    }).slice(0,8);
    const ra = $('recent-alerts'); 
    if(ra) {
        ra.innerHTML = '';
        recent.forEach(i => {
            const sev = String(i.severity||'').toUpperCase();
            const d = document.createElement('div');
            d.style.cssText = 'padding:6px 8px;background:rgba(0,0,0,0.3);border-radius:6px;border-left:3px solid '+(sev==='CRITICAL'?'var(--red)':'var(--orange)');
            d.innerHTML = '<div style="font-weight:700;font-size:11px;color:#fff">'+esc(i.type||'')+'</div><div style="font-size:10px;color:var(--muted);margin-top:2px">'+esc(i.description||'').slice(0,60)+'</div>';
            ra.appendChild(d);
        });
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// LOGIN
// ══════════════════════════════════════════════════════════════════════════════
async function doLogin() {
    const host = $('inp-host').value.trim();
    const port = $('inp-port').value.trim() || '8080';
    const username = $('inp-user').value.trim();
    const password = $('inp-pass').value;
    const errEl = $('login-error'), statusEl = $('login-status'), btn = $('btn-login');
    if (!host) { errEl.textContent = 'Укажите IP/хост сервера'; return; }
    if (!username || !password) { errEl.textContent = 'Введите логин и пароль'; return; }
    errEl.textContent = ''; btn.disabled = true; statusEl.textContent = 'Проверка соединения...';
    
    if (window.electronAPI) {
        const res = await window.electronAPI.connectServer({ host, port, username, password });
        if (res.success) {
            serverBase = res.base;
            statusEl.textContent = 'Авторизован. Подключение к WebSocket...';
            $('login-screen').classList.add('hidden');
            $('app').classList.remove('hidden');
            btn.disabled = false;
            initCharts(); loadUsers(); loadQuarantine();
        } else {
            errEl.textContent = res.error || 'Неверный логин или пароль'; btn.disabled = false; statusEl.textContent = ''; return;
        }
    }
}
function doLogout() {
    if (window.electronAPI) window.electronAPI.disconnectServer();
    token = null; serverBase = '';
    $('login-screen').classList.remove('hidden');
    $('app').classList.add('hidden');
    $('running-logs').innerHTML = '';
    $('incidents-list').innerHTML = '';
    $('logs-feed').innerHTML = '';
    $('dangerous-list').innerHTML = '';
    allIncidents = [];
    currentLogsData = [];
    updateRlogCount(0);
    setConnStatus('', '—');
}

// ══════════════════════════════════════════════════════════════════════════════
// WEBSOCKET
// ══════════════════════════════════════════════════════════════════════════════
function connectWS(host, port) {
    // Logic moved to main.js for IPC
}
function setConnStatus(state, label) { 
    $('conn-dot').className='conn-dot '+state; 
    $('conn-label').textContent=label;
    lastConnState = state;
    lastConnLabel = label;
}
if (window.electronAPI) {
    window.electronAPI.onConnStatus((state, label) => {
        setConnStatus(state, label);
    });
    window.electronAPI.onWsMessage((msg) => {
        handleMessage(msg);
    });
    window.electronAPI.onInitialCache((cache) => {
        if(cache.stats) updateStats(cache.stats);
        if(cache.metrics) updateMetrics(cache.metrics);
        if(cache.model) { currentModel = cache.model; $('model-badge').textContent=currentModel; }
        if(cache.incidents && cache.incidents.length) {
            allIncidents = cache.incidents;
            renderIncidents(allIncidents);
            updateChartsFromIncidents(allIncidents);
            populateAIIncidentDropdown();
        }
    });
}

// ── Connection diagnostics popup ──────────────────────────────────────────────
let lastConnState = '', lastConnLabel = '—';
let lastWsUrl = '';
let diagOpen = false;

function toggleConnDiag() {
    const diag = $('conn-diag');
    diagOpen = !diagOpen;
    if (diagOpen) {
        updateDiagContent();
        diag.style.display = 'block';
    } else {
        diag.style.display = 'none';
    }
}

function updateDiagContent() {
    const el = $('diag-content');
    if (!el) return;
    const wsState = ws ? ['CONNECTING','OPEN','CLOSING','CLOSED'][ws.readyState] || '?' : 'НЕ СОЗДАН';
    const wsColor = ws?.readyState === 1 ? 'var(--green)' : 'var(--red)';
    const stateColor = lastConnState === 'connected' ? 'var(--green)' : lastConnState === 'connecting' ? 'var(--orange)' : 'var(--red)';
    el.innerHTML = `
        <div><span style="color:var(--muted)">Статус:</span> <span style="color:${stateColor};font-weight:700">${lastConnLabel}</span></div>
        <div><span style="color:var(--muted)">WS ReadyState:</span> <span style="color:${wsColor}">${wsState}</span></div>
        <div><span style="color:var(--muted)">URL сервера:</span> <span style="color:var(--cyan)">${serverBase || '—'}</span></div>
        <div><span style="color:var(--muted)">WS URL:</span> <span style="color:var(--cyan)">${lastWsUrl || '—'}</span></div>
        <div><span style="color:var(--muted)">Попытки реконн.:</span> <span>${reconnectAttempts}</span></div>
        <div><span style="color:var(--muted)">Токен:</span> <span style="color:${token ? 'var(--green)' : 'var(--red)'}">${token ? '✓ Получен' : '✗ Нет'}</span></div>
        <div style="margin-top:4px;padding-top:8px;border-top:1px solid var(--border);font-size:10px;color:var(--dim)">Совет: если WS = CLOSED и код 1006 — проверь что сервер запущен и доступен по сети. Код 4003 = неверный токен (перезайди).</div>
    `;
}

function diagReconnect() {
    if (!serverBase || !token) { showToast('Ошибка', 'Сначала войдите в систему', 'warn'); return; }
    reconnectAttempts = 0;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    const urlObj = new URL(serverBase);
    connectWS(urlObj.hostname, urlObj.port || '8080');
    toggleConnDiag();
    showToast('Переподключение', 'Попытка подключения к серверу...', 'info');
}


// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
// MESSAGE HANDLER
// ══════════════════════════════════════════════════════════════════════════════
function handleMessage(msg) {
    switch(msg.event) {
        case 'auth_success':
            setConnStatus('connected','Подключён');
            if(msg.data?.model){currentModel=msg.data.model;$('model-badge').textContent=currentModel;}
            break;
        case 'auth_error': setConnStatus('error','Ошибка авторизации'); break;
        case 'stats': updateStats(msg.data); break;
        case 'incidents_list':
            allIncidents = msg.data||[];
            renderIncidents(allIncidents);
            updateChartsFromIncidents(allIncidents);
            populateAIIncidentDropdown();
            break;
        case 'incident_updated':
            const idx = allIncidents.findIndex(i=>i.id===msg.data.id);
            if(idx!==-1) allIncidents[idx]=msg.data;
            renderIncidents(allIncidents);
            updateChartsFromIncidents(allIncidents);
            populateAIIncidentDropdown();
            break;
        case 'logs_list': 
            currentLogsData = msg.data || [];
            applyLogFilters();
            const rFeed = $('running-logs');
            if (rFeed) {
                rFeed.innerHTML = '';
                // Running logs: новые внизу, скроллим вниз
                (msg.data||[]).slice().reverse().forEach(log => {
                    const div = document.createElement('div');
                    const level = getAutoLevel(log);
                    div.className = `log-entry log-row-${level}`;
                    const t = (log.timestamp||'').slice(11,19);
                    div.innerHTML = `<span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg">${esc(log.message||'')}</span><span class="log-monitor">${esc(log.type||'')}</span>`;
                    rFeed.appendChild(div);
                });
                rFeed.scrollTop = rFeed.scrollHeight;
                updateRlogCount(rFeed.children.length);
            }
            break;
        case 'log': if(msg.data) addLiveEntry(msg.data); break;
        case 'incident':
            if(msg.data){
                allIncidents.unshift(msg.data);
                if(allIncidents.length>500) allIncidents.pop();
                
                // Update DOM if lists exist
                const listContainer = $('incidents-list');
                const dangerousContainer = $('dangerous-list');
                
                if (listContainer) addIncidentCard(msg.data, true, listContainer);
                
                addRadarBlip(msg.data);
                updateKillChain(msg.data);
                
                if(msg.data.severity==='CRITICAL'||msg.data.severity==='HIGH'){
                    if (dangerousContainer) addDangerousCard(msg.data, true, dangerousContainer);
                    showAlert(msg.data);
                    
                    if (!autoDefenseTriggered) {
                        threatCount++;
                        if (threatCount >= 3 || (msg.data.type && (msg.data.type.includes('Ransomware') || msg.data.type.includes('Privilege')))) {
                            executeEpicAutoDefense();
                        }
                    }
                }
                updateChartsFromIncidents(allIncidents);
                populateAIIncidentDropdown();
            }
            break;
        case 'metrics': updateMetrics(msg.data); break;
        case 'quarantine_updated': renderQuarantine(msg.data||[]); break;
        case 'model_changed':
            if(msg.data?.model){currentModel=msg.data.model;$('model-badge').textContent=currentModel;}
            break;
        case 'ai_result':
    const bubble = $('ai-typing-bubble');
    const ans = msg.data?.result || '(нет ответа)';
    chatHistory.push({role:'bot', content:ans});
    if (bubble) {
        bubble.removeAttribute('id'); bubble.innerHTML = parseMarkdown(ans);
    } else {
        const newB = appendChatMsg('bot', '', true); if(newB) newB.innerHTML = parseMarkdown(ans);
    }
    if($('btn-ai-send')) $('btn-ai-send').disabled = false;
    break;
        case 'ai_error':
    const errB = $('ai-typing-bubble');
    if (errB) { errB.removeAttribute('id'); errB.innerHTML = '❌ Ошибка: ' + (msg.data?.error || 'unknown'); }
    if($('btn-ai-send')) $('btn-ai-send').disabled = false;
    break;
        case 'bot_notify': if(msg.data) showAlert(msg.data); break;
        case 'scan_result':
            const scanOutput = $('scan-output');
            if (scanOutput) {
                const r = msg.data || {};
                let text = `[SCAN RESULTS - ${r.scanner ? r.scanner.toUpperCase() : 'UNKNOWN'}]\n`;
                text += `Target: ${r.target || 'N/A'}\n`;
                text += `Timestamp: ${r.timestamp || new Date().toLocaleString()}\n`;
                text += `--------------------------------------------------\n\n`;
                
                if (r.error) {
                    text += `❌ ERROR: ${r.error}\n`;
                } else if (!r.findings || r.findings.length === 0) {
                    text += `✅ SUCCESS: No findings / vulnerabilities detected!\n`;
                } else {
                    text += `⚠️ Found ${r.findings.length} findings:\n\n`;
                    r.findings.forEach((f, idx) => {
                        if (r.scanner === 'semgrep') {
                            text += `[#${idx + 1}] [${f.severity || 'MEDIUM'}] Rule: ${f.rule || 'N/A'}\n`;
                            text += `     Path: ${f.path || 'N/A'}:${f.line || '?'}\n`;
                            text += `     Message: ${f.message || 'No description'}\n\n`;
                        } else {
                            text += `[#${idx + 1}] [${f.severity || 'UNKNOWN'}] ${f.vulnId || 'N/A'} in ${f.pkg || 'N/A'}\n`;
                            text += `     Target: ${f.target || 'N/A'}\n`;
                            text += `     Title: ${f.title || 'No title'}\n`;
                            if (f.fixedVersion) text += `     Fixed in: ${f.fixedVersion}\n`;
                            text += `\n`;
                        }
                    });
                }
                scanOutput.textContent = text;
            }
            $('btn-run-semgrep').disabled = false;
            $('btn-run-trivy').disabled = false;
            break;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// DEFCON & TICKER TAPE
// ══════════════════════════════════════════════════════════════════════════════
function setDefcon(level) {
    if (level === 1 && window.currentDefcon !== 1) {
        speakAlert('Внимание! Зафиксирована критическая угроза. Инициализирую защитные протоколы.');
    }
    window.currentDefcon = level;
    const root = document.documentElement;
    const tickerLbl = $('ticker-label');
    const tickerText1 = $('ticker-text');
    const tickerText2 = $('ticker-text2');
    
    if (level === 1) {
        root.style.setProperty('--defcon-bg', '#000000');
        root.style.setProperty('--defcon-border', '#ef4444');
        root.style.setProperty('--defcon-accent', '#ef4444');
        root.style.setProperty('--defcon-glow', 'rgba(239, 68, 68, 0.15)');
        tickerLbl.textContent = 'DEFCON 1';
        tickerLbl.style.background = 'var(--red)';
        const tMsg = '[CRITICAL ALERT] UNAUTHORIZED ACTIVITY DETECTED | INITIATING DEFENSE PROTOCOLS | SYSTEM UNDER ATTACK ';
        tickerText1.textContent = tMsg; tickerText2.textContent = tMsg;
        tickerText1.style.color = '#fca5a5'; tickerText2.style.color = '#fca5a5';
    } else if (level === 2) {
        root.style.setProperty('--defcon-bg', '#000000');
        root.style.setProperty('--defcon-border', '#f59e0b');
        root.style.setProperty('--defcon-accent', '#f59e0b');
        root.style.setProperty('--defcon-glow', 'rgba(245, 158, 11, 0.1)');
        tickerLbl.textContent = 'DEFCON 2';
        tickerLbl.style.background = 'var(--orange)';
        const tMsg = '[WARNING] SUSPICIOUS ANOMALIES DETECTED | ELEVATING SECURITY POSTURE | INVESTIGATION REQUIRED ';
        tickerText1.textContent = tMsg; tickerText2.textContent = tMsg;
        tickerText1.style.color = '#fcd34d'; tickerText2.style.color = '#fcd34d';
    } else {
        root.style.setProperty('--defcon-bg', '#000000');
        root.style.setProperty('--defcon-border', '#cc0000');
        root.style.setProperty('--defcon-accent', '#ff0000');
        root.style.setProperty('--defcon-glow', 'rgba(255, 0, 0, 0.1)');
        tickerLbl.textContent = 'DEFCON 5';
        tickerLbl.style.background = 'var(--blue)';
        const tMsg = 'SYSTEM SECURE | ALL SERVICES ONLINE | ROUTINE MONITORING ACTIVE | NO THREATS DETECTED ';
        tickerText1.textContent = tMsg; tickerText2.textContent = tMsg;
        tickerText1.style.color = 'var(--text)'; tickerText2.style.color = 'var(--text)';
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// STATS
// ══════════════════════════════════════════════════════════════════════════════
function updateStats(data) {
    if(!data?.incidents) return;
    $('s-critical').textContent = data.incidents.critical||0;
    $('s-threats').textContent = (data.incidents.critical||0)+(data.incidents.high||0)+(data.incidents.medium||0)+(data.incidents.low||0);
    $('s-vuln').textContent = data.cveLogs||0;
    // Also update risk level table
    $('rl-crit').textContent = data.incidents.critical||0;
    $('rl-high').textContent = data.incidents.high||0;
    $('rl-med').textContent = data.incidents.medium||0;
    $('rl-low').textContent = data.incidents.low||0;
}

// ══════════════════════════════════════════════════════════════════════════════
// LIVE FEED
// ══════════════════════════════════════════════════════════════════════════════
function getAutoLevel(entry) {
    let level = (entry.level || 'info').toLowerCase();
    const msg = (entry.message || '').toLowerCase();
    if (msg.includes('error') || msg.includes('fail') || msg.includes('crash') || msg.includes('down') || msg.includes('падение') || msg.includes('ошибка')) {
        level = 'error';
    } else if (msg.includes('warn') || msg.includes('warning') || msg.includes('внимание')) {
        level = 'warn';
    } else if (msg.includes('ssh') || msg.includes('login') || msg.includes('auth') || msg.includes('success') || msg.includes('успешн') || msg.includes('accepted')) {
        if (level !== 'error') level = 'info';
    }
    return level;
}

function addLiveEntry(entry) {
    const feed = $('logs-feed');
    const rFeed = $('running-logs');
    const div = document.createElement('div');
    const level = getAutoLevel(entry);
    div.className = `log-entry log-row-${level}`;
    const t = (entry.timestamp||'').slice(11,19);
    div.innerHTML = `<span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg">${esc(entry.message||'')}</span><span class="log-monitor">${esc(entry.type||'')}</span>`;
    
    // Add to currentLogsData and re-filter
    if (entry.type === $('log-type').value || !$('log-type').value) {
        currentLogsData.unshift(entry);
        if (currentLogsData.length > 2000) currentLogsData.pop();
        applyLogFilters();
    }
    
    if (rFeed) {
        const d2 = div.cloneNode(true);
        rFeed.appendChild(d2);
        // Auto-scroll down — running logs всегда идут вниз
        rFeed.scrollTop = rFeed.scrollHeight;
        if (rFeed.children.length > 200) rFeed.removeChild(rFeed.firstChild);
        updateRlogCount(rFeed.children.length);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// INCIDENTS (with status/severity controls)
// ══════════════════════════════════════════════════════════════════════════════
function renderIncidents(list) {
    const el = $('incidents-list');
    const dEl = $('dangerous-list');
    el.innerHTML = '';
    if(dEl) dEl.innerHTML = '';
    // limit DOM nodes to prevent freezing
    list.slice(0, 100).forEach(i => {
        addIncidentCard(i, false, el);
        if(i.severity==='CRITICAL'||i.severity==='HIGH') addDangerousCard(i, false, dEl);
    });
}

function patchIncident(id, body) {
    fetch(`${serverBase}/api/incidents/${id}`, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}).catch(console.error);
}

function addIncidentCard(inc, prepend, container) {
    if(!container) container = $('incidents-list');
    const div = document.createElement('div');
    div.className = `inc-card ${inc.severity||'LOW'}`;
    const sOpts = [['new','Новый'],['in_review','В рассмотрении'],['resolved','Решён']].map(([v,l])=>`<option value="${v}"${inc.status===v?' selected':''}>${l}</option>`).join('');
    const svOpts = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s=>`<option value="${s}"${inc.severity===s?' selected':''}>${s}</option>`).join('');
    div.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:8px; width:100%;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="inc-sev ${inc.severity}">${inc.severity}</span>
                <span class="inc-meta" style="background:rgba(255,255,255,0.05); padding:3px 8px; border-radius:4px; border:1px solid var(--glass-border);">${esc(inc.monitor||'')}</span>
            </div>
            <div class="inc-type" style="font-size:15px; font-weight:800; color:#fff; letter-spacing:0.5px; margin-top:4px;">${esc(inc.type||'')}</div>
            <div class="inc-desc" style="color:var(--muted); font-size:12px; line-height:1.5;">${esc(inc.description||'')}</div>
            <div style="height:1px; background:var(--glass-border); margin:4px 0;"></div>
            <div class="inc-ctrls">
                <select class="inc-sel" onchange="patchIncident('${inc.id}',{status:this.value})">${sOpts}</select>
                <select class="inc-sel" onchange="patchIncident('${inc.id}',{severity:this.value})">${svOpts}</select>
                <button class="btn-ai" onclick="analyzeContext('${inc.id}')">🧠 ИИ Анализ</button>
                <span style="margin-left:auto; font-size:10px; font-family:'JetBrains Mono',monospace; color:var(--dim);">${(inc.timestamp||'').slice(0,19).replace('T',' ')}</span>
            </div>
        </div>
    `;
    if(prepend) container.insertBefore(div, container.firstChild);
    else container.appendChild(div);
}

function addDangerousCard(inc, prepend, container) {
    if(!container) container = $('dangerous-list');
    const div = document.createElement('div');
    div.className = `inc-card ${inc.severity}`;
    let ctxHtml = '';
    if(inc.contextBlock) ctxHtml = `<div class="inc-ctx">${esc(inc.contextBlock)}</div>`;
    const sOpts = [['new','Новый'],['in_review','В рассмотрении'],['resolved','Решён']].map(([v,l])=>`<option value="${v}"${inc.status===v?' selected':''}>${l}</option>`).join('');
    const svOpts = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s=>`<option value="${s}"${inc.severity===s?' selected':''}>${s}</option>`).join('');
    div.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:8px; width:100%;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="inc-sev ${inc.severity}">${inc.severity}</span>
                <span class="inc-meta" style="background:rgba(255,255,255,0.05); padding:3px 8px; border-radius:4px; border:1px solid var(--glass-border);">${esc(inc.monitor||'')}</span>
            </div>
            <div class="inc-type" style="font-size:15px; font-weight:800; color:#fff; letter-spacing:0.5px; margin-top:4px;">${esc(inc.type||'')}</div>
            <div class="inc-desc" style="color:var(--muted); font-size:12px; line-height:1.5;">${esc(inc.description||'')}</div>
            ${ctxHtml}
            <div style="height:1px; background:var(--glass-border); margin:4px 0;"></div>
            <div class="inc-ctrls">
                <select class="inc-sel" onchange="patchIncident('${inc.id}',{status:this.value})">${sOpts}</select>
                <select class="inc-sel" onchange="patchIncident('${inc.id}',{severity:this.value})">${svOpts}</select>
                <button class="btn-ai" onclick="analyzeContext('${inc.id}')">🧠 ИИ Анализ</button>
                <span style="margin-left:auto; font-size:10px; font-family:'JetBrains Mono',monospace; color:var(--dim);">${(inc.timestamp||'').slice(0,19).replace('T',' ')}</span>
            </div>
        </div>
    `;
    if(prepend) container.insertBefore(div, container.firstChild);
    else container.appendChild(div);
}

// ══════════════════════════════════════════════════════════════════════════════
// LOGS — with filters
// ══════════════════════════════════════════════════════════════════════════════
let currentLogsData = [];

function renderLogs(list) {
    currentLogsData = list || [];
    applyLogFilters();
}

function applyLogFilters() {
    const feed = $('logs-feed'); 
    if (!feed) return;
    const levelFilter = $('log-level-filter')?.value || 'all';
    const dateFrom = $('log-date-from')?.value || '';
    const dateTo = $('log-date-to')?.value || '';
    const searchText = ($('log-search')?.value || '').toLowerCase();
    
    let filtered = currentLogsData.filter(entry => {
        if (levelFilter !== 'all') {
            const lv = getAutoLevel(entry);
            if (lv !== levelFilter) return false;
        }
        if (dateFrom) {
            const entryDate = (entry.timestamp||'').slice(0,10);
            if (entryDate < dateFrom) return false;
        }
        if (dateTo) {
            const entryDate = (entry.timestamp||'').slice(0,10);
            if (entryDate > dateTo) return false;
        }
        if (searchText) {
            const msg = (entry.message||'').toLowerCase();
            if (!msg.includes(searchText)) return false;
        }
        return true;
    });
    
    const badge = $('logs-count-badge');
    if (badge) badge.textContent = `${filtered.length} / ${currentLogsData.length}`;
    
    feed.innerHTML = '';
    filtered.forEach(entry => {
        const div = document.createElement('div'); 
        div.className = 'log-entry';
        const t = (entry.timestamp||'').slice(0,19).replace('T',' ');
        const level = getAutoLevel(entry);
        div.innerHTML = `<span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg">${esc(entry.message||'')}</span>`;
        feed.appendChild(div);
    });
}

function clearLogFilters() {
    const lf = $('log-level-filter'); if (lf) lf.value = 'all';
    const df = $('log-date-from'); if (df) df.value = '';
    const dt = $('log-date-to'); if (dt) dt.value = '';
    const ls = $('log-search'); if (ls) ls.value = '';
    applyLogFilters();
}

function sendLogsToAI() {
    const levelFilter = $('log-level-filter')?.value || 'all';
    const dateFrom = $('log-date-from')?.value;
    const dateTo = $('log-date-to')?.value;
    const searchText = $('log-search')?.value;
    
    let filtered = currentLogsData.filter(entry => {
        if (levelFilter !== 'all') { const lv = getAutoLevel(entry); if (lv !== levelFilter) return false; }
        if (dateFrom) { const ed = (entry.timestamp||'').slice(0,10); if (ed < dateFrom) return false; }
        if (dateTo) { const ed = (entry.timestamp||'').slice(0,10); if (ed > dateTo) return false; }
        if (searchText) { const msg = (entry.message||'').toLowerCase(); if (!msg.includes(searchText.toLowerCase())) return false; }
        return true;
    });
    
    if (!filtered.length) { showToast('Нет данных', 'Нет логов для отправки в ИИ', 'warn'); return; }
    
    const logText = filtered.slice(0, 50).map(e => `[${(e.timestamp||'').slice(0,19).replace('T',' ')}] [${getAutoLevel(e).toUpperCase()}] ${e.message}`).join('\n');
    const filterDesc = [levelFilter !== 'all' ? `Уровень: ${levelFilter}` : '', dateFrom ? `С: ${dateFrom}` : '', dateTo ? `По: ${dateTo}` : '', searchText ? `Поиск: "${searchText}"` : ''].filter(Boolean).join(', ');
    
    switchTab('ai');
    $('ai-task').value = `Проанализируй следующие системные логи${filterDesc ? ' (фильтр: '+filterDesc+')' : ''} и выяви аномалии, угрозы и паттерны атак:\n\n${logText}\n\nДай краткое резюме угроз и рекомендации по устранению.`;
    showToast('Логи отправлены', `${filtered.length > 50 ? 50 : filtered.length} записей отправлено в ИИ`, 'info');
}

function updateRlogCount(n) {
    const el = $('rlog-count'); if (el) el.textContent = n + ' записей';
}

function loadLogs() {
    const type = $('log-type').value;
    currentLogsData = [];
    if(window.electronAPI) if (window.electronAPI) { window.electronAPI.sendWsMessage({event:'get_logs',data:{type,limit:500}}); }
}

// ══════════════════════════════════════════════════════════════════════════════
// METRICS (original + dashboard update)
// ══════════════════════════════════════════════════════════════════════════════
function updateMetrics(data) {
    if (!data) return;
    // Metrics tab bars
    setMetric('cpu', data.cpu, '%');
    if(data.ram) setMetric('ram', data.ram.percent, '%');
    if(data.disk) setMetric('disk', data.disk.percent, '%');
    // Dashboard system health
    if(data.cpu != null) { $('sys-cpu').style.width=data.cpu+'%'; $('sys-cpu-val').textContent=data.cpu+'%'; }
    if(data.ram) { $('sys-ram').style.width=data.ram.percent+'%'; $('sys-ram-val').textContent=data.ram.percent+'%'; }
    if(data.disk) { $('sys-disk').style.width=data.disk.percent+'%'; $('sys-disk-val').textContent=data.disk.percent+'%'; }
    if(data.top_process) {
        const tp = data.top_process;
        $('top-process-info').textContent = `${tp.name} [PID: ${tp.pid}] — CPU: ${tp.cpu}% / RAM: ${tp.mem}%`;
        // Если поле пустое, можно автозаполнить для удобства, но лучше не надо, чтобы случайно не кликнули
    }
    // Network chart
    if(data.connections!=null && chartNet) { const ds=chartNet.data.datasets[0].data; ds.shift(); ds.push(data.connections); chartNet.update(); }
    // Metrics feed
    const feed = $('metrics-feed');
    const div = document.createElement('div'); div.className = 'log-entry';
    const t = (data.receivedAt || data.timestamp || '').slice(11,19);
    const parts = [];
    if(data.cpu!=null) parts.push(`CPU:${data.cpu}%`);
    if(data.ram) parts.push(`RAM:${data.ram.percent}%`);
    if(data.disk) parts.push(`Disk:${data.disk.percent}%`);
    if(data.connections!=null) parts.push(`Conn:${data.connections}`);
    div.innerHTML = `<span class="log-time">${t}</span><span class="log-level info">METRICS</span><span class="log-msg">${esc(data.monitor||'monitor')} — ${parts.join(' | ')}</span>`;
    feed.insertBefore(div, feed.firstChild);
    if(feed.children.length > 100) feed.removeChild(feed.lastChild);
    
    // Check for high CPU to trigger DEFCON 2 warning
    if(data.cpu != null && data.cpu >= 90) {
        setDefcon(2);
        showToast('SYSTEM WARNING', `High CPU load detected: ${data.cpu}%`, 'warn');
        setTimeout(() => setDefcon(5), 15000);
    }
    // DDoS indicators for network tab & dashboard (via ddos metrics)
    if(data.ddos && data.ddos.top_ips && Array.isArray(data.ddos.top_ips)) {
        const tb = $('ssh-tbody'); // Network tab table body ID
        const dashTb = $('dash-ssh-tbody'); // Dashboard tab table body ID
        
        if (tb) {
            tb.innerHTML = '';
            if(!data.ddos.top_ips.length) {
                tb.innerHTML='<tr><td colspan="4" class="empty-td">Ожидание данных от DDoS-анализатора (Lua)...</td></tr>';
            } else {
                data.ddos.top_ips.forEach(s => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `<td>DDoS Attacker</td><td><span class="ip-chip">${esc(s.ip||'?')}</span></td><td>${esc(s.count||0)}</td><td><button class="btn-sm btn-q" onclick="quarantineIp('${esc(s.ip)}','Blocked by Anti-DDoS')">🛡 ЗАБАНИТЬ IP</button></td>`;
                    tb.appendChild(tr);
                });
            }
        }
        
        if (dashTb) {
            dashTb.innerHTML = '';
            if(!data.ddos.top_ips.length) {
                dashTb.innerHTML='<tr><td colspan="4" class="empty-td">Ожидание данных от DDoS-анализатора (Lua)...</td></tr>';
            } else {
                data.ddos.top_ips.forEach(s => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `<td>DDoS Attacker</td><td><span class="ip-chip">${esc(s.ip||'?')}</span></td><td>${esc(s.count||0)}</td><td><button class="btn-sm btn-q" onclick="quarantineIp('${esc(s.ip)}','Blocked by Anti-DDoS')">🛡 ЗАБАНИТЬ IP</button></td>`;
                    dashTb.appendChild(tr);
                });
            }
        }
    }
}
function setMetric(id, val, unit) {
    if(val==null) return;
    const bar = $(id+'-bar'), valEl = $(id+'-val');
    if(!bar||!valEl) return;
    bar.style.width = Math.min(val,100)+'%';
    bar.className = 'm-fill'+(val>90?' danger':val>70?' warn':'');
    valEl.textContent = val + unit;
}

// ══════════════════════════════════════════════════════════════════════════════
// QUARANTINE
// ══════════════════════════════════════════════════════════════════════════════
function loadQuarantine() {
    if(!serverBase) return;
    fetch(`${serverBase}/api/quarantine`).then(r=>r.json()).then(d=>renderQuarantine(d||[])).catch(()=>{});
}
function renderQuarantine(list) {
    const tb = $('quarantine-tbody');
    $('q-count').textContent = list.length;
    if(!list.length) { tb.innerHTML='<tr><td colspan="4" class="empty-td">Нет заблокированных IP</td></tr>'; return; }
    tb.innerHTML = '';
    list.forEach(q => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><span class="ip-chip">${esc(q.ip)}</span></td><td>${esc(q.reason||'Manual')}</td><td>${esc((q.timestamp||'').slice(0,19).replace('T',' '))}</td><td><button class="btn-sm btn-unq" onclick="unquarantineIp('${esc(q.ip)}')">🔓 РАЗБЛОКИРОВАТЬ</button></td>`;
        tb.appendChild(tr);
    });
}
function quarantineIp(ip, reason) {
    fetch(`${serverBase}/api/quarantine`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip,reason:reason||'Manual block'})}).catch(console.error);
}
function unquarantineIp(ip) {
    fetch(`${serverBase}/api/quarantine/${encodeURIComponent(ip)}`, {method:'DELETE'}).catch(console.error);
}

// ══════════════════════════════════════════════════════════════════════════════
// AI
// ══════════════════════════════════════════════════════════════════════════════

let chatHistory = [];
function appendChatMsg(role, text, isHtml = false) {
    const historyEl = $('ai-chat-history');
    if(!historyEl) return null;
    const div = document.createElement('div');
    div.className = 'ai-msg ' + (role==='user'?'user':'bot');
    const avatar = document.createElement('div');
    avatar.className = 'msg-avatar';
    avatar.textContent = role==='user' ? 'U' : '🤖';
    const bubble = document.createElement('div');
    bubble.className = 'msg-bubble';
    if (isHtml) bubble.innerHTML = text; else bubble.textContent = text;
    div.appendChild(avatar); div.appendChild(bubble);
    historyEl.appendChild(div); historyEl.scrollTop = historyEl.scrollHeight;
    return bubble;
}
function parseMarkdown(md) {
    let html = md.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\[ \] (.*?)(<br>|\n|$)/g, '<label style="display:flex;align-items:center;gap:6px;margin:4px 0;"><input type="checkbox"> $1</label>$2');
    html = html.replace(/\[x\] (.*?)(<br>|\n|$)/gi, '<label style="display:flex;align-items:center;gap:6px;margin:4px 0;"><input type="checkbox" checked> $1</label>$2');
    const codeRegex = /```(bash|sh|shell)?\n([\s\S]*?)```/g;
    html = html.replace(codeRegex, (match, lang, code) => {
        const encCode = btoa(unescape(encodeURIComponent(code.trim())));
        return `<div style="background:#0a0a0a; border:1px solid #333; border-radius:6px; margin:10px 0; overflow:hidden;">
            <div style="background:#1a1a1a; padding:6px 12px; font-size:10px; font-family:monospace; color:#aaa; border-bottom:1px solid #333; display:flex; justify-content:space-between; align-items:center;">
                ${lang||'bash'} <button onclick="executeAIScript('${encCode}')" style="background:var(--green); border:none; border-radius:4px; color:#000; font-weight:bold; font-size:9px; padding:4px 8px; cursor:pointer;">⚡ ВЫПОЛНИТЬ</button>
            </div><pre style="padding:12px; margin:0; font-family:monospace; font-size:11px; overflow-x:auto; color:#fff;">${esc(code.trim())}</pre></div>`;
    });
    html = html.replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1); padding:2px 4px; border-radius:4px; font-family:monospace;">$1</code>');
    return html.replace(/\n/g, '<br>');
}
function executeAIScript(base64code) {
    const code = decodeURIComponent(escape(atob(base64code)));
    if(!confirm('ВНИМАНИЕ! Выполнить скрипт на сервере?\n\n' + code)) return;
    appendChatMsg('user', 'Выполни этот скрипт.');
    const bubble = appendChatMsg('bot', '⏳ Выполнение...');
    window.electronAPI.sendApiRequest('/api/execute-ai-script', 'POST', {script: code})
        .then(res => { bubble.innerHTML = '✅ <strong>Выполнено:</strong><br><pre style="background:#000;padding:10px;color:#0f0;margin-top:5px;">'+(res.output||res.error||'Успешно')+'</pre>'; })
        .catch(err => { bubble.innerHTML = '❌ <strong>Ошибка:</strong><br>'+err.message; });
}
function sendAITask(taskText = null) {
    const inp = $('ai-task');
    const task = taskText || (inp ? inp.value.trim() : '');
    if(!task) return;
    if(inp) inp.value = '';
    appendChatMsg('user', task); chatHistory.push({role:'user', content:task});
    $('btn-ai-send').disabled = true;
    const bubble = appendChatMsg('bot', '⏳ Анализ...'); bubble.id = 'ai-typing-bubble';
    if (window.electronAPI) window.electronAPI.sendWsMessage({event:'ai_task', data:{task, history: chatHistory, model:currentModel}});
}
window.askAI = function(promptText) { switchTab('ai'); sendAITask(promptText); };
function generateDailyBriefing() {
    askAI('Сгенерируй Executive-отчёт (Daily Briefing) за последние 24 часа. Метрики: ' + JSON.stringify({threats: $('s-threats')?.textContent||'0', crit: $('s-critical')?.textContent||'0'}));
}


// ══════════════════════════════════════════════════════════════════════════════
// SECURITY SCANNERS
// ══════════════════════════════════════════════════════════════════════════════
function runSecurityScan(type) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        $('scan-output').textContent = '❌ Нет соединения с сервером';
        return;
    }
    let target = '';
    if (type === 'semgrep') {
        target = $('semgrep-target').value.trim();
    } else if (type === 'trivy') {
        target = $('trivy-target').value.trim();
    }
    
    if (!target) {
        alert('Пожалуйста, укажите целевую директорию или образ.');
        return;
    }
    
    $('btn-run-semgrep').disabled = true;
    $('btn-run-trivy').disabled = true;
    $('scan-output').textContent = `⏳ Запуск сканирования ${type.toUpperCase()} на цели: ${target}...\nПожалуйста, подождите, это может занять некоторое время...`;
    
    ws.send(JSON.stringify({
        event: 'run_scan',
        data: {
            scanType: type,
            target: target
        }
    }));
}
function executeEpicAutoDefense() {
    if (autoDefenseTriggered) return;
    autoDefenseTriggered = true;
    setDefcon(1);
    const term = $('ai-terminal');
    const content = $('ai-term-content');
    term.style.display = 'block';
    
    const threats = allIncidents.filter(i => i.severity==='CRITICAL'||i.severity==='HIGH').slice(0,3);
    const contextText = threats.map(t => `[${t.severity}] ${t.type}: ${t.description}`).join('\n');
    const recentLogs = currentLogsData.slice(0,5).map(l => `[${getAutoLevel(l).toUpperCase()}] ${l.message}`).join('\n');
    
    const promptText = `> INITIALIZING NEURAL COUNTERMEASURES...\n> ANALYZING THREAT VECTORS:\n${contextText}\n\n> RECENT SYSTEM LOGS:\n${recentLogs}\n\n> FORMULATING DEFENSE STRATEGY...\n`;
    
    typeText(content, promptText, 15, () => {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            content.innerHTML += '<br><span style="color:#f00">> OFFLINE. CANNOT REACH AI CORE.</span>';
            return;
        }
        ws.send(JSON.stringify({
            event: 'ai_task',
            data: {
                task: `КРИТИЧЕСКАЯ ИНЦИДЕНТ! Зафиксирована серия из 3 атак.\nУгрозы:\n${contextText}\nПодозрительные логи:\n${recentLogs}\n\nТВОЯ ЗАДАЧА: Срочно сломай сессию атакующему и полностью заблокируй доступ к серверу! Выдай чёткий bash-скрипт: дропни TCP-коннекты (kill, ss), забань IP в iptables, убей все левые tty/pts сессии, заблокируй root-а. Не пиши воду, только агрессивный скрипт "как уничтожить доступ хакеру". Начни ответ с "ВЫПОЛНЯЮ ЗАЩИТНЫЙ ПРОТОКОЛ...".`,
                model: currentModel
            }
        }));
        content.innerHTML += `<br><span style="color:#0ff">> AI REQUEST SENT. AWAITING NEURAL RESPONSE...</span><br>`;
        $('ai-term-input').style.display = 'block';
        $('ai-term-input').focus();
    });
}

function typeText(element, text, speed, callback) {
    let i = 0;
    function type() {
        if (i < text.length) {
            let char = text.charAt(i);
            if (char === '\n') {
                element.appendChild(document.createElement('br'));
            } else {
                element.appendChild(document.createTextNode(char));
            }
            element.parentElement.scrollTop = element.parentElement.scrollHeight;
            i++;
            setTimeout(type, speed);
        } else {
            if (callback) callback();
        }
    }
    element.innerHTML = '';
    type();
}

// ══════════════════════════════════════════════════════════════════════════════
// USERS
// ══════════════════════════════════════════════════════════════════════════════
async function loadUsers() {
    try {
        const r = await fetch(`${serverBase}/api/users`);
        const users = await r.json();
        const el = $('users-list'); el.innerHTML = '';
        users.forEach(u => {
            const div = document.createElement('div'); div.className='user-card';
            div.innerHTML = `<div class="user-avatar">${(u.username||'?')[0].toUpperCase()}</div><div class="user-info"><div class="name">${esc(u.username)}</div><div class="role role-${u.role||'operator'}">${esc(u.role||'operator')}</div></div>${u.chat_id?'<span class="user-tg">TELEGRAM</span>':''}`;
            el.appendChild(div);
        });
    } catch(e) {}
}
async function addUser() {
    const username=$('nu-user').value.trim(), password=$('nu-pass').value, role=$('nu-role').value;
    if(!username||!password) return;
    try {
        const r = await fetch(`${serverBase}/api/users`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username,password,role})});
        const data = await r.json();
        if(data.success) { $('nu-user').value=''; $('nu-pass').value=''; loadUsers(); }
        else alert(data.error||'Ошибка');
    } catch(e) { alert('Ошибка соединения'); }
}

// ══════════════════════════════════════════════════════════════════════════════
// ALERTS & TOASTS
// ══════════════════════════════════════════════════════════════════════════════
function showAlert(data) {
    const sev = (data.severity || data.type || 'ALERT').toUpperCase();
    
    if (sev === 'CRITICAL' || sev === 'HIGH') {
        setDefcon(1);
        showToast(`DEFCON 1: ${sev}`, data.description || data.type || 'Critical threat detected!', 'critical');
        // Reset to normal after 20 seconds
        setTimeout(() => setDefcon(5), 20000);
    } else if (sev === 'MEDIUM' || sev === 'WARN') {
        showToast(`WARNING: ${sev}`, data.description || data.type || 'Suspicious activity detected.', 'warn');
    } else {
        showToast('INFO', data.description || data.type || 'New event logged.', 'info');
    }
}

function showToast(title, message, type='info') {
    const container = $('toast-container');
    if (!container) return;
    const t = document.createElement('div');
    t.className = `toast t-${type}`;
    const time = new Date().toLocaleTimeString();
    t.innerHTML = `
        <div class="toast-hdr"><span>${esc(title)}</span> <span>${time}</span></div>
        <div class="toast-msg">${esc(message)}</div>
    `;
    container.appendChild(t);
    // Remove after 5 seconds (animation takes 5s)
    setTimeout(() => { if(t.parentNode===container) container.removeChild(t); }, 5000);
}

// ══════════════════════════════════════════════════════════════════════════════
// TABS
// ══════════════════════════════════════════════════════════════════════════════
const TAB_NAMES = ['dashboard','network','incidents','dangerous','logs','metrics','scanners','ai','users'];
function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab===name));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    $('panel-'+name).classList.add('active');
    if(name==='logs') loadLogs();
    if(name==='users') loadUsers();
    if(name==='network') loadQuarantine();
    if(name==='incidents' && window.electronAPI) if (window.electronAPI) { window.electronAPI.sendWsMessage({event:'get_incidents'}); }
}

function killProcess() {
    const pid = $('inp-kill-pid').value.trim();
    if(!pid) return;
    if(!confirm(`Точно сбросить процесс PID ${pid}?`)) return;
    fetch(`${serverBase}/api/process/${pid}`, {method:'DELETE', headers:{'X-Auth-Token':token}}).then(r=>r.json()).then(res=>{
        if(res.success) {
            alert(`Процесс ${pid} успешно сброшен`);
            $('inp-kill-pid').value = '';
        } else {
            alert('Ошибка: ' + (res.error||'Неизвестно'));
        }
    }).catch(()=>alert('Network error'));
}

function closeAITerminal() {
    $('ai-terminal').style.display = 'none';
    autoDefenseTriggered = false;
    threatCount = 0;
    setDefcon(5);
    showToast('SYSTEM', 'Управление перехвачено оператором', 'info');
}

function sendAITerminalInput(text) {
    if (!text.trim()) return;
    const content = $('ai-term-content');
    content.innerHTML += `<br><br><span style="color:#fff">> OPERATOR: ${esc(text)}</span><br><span style="color:#0ff">> AWAITING NEURAL RESPONSE...</span><br>`;
    $('ai-term-input').value = '';
    
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            event: 'ai_task',
            data: {
                task: text,
                model: currentModel
            }
        }));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// GLOBAL THREAT RADAR
// ══════════════════════════════════════════════════════════════════════════════
function addRadarBlip(incident) {
    const radar = $('radar-container');
    if (!radar) return;
    
    // Create blip
    const dot = document.createElement('div');
    dot.className = 'radar-dot';
    
    // Random position within circle radius (max 140px from center)
    const angle = Math.random() * Math.PI * 2;
    const distance = Math.random() * 120; // 120 max to stay inside 140px radius
    
    const x = Math.cos(angle) * distance;
    const y = Math.sin(angle) * distance;
    
    dot.style.left = `calc(50% + ${x}px)`;
    dot.style.top = `calc(50% + ${y}px)`;
    
    // Color based on severity
    if (incident.severity === 'CRITICAL') dot.style.background = dot.style.boxShadowColor = 'var(--red)';
    else if (incident.severity === 'HIGH') dot.style.background = dot.style.boxShadowColor = 'var(--orange)';
    else if (incident.severity === 'MEDIUM') dot.style.background = dot.style.boxShadowColor = 'var(--blue)';
    else dot.style.background = dot.style.boxShadowColor = 'var(--muted)';
    
    radar.appendChild(dot);
    
    // Remove after ping animation completes
    setTimeout(() => { if (dot.parentNode) dot.parentNode.removeChild(dot); }, 1500);
}

// ══════════════════════════════════════════════════════════════════════════════
// KILL-CHAIN TIMELINE
// ══════════════════════════════════════════════════════════════════════════════
function updateKillChain(incident) {
    if (!incident || !incident.type) return;
    const t = incident.type.toLowerCase();
    let step = '';
    if (t.includes('scan') || t.includes('recon')) step = 'recon';
    else if (t.includes('brute') || t.includes('ssh success') || t.includes('auth')) step = 'initial';
    else if (t.includes('sql') || t.includes('rce') || t.includes('bypass') || t.includes('exec') || t.includes('injection')) step = 'exec';
    else if (t.includes('privilege') || t.includes('persistence') || t.includes('shadow')) step = 'priv';
    else if (t.includes('ransomware') || t.includes('crypto') || t.includes('mass') || t.includes('encrypt')) step = 'impact';
    
    if (step) {
        const steps = ['recon', 'initial', 'exec', 'priv', 'impact'];
        const idx = steps.indexOf(step);
        for(let i=0; i<=idx; i++) {
            const el = $('kc-' + steps[i]);
            if(el) el.classList.add('active');
            if(i < idx) {
                const lineFill = document.querySelectorAll('.kc-line-fill')[i];
                if(lineFill) lineFill.style.width = '100%';
            }
        }
    }
}

// Enter to login
$('inp-pass').addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });

// ══════════════════════════════════════════════════════════════════════════════
// SESSION TIMEOUT (AUTO-LOCK)
// ══════════════════════════════════════════════════════════════════════════════
let idleTimer = null;
const IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

function resetIdleTimer() {
    const appEl = document.getElementById('app');
    if (appEl && !appEl.classList.contains('hidden')) {
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            console.log('Session expired due to inactivity');
            doLogout();
            showToast('Security', 'Сессия завершена из-за неактивности', 'warn');
        }, IDLE_TIMEOUT_MS);
    }
}

window.addEventListener('mousemove', resetIdleTimer);
window.addEventListener('keypress', resetIdleTimer);
window.addEventListener('click', resetIdleTimer);
window.addEventListener('scroll', resetIdleTimer, true);

function speakAlert(text) {
    if (!window.speechSynthesis) return;
    const ut = new SpeechSynthesisUtterance(text);
    ut.lang = 'ru-RU'; ut.rate = 1.1; ut.pitch = 0.9;
    window.speechSynthesis.speak(ut);
}

const logSearchInp = $('log-search');
if (logSearchInp) {
    logSearchInp.addEventListener('keydown', (e) => {
        if(e.key === 'Enter') {
            const query = logSearchInp.value.trim();
            if (query && query.length > 10 && !query.includes('=')) {
                logSearchInp.value = '⏳ Анализ...';
                window.electronAPI.sendApiRequest('/api/ai-nlp-search', 'POST', {query}).then(res => {
                    logSearchInp.value = query;
                    if (res && res.filter) {
                        if(res.filter.type) $('log-type').value = res.filter.type;
                        if(res.filter.level) $('log-level-filter').value = res.filter.level;
                        applyLogFilters(); showToast('NLP', 'Фильтры применены', 'info');
                    }
                }).catch(() => { logSearchInp.value = query; });
            }
        }
    });
}

function populateAIIncidentDropdown() {
    const select = $("ai-incident-select");
    if (!select) return;
    const currentVal = select.value;
    select.innerHTML = '<option value="">-- Выберите инцидент для глубокого анализа --</option>';
    allIncidents.slice(0, 50).forEach(inc => {
        if(inc.severity !== "CRITICAL" && inc.severity !== "HIGH") return;
        const opt = document.createElement("option");
        opt.value = inc.id;
        opt.textContent = `[${inc.severity}] ${inc.type} | IP: ${inc.ip || "N/A"}`;
        select.appendChild(opt);
    });
    if (currentVal && Array.from(select.options).some(o => o.value === currentVal)) {
        select.value = currentVal;
    }
}

function selectIncidentForAI() {
    const select = $("ai-incident-select");
    if (!select || !select.value) return;
    const inc = allIncidents.find(i => i.id === select.value);
    if (!inc) return;
    const prompt = `Проанализируй опасный участок логов. Тип атаки: ${inc.type}. Описание: ${inc.description}.\n\nКонтекст:\n${inc.contextBlock || "Неизвестно"}\n\nЧто делает атакующий и какие меры предпринять? Ничего не отключай и не ломай.`;
    $("ai-task").value = prompt;
}

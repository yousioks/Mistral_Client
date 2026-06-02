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


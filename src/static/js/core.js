// ══════════════════════════════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════════════════════════════
let ws = null, token = null, serverBase = '';
window.currentModel = 'deepseek-v4-pro';
let reconnectTimer = null, reconnectAttempts = 0;
let allIncidents = [];
let chartRisk = null, chartNet = null, chartType = null;
let autoDefenseTriggered = false;
let threatCount = 0;
let cyberMap = null;
let miniGlobe = null;
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
        if(cache.model) { window.currentModel = cache.model; $('model-badge').textContent=window.currentModel; }
        if(cache.incidents && cache.incidents.length) {
            allIncidents = cache.incidents;
            renderIncidents(allIncidents);
            updateChartsFromIncidents(allIncidents);
            populateAIIncidentDropdown();
        }
    });
    window.electronAPI.onNotificationClickIp((ip) => {
        if (window.filterLogsByIp) {
            window.filterLogsByIp(ip);
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
        <div><span style="color:var(--muted)">Мой IP (Клиент):</span> <span style="color:var(--green);font-weight:700">${window.clientIp || 'Неизвестно'}</span></div>
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
    if (window.electronAPI) {
        window.electronAPI.reconnectServer().then(res => {
            if (res.success) {
                showToast('Соединение', 'Попытка переподключения...', 'info');
            } else {
                showToast('Ошибка', res.error, 'warn');
            }
        });
    }
    toggleConnDiag();
}

function diagDisconnect() {
    if (window.electronAPI) {
        window.electronAPI.disconnectWs().then(() => {
            showToast('Соединение', 'Соединение разорвано пользователем', 'info');
        });
    }
    toggleConnDiag();
}


window.clientIp = '';
function updateIPDisplays() {
    const clientEl = $('client-ip-display');
    const serverEl = $('server-ip-display');
    if (clientEl) {
        clientEl.textContent = window.clientIp || 'Неизвестно';
    }
    if (serverEl) {
        let host = 'Неизвестно';
        if (serverBase) {
            try {
                const url = new URL(serverBase);
                host = url.hostname;
            } catch (e) {
                host = serverBase;
            }
        }
        serverEl.textContent = host;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
// MESSAGE HANDLER
// ══════════════════════════════════════════════════════════════════════════════
function handleMessage(msg) {
    try {
        switch(msg.event) {
        case 'auth_success':
            setConnStatus('connected','Подключён');
            if(msg.data?.model){window.currentModel=msg.data.model;$('model-badge').textContent=window.currentModel;}
            if(msg.data?.clientIp) {
                window.clientIp = msg.data.clientIp;
                updateIPDisplays();
            }
            break;
        case 'auth_error': setConnStatus('error','Ошибка авторизации'); break;
        case 'stats': updateStats(msg.data); break;
        case 'incidents_list':
            allIncidents = msg.data||[];
            renderIncidents(allIncidents);
            updateChartsFromIncidents(allIncidents);
            populateAIIncidentDropdown();
            if(window.updateDefensePosture) updateDefensePosture();
            if(window.updateMitreMatrix) updateMitreMatrix();
            break;
        case 'incident_updated':
            const idx = allIncidents.findIndex(i=>i.id===msg.data.id);
            if(idx!==-1) allIncidents[idx]=msg.data;
            renderIncidents(allIncidents);
            updateChartsFromIncidents(allIncidents);
            populateAIIncidentDropdown();
            if(window.updateDefensePosture) updateDefensePosture();
            if(window.updateMitreMatrix) updateMitreMatrix();
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
                
                // Cyber Threat Map and Mini-Globe animations
                if (msg.data.geo) {
                    if (cyberMap) cyberMap.animateAttack(msg.data.geo, msg.data.type);
                    if (miniGlobe) {
                        const techId = getMitreTechId(msg.data);
                        miniGlobe.animateThreat(msg.data.geo, techId);
                    }
                }
                
                if(msg.data.severity==='CRITICAL'||msg.data.severity==='HIGH'){
                    showAlert(msg.data);
                    if (window.playAlertSound) window.playAlertSound(msg.data.severity);
                    
                    const settings = window.soarSettings || {};
                    if (settings.aiDefenseEnabled && !msg.data.aiMitigated) {
                        threatCount++;
                        
                        let shouldTrigger = false;
                        
                        // Condition 1: Incident frequency threshold
                        if (threatCount >= (settings.aiThreatThreshold || 3)) {
                            shouldTrigger = true;
                        }
                        
                        // Condition 2: Data leak trigger
                        if (settings.aiTriggerOnLeaks && (msg.data.type === 'DATA_LEAK' || msg.data.type === 'anomaly')) {
                            shouldTrigger = true;
                        }
                        
                        // Condition 3: Critical vulnerability trigger
                        if (settings.aiTriggerOnCritical && msg.data.severity === 'CRITICAL') {
                            shouldTrigger = true;
                        }
                        
                        if (shouldTrigger) {
                            triggerSilentAIResponse(msg.data);
                            threatCount = 0; // Reset
                        }
                    }
                }
                updateChartsFromIncidents(allIncidents);
                populateAIIncidentDropdown();
                if(window.updateDefensePosture) updateDefensePosture();
                if(window.updateMitreMatrix) updateMitreMatrix();
            }
            break;
        case 'metrics':
            window.lastMetricsData = msg.data;
            updateMetrics(msg.data);
            if (typeof window.loadServerInfo === 'function' && document.getElementById('panel-server_info') && document.getElementById('panel-server_info').classList.contains('active')) {
                window.loadServerInfo();
            }
            if (typeof window.loadApplicationsInfo === 'function' && document.getElementById('panel-apps') && document.getElementById('panel-apps').classList.contains('active')) {
                window.loadApplicationsInfo();
            }
            break;
        case 'quarantine_updated': renderQuarantine(msg.data||[]); break;
        case 'soar_settings_updated':
            if (msg.data) {
                window.soarSettings = msg.data;
                updateSoarCheckboxes(msg.data);
            }
            break;
        case 'model_changed':
            if(msg.data?.model){
                window.currentModel=msg.data.model;
                $('model-badge').textContent=window.currentModel;
                document.querySelectorAll('.model-btn').forEach(b => {
                    const clickAttr = b.getAttribute('onclick') || '';
                    if (clickAttr.includes(msg.data.model) || b.textContent.trim().toLowerCase() === msg.data.model.toLowerCase()) {
                        b.classList.add('active');
                    } else {
                        b.classList.remove('active');
                    }
                });
            }
            break;
        case 'ai_result':
            const ans = msg.data?.result || '(нет ответа)';
            
            // Auto-Defense Audit Parsing
            const banMatch = ans.match(/\[AUTOBAN:\s*([a-zA-Z0-9\.\:]+)\]/i);
            const incMatch = ans.match(/\[INCIDENT_ID:\s*([^\]]+)\]/i);
            const isAutoDefense = !!msg.data?.isAutoDefense;
            const makeChanges = (window.soarSettings && window.soarSettings.aiMakeChanges) !== false;
            
            if (isAutoDefense) {
                const logMessage = `[ИИ-Агент] Решение по инциденту ${msg.data.incidentId || '—'}. Режим: ${makeChanges ? 'АВТОНОМНЫЙ (блокировка)' : 'ИНФОРМАЦИОННЫЙ (справка)'}. Анализ: ${ans.slice(0, 300)}...`;
                if (window.electronAPI) {
                    window.electronAPI.sendApiRequest('/api/logs', 'POST', {
                        type: 'server',
                        level: makeChanges ? 'warn' : 'info',
                        message: logMessage
                    });
                }
            }

            if(banMatch) {
                const ip = banMatch[1];
                if (makeChanges) {
                    quarantineIp(ip, 'AI Autonomous Mitigation');
                    showToast('AI AGENT', `Threat neutralized. IP Banned: ${ip}`, 'green');
                    
                    if (incMatch) {
                        const incId = incMatch[1].trim();
                        const inc = allIncidents.find(i => i.id === incId);
                        if (inc) {
                            inc.aiAudit = ans;
                            inc.status = 'resolved';
                            patchIncident(incId, { status: 'resolved' });
                            if($('incident-drawer').classList.contains('open')) {
                                openIncidentDrawer(incId); // Refresh drawer
                            }
                        }
                    }
                } else {
                    showToast('AI AGENT', 'Автономные изменения запрещены. Сформирована справка.', 'warn');
                    if (incMatch) {
                        const incId = incMatch[1].trim();
                        const inc = allIncidents.find(i => i.id === incId);
                        if (inc) {
                            inc.aiAudit = ans;
                            inc.status = 'advisory';
                            patchIncident(incId, { status: 'advisory' });
                            if($('incident-drawer').classList.contains('open')) {
                                openIncidentDrawer(incId);
                            }
                        }
                    }
                }
                if(window.updateDefensePosture) updateDefensePosture();
                if(window.updateMitreMatrix) updateMitreMatrix();
            } else {
                if (isAutoDefense && incMatch) {
                    const incId = incMatch[1].trim();
                    const inc = allIncidents.find(i => i.id === incId);
                    if (inc) {
                        inc.aiAudit = ans;
                        inc.status = makeChanges ? 'resolved' : 'advisory';
                        patchIncident(incId, { status: inc.status });
                    }
                }
            }

            const bubble = $('ai-typing-bubble');
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
            if (window.renderScanResultsInTerminal) {
                window.renderScanResultsInTerminal(msg.data || {});
            }
            $('btn-run-semgrep').disabled = false;
            $('btn-run-trivy').disabled = false;
            break;
        }
    } catch (err) {
        console.error("Error in handleMessage:", err, msg);
        showToast("Ошибка UI", "Сбой обработки события: " + err.message, "warn");
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
    $('scan-output').textContent = `Запуск сканирования ${type.toUpperCase()} на цели: ${target}...\nПожалуйста, подождите, это может занять некоторое время...`;
    
    ws.send(JSON.stringify({
        event: 'run_scan',
        data: {
            scanType: type,
            target: target
        }
    }));
}
function triggerSilentAIResponse(incident) {
    if (lastConnState !== 'connected' || !window.electronAPI) return;
    
    const makeChanges = (window.soarSettings && window.soarSettings.aiMakeChanges) !== false;
    
    // Show silent Toast
    if (makeChanges) {
        showToast('AI AGENT', 'AUTONOMOUS MITIGATION STARTED (AUTOPILOT)', 'critical');
    } else {
        showToast('AI AGENT', 'ADVISORY MITIGATION TRIGGERED (READ-ONLY)', 'info');
    }
    
    // Change incident status in local state
    const incIdx = allIncidents.findIndex(i => i.id === incident.id);
    if(incIdx !== -1) {
        allIncidents[incIdx].status = makeChanges ? 'ai_mitigation' : 'ai_advisory';
        allIncidents[incIdx].aiMitigated = true;
        renderIncidents(allIncidents);
    }
    
    const context = `Incident ID: ${incident.id}\nType: ${incident.type}\nTarget/IP: ${incident.ip || incident.target}\nContext: ${incident.contextBlock || ''}`;
    
    let actionInstruction = '';
    if (makeChanges) {
        actionInstruction = `РЕЖИМ АВТОЗАЩИТЫ: АВТОНОМНЫЙ (РАЗРЕШЕНО ВНЕСЕНИЕ ИЗМЕНЕНИЙ).
Вы можете применить автоматические меры защиты. Если требуется заблокировать атакующий IP, ОБЯЗАТЕЛЬНО включи в ответ теги:
[AUTOBAN: ${incident.ip || ''}] и [INCIDENT_ID: ${incident.id}]

В секции 3 подробно распиши:
- ЧТО было сделано (блокировка IP-адреса)
- ЗАЧЕМ и ПОЧЕМУ это было сделано (логика и причины на основе логов инцидента)
- КАК это было сделано технически (команда блокировки)`;
    } else {
        actionInstruction = `РЕЖИМ АВТОЗАЩИТЫ: ИНФОРМАЦИОННЫЙ (ВНЕСЕНИЕ ИЗМЕНЕНИЙ ЗАПРЕЩЕНО).
Вам ЗАПРЕЩЕНО самостоятельно вносить изменения в систему или блокировать IP. НЕ выводи теги автоблокировки (например, [AUTOBAN]).
Вместо этого в секции 3 предоставь полную справку-руководство для оператора:
- ЧТО необходимо сделать оператору для устранения угрозы
- ЗАЧЕМ и ПОЧЕМУ это требуется сделать (какая логика анализа)
- КАК оператор должен прописать команды вручную (конкретные bash, ufw, docker-команды)`;
    }
    
    const taskPrompt = `ПРОТОКОЛ ЗАЩИТЫ MISTRAL.
Активирован ИИ-агент на основе инцидента с логом (Идентификатор инцидента: ${incident.id}).
Тип инцидента: ${incident.type}
Описание: ${incident.description}
Источник IP: ${incident.ip || 'Неизвестен'}

${actionInstruction}

СТРОГО СЛЕДУЙ ФОРМАТУ ОТЧЕТА:
1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
   [Подробно: почему включился ИИ-агент, какой инцидент с логом послужил триггером]
2. АНАЛИЗ УГРОЗЫ И ЛОГОВ (ЗАЧЕМ И ПОЧЕМУ):
   [Детальный разбор, почему это является угрозой на основе контекста]
3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ (ЕСЛИ РАЗРЕШЕНО) ИЛИ ПОЛНАЯ СПРАВКА ДЛЯ ОПЕРАТОРА (ЕСЛИ ЗАПРЕЩЕНО):
   [Либо отчет об автоблокировке с объяснением ЧТО, ЗАЧЕМ, КАК сделано; либо подробная инструкция для ручного ввода оператором]
4. РЕКОМЕНДАЦИИ ПО УКРЕПЛЕНИЮ СИСТЕМЫ:
   [Дальнейшие шаги]

Контекст логов инцидента:
${incident.contextBlock || ''}`;

    window.electronAPI.sendWsMessage({
        event: 'ai_task',
        data: {
            task: taskPrompt,
            model: (window.soarSettings && window.soarSettings.aiModel) || window.currentModel,
            isAutoDefense: true,
            incidentId: incident.id
        }
    });
}

// ── SOAR & Cyber Map Initialization & Helper functions ──────────────────────
window.addEventListener('DOMContentLoaded', () => {
    if ($('cyber-map')) {
        cyberMap = new CyberMap('cyber-map');
    }
    if ($('mitre-mini-globe')) {
        miniGlobe = new MiniGlobeRenderer('mitre-mini-globe');
    }
    
    // Load Settings on Boot
    const isMuted = localStorage.getItem('mute_audio_alerts') === 'true';
    const uiAudioCheckbox = $('ui-audio-alerts');
    if (uiAudioCheckbox) {
        uiAudioCheckbox.checked = !isMuted;
    }
    
    const glowEnabled = localStorage.getItem('glow_effects_enabled') === 'true';
    const uiGlowCheckbox = $('ui-glow-effects');
    if (uiGlowCheckbox) {
        uiGlowCheckbox.checked = glowEnabled;
    }
    if (glowEnabled) {
        document.body.classList.add('glow-active');
    }
});

// Synthesizer for warning alarm sounds using Web Audio API
window.playAlertSound = function(severity) {
    if (localStorage.getItem('mute_audio_alerts') === 'true') return;
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        const ctx = new AudioContext();
        
        // Base synth parameters
        const osc = ctx.createOscillator();
        const osc2 = ctx.createOscillator();
        const gainNode = ctx.createGain();
        const filter = ctx.createBiquadFilter();
        
        osc.type = severity === 'CRITICAL' ? 'sawtooth' : 'sine';
        osc2.type = 'triangle';
        
        // Frequencies matching premium alarm alerts
        const baseFreq = severity === 'CRITICAL' ? 880 : 554.37; // A5 or C#5
        osc.frequency.setValueAtTime(baseFreq, ctx.currentTime);
        osc2.frequency.setValueAtTime(baseFreq * 1.5, ctx.currentTime);
        
        // Frequency sweep effect
        osc.frequency.exponentialRampToValueAtTime(baseFreq / 2, ctx.currentTime + 0.6);
        osc2.frequency.exponentialRampToValueAtTime(baseFreq * 0.75, ctx.currentTime + 0.6);
        
        filter.type = 'lowpass';
        filter.frequency.setValueAtTime(1200, ctx.currentTime);
        
        gainNode.gain.setValueAtTime(0.12, ctx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.8);
        
        osc.connect(filter);
        osc2.connect(filter);
        filter.connect(gainNode);
        gainNode.connect(ctx.destination);
        
        osc.start();
        osc2.start();
        osc.stop(ctx.currentTime + 0.8);
        osc2.stop(ctx.currentTime + 0.8);
    } catch (e) {
        console.warn('Audio alert failed', e);
    }
};

function getMitreTechId(inc) {
    const type = (inc.type || '').toLowerCase();
    const desc = (inc.description || '').toLowerCase();
    
    if (type.includes('ssh') || type.includes('brute') || type.includes('login') || desc.includes('auth')) return 'T1110';
    if (type.includes('ddos') || type.includes('flood') || type.includes('syn')) return 'T1498';
    if (type.includes('ransomware') || type.includes('encrypt') || desc.includes('ransom')) return 'T1486';
    if (type.includes('privilege') || type.includes('root') || type.includes('sudo') || desc.includes('root') || type.includes('escalation')) return 'T1548';
    if (type.includes('malware') || type.includes('virus') || desc.includes('malware') || desc.includes('payload')) return 'T1059';
    if (type.includes('scan') || type.includes('nmap') || type.includes('port') || desc.includes('scan')) return 'T1046';
    if (type.includes('sql') || type.includes('xss') || type.includes('web') || type.includes('injection')) return 'T1190';
    if (type.includes('phish') || desc.includes('email')) return 'T1566';
    if (type.includes('anomaly') || desc.includes('anomaly')) return 'T1071';
    
    if (inc.severity === 'CRITICAL' || inc.severity === 'HIGH') {
        const fallbackTechs = ['T1078', 'T1105', 'T1070', 'T1083', 'T1021'];
        const idStr = inc.id != null ? String(inc.id) : '';
        const hash = idStr.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
        return fallbackTechs[hash % fallbackTechs.length];
    }
    return null;
}

function updateSoarCheckboxes(settings) {
    const ddosCheckbox = $('soar-autoban-ddos');
    const bruteCheckbox = $('soar-autoban-bruteforce');
    
    const aiEnabled = $('soar-ai-enabled');
    const aiMakeChanges = $('soar-ai-make-changes');
    const aiModel = $('soar-ai-model');
    const aiThreshold = $('soar-ai-threshold');
    const aiLeaks = $('soar-ai-leaks');
    const aiCritical = $('soar-ai-critical');
    
    if (ddosCheckbox) ddosCheckbox.checked = !!settings.autoBanDdos;
    if (bruteCheckbox) bruteCheckbox.checked = !!settings.autoBanBruteForce;
    
    if (aiEnabled) aiEnabled.checked = !!settings.aiDefenseEnabled;
    if (aiMakeChanges) aiMakeChanges.checked = settings.aiMakeChanges !== false;
    if (aiModel) aiModel.value = settings.aiModel || 'deepseek-v4-pro';
    if (aiThreshold) aiThreshold.value = settings.aiThreatThreshold || 3;
    if (aiLeaks) aiLeaks.checked = settings.aiTriggerOnLeaks !== false;
    if (aiCritical) aiCritical.checked = settings.aiTriggerOnCritical !== false;
}

window.saveSoarSettingsUI = function() {
    const ddosCheckbox = $('soar-autoban-ddos');
    const bruteCheckbox = $('soar-autoban-bruteforce');
    
    const aiEnabled = $('soar-ai-enabled');
    const aiMakeChanges = $('soar-ai-make-changes');
    const aiModel = $('soar-ai-model');
    const aiThreshold = $('soar-ai-threshold');
    const aiLeaks = $('soar-ai-leaks');
    const aiCritical = $('soar-ai-critical');
    
    const settings = {
        autoBanDdos: ddosCheckbox ? ddosCheckbox.checked : false,
        autoBanBruteForce: bruteCheckbox ? bruteCheckbox.checked : false,
        aiDefenseEnabled: aiEnabled ? aiEnabled.checked : false,
        aiMakeChanges: aiMakeChanges ? aiMakeChanges.checked : false,
        aiModel: aiModel ? aiModel.value : 'deepseek-v4-pro',
        aiThreatThreshold: aiThreshold ? parseInt(aiThreshold.value, 10) : 3,
        aiTriggerOnLeaks: aiLeaks ? aiLeaks.checked : false,
        aiTriggerOnCritical: aiCritical ? aiCritical.checked : false
    };
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/soar-settings', 'POST', settings)
            .then(res => {
                if (res && res.success) {
                    showToast('SOAR Settings', 'Правила автоматизации успешно сохранены на сервере', 'green');
                } else {
                    showToast('Ошибка SOAR', (res && res.error) || 'Не удалось сохранить настройки SOAR', 'warn');
                }
            })
            .catch(err => {
                showToast('Ошибка SOAR', 'Не удалось сохранить настройки SOAR: ' + err.message, 'warn');
            });
    } else {
        fetch(`${serverBase}/api/soar-settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify(settings)
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showToast('SOAR Settings', 'Правила автоматизации успешно сохранены на сервере', 'green');
            } else {
                showToast('Ошибка SOAR', res.error || 'Не удалось сохранить настройки', 'warn');
            }
        })
        .catch(err => {
            showToast('Ошибка SOAR', 'Не удалось сохранить настройки SOAR: ' + err.message, 'warn');
        });
    }
};

window.renderScanResultsInTerminal = function(r) {
    const scanOutput = $('scan-output');
    if (!scanOutput) return;
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
};

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

function formatLogMessageWithIpActions(message) {
    let msgHtml = esc(message || '');
    const ipMatch = (message || '').match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
    let actionsHtml = '';
    if (ipMatch) {
        const ip = ipMatch[0];
        const safeIp = esc(ip);
        
        let serverHost = '';
        if (serverBase) {
            try { serverHost = new URL(serverBase).hostname; } catch(e) { serverHost = serverBase; }
        }
        
        const isWhitelisted = window.soarSettings && (
            (window.soarSettings.whitelist && window.soarSettings.whitelist.includes(ip)) ||
            (window.soarSettings.activeSshSessions && window.soarSettings.activeSshSessions.includes(ip))
        );
        const isSafe = ip === '127.0.0.1' || ip === 'localhost' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip === serverHost || ip === window.clientIp || isWhitelisted;
        
        if (isWhitelisted) {
            msgHtml = msgHtml.replace(ip, `<span class="ip-chip clickable" style="border-color:var(--green); background:rgba(34,197,94,0.1); color:var(--green);" onclick="filterLogsByIp('${safeIp}')" title="Фильтровать логи по IP (Белый список): ${safeIp}">${safeIp} 🛡️</span>`);
        } else {
            msgHtml = msgHtml.replace(ip, `<span class="ip-chip clickable" onclick="filterLogsByIp('${safeIp}')" title="Фильтровать логи по IP: ${safeIp}">${safeIp}</span>`);
        }
        
        if (!isSafe) {
            const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === ip);
            const btnClass = isBanned ? 'btn-unq' : 'btn-q';
            const btnText = isBanned ? 'РАЗБЛОКИРОВАТЬ' : 'ЗАБЛОКИРОВАТЬ';
            const btnFunc = isBanned ? `unquarantineIp('${safeIp}')` : `quarantineIp('${safeIp}', 'Log Quick Ban')`;
            
            actionsHtml = `<button class="btn-sm ${btnClass}" style="margin-left: 10px; padding: 2px 6px; font-size: 9px; vertical-align: middle; line-height: 1;" onclick="${btnFunc}; setTimeout(loadLogs, 300);">${btnText}</button>`;
        }
    }

    // Highlight CVEs
    msgHtml = msgHtml.replace(/\b(CVE-\d{4}-\d+)\b/g, `<span class="cve-badge" onclick="searchCve('$1')" title="Найти в базе сигнатур MISTRAL">$1</span>`);

    // 1. Highlight bracketed source tag at the start of the message (e.g., [Docker] or [ИИ-Агент])
    msgHtml = msgHtml.replace(/^\[([^\]]+)\]/, (match, p1) => {
        const classFriendly = p1.toLowerCase().replace(/[^a-zа-я0-9]/g, '-');
        return `<span class="log-badge-source src-${classFriendly}">[${p1}]</span>`;
    });

    // 2. Highlight key action/status verbs (Cyrillic-boundary safe regexes using lookbehinds/lookaheads)
    const verbHighlights = [
        { pattern: 'запущен[а-я]*|запуск|подключен[а-я]*|started|connected', cls: 'log-verb-success' },
        { pattern: 'остановлен[а-я]*|отключен[а-я]*|stopped|disconnected', cls: 'log-verb-warn' },
        { pattern: 'удален[а-я]*|удаление|killed|removed', cls: 'log-verb-danger' },
        { pattern: 'блокировк[а-я]*|заблокирован[а-я]*|заблокировать|blocked|banned', cls: 'log-verb-danger' },
        { pattern: 'карантин[а-я]*|quarantine', cls: 'log-verb-accent' },
        { pattern: 'атак[а-я]*|угроз[а-я]*|attack|threat', cls: 'log-verb-danger-glow' },
        { pattern: 'успешно|успешн[а-я]*|success', cls: 'log-verb-success' },
        { pattern: 'ошибк[а-я]*|провал[а-я]*|fail|опасность|error|failure', cls: 'log-verb-error' }
    ];
    verbHighlights.forEach(({ pattern, cls }) => {
        const rx = new RegExp(`(?<![а-яА-ЯёЁa-zA-Z0-9])(${pattern})(?![а-яА-ЯёЁa-zA-Z0-9])`, 'gi');
        msgHtml = msgHtml.replace(rx, `<span class="${cls}">$1</span>`);
    });

    return msgHtml + actionsHtml;
}
window.formatLogMessageWithIpActions = formatLogMessageWithIpActions;
 
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
    window.electronAPI.onNotificationClickIncident((incidentId) => {
        switchTab('incidents');
        if (window.openIncidentDrawer) {
            window.openIncidentDrawer(incidentId);
        }
        const select = $('ai-incident-select');
        if (select) {
            select.value = incidentId;
            if (typeof selectIncidentForAI === 'function') {
                selectIncidentForAI();
            }
        }
    });
    // Auth-required: server rejected token (e.g. server restarted → new token)
    // Stop the reconnect loop and show the login screen so user can re-authenticate.
    if (typeof window.electronAPI.onAuthRequired === 'function') {
        window.electronAPI.onAuthRequired(() => {
            console.warn('[WS] Auth required — server issued new token. Showing login screen.');
            if (typeof doLogout === 'function') doLogout();
            if (typeof showToast === 'function') {
                showToast('🔑 Сессия завершена', 'Сервер был перезапущен и выдал новый токен. Пожалуйста, войдите снова.', 'warn');
            }
        });
    }
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
            if (window.selectedIncidents) window.selectedIncidents.clear();
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
            if (window.selectedLogs) window.selectedLogs.clear();
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
                    div.innerHTML = `<span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg">${formatLogMessageWithIpActions(log.message)}</span><span class="log-monitor">${esc(log.type||'')}</span>`;
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
                
                // Prepend to incidents table
                addIncidentRow(msg.data, true, $('incidents-tbody'));
                
                addRadarBlip(msg.data);
                updateKillChain(msg.data);
                
                // Cyber Threat Map and Mini-Globe animations
                let mapGeo = msg.data.geo;
                if (!mapGeo) {
                    mapGeo = { ip: msg.data.ip || '127.0.0.1', country: 'Локальная сеть / РФ', code: 'RU', lat: 55.75, lon: 37.61, isp: 'Внутренний провайдер', reputation: 10 };
                }
                if (cyberMap) cyberMap.animateAttack(mapGeo, msg.data.type || 'Intrusion');
                if (miniGlobe) {
                    const techId = getMitreTechId(msg.data);
                    miniGlobe.animateThreat(mapGeo, techId);
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
                if (typeof window.updateSecurityStatus === 'function') window.updateSecurityStatus();
            }
            if (typeof window.loadApplicationsInfo === 'function' && document.getElementById('panel-apps') && document.getElementById('panel-apps').classList.contains('active')) {
                window.loadApplicationsInfo();
            }
            break;
        case 'quarantine_updated': 
            renderQuarantine(msg.data||[]); 
            if (document.getElementById('panel-logs') && document.getElementById('panel-logs').classList.contains('active')) {
                if (window.applyLogFilters) window.applyLogFilters();
            }
            break;
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
        case 'ai_progress':
            if (msg.data && typeof window.updateAIProgressUI === 'function') {
                window.updateAIProgressUI(msg.data);
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

            if (window.aiSendTimeout) clearTimeout(window.aiSendTimeout);
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
            if (window.aiSendTimeout) clearTimeout(window.aiSendTimeout);
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
    if (lastConnState !== 'connected' || !window.electronAPI) {
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
    
    window.electronAPI.sendWsMessage({
        event: 'run_scan',
        data: {
            scanType: type,
            target: target
        }
    });
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
    
    // Append to AI chat history so it shows progress visually in the tab
    if (typeof window.appendChatMsg === 'function') {
        window.appendChatMsg('user', `[Система] Запущен ИИ-анализ инцидента: [${incident.severity}] ${incident.type} (IP: ${incident.ip || '—'})`);
        const bubble = window.appendChatMsg('bot', 'Инициализация анализа...');
        if (bubble) bubble.id = 'ai-typing-bubble';
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
        window.cyberMap = cyberMap;
    }
    if ($('docker-topology-map')) {
        window.dockerTopologyMap = new DockerTopologyMap('docker-topology-map');
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
    
    const osNotificationsEnabled = localStorage.getItem('os_notifications_enabled') !== 'false';
    const uiOSNotificationsCheckbox = $('ui-os-notifications');
    if (uiOSNotificationsCheckbox) {
        uiOSNotificationsCheckbox.checked = osNotificationsEnabled;
    }
    if (window.electronAPI && window.electronAPI.setNotificationsEnabled) {
        window.electronAPI.setNotificationsEnabled(osNotificationsEnabled);
    }

    const toastsEnabled = localStorage.getItem('ui_toasts_enabled') !== 'false';
    const uiToastsCheckbox = $('ui-toasts-enabled');
    if (uiToastsCheckbox) {
        uiToastsCheckbox.checked = toastsEnabled;
    }

    const antiFloodEnabled = localStorage.getItem('ui_notifications_antiflood') !== 'false';
    const uiAntiFloodCheckbox = $('ui-notifications-antiflood');
    if (uiAntiFloodCheckbox) {
        uiAntiFloodCheckbox.checked = antiFloodEnabled;
    }
    
    const glowEnabled = localStorage.getItem('glow_effects_enabled') === 'true';
    const uiGlowCheckbox = $('ui-glow-effects');
    if (uiGlowCheckbox) {
        uiGlowCheckbox.checked = glowEnabled;
    }
    if (glowEnabled) {
        document.body.classList.add('glow-active');
    }

    // Prefill login config from Store if available
    if (window.electronAPI && typeof window.electronAPI.getSavedConfig === 'function') {
        window.electronAPI.getSavedConfig().then(config => {
            if (config) {
                if (config.host && $('inp-host')) $('inp-host').value = config.host;
                if (config.port && $('inp-port')) $('inp-port').value = config.port;
                if (config.username && $('inp-user')) $('inp-user').value = config.username;
            }
        }).catch(err => console.error("Failed to load saved server config:", err));
    }

    // MITRE cells event bindings
    document.querySelectorAll('.mitre-cell').forEach(cell => {
        cell.onclick = () => {
            const techId = cell.id;
            if (techId) {
                window.filterIncidentsByMitre(techId);
            }
        };
        // Add hover tooltip bindings
        cell.onmouseenter = (e) => {
            const techText = cell.querySelector('.mitre-tech')?.textContent || '';
            const desc = cell.textContent.replace(techText, '').trim();
            showMitreTooltip(e.pageX, e.pageY, techText || cell.id, desc);
        };
        cell.onmouseleave = () => {
            hideMitreTooltip();
        };
        cell.onmousemove = (e) => {
            const t = $('mitre-tooltip-el');
            if (t) {
                t.style.left = (e.pageX + 10) + 'px';
                t.style.top = (e.pageY + 10) + 'px';
            }
        };
    });
});

window.showMitreTooltip = function(x, y, techId, desc) {
    let t = $('mitre-tooltip-el');
    if (!t) {
        t = document.createElement('div');
        t.id = 'mitre-tooltip-el';
        t.className = 'mitre-tooltip';
        document.body.appendChild(t);
    }
    t.innerHTML = `<strong style="color:var(--cyan); font-family:monospace; display:block; margin-bottom:4px;">${techId}</strong><span>${desc}</span><br><span style="font-size:9px; color:var(--dim); margin-top:4px; display:block;">Нажмите для фильтрации инцидентов</span>`;
    t.style.left = (x + 10) + 'px';
    t.style.top = (y + 10) + 'px';
    t.style.display = 'block';
};

window.hideMitreTooltip = function() {
    const t = $('mitre-tooltip-el');
    if (t) t.style.display = 'none';
};

// Track active audio contexts to close them on unload and prevent Chromium exit crashes (ffmpeg.dll GPF)
const activeAudioContexts = new Set();
window.addEventListener('beforeunload', () => {
    for (const ctx of activeAudioContexts) {
        try {
            ctx.close();
        } catch (_) {}
    }
    activeAudioContexts.clear();
});

// Synthesizer for warning alarm sounds using Web Audio API
window.playAlertSound = function(severity) {
    if (localStorage.getItem('mute_audio_alerts') === 'true') return;
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        const ctx = new AudioContext();
        activeAudioContexts.add(ctx);
        
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

        // Safely close the context after sound finishes to free Chromium audio handles
        setTimeout(() => {
            try {
                ctx.close();
            } catch (_) {}
            activeAudioContexts.delete(ctx);
        }, 1000);
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
    const honeypotCheckbox = $('soar-honeypot-enabled');
    
    const aiEnabled = $('soar-ai-enabled');
    const aiMakeChanges = $('soar-ai-make-changes');
    const aiModel = $('soar-ai-model');
    const aiThreshold = $('soar-ai-threshold');
    const aiLeaks = $('soar-ai-leaks');
    const aiCritical = $('soar-ai-critical');
    
    if (ddosCheckbox) ddosCheckbox.checked = !!settings.autoBanDdos;
    if (bruteCheckbox) bruteCheckbox.checked = !!settings.autoBanBruteForce;
    if (honeypotCheckbox) honeypotCheckbox.checked = !!settings.honeypotEnabled;
    
    if (aiEnabled) aiEnabled.checked = !!settings.aiDefenseEnabled;
    if (aiMakeChanges) aiMakeChanges.checked = settings.aiMakeChanges !== false;
    if (aiModel) aiModel.value = settings.aiModel || 'deepseek-v4-pro';
    if (aiThreshold) aiThreshold.value = settings.aiThreatThreshold || 3;
    if (aiLeaks) aiLeaks.checked = settings.aiTriggerOnLeaks !== false;
    if (aiCritical) aiCritical.checked = settings.aiTriggerOnCritical !== false;

    // Render Whitelist
    const listEl = $('whitelist-ips-list');
    if (listEl) {
        listEl.innerHTML = '';
        const staticIps = settings.whitelist || [];
        const staticCidrs = settings.whitelistCidrs || [];
        const sshSessions = settings.activeSshSessions || [];

        // Dynamic SSH connections
        sshSessions.forEach(ip => {
            const row = document.createElement('div');
            row.style = 'display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(34,197,94,0.08); border:1px solid rgba(34,197,94,0.2); border-radius:6px; margin-bottom:4px; font-family:\'JetBrains Mono\', monospace;';
            row.innerHTML = `<span style="color:var(--green); font-weight:bold;">${ip} <span style="font-size:9px; color:var(--muted); font-weight:normal;">[SSH Session]</span></span>
                             <span style="font-size:9px; color:var(--muted); text-transform:uppercase; font-weight:bold;">Неблокируемый</span>`;
            listEl.appendChild(row);
        });

        // Static IPs
        staticIps.forEach(ip => {
            if (sshSessions.includes(ip)) return; // Avoid duplicate display
            const isDefault = ['127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1', '172.18.32.1', '109.120.5.41'].includes(ip);
            const row = document.createElement('div');
            row.style = 'display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(255,255,255,0.03); border:1px solid var(--border); border-radius:6px; margin-bottom:4px; font-family:\'JetBrains Mono\', monospace;';
            
            if (isDefault) {
                row.innerHTML = `<span style="color:#fff;">${ip} <span style="font-size:9px; color:var(--muted);">[Default]</span></span>
                                 <span style="font-size:9px; color:var(--muted); text-transform:uppercase;">Системный</span>`;
            } else {
                row.innerHTML = `<span style="color:#fff;">${ip}</span>
                                 <span style="color:var(--red); cursor:pointer; font-weight:bold; font-size:12px; padding:0 4px;" onclick="removeWhitelistIpUI('${ip}')" title="Удалить из списка">✕</span>`;
            }
            listEl.appendChild(row);
        });

        // Static CIDRs
        staticCidrs.forEach(cidr => {
            const row = document.createElement('div');
            row.style = 'display:flex; justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(6,182,212,0.05); border:1px solid rgba(6,182,212,0.15); border-radius:6px; margin-bottom:4px; font-family:\'JetBrains Mono\', monospace;';
            row.innerHTML = `<span style="color:var(--cyan); font-weight:bold;">${cidr}</span>
                             <span style="color:var(--red); cursor:pointer; font-weight:bold; font-size:12px; padding:0 4px;" onclick="removeWhitelistIpUI('${cidr}')" title="Удалить из списка">✕</span>`;
            listEl.appendChild(row);
        });

        if (listEl.children.length === 0) {
            listEl.innerHTML = '<div style="color:var(--muted); text-align:center; padding:8px; font-size:11px;">Список исключений пуст</div>';
        }
    }
}

window.addWhitelistIpUI = function() {
    const input = $('new-whitelist-ip');
    if (!input || !input.value.trim()) return;
    const ip = input.value.trim();

    const requestBody = { ip };

    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/whitelist/add', 'POST', requestBody)
            .then(res => {
                if (res && res.success) {
                    showToast('IP Whitelist', `Адрес ${ip} успешно внесен в белый список.`, 'green');
                    input.value = '';
                } else {
                    showToast('Ошибка Whitelist', (res && res.error) || 'Не удалось добавить IP в белый список', 'warn');
                }
            })
            .catch(err => {
                showToast('Ошибка Whitelist', err.message, 'warn');
            });
    } else {
        fetch(`${serverBase}/api/whitelist/add`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify(requestBody)
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showToast('IP Whitelist', `Адрес ${ip} успешно внесен в белый список.`, 'green');
                input.value = '';
            } else {
                showToast('Ошибка Whitelist', res.error || 'Не удалось добавить IP', 'warn');
            }
        })
        .catch(err => {
            showToast('Ошибка Whitelist', err.message, 'warn');
        });
    }
};

window.removeWhitelistIpUI = function(ip) {
    if (!confirm(`Вы действительно хотите удалить ${ip} из белого списка?`)) return;

    const requestBody = { ip };

    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/whitelist/remove', 'POST', requestBody)
            .then(res => {
                if (res && res.success) {
                    showToast('IP Whitelist', `Адрес ${ip} успешно удален из белого списка.`, 'green');
                } else {
                    showToast('Ошибка Whitelist', (res && res.error) || 'Не удалось удалить IP', 'warn');
                }
            })
            .catch(err => {
                showToast('Ошибка Whitelist', err.message, 'warn');
            });
    } else {
        fetch(`${serverBase}/api/whitelist/remove`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify(requestBody)
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showToast('IP Whitelist', `Адрес ${ip} успешно удален из белого списка.`, 'green');
            } else {
                showToast('Ошибка Whitelist', res.error || 'Не удалось удалить IP', 'warn');
            }
        })
        .catch(err => {
            showToast('Ошибка Whitelist', err.message, 'warn');
        });
    }
};

window.saveSoarSettingsUI = function() {
    const ddosCheckbox = $('soar-autoban-ddos');
    const bruteCheckbox = $('soar-autoban-bruteforce');
    const honeypotCheckbox = $('soar-honeypot-enabled');
    
    const aiEnabled = $('soar-ai-enabled');
    const aiMakeChanges = $('soar-ai-make-changes');
    const aiModel = $('soar-ai-model');
    const aiThreshold = $('soar-ai-threshold');
    const aiLeaks = $('soar-ai-leaks');
    const aiCritical = $('soar-ai-critical');
    
    const settings = {
        autoBanDdos: ddosCheckbox ? ddosCheckbox.checked : false,
        autoBanBruteForce: bruteCheckbox ? bruteCheckbox.checked : false,
        honeypotEnabled: honeypotCheckbox ? honeypotCheckbox.checked : false,
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

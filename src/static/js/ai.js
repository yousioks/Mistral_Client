// ══════════════════════════════════════════════════════════════════════════════
// ANALYZE (from original)
// ══════════════════════════════════════════════════════════════════════════════
window.analyzeLog = function(entryOrText) {
    let msgText = '';
    let logContext = '';
    
    if (entryOrText && typeof entryOrText === 'object') {
        msgText = entryOrText.message || '';
        
        // Find surrounding logs in currentLogsData for richer context
        const logList = window.currentLogsData || currentLogsData || [];
        if (logList.length > 0) {
            const idx = logList.findIndex(l => l.timestamp === entryOrText.timestamp && l.message === entryOrText.message);
            if (idx !== -1) {
                // Get 5 preceding logs (older) and 5 succeeding logs (newer)
                const start = Math.max(0, idx - 5);
                const end = Math.min(logList.length - 1, idx + 5);
                const surrounding = logList.slice(start, end + 1).reverse(); // chronological order
                
                logContext = surrounding.map(l => {
                    const marker = l.timestamp === entryOrText.timestamp && l.message === entryOrText.message ? '==> ' : '    ';
                    const time = (l.timestamp || '').slice(11, 19);
                    const lvl = typeof getAutoLevel === 'function' ? getAutoLevel(l) : (l.level || 'info');
                    return `${marker}[${time}] [${l.type || 'server'}] [${lvl.toUpperCase()}] ${l.message}`;
                }).join('\n');
            }
        }
    } else {
        msgText = entryOrText || '';
    }
    
    let prompt = '';
    if (logContext) {
        prompt = `ПРОТОКОЛ АНАЛИЗА ЛОГОВ MISTRAL SOC.

В системе безопасности зафиксировано подозрительное событие.
Пожалуйста, проведи расследование инцидента на основе этой строки лога и окружающего контекста событий.

СТРОКА ЛОГА ДЛЯ АНАЛИЗА:
==> ${msgText}

КОНТЕКСТ ОКРУЖАЮЩИХ СОБЫТИЙ (Хронологический порядок):
${logContext}

ТРЕБОВАНИЯ К ОТЧЕТУ:
1. Выдели ключевой вектор угрозы и определи, является ли это легитимным действием или атакой.
2. Проанализируй хронологическую последовательность событий из контекста (что привело к событию, каковы последствия).
3. Дай техническое объяснение кодов ответов, IP-адресов, портов и сигнатур.
4. Разработай конкретные, пошаговые рекомендации для оператора по реагированию и предотвращению (команды брандмауэра, настройки систем, правила WAF).`;
    } else {
        prompt = `Проанализируй следующую строку логов с сервера. Скажи, нормальное ли это поведение или атака, и что она означает:\n\n${msgText}\n\nУчти строгие правила: ничего не ломать, не отключать.`;
    }
    
    if (window.askAI) {
        window.askAI(prompt);
    } else {
        $('ai-task').value = prompt; 
        switchTab('ai'); 
        sendAITask();
    }
};
window.analyzeContext = function(id) {
    const inc = allIncidents.find(i => i.id === id);
    if(!inc) return;
    
    let template = $('ai-system-prompt')?.value;
    if (!template) {
        template = `ПРОТОКОЛ АВТОЗАЩИТЫ MISTRAL.
Проанализируй инцидент и предоставь подробный отчет строго в следующем формате:

1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
   [Подробное описание, почему включился ИИ-агент безопасности, оценка степени угрозы]

2. ПРЕДШЕСТВУЮЩЕЕ СОБЫТИЕ (ТРИГГЕР):
   [Детальный разбор события, которое вызвало алерт: тип инцидента, источник атаки, время, логи и контекст]

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ И МИТИГАЦИЯ:
   [Какие меры были предприняты или рекомендуются. Если требуется блокировка, укажи [AUTOBAN: {{ip}}] и [INCIDENT_ID: {{incident_id}}]]

4. РЕКОМЕНДАЦИИ ДЛЯ АДМИНИСТРАТОРА:
   [Дальнейшие шаги по укреплению защиты системы]

Контекст инцидента:
Тип атаки: {{type}}
Описание: {{description}}
Контекст логов:
{{context}}`;
    }
    
    const prompt = template
        .replace(/\{\{type\}\}/g, inc.type || 'SECURITY_ALERT')
        .replace(/\{\{description\}\}/g, inc.description || 'No description')
        .replace(/\{\{context\}\}/g, inc.contextBlock || 'Неизвестно')
        .replace(/\{\{ip\}\}/g, inc.ip || 'N/A')
        .replace(/\{\{incident_id\}\}/g, inc.id || 'N/A');
        
    $('ai-task').value = prompt; 
    switchTab('ai'); 
    sendAITask();
};
 
// ══════════════════════════════════════════════════════════════════════════════
// AI
// ══════════════════════════════════════════════════════════════════════════════

let chatHistory = window.chatHistory = [];
window.appendChatMsg = function(role, text, isHtml = false) {
    const historyEl = $('ai-chat-history');
    if(!historyEl) return null;
    const div = document.createElement('div');
    div.className = 'ai-msg ' + (role==='user'?'user':'bot');
    const avatar = document.createElement('div');
    avatar.className = 'msg-avatar';
    avatar.textContent = role==='user' ? 'USR' : 'AI';
    const bubble = document.createElement('div');
    bubble.className = 'msg-bubble';
    if (isHtml) bubble.innerHTML = text; else bubble.textContent = text;
    div.appendChild(avatar); div.appendChild(bubble);
    historyEl.appendChild(div); historyEl.scrollTop = historyEl.scrollHeight;
    return bubble;
};
function parseMarkdown(md) {
    if (!md) return '';
    let html = md;
    
    // Convert code blocks first so we don't accidentally match content inside them
    const codeRegex = /```(bash|sh|shell)?\n([\s\S]*?)```/g;
    html = html.replace(codeRegex, (match, lang, code) => {
        const encCode = btoa(unescape(encodeURIComponent(code.trim())));
        return `<div style="background:#0a0a0a; border:1px solid #333; border-radius:6px; margin:12px 0; overflow:hidden; font-family:var(--font-mono, monospace);">
            <div style="background:#1a1a1a; padding:6px 12px; font-size:10px; color:#aaa; border-bottom:1px solid #333; display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:700; text-transform:uppercase;">${lang||'script'}</span>
                <button onclick="executeAIScript('${encCode}')" style="background:var(--green); border:none; border-radius:4px; color:#000; font-weight:bold; font-size:9px; padding:4px 8px; cursor:pointer; font-family:inherit;">ВЫПОЛНИТЬ</button>
            </div><pre style="padding:12px; margin:0; font-family:inherit; font-size:11px; overflow-x:auto; color:#fff; white-space:pre;">${esc(code.trim())}</pre></div>`;
    });
    
    // Checkboxes [ ] and [x]
    html = html.replace(/\[ \] (.*?)(?=\n|$)/g, '<label style="display:flex;align-items:center;gap:6px;margin:4px 0;"><input type="checkbox"> $1</label>');
    html = html.replace(/\[x\] (.*?)(?=\n|$)/gi, '<label style="display:flex;align-items:center;gap:6px;margin:4px 0;"><input type="checkbox" checked> $1</label>');
    
    // Headings: #, ##, ###, ####
    html = html.replace(/^#### (.*?)(?=\n|$)/gm, '<h5 style="margin:12px 0 6px 0; color:#fff; font-size:12px; font-weight:700; font-family:\'Inter\', sans-serif;">$1</h5>');
    html = html.replace(/^### (.*?)(?=\n|$)/gm, '<h4 style="margin:14px 0 8px 0; color:#fff; font-size:13px; font-weight:700; font-family:\'Inter\', sans-serif; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom:4px;">$1</h4>');
    html = html.replace(/^## (.*?)(?=\n|$)/gm, '<h3 style="margin:16px 0 10px 0; color:var(--cyan); font-size:14px; font-weight:800; font-family:\'Inter\', sans-serif; border-bottom: 1px solid rgba(6,182,212,0.15); padding-bottom:6px;">$1</h3>');
    html = html.replace(/^# (.*?)(?=\n|$)/gm, '<h2 style="margin:18px 0 12px 0; color:var(--green); font-size:16px; font-weight:900; font-family:\'Inter\', sans-serif; border-bottom: 1px solid rgba(34,197,94,0.25); padding-bottom:8px;">$1</h2>');

    // Bullet lists starting with - or *
    html = html.replace(/^[-\*]\s+(.*?)(?=\n|$)/gm, '<li style="margin-left:16px; margin-bottom:4px; list-style-type:square;">$1</li>');

    // Bold text **text**
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="color:#fff; font-weight:700;">$1</strong>');
    
    // Inline code `code`
    html = html.replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1); padding:2px 4px; border-radius:4px; font-family:monospace; color:var(--orange);">$1</code>');
    
    // Horizontal rule ---
    html = html.replace(/^---$/gm, '<hr style="border:0; border-top:1px solid var(--border); margin:16px 0;">');

    // Handle line breaks (only single newlines)
    html = html.replace(/\n/g, '<br>');
    
    return html;
}
function executeAIScript(base64code) {
    const code = decodeURIComponent(escape(atob(base64code)));
    if(!confirm('ВНИМАНИЕ! Выполнить скрипт на сервере?\n\n' + code)) return;
    appendChatMsg('user', 'Выполни этот скрипт.');
    const bubble = appendChatMsg('bot', 'Выполнение...');
    window.electronAPI.sendApiRequest('/api/execute-ai-script', 'POST', {script: code})
        .then(res => { bubble.innerHTML = '<strong>Выполнено:</strong><br><pre style="background:#000;padding:10px;color:#0f0;margin-top:5px;">'+(res.output||res.error||'Успешно')+'</pre>'; })
        .catch(err => { bubble.innerHTML = '<strong>Ошибка:</strong><br>'+err.message; });
}
window.sendAITask = function(taskText = null) {
    // In Electron renderer, ws is managed by main process — check lastConnState instead
    if (typeof lastConnState === 'undefined' || lastConnState !== 'connected') {
        showToast('ИИ-Агент', 'Нет соединения с сервером. Подключитесь перед отправкой.', 'warn');
        return;
    }
    if (!window.electronAPI) {
        showToast('ИИ-Агент', 'Electron API недоступен.', 'warn');
        return;
    }

    const inp = $('ai-task');
    let task = '';
    if (typeof taskText === 'string' && taskText.trim().length > 0) {
        task = taskText;
    } else if (inp) {
        task = inp.value.trim();
    }
    
    if(!task) return;
    if(inp) inp.value = '';
    
    appendChatMsg('user', task); 
    chatHistory.push({role:'user', content:task});
    
    const btn = $('btn-ai-send');
    if(btn) btn.disabled = true;
    
    const bubble = appendChatMsg('bot', 'Анализ...'); 
    if(bubble) bubble.id = 'ai-typing-bubble';
    
    // Safety timeout: automatically re-enable button after 120 seconds if server doesn't respond
    if (window.aiSendTimeout) clearTimeout(window.aiSendTimeout);
    window.aiSendTimeout = setTimeout(() => {
        if ($('btn-ai-send')) $('btn-ai-send').disabled = false;
        const tbubble = $('ai-typing-bubble');
        if (tbubble) {
            tbubble.removeAttribute('id');
            tbubble.innerHTML = '⚠️ Превышено время ожидания ответа от сервера.';
        }
    }, 120000);
    
    window.electronAPI.sendWsMessage({
        event:'ai_task', 
        data: {
            task: task, 
            history: chatHistory, 
            model: (typeof window.currentModel !== 'undefined' && window.currentModel) ? window.currentModel : 'deepseek-v4-pro'
        }
    });
};
window.askAI = function(promptText) { switchTab('ai'); window.sendAITask(promptText); };
function generateDailyBriefing() {
    askAI('Сгенерируй Executive-отчёт (Daily Briefing) за последние 24 часа. Метрики: ' + JSON.stringify({threats: $('s-threats')?.textContent||'0', crit: $('s-critical')?.textContent||'0'}));
}

window.selectModel = function(model, btn) {
    window.currentModel = model;
    document.querySelectorAll('.model-btn').forEach(b => b.classList.remove('active'));
    if(btn) btn.classList.add('active');
    
    if (window.electronAPI) {
        window.electronAPI.sendWsMessage({
            event: 'switch_model',
            data: { model: model }
        });
    }
};

function populateAIIncidentDropdown() {
    const select = $("ai-incident-select");
    if (!select) return;
    const currentVal = select.value;
    select.innerHTML = '<option value="">-- Выберите инцидент для глубокого анализа --</option>';
    allIncidents.slice(0, 100).forEach(inc => {
        const opt = document.createElement("option");
        opt.value = inc.id;
        opt.textContent = `[${inc.severity || 'LOW'}] ${inc.type} | IP: ${inc.ip || "N/A"}`;
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
    
    let template = $('ai-system-prompt')?.value;
    if (!template) {
        template = `ПРОТОКОЛ АВТОЗАЩИТЫ MISTRAL.
Проанализируй инцидент и предоставь подробный отчет строго в следующем формате:

1. ПРИЧИНА АКТИВИЗАЦИИ АГЕНТА:
   [Подробное описание, почему включился ИИ-агент безопасности, оценка степени угрозы]

2. ПРЕДШЕСТВУЮЩЕЕ СОБЫТИЕ (ТРИГГЕР):
   [Детальный разбор события, которое вызвало алерт: тип инцидента, источник атаки, время, логи и контекст]

3. ПРЕДПРИНЯТЫЕ ДЕЙСТВИЯ И МИТИГАЦИЯ:
   [Какие меры были предприняты или рекомендуются. Если требуется блокировка, укажи [AUTOBAN: {{ip}}] и [INCIDENT_ID: {{incident_id}}]]

4. РЕКОМЕНДАЦИИ ДЛЯ АДМИНИСТРАТОРА:
   [Дальнейшие шаги по укреплению защиты системы]

Контекст инцидента:
Тип атаки: {{type}}
Описание: {{description}}
Контекст логов:
{{context}}`;
    }
    
    const prompt = template
        .replace(/\{\{type\}\}/g, inc.type || 'SECURITY_ALERT')
        .replace(/\{\{description\}\}/g, inc.description || 'No description')
        .replace(/\{\{context\}\}/g, inc.contextBlock || 'Неизвестно')
        .replace(/\{\{ip\}\}/g, inc.ip || 'N/A')
        .replace(/\{\{incident_id\}\}/g, inc.id || 'N/A');
        
    $("ai-task").value = prompt;
}

window.updateAIProgressUI = function(data) {
    // 1. Update the typing bubble if it exists in chat
    const bubble = $('ai-typing-bubble');
    if (bubble) {
        let pct = Math.round((data.step / data.total) * 100);
        let progressHtml = `
            <div class="ai-progress-widget" style="font-family:'JetBrains Mono', monospace; font-size:11px; color:#fff; display:flex; flex-direction:column; gap:8px; width:100%; min-width:260px;">
                <div style="display:flex; justify-content:space-between; font-weight:700; color:var(--cyan); font-size:10px;">
                    <span>🤖 ИИ-АГЕНТ MISTRAL</span>
                    <span>${pct}%</span>
                </div>
                <div style="height:5px; background:rgba(255,255,255,0.06); border-radius:3px; overflow:hidden; border:1px solid rgba(255,255,255,0.02);">
                    <div style="height:100%; width:${pct}%; background:linear-gradient(90deg, var(--blue), var(--cyan)); box-shadow:0 0 8px var(--cyan); transition:width 0.3s ease;"></div>
                </div>
                <div style="color:#e2e8f0; font-size:10px; display:flex; align-items:center; gap:6px;">
                    <span style="color:var(--orange); font-size:8px; animation: pulse 1s infinite;">●</span>
                    <span>${esc(data.message)}</span>
                </div>
            </div>
        `;
        bubble.innerHTML = progressHtml;
    }
    
    // 2. Update the sidebar UI blocks
    const shieldAi = $('shield-ai');
    if (shieldAi) {
        if (data.done) {
            shieldAi.style.color = 'var(--green)';
            shieldAi.innerHTML = `<div style="width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 5px var(--green)"></div>ARMED`;
        } else {
            let pct = Math.round((data.step / data.total) * 100);
            shieldAi.style.color = 'var(--orange)';
            shieldAi.innerHTML = `<div style="width:6px;height:6px;border-radius:50%;background:var(--orange);box-shadow:0 0 5px var(--orange);animation:pulse 1s infinite"></div>ACTIVE (${pct}%)`;
        }
    }
    
    const lastAction = $('ai-last-action');
    if (lastAction && data.message) {
        lastAction.textContent = data.message;
        lastAction.style.color = 'var(--orange)';
        if (data.done) {
            setTimeout(() => {
                lastAction.style.color = 'var(--cyan)';
            }, 3000);
        }
    }

    // 3. Update the Mitigation Log widget collapsible card
    if (data.incidentId) {
        const card = document.getElementById('ai-action-' + data.incidentId);
        if (card) {
            const pct = Math.round((data.step / data.total) * 100);
            const statusEl = card.querySelector('.ai-action-status');
            if (statusEl && statusEl.textContent.includes('АНАЛИЗ')) {
                statusEl.textContent = `АНАЛИЗ (${pct}%)`;
                statusEl.style.color = 'var(--orange)';
            }
            
            const progLog = card.querySelector('.ai-action-progress-log');
            if (progLog && data.message) {
                if (!progLog.innerHTML.includes(data.message)) {
                    const time = new Date().toLocaleTimeString();
                    const div = document.createElement('div');
                    div.innerHTML = `<span style="color:var(--dim);">${time}</span> - ${esc(data.message)}`;
                    progLog.appendChild(div);
                    progLog.scrollTop = progLog.scrollHeight;
                }
            }
            
            if (data.done) {
                const statusEl = card.querySelector('.ai-action-status');
                if (statusEl && statusEl.textContent.includes('АНАЛИЗ')) {
                    statusEl.textContent = 'ЗАКВЕРЖДЕНО';
                    statusEl.style.color = 'var(--green)';
                }
            }
        }
    }
};

window.copyLastAIResponse = function() {
    const history = window.chatHistory || [];
    const botMsgs = history.filter(m => m.role === 'bot' || m.role === 'assistant');
    if (botMsgs.length === 0) {
        showToast('ИИ-Агент', 'Нет ответов для копирования', 'warn');
        return;
    }
    const text = botMsgs[botMsgs.length - 1].content;
    navigator.clipboard.writeText(text)
        .then(() => showToast('ИИ-Агент', 'Ответ успешно скопирован в буфер обмена', 'green'))
        .catch(err => showToast('Ошибка', 'Не удалось скопировать: ' + err.message, 'warn'));
};

window.downloadLastAIResponse = function() {
    const history = window.chatHistory || [];
    const botMsgs = history.filter(m => m.role === 'bot' || m.role === 'assistant');
    if (botMsgs.length === 0) {
        showToast('ИИ-Агент', 'Нет ответов для скачивания', 'warn');
        return;
    }
    const text = botMsgs[botMsgs.length - 1].content;
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `mistral_ai_report_${new Date().toISOString().slice(0,10)}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('ИИ-Агент', 'Отчёт загружен в формате Markdown', 'green');
};

// ══════════════════════════════════════════════════════════════════════════════
// CUSTOM MODELS MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

window.customModelsList = [];

window.openCustomModelsModal = function() {
    const modal = $('modal-custom-models');
    if (modal) {
        modal.classList.remove('hidden');
        window.renderCustomModelsListModal();
    }
};

window.closeCustomModelsModal = function() {
    const modal = $('modal-custom-models');
    if (modal) {
        modal.classList.add('hidden');
    }
};

window.clearCustomModelForm = function() {
    $('custom-model-edit-id').value = '';
    $('custom-model-name').value = '';
    $('custom-model-api-name').value = '';
    $('custom-model-base-url').value = '';
    $('custom-model-api-key').value = '';
};

window.renderCustomModelsListModal = function() {
    const container = $('custom-models-list-container');
    if (!container) return;
    
    if (!window.customModelsList || window.customModelsList.length === 0) {
        container.innerHTML = '<div style="color:var(--dim); font-size:11px; padding:8px 0; text-align:center;">Нет сохраненных моделей</div>';
        return;
    }
    
    let html = '';
    window.customModelsList.forEach(m => {
        html += `
            <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.05); padding:8px; border-radius:6px; gap: 8px;">
                <div style="display:flex; flex-direction:column; gap:2px; overflow:hidden;">
                    <strong style="font-size:11px; color:#fff;">${esc(m.name)}</strong>
                    <span style="font-size:10px; color:var(--muted); font-family:monospace; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">API ID: ${esc(m.model_name)}</span>
                    <span style="font-size:9px; color:var(--dim); font-family:monospace; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${esc(m.base_url)}">${esc(m.base_url)}</span>
                </div>
                <div style="display:flex; gap:6px; flex-shrink:0;">
                    <button class="btn-sm" onclick="window.editCustomModel('${esc(m.id)}')" style="padding:4px 8px; font-size:10px; background:rgba(6,182,212,0.1); border:1px solid rgba(6,182,212,0.2); color:var(--cyan); font-family:'JetBrains Mono',monospace;">Изм.</button>
                    <button class="btn-sm" onclick="window.deleteCustomModel('${esc(m.id)}')" style="padding:4px 8px; font-size:10px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.2); color:var(--red); font-family:'JetBrains Mono',monospace;">Уд.</button>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
};

window.editCustomModel = function(id) {
    const m = window.customModelsList.find(x => x.id === id);
    if (!m) return;
    $('custom-model-edit-id').value = m.id;
    $('custom-model-name').value = m.name;
    $('custom-model-api-name').value = m.model_name;
    $('custom-model-base-url').value = m.base_url;
    $('custom-model-api-key').value = m.api_key || '********';
};

window.saveCustomModelFromUI = function() {
    const id = $('custom-model-edit-id').value || 'cm_' + Math.random().toString(36).slice(2, 11);
    const name = $('custom-model-name').value.trim();
    const model_name = $('custom-model-api-name').value.trim();
    const base_url = $('custom-model-base-url').value.trim();
    const api_key = $('custom-model-api-key').value;
    
    if (!name || !model_name || !base_url) {
        showToast('Ошибка', 'Заполните Название, Имя модели и Base URL', 'warn');
        return;
    }
    
    const body = { id, name, model_name, base_url, api_key };
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/custom-models', 'POST', body)
            .then(res => {
                if (res && res.success) {
                    showToast('ИИ-Модели', 'Модель успешно сохранена', 'green');
                    window.clearCustomModelForm();
                } else {
                    showToast('Ошибка', (res && res.error) || 'Не удалось сохранить модель', 'warn');
                }
            })
            .catch(err => {
                showToast('Ошибка', 'Ошибка сохранения: ' + err.message, 'warn');
            });
    }
};

window.deleteCustomModel = function(id) {
    if (!confirm('Вы уверены, что хотите удалить эту модель?')) return;
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest(`/api/custom-models/${id}`, 'DELETE')
            .then(res => {
                if (res && res.success) {
                    showToast('ИИ-Модели', 'Модель успешно удалена', 'green');
                    if ($('custom-model-edit-id').value === id) {
                        window.clearCustomModelForm();
                    }
                } else {
                    showToast('Ошибка', (res && res.error) || 'Не удалось удалить модель', 'warn');
                }
            })
            .catch(err => {
                showToast('Ошибка', 'Ошибка удаления: ' + err.message, 'warn');
            });
    }
};

window.renderAIModels = function(customModels) {
    window.customModelsList = customModels || [];
    const container = $('ai-models-container');
    if (!container) return;
    
    let html = `
        <button class="model-btn ${window.currentModel === 'deepseek-v4-pro' ? 'active' : ''}" onclick="selectModel('deepseek-v4-pro',this)">DeepSeek V4 Pro</button>
        <button class="model-btn ${window.currentModel === 'kimi-k2.6' ? 'active' : ''}" onclick="selectModel('kimi-k2.6',this)">Kimi K2.6</button>
        <button class="model-btn ${window.currentModel === 'claude-sonnet-4.6' ? 'active' : ''}" onclick="selectModel('claude-sonnet-4.6',this)">Claude Sonnet 4.6</button>
    `;
    
    window.customModelsList.forEach(m => {
        html += `<button class="model-btn ${window.currentModel === m.id ? 'active' : ''}" onclick="selectModel('${esc(m.id)}',this)">${esc(m.name)}</button>`;
    });
    
    html += `
        <button class="model-btn" onclick="openCustomModelsModal()" style="border: 1px dashed var(--border); background: rgba(255,255,255,0.05); color: var(--cyan);">+ Настроить модели</button>
    `;
    
    container.innerHTML = html;
    
    // Also update settings dropdown soar-ai-model
    const dropdown = $('soar-ai-model');
    if (dropdown) {
        let selectHtml = `
            <option value="deepseek-v4-pro" ${window.soarSettings?.aiModel === 'deepseek-v4-pro' ? 'selected' : ''}>DeepSeek V4 Pro</option>
            <option value="kimi-k2.6" ${window.soarSettings?.aiModel === 'kimi-k2.6' ? 'selected' : ''}>Kimi K2.6</option>
            <option value="claude-sonnet-4.6" ${window.soarSettings?.aiModel === 'claude-sonnet-4.6' ? 'selected' : ''}>Claude Sonnet 4.6</option>
        `;
        window.customModelsList.forEach(m => {
            selectHtml += `<option value="${esc(m.id)}" ${window.soarSettings?.aiModel === m.id ? 'selected' : ''}>${esc(m.name)}</option>`;
        });
        dropdown.innerHTML = selectHtml;
    }

    // Refresh the list inside modal if open
    window.renderCustomModelsListModal();
};

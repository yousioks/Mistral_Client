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
        .replace(/\{\{type\}\}/g, inc.type || 'Unknown')
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

let chatHistory = [];
function appendChatMsg(role, text, isHtml = false) {
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
                ${lang||'bash'} <button onclick="executeAIScript('${encCode}')" style="background:var(--green); border:none; border-radius:4px; color:#000; font-weight:bold; font-size:9px; padding:4px 8px; cursor:pointer;">ВЫПОЛНИТЬ</button>
            </div><pre style="padding:12px; margin:0; font-family:monospace; font-size:11px; overflow-x:auto; color:#fff;">${esc(code.trim())}</pre></div>`;
    });
    html = html.replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.1); padding:2px 4px; border-radius:4px; font-family:monospace;">$1</code>');
    return html.replace(/\n/g, '<br>');
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
    
    // Safety timeout: automatically re-enable button after 30 seconds if server doesn't respond
    if (window.aiSendTimeout) clearTimeout(window.aiSendTimeout);
    window.aiSendTimeout = setTimeout(() => {
        if ($('btn-ai-send')) $('btn-ai-send').disabled = false;
        const tbubble = $('ai-typing-bubble');
        if (tbubble) {
            tbubble.removeAttribute('id');
            tbubble.innerHTML = '⚠️ Превышено время ожидания ответа от сервера.';
        }
    }, 30000);
    
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

window.promptCustomModel = function() {
    const modelName = prompt('Enter custom neural network model ID (e.g., gpt-4o, llama-3):');
    if (!modelName || !modelName.trim()) return;
    
    const container = document.getElementById('ai-models-container');
    if (container) {
        const btn = document.createElement('button');
        btn.className = 'model-btn active';
        btn.textContent = modelName.trim();
        btn.onclick = function() { window.selectModel(modelName.trim(), this); };
        
        container.insertBefore(btn, container.lastElementChild);
        window.selectModel(modelName.trim(), btn);
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
        .replace(/\{\{type\}\}/g, inc.type || 'Unknown')
        .replace(/\{\{description\}\}/g, inc.description || 'No description')
        .replace(/\{\{context\}\}/g, inc.contextBlock || 'Неизвестно')
        .replace(/\{\{ip\}\}/g, inc.ip || 'N/A')
        .replace(/\{\{incident_id\}\}/g, inc.id || 'N/A');
        
    $("ai-task").value = prompt;
}

// ══════════════════════════════════════════════════════════════════════════════
// LOGIN
// ══════════════════════════════════════════════════════════════════════════════
async function doLogin() {
    try {
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
                token = res.token;
                statusEl.textContent = 'Авторизован. Подключение к WebSocket...';
                $('login-screen').classList.add('hidden');
                $('app').classList.remove('hidden');
                btn.disabled = false;
                try { updateIPDisplays(); } catch(e) { console.error(e); }
                try { initCharts(); } catch(e) { console.error(e); }
                try { if (typeof drawNetworkSpeedGauge === 'function') drawNetworkSpeedGauge(0); } catch(e) { console.error(e); }
                try { loadUsers(); } catch(e) { console.error(e); }
                try { loadQuarantine(); } catch(e) { console.error(e); }
            } else {
                errEl.textContent = res.error || 'Неверный логин или пароль'; btn.disabled = false; statusEl.textContent = ''; return;
            }
        }
    } catch (err) {
        alert("Login Error: " + err.message);
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
// USERS
// ══════════════════════════════════════════════════════════════════════════════
async function loadUsers() {
    try {
        const r = await fetch(`${serverBase}/api/users`);
        const users = await r.json();
        const el = $('users-list'); 
        if(!el) return;
        el.innerHTML = '';
        if (users && users.error) {
            el.innerHTML = `<div style="color:var(--red); font-size:11px; padding:10px;">Ошибка: ${esc(users.error)}</div>`;
            return;
        }
        if (!Array.isArray(users)) {
            el.innerHTML = '<div style="color:var(--red); font-size:11px; padding:10px;">Ошибка: неверный формат данных</div>';
            return;
        }
        users.forEach(u => {
            const div = document.createElement('div'); div.className='user-card';
            div.innerHTML = `<div class="user-avatar">${(u.username||'?')[0].toUpperCase()}</div><div class="user-info"><div class="name">${esc(u.username)}</div><div class="role role-${u.role||'operator'}">${esc(u.role||'operator')}</div></div>${u.chat_id?'<span class="user-tg">TELEGRAM</span>':''}`;
            el.appendChild(div);
        });
    } catch(e) {
        const el = $('users-list');
        if(el) el.innerHTML = `<div style="color:var(--red); font-size:11px; padding:10px;">Ошибка сети: ${esc(e.message)}</div>`;
    }
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
                logSearchInp.value = 'Анализ...';
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


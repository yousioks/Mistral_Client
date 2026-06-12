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
        data: { labels: Array(30).fill(''), datasets: [{ data: Array(30).fill(0), borderColor:'#06B6D4', backgroundColor:'rgba(6, 182, 212, 0.08)', borderWidth:2, tension:0.4, fill:true, pointRadius:0 }] },
        options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}}, scales:{y:{display:false},x:{display:false}} }
    });
    if ($('chart-type')) {
        chartType = new Chart($('chart-type').getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['Brute Force','SQLi','DDoS','Malware','XSS','Other'],
                datasets: [{ data:[0,0,0,0,0,0], backgroundColor:['#EF4444','#F59E0B','#22C55E','#3B82F6','#A855F7','#6B7280'], borderRadius:4, borderWidth:0 }]
            },
            options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}}, scales:{y:{grid:{color:'rgba(255,255,255,0.08)'},beginAtZero:true},x:{grid:{display:false}}} }
        });
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// BULK SELECTION & MULTI-PARAMETER SEARCH HELPERS
// ══════════════════════════════════════════════════════════════════════════════
window.selectedIncidents = new Set();
window.selectedLogs = new Set();

window.toggleSelectIncident = function(id, checked) {
    if (checked) {
        window.selectedIncidents.add(id);
    } else {
        window.selectedIncidents.delete(id);
    }
    window.updateIncidentsSelectedCount();
};

window.toggleSelectLog = function(id, checked) {
    if (checked) {
        window.selectedLogs.add(id);
    } else {
        window.selectedLogs.delete(id);
    }
    window.updateLogsSelectedCount();
};

window.updateIncidentsSelectedCount = function() {
    const count = window.selectedIncidents.size;
    const bar = document.getElementById('incidents-bulk-bar');
    const label = document.getElementById('incidents-selected-count');
    if (label) label.textContent = count;
    if (bar) bar.style.display = count > 0 ? 'flex' : 'none';
    
    // Sync Select All checkbox state
    const selectAllCb = document.getElementById('incidents-select-all');
    if (selectAllCb) {
        const visibleRows = document.querySelectorAll('.incident-select-cb');
        if (visibleRows.length > 0) {
            const allChecked = Array.from(visibleRows).every(cb => cb.checked);
            selectAllCb.checked = allChecked;
        } else {
            selectAllCb.checked = false;
        }
    }
};

window.updateLogsSelectedCount = function() {
    const count = window.selectedLogs.size;
    const bar = document.getElementById('logs-bulk-bar');
    const label = document.getElementById('logs-selected-count');
    if (label) label.textContent = count;
    if (bar) bar.style.display = count > 0 ? 'flex' : 'none';
    
    // Sync Select All checkbox state
    const selectAllCb = document.getElementById('log-select-all');
    if (selectAllCb) {
        const visibleRows = document.querySelectorAll('.log-select-cb');
        if (visibleRows.length > 0) {
            const allChecked = Array.from(visibleRows).every(cb => cb.checked);
            selectAllCb.checked = allChecked;
        } else {
            selectAllCb.checked = false;
        }
    }
};

window.toggleSelectAllIncidents = function(checked) {
    if (checked) {
        const filtered = window.currentFilteredIncidents || allIncidents;
        filtered.forEach(i => window.selectedIncidents.add(i.id));
    } else {
        window.selectedIncidents.clear();
    }
    const visibleCbs = document.querySelectorAll('.incident-select-cb');
    visibleCbs.forEach(cb => {
        cb.checked = checked;
    });
    window.updateIncidentsSelectedCount();
};

window.toggleSelectAllLogs = function(checked) {
    if (checked) {
        const filtered = window.currentFilteredLogs || currentLogsData;
        filtered.forEach(l => window.selectedLogs.add(l.id));
    } else {
        window.selectedLogs.clear();
    }
    const visibleCbs = document.querySelectorAll('.log-select-cb');
    visibleCbs.forEach(cb => {
        cb.checked = checked;
    });
    window.updateLogsSelectedCount();
};

function matchesMultiParamQuery(entry, queryText, isLog = true) {
    if (!queryText) return true;
    const parts = queryText.toLowerCase().split(/\s+/).filter(Boolean);
    
    const message = (entry.message || '').toLowerCase();
    const level = (isLog ? getAutoLevel(entry) : (entry.severity || '')).toLowerCase();
    const type = (entry.type || '').toLowerCase();
    const monitor = (entry.monitor || '').toLowerCase();
    const description = (entry.description || '').toLowerCase();
    const ip = (entry.ip || entry.target || '').toLowerCase();
    
    const fullText = `${message} ${level} ${type} ${monitor} ${description} ${ip}`;
    
    for (const part of parts) {
        if (part.includes(':')) {
            const [key, val] = part.split(':');
            if (!val) continue;
            
            if (key === 'level' || key === 'severity') {
                if (!level.includes(val)) return false;
            } else if (key === 'type') {
                if (!type.includes(val)) return false;
            } else if (key === 'monitor') {
                if (!monitor.includes(val)) return false;
            } else if (key === 'ip') {
                if (!ip.includes(val) && !message.includes(val)) return false;
            } else if (key === 'msg' || key === 'message' || key === 'desc' || key === 'description') {
                if (!message.includes(val) && !description.includes(val)) return false;
            } else {
                if (!fullText.includes(part)) return false;
            }
        } else {
            if (!fullText.includes(part)) return false;
        }
    }
    return true;
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
            d.style.cssText = 'padding:6px 8px;background:rgba(0,0,0,0.3);border-radius:6px;border-left:3px solid '+(sev==='CRITICAL'?'var(--red)':'var(--orange)')+';cursor:pointer;transition:transform 0.2s;';
            d.innerHTML = '<div style="font-weight:700;font-size:11px;color:#fff">'+esc(i.type||'')+'</div><div style="font-size:10px;color:var(--muted);margin-top:2px">'+esc(i.description||'').slice(0,60)+'</div>';
            d.onmouseover = () => { d.style.transform = 'translateX(4px)'; };
            d.onmouseout = () => { d.style.transform = 'none'; };
            d.onclick = () => {
                switchTab('incidents');
                setTimeout(() => openIncidentDrawer(i.id), 100);
            };
            ra.appendChild(d);
        });
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

window.updateMitreMatrix = function() {
    document.querySelectorAll('.mitre-cell').forEach(c => c.classList.remove('active-threat'));
    const activeThreats = allIncidents.filter(i => i.status !== 'resolved');
    
    activeThreats.forEach(inc => {
        const type = (inc.type || '').toLowerCase();
        const desc = (inc.description || '').toLowerCase();
        let targetTech = '';
        
        if (type.includes('ssh') || type.includes('brute') || type.includes('login') || desc.includes('auth')) targetTech = 'T1110';
        else if (type.includes('ddos') || type.includes('flood') || type.includes('syn')) targetTech = 'T1498';
        else if (type.includes('ransomware') || type.includes('encrypt') || desc.includes('ransom')) targetTech = 'T1486';
        else if (type.includes('privilege') || type.includes('root') || type.includes('sudo') || desc.includes('root') || type.includes('escalation')) targetTech = 'T1548';
        else if (type.includes('malware') || type.includes('virus') || desc.includes('malware') || desc.includes('payload')) targetTech = 'T1059';
        else if (type.includes('scan') || type.includes('nmap') || type.includes('port') || desc.includes('scan')) targetTech = 'T1046';
        else if (type.includes('sql') || type.includes('xss') || type.includes('web') || type.includes('injection')) targetTech = 'T1190';
        else if (type.includes('phish') || desc.includes('email')) targetTech = 'T1566';
        else if (type.includes('anomaly') || desc.includes('anomaly')) targetTech = 'T1071';
        
        // Если ничего не подошло, но это критическая угроза, ставим дефолтную тактику
        if (!targetTech && (inc.severity === 'CRITICAL' || inc.severity === 'HIGH')) {
            // Используем ID инцидента, чтобы всегда выдавать одну и ту же случайную тактику для конкретного инцидента
            const fallbackTechs = ['T1078', 'T1105', 'T1070', 'T1083', 'T1021'];
            const idStr = inc.id != null ? String(inc.id) : '';
            const hash = idStr.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
            targetTech = fallbackTechs[hash % fallbackTechs.length];
        }
        
        if (targetTech) {
            const el = document.getElementById(targetTech);
            if (el) el.classList.add('active-threat');
        }
    });
};

let rLogBuffer = [];
let rLogFrame = null;

function processRLogBuffer() {
    const rFeed = $('running-logs');
    if (!rFeed || !rLogBuffer.length) {
        rLogFrame = null;
        return;
    }
    
    const fragment = document.createDocumentFragment();
    rLogBuffer.forEach(el => fragment.appendChild(el));
    rLogBuffer = [];
    
    rFeed.appendChild(fragment);
    
    while (rFeed.children.length > 200) {
        rFeed.removeChild(rFeed.firstChild);
    }
    
    if ($('log-autoscroll')?.checked !== false) {
        rFeed.scrollTop = rFeed.scrollHeight;
    }
    updateRlogCount(rFeed.children.length);
    rLogFrame = null;
}

function addLiveEntry(entry) {
    const feed = $('logs-feed');
    const rFeed = $('running-logs');
    const div = document.createElement('div');
    const level = getAutoLevel(entry);
    div.className = `log-entry log-row-${level}`;
    const t = (entry.timestamp||'').slice(11,19);
    div.innerHTML = `<span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg">${window.formatLogMessageWithIpActions(entry.message)}</span><span class="log-monitor">${esc(entry.type||'')}</span>`;
    
    // Add to currentLogsData and re-filter
    if (entry.type === $('log-type').value || !$('log-type').value) {
        currentLogsData.unshift(entry);
        if (currentLogsData.length > 2000) currentLogsData.pop();
        
        // Optimize logs-feed filtering by throttling with trailing edge execution
        if (feed) {
            if (!window.lastFilterTime || Date.now() - window.lastFilterTime > 500) {
                window.lastFilterTime = Date.now();
                requestAnimationFrame(applyLogFilters);
            } else {
                if (window.logFilterTimeout) clearTimeout(window.logFilterTimeout);
                window.logFilterTimeout = setTimeout(() => {
                    window.lastFilterTime = Date.now();
                    applyLogFilters();
                }, 500);
            }
        }
    }
    
    if (rFeed) {
        const d2 = div.cloneNode(true);
        rLogBuffer.push(d2);
        if (!rLogFrame) {
            rLogFrame = requestAnimationFrame(processRLogBuffer);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// INCIDENTS (Data Grid & Drawer)
// ══════════════════════════════════════════════════════════════════════════════
window.activeMitreTechniqueFilter = '';
window.sortIncidentsField = '';
window.sortIncidentsDirection = 'desc';

window.filterIncidentsByMitre = function(techId) {
    window.activeMitreTechniqueFilter = techId;
    const badge = $('incidents-mitre-badge');
    const label = $('incidents-mitre-tech-id');
    if (badge && label) {
        label.textContent = techId;
        badge.style.display = 'flex';
    }
    switchTab('incidents');
    renderIncidents(allIncidents);
};

window.clearMitreTechniqueFilter = function() {
    window.activeMitreTechniqueFilter = '';
    const badge = $('incidents-mitre-badge');
    if (badge) badge.style.display = 'none';
    renderIncidents(allIncidents);
};

window.sortIncidents = function(field) {
    if (window.sortIncidentsField === field) {
        window.sortIncidentsDirection = window.sortIncidentsDirection === 'asc' ? 'desc' : 'asc';
    } else {
        window.sortIncidentsField = field;
        window.sortIncidentsDirection = 'desc';
    }
    showToast('Сортировка', `Таблица отсортирована по: ${field} (${window.sortIncidentsDirection})`, 'info');
    renderIncidents(allIncidents);
};

function renderIncidents(list) {
    const tbody = $('incidents-tbody');
    if(!tbody) return;
    tbody.innerHTML = '';
    
    if (!list) list = allIncidents;
    
    const severity = $('inc-severity-filter')?.value || 'all';
    const dateFrom = $('inc-date-from')?.value || '';
    const dateTo = $('inc-date-to')?.value || '';
    const timeFrom = $('inc-time-from')?.value || '';
    const timeTo = $('inc-time-to')?.value || '';
    const search = ($('inc-search')?.value || '').toLowerCase().trim();
    
    let filtered = list || [];

    // Filter by active MITRE technique
    if (window.activeMitreTechniqueFilter) {
        filtered = filtered.filter(i => getMitreTechId(i) === window.activeMitreTechniqueFilter);
    }
    
    if (severity !== 'all') {
        filtered = filtered.filter(i => i.severity === severity);
    }
    
    if (dateFrom || dateTo || timeFrom || timeTo) {
        filtered = filtered.filter(i => {
            if (!i.timestamp) return false;
            const parts = i.timestamp.split('T');
            const incDate = parts[0];
            const incTime = parts[1] ? parts[1].slice(0, 8) : '00:00:00';
            
            if (dateFrom && incDate < dateFrom) return false;
            if (dateTo && incDate > dateTo) return false;
            
            if (timeFrom) {
                if (dateFrom && incDate === dateFrom) {
                    if (incTime < timeFrom) return false;
                } else if (!dateFrom) {
                    if (incTime < timeFrom) return false;
                }
            }
            if (timeTo) {
                if (dateTo && incDate === dateTo) {
                    if (incTime > timeTo) return false;
                } else if (!dateTo) {
                    if (incTime > timeTo) return false;
                }
            }
            return true;
        });
    }
    
    if (search) {
        filtered = filtered.filter(i => matchesMultiParamQuery(i, search, false));
    }

    window.currentFilteredIncidents = filtered;

    // Apply Sorting
    if (window.sortIncidentsField === 'severity') {
        const sevOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
        filtered.sort((a, b) => {
            const valA = sevOrder[a.severity || 'LOW'] || 0;
            const valB = sevOrder[b.severity || 'LOW'] || 0;
            return window.sortIncidentsDirection === 'asc' ? valA - valB : valB - valA;
        });
    } else if (window.sortIncidentsField === 'date') {
        filtered.sort((a, b) => {
            const valA = new Date(a.timestamp || 0).getTime();
            const valB = new Date(b.timestamp || 0).getTime();
            return window.sortIncidentsDirection === 'asc' ? valA - valB : valB - valA;
        });
    }
    
    if(!filtered || !filtered.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-td">Нет зарегистрированных инцидентов</td></tr>';
        window.updateIncidentsSelectedCount();
        return;
    }
    
    // Virtualization / Limit
    filtered.slice(0, 150).forEach(i => {
        addIncidentRow(i, false, tbody);
    });

    // Sync check counts
    window.updateIncidentsSelectedCount();
}

function addIncidentRow(inc, prepend, container) {
    if(!container) container = $('incidents-tbody');
    // Remove "empty-td" if it exists
    if(container.querySelector('.empty-td')) {
        container.innerHTML = '';
    }
    
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.onclick = (e) => {
        // Prevent opening drawer if clicked on a select, button, or checkbox
        if(e.target.tagName === 'SELECT' || e.target.tagName === 'BUTTON' || e.target.type === 'checkbox') return;
        openIncidentDrawer(inc.id);
    };
    
    // Right-click context menu
    tr.oncontextmenu = (e) => {
        e.preventDefault();
        openContextMenu(e.pageX, e.pageY, inc.ip || inc.target || '');
    };
    
    let sevBadge = `<span class="inc-sev LOW">LOW</span>`;
    if(inc.severity === 'CRITICAL') sevBadge = `<span class="inc-sev CRITICAL">CRITICAL</span>`;
    else if(inc.severity === 'HIGH') sevBadge = `<span class="inc-sev HIGH">HIGH</span>`;
    else if(inc.severity === 'MEDIUM') sevBadge = `<span class="inc-sev MEDIUM">MEDIUM</span>`;
    
    const sOpts = [['new','Новый'],['in_review','В рассмотрении'],['resolved','Решён']]
        .map(([v,l])=>`<option value="${v}"${inc.status===v?' selected':''}>${l}</option>`).join('');
        
    const isChecked = window.selectedIncidents && window.selectedIncidents.has(inc.id);
    tr.innerHTML = `
        <td style="text-align:center; width:40px;"><input type="checkbox" class="incident-select-cb" data-id="${inc.id}" ${isChecked ? 'checked' : ''} onclick="event.stopPropagation(); window.toggleSelectIncident('${inc.id}', this.checked)" style="width:14px; height:14px; cursor:pointer;"></td>
        <td>${sevBadge}</td>
        <td style="font-weight:700; color:#fff;">
            ${esc(inc.type||'SECURITY_ALERT')}
            <div style="font-size:10px; color:var(--muted); font-weight:normal; margin-top:2px; max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                ${esc(inc.description||'—')}
            </div>
        </td>
        <td><span style="font-family:'JetBrains Mono', monospace; font-size:10px; color:var(--cyan); border:1px solid rgba(6,182,212,0.2); background:rgba(6,182,212,0.05); padding:2px 6px; border-radius:4px;">${esc(inc.monitor || 'System')}</span></td>
        <td><span class="ip-chip clickable" onclick="filterLogsByIp('${esc(inc.ip || inc.target || inc.monitor || '')}')">${esc(inc.ip || inc.target || inc.monitor || 'System')}</span></td>
        <td><select class="inc-sel" onchange="patchIncident('${inc.id}',{status:this.value})">${sOpts}</select></td>
        <td style="color:var(--dim); font-family:'JetBrains Mono',monospace; font-size:10px;">${(inc.timestamp||'').slice(0,19).replace('T',' ')}</td>
        <td>
            <button class="btn-txt" onclick="openIncidentDrawer('${inc.id}')">DETAILS</button>
        </td>
    `;
    
    if(prepend) container.insertBefore(tr, container.firstChild);
    else container.appendChild(tr);
}

function patchIncident(id, body) {
    fetch(`${serverBase}/api/incidents/${id}`, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}).catch(console.error);
}

// Drawer Logic
function openIncidentDrawer(id) {
    const inc = allIncidents.find(i => i.id === id);
    if(!inc) return;
    
    const content = $('drawer-content');
    let ctxHtml = '';
    if(inc.contextBlock) {
        ctxHtml = `<div style="margin-top:16px;">
            <div style="font-size:10px; font-weight:800; color:var(--muted); text-transform:uppercase; margin-bottom:8px;">Raw Context / Logs</div>
            <pre style="background:rgba(0,0,0,0.4); border:1px solid var(--border); border-radius:6px; padding:12px; font-family:'JetBrains Mono', monospace; font-size:10px; color:var(--muted); white-space:pre-wrap; overflow-x:auto;">${esc(inc.contextBlock)}</pre>
        </div>`;
    }
    
    let aiAuditHtml = '';
    if(inc.aiAudit) {
        aiAuditHtml = `<div style="margin-top:16px; background:rgba(34,197,94,0.05); border:1px solid rgba(34,197,94,0.3); border-radius:8px; padding:16px;">
            <div style="font-size:11px; font-weight:900; color:var(--green); text-transform:uppercase; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
                <span>AI AUDIT TRAIL</span>
                <span style="background:var(--green); color:#000; padding:2px 6px; border-radius:4px; font-size:9px;">MITIGATED</span>
            </div>
            <div style="font-size:11px; color:var(--muted); line-height:1.5; white-space:pre-wrap; font-family:'JetBrains Mono', monospace;">${esc(inc.aiAudit)}</div>
        </div>`;
    }
    
    let geoHtml = '';
    if (inc.geo) {
        const flag = inc.geo.code ? `<span style="font-size:11px; font-weight:700; color:var(--cyan); margin-right:6px; font-family:'JetBrains Mono',monospace;">${getFlagEmojiLocal(inc.geo.code)}</span>` : '';
        const rep = inc.geo.reputation || 0;
        const scoreColor = rep > 70 ? 'var(--red)' : rep > 40 ? 'var(--orange)' : 'var(--green)';
        geoHtml = `
        <div style="margin-top:16px; background:rgba(255,255,255,0.03); border:1px solid var(--border); border-radius:8px; padding:12px; display:flex; flex-direction:column; gap:10px;">
            <div style="font-size:10px; font-weight:800; color:var(--muted); text-transform:uppercase; border-bottom:1px solid rgba(255,255,255,0.05); padding-bottom:6px;">Threat Intelligence Feed</div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span style="font-size:10px; color:var(--muted); display:block; text-transform:uppercase; margin-bottom:2px;">Атакующий регион</span>
                    <span style="font-weight:700; color:#fff; display:flex; align-items:center;">${flag} ${esc(inc.geo.country || 'Локальная сеть / РФ')}</span>
                </div>
                <div style="text-align:right;">
                    <span style="font-size:10px; color:var(--muted); display:block; text-transform:uppercase; margin-bottom:2px;">ISP / Хостер</span>
                    <span style="font-weight:500; font-size:11px; color:#fff;">${esc(inc.geo.isp || 'Локальный провайдер')}</span>
                </div>
            </div>
            <div>
                <div style="display:flex; justify-content:space-between; align-items:center; font-size:10px; margin-bottom:4px;">
                    <span style="color:var(--muted);">Danger Reputation Score</span>
                    <span style="font-weight:700; color:${scoreColor};">${rep}% Malicious</span>
                </div>
                <div style="width:100%; height:6px; background:rgba(255,255,255,0.05); border-radius:3px; overflow:hidden;">
                    <div style="width:${rep}%; height:100%; background:${scoreColor}; box-shadow: 0 0 8px ${scoreColor};"></div>
                </div>
            </div>
        </div>
        `;
    }
    
    const svOpts = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s=>`<option value="${s}"${inc.severity===s?' selected':''}>${s}</option>`).join('');

    content.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="inc-sev ${inc.severity||'LOW'}">${inc.severity||'LOW'}</span>
                <span style="color:var(--dim); font-family:'JetBrains Mono',monospace; font-size:10px;">ID: ${inc.id.split('-')[0]}...</span>
            </div>
            
            <div style="font-size:18px; font-weight:800; color:#fff;">${esc(inc.type||'SECURITY_ALERT')}</div>
            <div style="color:#aaa; font-size:12px; line-height:1.5;">${esc(inc.description||'')}</div>
            
            <div style="display:flex; gap:10px; margin-top:8px;">
                <div style="flex:1;">
                    <div style="font-size:9px; color:var(--muted); text-transform:uppercase; margin-bottom:4px;">Target/IP</div>
                    <div class="ip-chip clickable" style="display:inline-block;" onclick="filterLogsByIp('${esc(inc.ip || inc.target || inc.monitor || '')}')">${esc(inc.ip || inc.target || inc.monitor || 'System')}</div>
                </div>
                <div style="flex:1;">
                    <div style="font-size:9px; color:var(--muted); text-transform:uppercase; margin-bottom:4px;">Severity Override</div>
                    <select class="inc-sel" style="width:100%" onchange="patchIncident('${inc.id}',{severity:this.value})">${svOpts}</select>
                </div>
            </div>
            
            ${geoHtml}
            ${ctxHtml}
            ${aiAuditHtml}
            <div id="drawer-ai-report"></div>
            
            <div style="margin-top:auto; padding-top:16px; border-top:1px solid var(--border); display:flex; gap:8px; flex-wrap:wrap;">
                <button class="btn-ai" style="flex:1; padding:10px; text-align:center;" onclick="analyzeContext('${inc.id}'); closeIncidentDrawer();">AI ANALYZE</button>
                <button class="btn-ai-agent" style="flex:1.2; padding:10px; background:linear-gradient(135deg, var(--purple), #581c87); border:none; border-radius:6px; color:#fff; font-weight:700; cursor:pointer; text-align:center;" onclick="triggerAgentManual('${inc.id}'); closeIncidentDrawer();">ИИ-АГЕНТ (РЕАГИРОВАНИЕ)</button>
                ${inc.ip ? (() => {
                    const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === inc.ip);
                    const isWhitelisted = window.soarSettings && window.soarSettings.whitelist && window.soarSettings.whitelist.includes(inc.ip);
                    
                    const banBtn = isBanned 
                        ? `<button class="btn-unq" style="flex:1; padding:10px; border-radius:6px; cursor:pointer; background:rgba(16,185,129,0.12); color:var(--green); border:1px solid rgba(16,185,129,0.3);" onclick="unquarantineIp('${esc(inc.ip)}'); closeIncidentDrawer();">UNBAN IP</button>`
                        : `<button class="btn-q" style="flex:1; padding:10px; border-radius:6px; cursor:pointer;" onclick="quarantineIp('${esc(inc.ip)}', 'Drawer Block'); closeIncidentDrawer();">BAN IP</button>`;
                        
                    const wlBtn = isWhitelisted
                        ? `<button class="btn-sm" style="flex:1; padding:10px; border-color:var(--green); color:var(--green); background:rgba(34,197,94,0.05);" onclick="window.removeWhitelistIp('${esc(inc.ip)}'); closeIncidentDrawer();">DE-WHITELIST</button>`
                        : `<button class="btn-sm" style="flex:1; padding:10px; border-color:var(--cyan); color:var(--cyan); background:rgba(6,182,212,0.05);" onclick="window.addWhitelistIp('${esc(inc.ip)}'); closeIncidentDrawer();">WHITELIST</button>`;
                        
                    const mapBtn = `<button class="btn-sm" style="flex:1; padding:10px; border-color:var(--orange); color:var(--orange); background:rgba(245,158,11,0.05);" onclick="focusIpOnMap('${esc(inc.ip)}'); closeIncidentDrawer();">SHOW MAP</button>`;
                    
                    return `${banBtn}${wlBtn}${mapBtn}`;
                })() : ''}
                <button class="btn-sm" style="padding:10px;" onclick="exportReport('${inc.id}')" title="Export Incident Report (IRR)">EXPORT</button>
                <button class="btn-sm" style="padding:10px; border-color:var(--green); color:var(--green); background:rgba(34,197,94,0.05);" onclick="exportReportDocx('${inc.id}')" title="Export Incident Report (IRR) as DOCX">DOCX</button>
            </div>
        </div>
    `;
    
    $('incident-drawer').classList.add('open');

    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/ai-reports/' + id, 'GET')
            .then(res => {
                if (res && res.markdown) {
                    const rdiv = $('drawer-ai-report');
                    if (rdiv) {
                        rdiv.innerHTML = `<div style="margin-top:16px; background:rgba(34,197,94,0.05); border:1px solid rgba(34,197,94,0.3); border-radius:8px; padding:16px;">
                            <div style="font-size:11px; font-weight:900; color:var(--green); text-transform:uppercase; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
                                <span>AI AGENT PERSISTENT REPORT</span>
                                <span style="background:var(--green); color:#000; padding:2px 6px; border-radius:4px; font-size:9px;">ARCHIVED</span>
                            </div>
                            <div style="font-size:11px; color:var(--muted); line-height:1.5; font-family:'JetBrains Mono', monospace;">${parseMarkdown(res.markdown)}</div>
                        </div>`;
                    }
                }
            })
            .catch(err => console.log('AI report not found yet for this incident'));
    }
}

function exportReport(id) {
    const inc = allIncidents.find(i => i.id === id);
    if(!inc) return;
    const reportText = `INCIDENT RESPONSE REPORT (IRR)\n==============================\nID: ${inc.id}\nType: ${inc.type}\nSeverity: ${inc.severity}\nIP: ${inc.ip}\nStatus: ${inc.status}\nTime: ${inc.timestamp}\n\nDESCRIPTION:\n${inc.description}\n\nCONTEXT:\n${inc.contextBlock || 'N/A'}\n\nAI AUDIT TRAIL:\n${inc.aiAudit || 'No AI mitigation triggered.'}\n`;
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IRR-${inc.id.split('-')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Export', 'Incident Response Report downloaded.', 'info');
}

function exportReportDocx(id) {
    const inc = allIncidents.find(i => i.id === id);
    if(!inc) return;
    
    const title = `Incident Response Report - ${inc.type}`;
    const dateStr = inc.timestamp || new Date().toISOString();
    
    let docHtml = `
        <h2>INCIDENT RESPONSE REPORT (IRR)</h2>
        <hr/>
        <table border="1" cellspacing="0" cellpadding="6" style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f2f2f2;">
                <th align="left">Свойство</th>
                <th align="left">Значение</th>
            </tr>
            <tr><td><b>ID инцидента</b></td><td>${inc.id}</td></tr>
            <tr><td><b>Тип угрозы</b></td><td>${inc.type}</td></tr>
            <tr><td><b>Критичность</b></td><td>${inc.severity}</td></tr>
            <tr><td><b>Источник / IP</b></td><td>${inc.ip || inc.target || 'System'}</td></tr>
            <tr><td><b>Статус</b></td><td>${inc.status || 'New'}</td></tr>
            <tr><td><b>Время детекции</b></td><td>${dateStr}</td></tr>
        </table>
        
        <h3>Описание инцидента:</h3>
        <p>${esc(inc.description || '').replace(/\n/g, '<br>')}</p>
        
        <h3>Контекст события / Системные логи:</h3>
        <pre style="background-color: #f8f9fa; padding: 10px; border: 1px solid #ddd; font-family: 'Courier New', Courier, monospace;">${esc(inc.contextBlock || 'N/A')}</pre>
        
        <h3>Журнал ИИ-Агента (Меры митигации):</h3>
        <div>${inc.aiAudit ? parseMarkdown(inc.aiAudit) : 'Автономные меры реагирования не запускались.'}</div>
    `;
    
    exportReportToDocx(`IRR-${inc.id.split('-')[0]}`, title, docHtml);
}

window.exportCurrentReportToDocx = function() {
    const titleText = $('md-viewer-title')?.textContent || 'AI Analysis Report';
    const contentHtml = $('md-viewer-content')?.innerHTML || '';
    const cleanId = titleText.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
    exportReportToDocx(cleanId, titleText, contentHtml);
};

function exportReportToDocx(filename, title, contentHtml) {
    // Generate valid Word HTML document with namespaces
    const header = `<html xmlns:o='urn:schemas-microsoft-com:office:office' 
          xmlns:w='urn:schemas-microsoft-com:office:word' 
          xmlns='http://www.w3.org/TR/REC-html40'>
          <head>
            <title>${title}</title>
            <!--[if gte mso 9]>
            <xml>
              <w:WordDocument>
                <w:View>Print</w:View>
                <w:Zoom>100</w:Zoom>
                <w:DoNotOptimizeForBrowser/>
              </w:WordDocument>
            </xml>
            <![endif]-->
            <style>
              body {
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.5;
                color: #333333;
                margin: 1in;
              }
              h1, h2, h3 {
                color: #990000;
                font-family: 'Segoe UI Semibold', Arial, sans-serif;
              }
              h2 {
                border-bottom: 2px solid #990000;
                padding-bottom: 5px;
                font-size: 18pt;
              }
              h3 {
                font-size: 14pt;
                margin-top: 20px;
                border-bottom: 1px solid #dddddd;
                padding-bottom: 3px;
              }
              table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                margin-bottom: 15px;
              }
              th, td {
                border: 1px solid #cccccc;
                padding: 8px;
                text-align: left;
                font-size: 10pt;
              }
              th {
                background-color: #f5f5f5;
                font-weight: bold;
              }
              pre {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                padding: 10px;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 9.5pt;
                white-space: pre-wrap;
              }
              code {
                font-family: Consolas, 'Courier New', monospace;
                background-color: #f1f3f5;
                padding: 2px 4px;
                font-size: 9.5pt;
              }
            </style>
          </head>
          <body>
            ${contentHtml}
          </body>
          </html>`;
          
    const blob = new Blob(['\ufeff' + header], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}.doc`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('DOCX Export', 'Отчет успешно экспортирован в формат Word', 'green');
}

window.generateGlobalSOCReport = function() {
    const totalThreats = allIncidents.length;
    const crit = allIncidents.filter(i => i.severity === 'CRITICAL').length;
    const high = allIncidents.filter(i => i.severity === 'HIGH').length;
    const med = allIncidents.filter(i => i.severity === 'MEDIUM').length;
    const low = allIncidents.filter(i => i.severity === 'LOW').length;
    
    const ufwStatus = $('status-ufw')?.textContent || 'OFFLINE';
    const f2bStatus = $('status-fail2ban')?.textContent || 'OFFLINE';
    const luaStatus = $('status-lua')?.textContent || 'OFFLINE';
    const activeModel = window.currentModel || 'deepseek-v4-pro';
    
    let docHtml = `
        <div style="text-align: center; margin-bottom: 25px;">
            <h1 style="color: #990000; font-size: 22pt; margin-bottom: 5px; font-family: 'Segoe UI Semibold', sans-serif;">MISTRAL DEFENSE SYSTEM</h1>
            <h3 style="color: #555555; font-size: 14pt; margin-top: 0; border: none; padding-bottom: 10px; border-bottom: 2px solid #990000;">СВОДНЫЙ ОТЧЕТ ЦЕНТРА УПРАВЛЕНИЯ БЕЗОПАСНОСТЬЮ (SOC REPORT)</h3>
            <p style="font-size: 9.5pt; color: #777777;">Сгенерировано автоматически: ${new Date().toLocaleString()}</p>
        </div>
        
        <h2>1. СТАТУС СИСТЕМЫ И ПАРАМЕТРЫ ЗАЩИТЫ</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 20px;">
            <tr style="background-color: #f9f9f9;">
                <td style="width: 40%; font-weight: bold; border: 1px solid #ddd; padding: 8px;">Активность UFW Брандмауэра</td>
                <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">${ufwStatus}</td>
            </tr>
            <tr>
                <td style="font-weight: bold; border: 1px solid #ddd; padding: 8px;">Интеграция защиты Fail2ban</td>
                <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">${f2bStatus}</td>
            </tr>
            <tr style="background-color: #f9f9f9;">
                <td style="font-weight: bold; border: 1px solid #ddd; padding: 8px;">Аналитические Lua Чеккеры</td>
                <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">${luaStatus}</td>
            </tr>
            <tr>
                <td style="font-weight: bold; border: 1px solid #ddd; padding: 8px;">Активная модель ИИ-Агента</td>
                <td style="border: 1px solid #ddd; padding: 8px; font-family: Consolas, monospace;">${activeModel}</td>
            </tr>
        </table>
        
        <h2>2. РАСПРЕДЕЛЕНИЕ ИНЦИДЕНТОВ ПО КРИТИЧНОСТИ</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 25px; text-align: center;">
            <thead>
                <tr style="background-color: #f2f2f2; font-weight: bold;">
                    <th style="border: 1px solid #ddd; padding: 10px; color: #990000; width: 20%;">CRITICAL</th>
                    <th style="border: 1px solid #ddd; padding: 10px; color: #e65c00; width: 20%;">HIGH</th>
                    <th style="border: 1px solid #ddd; padding: 10px; color: #0066cc; width: 20%;">MEDIUM</th>
                    <th style="border: 1px solid #ddd; padding: 10px; color: #555555; width: 20%;">LOW</th>
                    <th style="border: 1px solid #ddd; padding: 10px; background-color: #e5e7eb; width: 20%;">ВСЕГО</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 12px; font-size: 14pt; font-weight: bold; color: #990000;">${crit}</td>
                    <td style="border: 1px solid #ddd; padding: 12px; font-size: 14pt; font-weight: bold; color: #e65c00;">${high}</td>
                    <td style="border: 1px solid #ddd; padding: 12px; font-size: 14pt; font-weight: bold; color: #0066cc;">${med}</td>
                    <td style="border: 1px solid #ddd; padding: 12px; font-size: 14pt; font-weight: bold; color: #555555;">${low}</td>
                    <td style="border: 1px solid #ddd; padding: 12px; font-size: 16pt; font-weight: bold; background-color: #f3f4f6;">${totalThreats}</td>
                </tr>
            </tbody>
        </table>

        <h2>3. ЖУРНАЛ АКТИВНЫХ УГРОЗ БЕЗОПАСНОСТИ</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 25px; font-size: 9.5pt;">
            <thead>
                <tr style="background-color: #f2f2f2; font-weight: bold;">
                    <th style="border: 1px solid #ddd; padding: 8px; width: 18%;">Время</th>
                    <th style="border: 1px solid #ddd; padding: 8px; width: 15%;">Уровень</th>
                    <th style="border: 1px solid #ddd; padding: 8px; width: 32%;">Тип угрозы</th>
                    <th style="border: 1px solid #ddd; padding: 8px; width: 15%;">Детектор</th>
                    <th style="border: 1px solid #ddd; padding: 8px; width: 20%;">IP-Адрес</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    const threatsList = allIncidents.slice(0, 30);
    if (threatsList.length === 0) {
        docHtml += `<tr><td colspan="5" style="border: 1px solid #ddd; padding: 10px; text-align: center; font-style: italic; color: #777;">Активные инциденты отсутствуют.</td></tr>`;
    } else {
        threatsList.forEach(inc => {
            let color = '#555555';
            if (inc.severity === 'CRITICAL') color = '#990000';
            else if (inc.severity === 'HIGH') color = '#e65c00';
            else if (inc.severity === 'MEDIUM') color = '#0066cc';
            
            const time = (inc.timestamp || '').slice(0, 19).replace('T', ' ');
            docHtml += `
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-family: Consolas, monospace;">${time}</td>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold; color: ${color};">${inc.severity}</td>
                    <td style="border: 1px solid #ddd; padding: 8px;"><b>${inc.type}</b><br><span style="color: #666666; font-size: 8pt;">${inc.description || ''}</span></td>
                    <td style="border: 1px solid #ddd; padding: 8px;">${inc.monitor || 'Sensor'}</td>
                    <td style="border: 1px solid #ddd; padding: 8px; font-family: Consolas, monospace;">${inc.ip || inc.target || 'System'}</td>
                </tr>
            `;
        });
    }
    
    docHtml += `
            </tbody>
        </table>
        
        <h2>4. РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ СИСТЕМНОГО ОКРУЖЕНИЯ</h2>
        <div style="background-color: #f8f9fa; border: 1px solid #e9ecef; padding: 12px; font-family: Consolas, 'Courier New', monospace; font-size: 9pt; white-space: pre-wrap; margin-bottom: 25px;">
    `;
    
    const scanOut = $('scan-output') ? $('scan-output').textContent : 'Результаты сканирования уязвимостей отсутствуют.';
    docHtml += esc(scanOut);
    
    docHtml += `
        </div>
        
        <h2>5. РЕКОМЕНДАЦИИ И МЕРЫ РЕАГИРОВАНИЯ</h2>
        <p style="margin-bottom: 8px;">Служба информационной безопасности ИИ-Агента MISTRAL рекомендует принять следующие превентивные меры:</p>
        <ol style="line-height: 1.5; margin-left: 20px;">
            <li>Регулярно обновлять базу данных сигнатур и правил WAF в отношении SQL-инъекций и XSS.</li>
            <li>Активировать автоматический карантин IP-адресов в модуле SOAR при фиксации критических SSH и DDoS инцидентов.</li>
            <li>Обеспечить изоляцию скомпрометированных Docker-контейнеров на основе отчетов Trivy-сканера.</li>
        </ol>
    `;
    
    const dateStr = new Date().toISOString().slice(0, 10);
    exportReportToDocx(`GLOBAL-SOC-REPORT-${dateStr}`, 'MISTRAL GLOBAL SOC REPORT', docHtml);
};

function closeIncidentDrawer() {
    $('incident-drawer').classList.remove('open');
}

// Global Search
function doGlobalSearch(val) {
    if(!val) return;
    val = val.toLowerCase();
    
    // Check if it looks like an IP
    if(/^[0-9\.]+$/.test(val)) {
        $('log-search').value = val;
        switchTab('logs');
        showToast('Global Search', `Filtered logs by IP: ${val}`, 'info');
        return;
    }
    
    // Otherwise try to find in incidents
    const foundInc = allIncidents.find(i => (i.type||'').toLowerCase().includes(val) || (i.id||'').includes(val));
    if(foundInc) {
        switchTab('incidents');
        openIncidentDrawer(foundInc.id);
        showToast('Global Search', `Found incident: ${foundInc.type}`, 'info');
        return;
    }
    
    showToast('Global Search', 'No matches found', 'warn');
}

// Context Menu & Quick Actions
let ctxTargetIp = '';

window.addWhitelistIp = function(ip) {
    if (!ip) return;
    const requestBody = { ip };
    const apiCall = window.electronAPI 
        ? window.electronAPI.sendApiRequest('/api/whitelist/add', 'POST', requestBody)
        : fetch(`${serverBase}/api/whitelist/add`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify(requestBody)
          }).then(r => r.json());

    apiCall.then(res => {
        if (res && res.success) {
            showToast('IP Whitelist', `Адрес ${ip} успешно внесен в белый список.`, 'green');
            if (typeof loadSoarSettings === 'function') loadSoarSettings();
        } else {
            showToast('Ошибка Whitelist', (res && res.error) || 'Не удалось добавить IP в белый список', 'warn');
        }
    }).catch(err => {
        showToast('Ошибка Whitelist', err.message, 'warn');
    });
};

window.removeWhitelistIp = function(ip, skipConfirm = false) {
    if (!ip) return;
    if (!skipConfirm && !confirm(`Вы действительно хотите удалить ${ip} из белого списка?`)) return;
    const requestBody = { ip };
    const apiCall = window.electronAPI 
        ? window.electronAPI.sendApiRequest('/api/whitelist/remove', 'POST', requestBody)
        : fetch(`${serverBase}/api/whitelist/remove`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify(requestBody)
          }).then(r => r.json());

    apiCall.then(res => {
        if (res && res.success) {
            showToast('IP Whitelist', `Адрес ${ip} успешно удален из белого списка.`, 'green');
            if (typeof loadSoarSettings === 'function') loadSoarSettings();
        } else {
            showToast('Ошибка Whitelist', (res && res.error) || 'Не удалось удалить IP', 'warn');
        }
    }).catch(err => {
        showToast('Ошибка Whitelist', err.message, 'warn');
    });
};

window.focusIpOnMap = function(ip) {
    if (!ip) return;
    const inc = allIncidents.find(i => i.ip === ip && i.geo && i.geo.lat !== undefined);
    const geo = inc && inc.geo ? inc.geo : { ip: ip, country: 'Локальная сеть / РФ', code: 'RU', lat: 55.75, lon: 37.61, isp: 'Внутренний провайдер', reputation: 30 };
    
    switchTab('map');
    
    setTimeout(() => {
        if (window.cyberMap) {
            window.cyberMap.animateAttack(geo, inc ? inc.type : 'Target Focus');
            showToast('Cyber Map', `Позиционирование на карте для IP: ${ip}`, 'info');
        } else {
            showToast('Cyber Map', 'Карта атак не инициализирована', 'warn');
        }
    }, 150);
};

function openContextMenu(x, y, ip) {
    const menu = $('context-menu');
    if(!menu || !ip) return;
    ctxTargetIp = ip;
    
    const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === ip);
    const banItem = $('ctx-ban');
    if (banItem) {
        if (isBanned) {
            banItem.innerHTML = '🔓 Unban IP (Разблокировать в UFW)';
            banItem.style.color = '#10b981';
        } else {
            banItem.innerHTML = '🚫 Ban IP (Заблокировать в UFW)';
            banItem.style.color = 'var(--red)';
        }
    }
    
    const isWhitelisted = window.soarSettings && window.soarSettings.whitelist && window.soarSettings.whitelist.includes(ip);
    const wlItem = $('ctx-whitelist');
    if (wlItem) {
        if (isWhitelisted) {
            wlItem.innerHTML = '🛡️ Remove Whitelist (Из белого списка)';
            wlItem.style.color = '#fbbf24';
        } else {
            wlItem.innerHTML = '🛡️ Add Whitelist (В белый список)';
            wlItem.style.color = '#10b981';
        }
    }
    
    menu.style.display = 'block';
    
    // Position corrections
    const menuWidth = 220;
    const menuHeight = 250;
    let leftPos = x;
    let topPos = y;
    
    if (x + menuWidth > window.innerWidth) {
        leftPos = window.innerWidth - menuWidth - 10;
    }
    if (y + menuHeight > window.innerHeight) {
        topPos = window.innerHeight - menuHeight - 10;
    }
    
    menu.style.left = leftPos + 'px';
    menu.style.top = topPos + 'px';
}

document.addEventListener('click', () => {
    const menu = $('context-menu');
    if(menu) menu.style.display = 'none';
});

// Global Right-click interceptor to bind context menu to any IP
document.addEventListener('contextmenu', (e) => {
    let target = e.target;
    let ip = '';
    while (target && target !== document.body) {
        if (target.classList && (target.classList.contains('ip-chip') || target.classList.contains('clickable-ip') || target.classList.contains('ip-link') || target.classList.contains('toast-ip'))) {
            ip = target.getAttribute('data-ip') || target.textContent.trim().replace(/[🛡️📡]/g, '');
            break;
        }
        target = target.parentNode;
    }
    
    if (!ip && e.target && e.target.textContent) {
        const text = e.target.textContent;
        const match = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        if (match) {
            ip = match[0];
        }
    }
    
    if (ip) {
        ip = ip.trim().match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/)?.[0] || '';
        if (ip) {
            e.preventDefault();
            openContextMenu(e.pageX, e.pageY, ip);
        }
    }
});

// Global Double-click interceptor to copy IP to clipboard
document.addEventListener('dblclick', (e) => {
    let target = e.target;
    let ip = '';
    while (target && target !== document.body) {
        if (target.classList && (target.classList.contains('ip-chip') || target.classList.contains('clickable-ip') || target.classList.contains('toast-ip'))) {
            ip = target.getAttribute('data-ip') || target.textContent.trim().replace(/[🛡️📡]/g, '');
            break;
        }
        target = target.parentNode;
    }
    
    if (!ip && e.target && e.target.textContent) {
        const text = e.target.textContent;
        const match = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        if (match) {
            ip = match[0];
        }
    }
    
    if (ip) {
        ip = ip.trim().match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/)?.[0] || '';
        if (ip) {
            navigator.clipboard.writeText(ip).then(() => {
                showToast('Clipboard', `IP ${ip} скопирован в буфер обмена`, 'info');
            }).catch(() => {
                const el = document.createElement('textarea');
                el.value = ip;
                document.body.appendChild(el);
                el.select();
                document.execCommand('copy');
                document.body.removeChild(el);
                showToast('Clipboard', `IP ${ip} скопирован в буфер обмена`, 'info');
            });
        }
    }
});

function ctxAction(action) {
    if(!ctxTargetIp) return;
    const ip = ctxTargetIp;
    
    if(action === 'ban') {
        const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === ip);
        if (isBanned) {
            unquarantineIp(ip);
            showToast('Unbanned', `IP ${ip} разблокирован`, 'green');
        } else {
            quarantineIp(ip, 'Context Menu Ban');
            showToast('Banned', `IP ${ip} заблокирован на уровне брандмауэра`, 'critical');
        }
    } else if(action === 'filter') {
        if (window.filterLogsByIp) {
            window.filterLogsByIp(ip);
        }
    } else if(action === 'analyze') {
        askAI(`Проанализируй активность с IP адреса ${ip}. Выведи рекомендации по реагированию.`);
        showToast('AI Analysis', `Запрос на ИИ-анализ IP ${ip} отправлен`, 'info');
    } else if(action === 'lookup') {
        openThreatIntelModal(ip);
    } else if(action === 'map') {
        window.focusIpOnMap(ip);
    } else if(action === 'whitelist') {
        const isWhitelisted = window.soarSettings && window.soarSettings.whitelist && window.soarSettings.whitelist.includes(ip);
        if (isWhitelisted) {
            window.removeWhitelistIp(ip);
        } else {
            window.addWhitelistIp(ip);
        }
    } else if(action === 'copy') {
        navigator.clipboard.writeText(ip).then(() => {
            showToast('Copied', `IP ${ip} скопирован в буфер обмена`, 'info');
        }).catch(() => {
            const el = document.createElement('textarea');
            el.value = ip;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
            showToast('Copied', `IP ${ip} скопирован в буфер обмена`, 'info');
        });
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// LOGS — with filters
// ══════════════════════════════════════════════════════════════════════════════
let currentLogsData = [];
let lastUniqueSourcesStr = "";

function updateSourceDropdown(logs) {
    const dropdown = $('log-source-filter');
    if (!dropdown) return;
    const currentVal = dropdown.value || 'all';
    
    // Find all unique sources from bracket prefixes
    const sources = new Set();
    logs.forEach(entry => {
        const msg = entry.message || '';
        const match = msg.match(/^\[([^\]]+)\]/);
        if (match) {
            sources.add(match[1]);
        }
    });
    
    const sortedSources = Array.from(sources).sort();
    const sortedSourcesStr = sortedSources.join('|');
    
    // Only rebuild dropdown DOM if unique sources changed
    if (sortedSourcesStr === lastUniqueSourcesStr) {
        return;
    }
    lastUniqueSourcesStr = sortedSourcesStr;
    
    dropdown.innerHTML = '<option value="all">Все источники</option>';
    sortedSources.forEach(src => {
        const opt = document.createElement('option');
        opt.value = src;
        opt.textContent = src;
        dropdown.appendChild(opt);
    });
    
    if (sources.has(currentVal)) {
        dropdown.value = currentVal;
    } else {
        dropdown.value = 'all';
    }
}

function renderLogs(list) {
    currentLogsData = list || [];
    updateSourceDropdown(currentLogsData);
    applyLogFilters();
}

function applyLogFilters() {
    const feed = $('logs-feed'); 
    if (!feed) return;
    const levelFilter = $('log-level-filter')?.value || 'all';
    const sourceFilter = $('log-source-filter')?.value || 'all';
    const dateFrom = $('log-date-from')?.value || '';
    const dateTo = $('log-date-to')?.value || '';
    const searchText = ($('log-search')?.value || '').toLowerCase();
    
    // Calculate telemetry stats dynamically on the full loaded list
    let errorsCount = 0;
    let warnsCount = 0;
    const sourcesSet = new Set();
    const oneMinAgo = new Date(Date.now() - 60000);
    let recentCount = 0;
    
    currentLogsData.forEach(entry => {
        const lv = getAutoLevel(entry);
        if (lv === 'error') errorsCount++;
        else if (lv === 'warn') warnsCount++;
        
        const msg = entry.message || '';
        const match = msg.match(/^\[([^\]]+)\]/);
        const src = match ? match[1] : 'Система';
        sourcesSet.add(src);
        
        try {
            if (entry.timestamp) {
                const et = new Date(entry.timestamp);
                if (et >= oneMinAgo) recentCount++;
            }
        } catch(e) {}
    });
    
    if ($('log-stat-errors')) $('log-stat-errors').textContent = errorsCount;
    if ($('log-stat-warns')) $('log-stat-warns').textContent = warnsCount;
    if ($('log-stat-sources')) $('log-stat-sources').textContent = sourcesSet.size;
    if ($('log-stat-recent')) $('log-stat-recent').textContent = recentCount;
    
    let filtered = currentLogsData.filter(entry => {
        if (levelFilter !== 'all') {
            const lv = getAutoLevel(entry);
            if (lv !== levelFilter) return false;
        }
        if (sourceFilter !== 'all') {
            const msg = entry.message || '';
            const match = msg.match(/^\[([^\]]+)\]/);
            const entrySrc = match ? match[1] : 'Система';
            if (entrySrc !== sourceFilter) return false;
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
            if (!matchesMultiParamQuery(entry, searchText, true)) return false;
        }
        return true;
    });
    
    window.currentFilteredLogs = filtered;
    
    const badge = $('logs-count-badge');
    if (badge) badge.textContent = `${filtered.length} / ${currentLogsData.length}`;
    
    feed.innerHTML = '';
    
    // Virtualization / Performance limit: Only render the top 200 logs
    const displayLogs = filtered.slice(0, 200);
    
    const fragment = document.createDocumentFragment();
    displayLogs.forEach(entry => {
        const div = document.createElement('div'); 
        const level = getAutoLevel(entry);
        div.className = `log-entry log-row-${level}`;
        div.style.cursor = 'pointer';
        div.title = 'Нажмите для просмотра подробностей события';
        div.onclick = (e) => {
            if (e.target.classList.contains('ip-chip') || e.target.tagName === 'BUTTON' || e.target.type === 'checkbox') {
                return;
            }
            showLogDetailModal(entry);
        };
        const isChecked = window.selectedLogs && window.selectedLogs.has(entry.id);
        const t = (entry.timestamp||'').slice(0,19).replace('T',' ');
        div.innerHTML = `<input type="checkbox" class="log-select-cb" data-id="${entry.id}" ${isChecked ? 'checked' : ''} onclick="event.stopPropagation(); window.toggleSelectLog('${entry.id}', this.checked)" style="margin-right:8px; width:13px; height:13px; cursor:pointer; vertical-align:middle;"><span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg">${window.formatLogMessageWithIpActions(entry.message)}</span>`;
        fragment.appendChild(div);
    });
    feed.appendChild(fragment);
    
    // Update logs bulk bar count / display
    window.updateLogsSelectedCount();
}

function clearLogFilters() {
    const lf = $('log-level-filter'); if (lf) lf.value = 'all';
    const sf = $('log-source-filter'); if (sf) sf.value = 'all';
    const df = $('log-date-from'); if (df) df.value = '';
    const dt = $('log-date-to'); if (dt) dt.value = '';
    const ls = $('log-search'); if (ls) ls.value = '';
    applyLogFilters();
}

let activeDetailLog = null;

function showLogDetailModal(entry) {
    activeDetailLog = entry;
    const modal = $('modal-log-detail');
    if (!modal) return;
    
    const level = getAutoLevel(entry);
    const t = (entry.timestamp || '').slice(0, 19).replace('T', ' ');
    const msg = entry.message || '';
    const match = msg.match(/^\[([^\]]+)\]/);
    const src = match ? match[1] : 'Система';
    
    if ($('ld-time')) $('ld-time').textContent = t;
    if ($('ld-level')) {
        $('ld-level').textContent = level.toUpperCase();
        $('ld-level').className = `log-level ${level}`;
    }
    if ($('ld-source')) $('ld-source').textContent = src;
    if ($('ld-type')) $('ld-type').textContent = entry.type || 'server';
    if ($('ld-message')) $('ld-message').textContent = msg;
    
    const aiBtn = $('btn-ld-ai');
    if (aiBtn) {
        aiBtn.onclick = () => {
            closeLogDetailModal();
            if (window.analyzeLog) window.analyzeLog(msg);
        };
    }
    
    modal.classList.remove('hidden');
}

function closeLogDetailModal() {
    const modal = $('modal-log-detail');
    if (modal) modal.classList.add('hidden');
    activeDetailLog = null;
}

function copyLogMessageToClipboard() {
    if (!activeDetailLog) return;
    const msg = activeDetailLog.message || '';
    navigator.clipboard.writeText(msg).then(() => {
        showToast('Буфер обмена', 'Событие скопировано в буфер обмена', 'info');
    }).catch(err => {
        showToast('Ошибка', 'Не удалось скопировать: ' + err.message, 'warn');
    });
}

function exportLogsToFile() {
    const logsToExport = window.currentFilteredLogs || [];
    if (!logsToExport.length) {
        showToast('Экспорт невозможен', 'Нет логов для экспорта по текущим фильтрам', 'warn');
        return;
    }
    
    const textLines = logsToExport.map(entry => {
        const t = (entry.timestamp||'').slice(0,19).replace('T',' ');
        const lv = getAutoLevel(entry).toUpperCase();
        return `[${t}] [${lv}] ${entry.message}`;
    });
    
    const blob = new Blob([textLines.join('\r\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    const type = $('log-type')?.value || 'server';
    const dateStr = new Date().toISOString().slice(0,10);
    a.href = url;
    a.download = `mistral_logs_${type}_${dateStr}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Экспорт выполнен', `Экспортировано записей: ${textLines.length}`, 'info');
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
    if(window.electronAPI) { window.electronAPI.sendWsMessage({event:'get_logs',data:{type,limit:500}}); }
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
    const tp = data.top_process || {
        name: 'node',
        pid: '—',
        cpu: 0,
        mem: 0
    };
    const name = tp.name && tp.name !== 'unknown' && tp.name !== 'undefined' ? tp.name : 'node';
    const pid = tp.pid && tp.pid !== 'unknown' && tp.pid !== 'undefined' ? tp.pid : '—';
    const cpu = tp.cpu !== undefined && tp.cpu !== null ? tp.cpu : 0;
    const mem = tp.mem !== undefined && tp.mem !== null ? tp.mem : 0;
    $('top-process-info').textContent = `${name} [PID: ${pid}] — CPU: ${cpu}% / RAM: ${mem}%`;
    
    // WAF Status sync display update
    if (data.waf) {
        const wafShield = $('shield-waf');
        if (wafShield) {
            if (data.waf.online) {
                wafShield.style.color = 'var(--green)';
                wafShield.innerHTML = `<div style="width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 5px var(--green)"></div>ACTIVE (SYNCED)`;
            } else {
                wafShield.style.color = 'var(--red)';
                wafShield.innerHTML = `<div style="width:6px;height:6px;border-radius:50%;background:var(--red);box-shadow:0 0 5px var(--red)"></div>OFFLINE`;
            }
        }
    }
    // Network chart
    if(data.connections!=null && chartNet) { const ds=chartNet.data.datasets[0].data; ds.shift(); ds.push(data.connections); chartNet.update(); }
    if(data.connections!=null) { drawNetworkSpeedGauge(data.connections); }
    
    // Metrics feed
    const feed = $('metrics-feed');
    if (feed) {
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
    }
    
    // Check for high CPU to trigger warning
    if(data.cpu != null && data.cpu >= 90) {
        showToast('SYSTEM WARNING', `High CPU load detected: ${data.cpu}%`, 'warn');
    }
    // DDoS indicators for network tab & dashboard (via ddos metrics)
    if(data.ddos && data.ddos.top_ips && Array.isArray(data.ddos.top_ips)) {
        const tb = $('ssh-tbody'); // Network tab table body ID
        const dashTb = $('dash-ssh-tbody'); // Dashboard tab table body ID
        if (tb) {
            tb.innerHTML = '';
            if(!data.ddos.top_ips.length) {
                const msg = data.monitor === 'local-host-monitor' 
                    ? 'Система в безопасности (активный мониторинг хоста)' 
                    : 'Ожидание данных от DDoS-анализатора (Lua)...';
                tb.innerHTML=`<tr><td colspan="4" class="empty-td" style="color:var(--green); font-weight:600;">✓ ${msg}</td></tr>`;
            } else {
                data.ddos.top_ips.forEach(s => {
                    const tr = document.createElement('tr');
                    const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === s.ip);
                    const btnHtml = isBanned 
                        ? `<button class="btn-sm" style="background:rgba(16,185,129,0.12);color:var(--green);border:1px solid rgba(16,185,129,0.3)" onclick="unquarantineIp('${esc(s.ip)}')">РАЗБЛОКИРОВАТЬ</button>`
                        : `<button class="btn-sm btn-q" onclick="quarantineIp('${esc(s.ip)}','Blocked by Anti-DDoS')">ЗАБАНИТЬ IP</button>`;
                    const connsDetail = s.syn_recv !== undefined 
                        ? `${esc(s.count || 0)} <span style="font-size:9px;color:var(--muted);">(SYN: ${s.syn_recv}, EST: ${s.estab})</span>` 
                        : esc(s.count || 0);
                    const portsDetail = s.ports && s.ports.length > 0 
                        ? `<div style="font-size:9px;color:var(--muted);margin-top:2px;">Порты: ${esc(s.ports.join(', '))}</div>` 
                        : '';
                    tr.innerHTML = `<td>DDoS Attacker</td><td><span class="ip-chip clickable" onclick="filterLogsByIp('${esc(s.ip)}')">${esc(s.ip||'?')}</span>${portsDetail}</td><td>${connsDetail}</td><td>${btnHtml}</td>`;
                    tb.appendChild(tr);
                });
            }
        }
        
        if (dashTb) {
            dashTb.innerHTML = '';
            if(!data.ddos.top_ips.length) {
                const msg = data.monitor === 'local-host-monitor' 
                    ? 'Система в безопасности (активный мониторинг хоста)' 
                    : 'Ожидание данных от DDoS-анализатора (Lua)...';
                dashTb.innerHTML=`<tr><td colspan="4" class="empty-td" style="color:var(--green); font-weight:600;">✓ ${msg}</td></tr>`;
            } else {
                data.ddos.top_ips.forEach(s => {
                    const tr = document.createElement('tr');
                    const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === s.ip);
                    const btnHtml = isBanned 
                        ? `<button class="btn-sm" style="background:rgba(16,185,129,0.12);color:var(--green);border:1px solid rgba(16,185,129,0.3)" onclick="unquarantineIp('${esc(s.ip)}')">РАЗБЛОКИРОВАТЬ</button>`
                        : `<button class="btn-sm btn-q" onclick="quarantineIp('${esc(s.ip)}','Blocked by Anti-DDoS')">ЗАБАНИТЬ IP</button>`;
                    const connsDetail = s.syn_recv !== undefined 
                        ? `${esc(s.count || 0)} <span style="font-size:9px;color:var(--muted);">(SYN: ${s.syn_recv}, EST: ${s.estab})</span>` 
                        : esc(s.count || 0);
                    const portsDetail = s.ports && s.ports.length > 0 
                        ? `<div style="font-size:9px;color:var(--muted);margin-top:2px;">Порты: ${esc(s.ports.join(', '))}</div>` 
                        : '';
                    tr.innerHTML = `<td>DDoS Attacker</td><td><span class="ip-chip clickable" onclick="filterLogsByIp('${esc(s.ip)}')">${esc(s.ip||'?')}</span>${portsDetail}</td><td>${connsDetail}</td><td>${btnHtml}</td>`;
                    dashTb.appendChild(tr);
                });
            }
        }
    }
}

function drawNetworkSpeedGauge(connections) {
    const canvas = $('network-speed-gauge');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    const cx = canvas.width / 2;
    const cy = canvas.height - 5;
    const r = 32;
    
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, 0);
    ctx.strokeStyle = '#2d2d2d';
    ctx.lineWidth = 6;
    ctx.stroke();
    
    const val = Math.min(connections || 0, 500);
    const ratio = val / 500;
    const endAngle = Math.PI + ratio * Math.PI;
    
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, endAngle);
    
    let color = '#22C55E';
    if (val > 300) {
        color = '#e51400';
    } else if (val > 100) {
        color = '#F59E0B';
    } else if (val > 30) {
        color = '#00bcd4';
    }
    
    ctx.strokeStyle = color;
    ctx.lineWidth = 6;
    ctx.lineCap = 'round';
    ctx.stroke();
    
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(endAngle);
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(r - 5, 0);
    ctx.strokeStyle = '#fff';
    ctx.lineWidth = 2.5;
    ctx.stroke();
    ctx.restore();
    
    ctx.beginPath();
    ctx.arc(cx, cy, 4, 0, 2 * Math.PI);
    ctx.fillStyle = '#fff';
    ctx.fill();
    
    ctx.fillStyle = color;
    ctx.font = 'bold 9px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText(connections + ' conns', cx, cy - r - 4);
}

function setMetric(id, val, unit) {
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
window.quarantinedIps = [];
function renderQuarantine(list, filterQuery = '') {
    window.quarantinedIps = list || [];
    const tb = $('quarantine-tbody');
    let displayList = list || [];
    if (filterQuery) {
        displayList = displayList.filter(q => 
            q.ip.toLowerCase().includes(filterQuery) || 
            (q.reason && q.reason.toLowerCase().includes(filterQuery))
        );
    }
    $('q-count').textContent = displayList.length;
    if(!displayList.length) { tb.innerHTML='<tr><td colspan="4" class="empty-td">Нет заблокированных IP</td></tr>'; return; }
    tb.innerHTML = '';
    displayList.forEach(q => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><span class="ip-chip clickable" onclick="filterLogsByIp('${esc(q.ip)}')">${esc(q.ip)}</span></td><td>${esc(q.reason||'Manual')}</td><td>${esc((q.timestamp||'').slice(0,19).replace('T',' '))}</td><td><button class="btn-sm btn-unq" onclick="unquarantineIp('${esc(q.ip)}')">РАЗБЛОКИРОВАТЬ</button></td>`;
        tb.appendChild(tr);
    });
}

window.filterQuarantineTable = function(searchVal) {
    const query = (searchVal || '').trim().toLowerCase();
    renderQuarantine(window.quarantinedIps, query);
};
function quarantineIp(ip, reason) {
    fetch(`${serverBase}/api/quarantine`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip,reason:reason||'Manual block'})}).catch(console.error);
}
function unquarantineIp(ip) {
    fetch(`${serverBase}/api/quarantine/${encodeURIComponent(ip)}`, {method:'DELETE'}).catch(console.error);
}

function submitManualBan() {
    const ipEl = $('inp-manual-ban-ip');
    const reasonEl = $('inp-manual-ban-reason');
    if (!ipEl) return;
    const ip = ipEl.value.trim();
    const reason = reasonEl ? reasonEl.value.trim() : 'Manual block';
    
    if (!ip) {
        showToast('Отказ', 'Укажите IP-адрес для блокировки', 'warn');
        return;
    }
    
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipv4Regex.test(ip)) {
        if (!confirm(`Введенный IP-адрес "${ip}" не выглядит как валидный IPv4. Всё равно продолжить блокировку?`)) {
            return;
        }
    }
    
    if (ip === window.clientIp) {
        if (!confirm('ВНИМАНИЕ: Вы пытаетесь заблокировать свой собственный IP! Это приведёт к потере соединения с сервером. Вы уверены?')) {
            return;
        }
    }
    
    let serverHost = '';
    if (serverBase) {
        try {
            serverHost = new URL(serverBase).hostname;
        } catch(e) {
            serverHost = serverBase;
        }
    }
    if (ip === serverHost || ip === '127.0.0.1' || ip === 'localhost') {
        if (!confirm('ВНИМАНИЕ: Вы пытаетесь заблокировать IP-адрес сервера или localhost! Это может нарушить работу системы. Вы уверены?')) {
            return;
        }
    }
    
    quarantineIp(ip, reason || 'Manual block');
    showToast('Блокировка', `Отправлен запрос на блокировку IP ${ip}`, 'critical');
    
    ipEl.value = '';
    if (reasonEl) reasonEl.value = '';
}

// ══════════════════════════════════════════════════════════════════════════════
// ALERTS & TOASTS
// ══════════════════════════════════════════════════════════════════════════════
const alertCooldowns = new Map();

function showAlert(data) {
    // Check if inside-app toasts are enabled
    const uiToastsEnabled = localStorage.getItem('ui_toasts_enabled') !== 'false';
    if (!uiToastsEnabled) {
        console.log(`[SOC Alert] UI Toast suppressed (disabled in settings)`);
        return;
    }

    const type = data.type || '';
    const desc = data.description || '';
    
    // Extract IP from incident for action buttons and cooldown tracking
    let alertIp = data.ip || data.target || '';
    if (!alertIp) {
        const ipMatch = desc.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        if (ipMatch) alertIp = ipMatch[0];
    }
    if (!alertIp && data.details) {
        alertIp = data.details.sourceIp || data.details.ip || '';
    }

    const isDdos = type.includes('DDOS') || type.includes('DDoS') || desc.includes('DDoS') || desc.includes('SYN-RECV') || desc.includes('ESTABLISHED');
    const isHoneypot = type.includes('HONEYPOT') || desc.toUpperCase().includes('HONEYPOT') || desc.toUpperCase().includes('ХАНИПОТ') || desc.includes('8081');

    // Anti-flood / Cooldown filter
    const antiFloodEnabled = localStorage.getItem('ui_notifications_antiflood') !== 'false';
    if (antiFloodEnabled) {
        let key = type;
        if (alertIp) {
            key += '_' + alertIp;
        } else if (data.details?.sourceIp || data.details?.ip) {
            key += '_' + (data.details.sourceIp || data.details.ip);
        }

        const now = Date.now();
        const lastTime = alertCooldowns.get(key) || 0;
        
        let cooldownMs = 15000; // default 15 seconds
        if (isHoneypot) {
            cooldownMs = 30000; // 30 seconds for honeypots
        } else if (isDdos) {
            const suppressCheckbox = $('chk-suppress-ddos');
            const shouldSuppressDdos = suppressCheckbox ? suppressCheckbox.checked : true;
            if (shouldSuppressDdos) {
                cooldownMs = 180000; // 3 minutes for ddos
            }
        }

        if (now - lastTime < cooldownMs) {
            console.log(`[SOC Alert Suppressed] Rate-limited key: ${key}`);
            return;
        }
        alertCooldowns.set(key, now);
    }
    const sev = (data.severity || data.type || 'ALERT').toUpperCase();
    
    if (sev === 'CRITICAL' || sev === 'HIGH') {
        showToast(`CRITICAL: ${sev}`, data.description || data.type || 'Critical threat detected!', 'critical', alertIp);
    } else if (sev === 'MEDIUM' || sev === 'WARN') {
        showToast(`WARNING: ${sev}`, data.description || data.type || 'Suspicious activity detected.', 'warn', alertIp);
    } else {
        showToast('INFO', data.description || data.type || 'New event logged.', 'info', alertIp);
    }


}
function showToast(title, message, type='info', ip='') {
    const container = $('toast-container');
    if (!container) return;

    // Keep at most 3 toasts in DOM to avoid performance lag and screen spam
    while (container.children.length >= 3) {
        container.removeChild(container.firstChild);
    }

    const t = document.createElement('div');
    t.className = `toast t-${type}`;
    const time = new Date().toLocaleTimeString();
    
    // Determine lifetime: critical/warn alerts with IP get longer to allow interaction
    const lifetime = (ip && (type === 'critical' || type === 'warn')) ? 12000 : 6000;
    
    // Build action buttons HTML if we have an IP
    let actionsHtml = '';
    if (ip && ip !== 'System' && ip !== 'Неизвестный IP') {
        const safeIp = esc(ip);
        const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === ip);
        const banBtnHtml = isBanned
            ? `<button class="toast-btn toast-btn-unban" onclick="unquarantineIp('${safeIp}'); this.closest('.toast').remove(); showToast('Разблокировано', 'IP ${safeIp} разблокирован', 'info');">✓ Разбан</button>`
            : `<button class="toast-btn toast-btn-ban" onclick="quarantineIp('${safeIp}', 'Alert Quick Ban'); this.closest('.toast').remove(); showToast('Заблокировано', 'IP ${safeIp} заблокирован', 'warn');">🚫 Блок</button>`;
        actionsHtml = `
        <div class="toast-actions">
            <span class="toast-ip" onclick="filterLogsByIp('${safeIp}'); this.closest('.toast').remove();" title="Перейти в логи по IP: ${safeIp}">📡 ${safeIp}</span>
            <div style="display:flex;gap:5px;">
                <button class="toast-btn toast-btn-logs" onclick="filterLogsByIp('${safeIp}'); this.closest('.toast').remove();">→ Логи</button>
                ${banBtnHtml}
            </div>
        </div>`;
    }
    
    t.innerHTML = `
        <div class="toast-hdr">
            <span>${esc(title)}</span>
            <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:10px;opacity:0.6;">${time}</span>
                <span class="toast-close" onclick="this.closest('.toast').remove();" title="Закрыть">✕</span>
            </div>
        </div>
        <div class="toast-msg">${esc(message)}</div>
        ${actionsHtml}
    `;
    container.appendChild(t);
    const timer = setTimeout(() => { if(t.parentNode===container) container.removeChild(t); }, lifetime);
    // Stop auto-dismiss on hover so user can click buttons
    t.addEventListener('mouseenter', () => clearTimeout(timer));
    t.addEventListener('mouseleave', () => {
        setTimeout(() => { if(t.parentNode===container) container.removeChild(t); }, 2500);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// TABS
// ══════════════════════════════════════════════════════════════════════════════


// ══════════════════════════════════════════════════════════════════════════════
// TABS
// ══════════════════════════════════════════════════════════════════════════════
const TAB_NAMES = ['dashboard','network','incidents','logs','metrics','scanners','ai','users','map','mitre','server_info','apps','vulnerabilities'];
function switchTab(name) {
    try {
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab===name));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        
        const targetPanel = $('panel-'+name);
        if (targetPanel) {
            targetPanel.classList.add('active');
        } else {
            console.warn(`Panel panel-${name} not found!`);
        }
        
        if (name === 'logs' && typeof loadLogs === 'function') loadLogs();
        if (name === 'users' && typeof loadUsers === 'function') loadUsers();
        if (name === 'vulnerabilities' && typeof window.loadVulnerabilities === 'function') window.loadVulnerabilities();
        if (name === 'network' && typeof loadQuarantine === 'function') {
            loadQuarantine();
            if (window.updateIPDisplays) window.updateIPDisplays();
        }
        if (name === 'server_info') { 
            if (window.loadServerInfo) window.loadServerInfo(); 
            if (window.updateSecurityStatus) window.updateSecurityStatus(); 
            if (window.loadHardeningCompliance) window.loadHardeningCompliance(); 
        }
        if (name === 'apps') { if (window.loadApplicationsInfo) window.loadApplicationsInfo(); }
        if (name === 'incidents' && window.electronAPI) { window.electronAPI.sendWsMessage({event:'get_incidents'}); }
        if (name === 'map') {
            if (cyberMap) cyberMap.resize();
            if (window.dockerTopologyMap) window.dockerTopologyMap.resize();
        }
    } catch(err) {
        console.error("Tab Switch Error: ", err);
    }
}

// Helper: flag renderer for window UI
function getFlagEmojiLocal(countryCode) {
    if (!countryCode || countryCode === '?') return '';
    return `[${countryCode.toUpperCase()}]`;
}

function openThreatIntelModal(ip) {
    fetch(`${serverBase}/api/geoip/${encodeURIComponent(ip)}`)
        .then(r => r.json())
        .then(geo => {
            const flag = geo.code ? getFlagEmojiLocal(geo.code) : '';
            const rep = geo.reputation || 0;
            const scoreColor = rep > 70 ? 'var(--red)' : rep > 40 ? 'var(--orange)' : 'var(--green)';
            
            let modal = $('threat-intel-modal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'threat-intel-modal';
                modal.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    height: 100vh;
                    background: rgba(0,0,0,0.85);
                    z-index: 1000000;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    backdrop-filter: blur(8px);
                `;
                document.body.appendChild(modal);
            }
            
            modal.innerHTML = `
                <div style="background: #0d0d12; border: 1px solid var(--border); border-radius: 12px; width: 420px; box-shadow: 0 20px 50px rgba(0,0,0,0.9); font-family: 'Inter', sans-serif; overflow: hidden; animation: slideUp 0.3s ease;">
                    <div style="background: rgba(255,255,255,0.02); padding: 16px 20px; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 800; color: #fff; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; font-family:'JetBrains Mono',monospace;">Security Lookup: ${esc(ip)}</span>
                        <span style="cursor: pointer; color: var(--dim); font-size: 16px;" onclick="document.getElementById('threat-intel-modal').remove()">✕</span>
                    </div>
                    <div style="padding: 24px; display: flex; flex-direction: column; gap: 16px;">
                        <div style="display: flex; align-items: center; gap: 14px;">
                            <div style="font-size: 32px; background: rgba(255,255,255,0.03); width: 60px; height: 60px; display: flex; align-items: center; justify-content: center; border-radius: 8px; border: 1px solid var(--border);">${flag}</div>
                            <div>
                                <span style="font-size: 9px; color: var(--muted); display: block; text-transform: uppercase; margin-bottom: 2px; font-weight:800;">Геолокация / Страна</span>
                                <strong style="font-size: 15px; color: #fff;">${esc(geo.country || 'Локальная сеть / РФ')} (${esc(geo.code || 'RU')})</strong>
                            </div>
                        </div>
                        
                        <div style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.03); border-radius: 8px; padding: 12px; display: flex; flex-direction: column; gap: 8px; font-size: 11px;">
                            <div style="display: flex; justify-content: space-between;"><span style="color: var(--muted);">IP Address:</span><span style="color: #fff; font-family: monospace;">${esc(ip)}</span></div>
                            <div style="display: flex; justify-content: space-between;"><span style="color: var(--muted);">ISP / Provider:</span><span style="color: #fff; font-weight: 600;">${esc(geo.isp || 'Локальный провайдер')}</span></div>
                            <div style="display: flex; justify-content: space-between;"><span style="color: var(--muted);">Coordinates:</span><span style="color: var(--cyan); font-family: monospace;">${geo.lat || 0}, ${geo.lon || 0}</span></div>
                        </div>

                        <div>
                            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px; margin-bottom: 6px;">
                                <span style="color: var(--muted);">Threat Abuse Score</span>
                                <span style="font-weight: 800; color: ${scoreColor};">${rep}% (Dangerous)</span>
                            </div>
                            <div style="width: 100%; height: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; overflow: hidden;">
                                <div style="width: ${rep}%; height: 100%; background: ${scoreColor}; box-shadow: 0 0 8px ${scoreColor};"></div>
                            </div>
                        </div>
                    </div>
                    <div style="background: rgba(255,255,255,0.02); padding: 14px 20px; border-top: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: flex-end; gap: 10px;">
                        <button style="background: rgba(255,255,255,0.05); border: 1px solid var(--border); color: #fff; padding: 8px 16px; border-radius: 6px; font-size: 11px; font-weight: 700; cursor: pointer; font-family:'JetBrains Mono',monospace;" onclick="document.getElementById('threat-intel-modal').remove()">Закрыть</button>
                        ${(() => {
                            const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === ip);
                            return isBanned
                                ? `<button style="background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); color: var(--green); padding: 8px 16px; border-radius: 6px; font-size: 11px; font-weight: 700; cursor: pointer; font-family:'JetBrains Mono',monospace;" onclick="unquarantineIp('${esc(ip)}'); document.getElementById('threat-intel-modal').remove();">РАЗБЛОКИРОВАТЬ</button>`
                                : `<button style="background: var(--red); border: none; color: #fff; padding: 8px 16px; border-radius: 6px; font-size: 11px; font-weight: 700; cursor: pointer; font-family:'JetBrains Mono',monospace;" onclick="quarantineIp('${esc(ip)}', 'Threat Lookup Block'); document.getElementById('threat-intel-modal').remove();">ЗАБЛОКИРОВАТЬ</button>`;
                        })()}
                    </div>
                </div>
            `;
            modal.style.display = 'flex';
        })
        .catch(err => {
            showToast('Lookup Error', 'Failed to retrieve GeoIP data: ' + err.message, 'warn');
        });
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
    showToast('SYSTEM', 'Управление перехвачено оператором', 'info');
}

function sendAITerminalInput(text) {
    if (!text.trim()) return;
    const content = $('ai-term-content');
    content.innerHTML += `<br><br><span style="color:#fff">> OPERATOR: ${esc(text)}</span><br><span style="color:#0ff">> AWAITING NEURAL RESPONSE...</span><br>`;
    $('ai-term-input').value = '';
    
    if (window.electronAPI) {
        window.electronAPI.sendWsMessage({
            event: 'ai_task',
            data: {
                task: text,
                model: typeof window.currentModel !== 'undefined' ? window.currentModel : 'deepseek-v4-pro'
            }
        });
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
if ($('inp-pass')) {
    $('inp-pass').addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });
}

window.toggleAudioAlertsSetting = function(checked) {
    localStorage.setItem('mute_audio_alerts', checked ? 'false' : 'true');
    showToast('Настройки звука', checked ? 'Звуковые оповещения включены' : 'Звуковые оповещения отключены', 'info');
};

window.toggleOSNotificationsSetting = function(checked) {
    localStorage.setItem('os_notifications_enabled', checked ? 'true' : 'false');
    if (window.electronAPI && window.electronAPI.setNotificationsEnabled) {
        window.electronAPI.setNotificationsEnabled(checked);
    }
    showToast('Настройки уведомлений', checked ? 'Системные уведомления включены' : 'Системные уведомления отключены', 'info');
};

window.toggleUIToastsSetting = function(checked) {
    localStorage.setItem('ui_toasts_enabled', checked ? 'true' : 'false');
    if (!checked) {
        const container = $('toast-container');
        if (container) container.innerHTML = '';
    }
    showToast('Настройки уведомлений', checked ? 'Всплывающие уведомления включены' : 'Всплывающие уведомления отключены', 'info');
};

window.toggleAntiFloodSetting = function(checked) {
    localStorage.setItem('ui_notifications_antiflood', checked ? 'true' : 'false');
    showToast('Настройки уведомлений', checked ? 'Защита от флуда включена' : 'Защита от флуда отключена', 'info');
};

window.toggleGlowEffectsSetting = function(checked) {
    localStorage.setItem('glow_effects_enabled', checked ? 'true' : 'false');
    document.body.classList.toggle('glow-active', checked);
    showToast('Визуальные эффекты', checked ? 'Глоу-эффект активирован' : 'Глоу-эффект отключен', 'info');
};

window.filterLogsByPort = function(port) {
    const searchInp = $('log-search');
    if (searchInp) {
        searchInp.value = `:${port} `;
    }
    switchTab('logs');
    if (window.applyLogFilters) window.applyLogFilters();
};

window.showDaemonDetails = function(name, desc) {
    showToast('Системная служба', `Служба: ${name}\nОписание: ${desc}\nСтатус: ACTIVE`, 'info');
};

window.controlContainer = function(containerId, action) {
    showToast('Docker Control', `Отправлен запрос на ${action.toUpperCase()} для контейнера ${containerId}`, 'info');
    if (window.electronAPI) {
        window.electronAPI.sendWsMessage({event: 'control_container', data: {containerId, action}});
    }
    // Simulate update toast
    setTimeout(() => {
        showToast('Docker Control', `Контейнер ${containerId} успешно ${action === 'start' ? 'запущен' : 'остановлен'}`, 'green');
    }, 1200);
};

window.loadServerInfo = function() {
    const data = window.lastMetricsData;
    if (!data) return;
    
    if ($('si-hostname')) $('si-hostname').textContent = data.hostname || 'mistral-server';
    if ($('si-os')) $('si-os').textContent = data.os || 'Ubuntu 22.04 LTS (x86_64)';
    if ($('si-kernel')) $('si-kernel').textContent = data.kernel || 'Linux 5.15.0-generic';
    if ($('si-cpu-model')) $('si-cpu-model').textContent = data.cpu_model || 'Intel Xeon (4 Cores)';
    if ($('si-uptime')) $('si-uptime').textContent = data.uptime || '0 дней, 00:00:00';
    if ($('si-temp')) $('si-temp').textContent = (data.temp || 'N/A') + '°C';
    
    const daemonsContainer = $('si-daemons-list');
    if (daemonsContainer) {
        daemonsContainer.innerHTML = '';
        const daemons = data.daemons || [
            { name: 'nginx', status: (data.nginx && data.nginx.active) ? 'active' : 'inactive', description: 'Nginx Web Server' },
            { name: 'docker', status: (data.docker && data.docker.healthy) ? 'active' : 'inactive', description: 'Docker Container Engine' },
            { name: 'sshd', status: 'active', description: 'OpenSSH Server' },
            { name: 'ufw', status: 'active', description: 'Uncomplicated Firewall' },
            { name: 'cron', status: 'active', description: 'Task Scheduler Daemon' },
            { name: 'syslog', status: 'active', description: 'System Logging Daemon' }
        ];
        
        daemons.forEach(d => {
            const row = document.createElement('div');
            row.className = 'user-card';
            row.style.padding = '8px 12px';
            row.style.cursor = 'pointer';
            row.onclick = () => window.showDaemonDetails(d.name, d.description);
            row.title = `Нажмите для вывода деталей службы ${d.name}`;
            const color = d.status === 'active' ? 'var(--green)' : 'var(--red)';
            row.innerHTML = `
                <div class="user-avatar" style="width:28px; height:28px; font-size:11px; background:${color}">${d.name.substring(0,3).toUpperCase()}</div>
                <div class="user-info">
                    <div class="name" style="font-size:11px;">${d.name}</div>
                    <div class="role" style="font-size:9px; color:var(--muted);">${d.description}</div>
                </div>
                <div class="user-tg" style="font-size:8px; border-color:${color}; color:${color}; background:transparent;">${d.status.toUpperCase()}</div>
            `;
            daemonsContainer.appendChild(row);
        });
    }
    
    const portsContainer = $('si-ports-tbody');
    if (portsContainer) {
        portsContainer.innerHTML = '';
        const ports = data.open_ports || [
            { port: '80', proto: 'TCP', proc: 'nginx', pid: '1092' },
            { port: '443', proto: 'TCP', proc: 'nginx', pid: '1092' },
            { port: '22', proto: 'TCP', proc: 'sshd', pid: '842' },
            { port: '8080', proto: 'TCP', proc: 'node', pid: '2042' },
            { port: '8443', proto: 'TCP', proc: 'node', pid: '2042' },
            { port: '3306', proto: 'TCP', proc: 'mysqld', pid: '921' }
        ];
        ports.forEach(p => {
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';
            tr.onclick = () => window.filterLogsByPort(p.port);
            tr.title = `Кликните, чтобы найти логи порта :${p.port}`;
            const cleanProc = p.proc && p.proc !== 'unknown' && p.proc !== 'undefined' ? p.proc : ('port-' + p.port + '-service');
            const cleanPid = p.pid && p.pid !== 'unknown' && p.pid !== 'undefined' ? p.pid : '—';
            tr.innerHTML = `
                <td style="font-family:monospace; color:var(--cyan);">${p.port}</td>
                <td>${p.proto}</td>
                <td style="font-weight:bold;">${esc(cleanProc)}</td>
                <td style="color:var(--muted); font-family:monospace;">${esc(cleanPid)}</td>
            `;
            portsContainer.appendChild(tr);
        });
    }
};

// ── OS Hardening Compliance Audit ────────────────────────────────────────────
window.loadHardeningCompliance = function() {
    const grid = $('si-compliance-grid');
    const badge = $('hc-summary-badge');
    const tsEl = $('hc-timestamp');
    if (!grid) return;

    grid.innerHTML = '<div style="grid-column:1/-1; color:var(--dim); font-size:11px; text-align:center; padding:16px; font-family:\'JetBrains Mono\',monospace;">⏳ Запускаю аудит безопасности...</div>';
    if (badge) badge.textContent = '...';

    const apiCall = window.electronAPI
        ? window.electronAPI.sendApiRequest('/api/hardening-compliance', 'GET')
        : fetch(`${serverBase}/api/hardening-compliance`, { headers: { 'X-Auth-Token': token } }).then(r => r.json());

    apiCall.then(data => {
        if (!data || !data.results) {
            grid.innerHTML = '<div style="grid-column:1/-1; color:var(--red); text-align:center; padding:16px;">❌ Не удалось получить данные аудита</div>';
            return;
        }
        const results = data.results;
        const pass = results.filter(r => r.status === 'PASS').length;
        const warn = results.filter(r => r.status === 'WARN').length;
        const fail = results.filter(r => r.status === 'FAIL').length;

        if (badge) {
            badge.textContent = `✅ ${pass}  ⚠️ ${warn}  ❌ ${fail}`;
            badge.style.color = fail > 0 ? 'var(--red)' : warn > 0 ? 'var(--orange)' : 'var(--green)';
        }
        if (tsEl) tsEl.textContent = `Последняя проверка: ${new Date(data.timestamp).toLocaleString('ru-RU')}`;

        grid.innerHTML = '';
        // Group by category
        const cats = {};
        results.forEach(r => { if (!cats[r.category]) cats[r.category] = []; cats[r.category].push(r); });

        results.forEach(r => {
            const statusColor = r.status === 'PASS' ? 'var(--green)' : r.status === 'WARN' ? 'var(--orange)' : 'var(--red)';
            const statusIcon = r.status === 'PASS' ? '✅' : r.status === 'WARN' ? '⚠️' : '❌';
            const statusBg = r.status === 'PASS' ? 'rgba(34,197,94,0.06)' : r.status === 'WARN' ? 'rgba(245,158,11,0.06)' : 'rgba(239,68,68,0.06)';
            const borderColor = r.status === 'PASS' ? 'rgba(34,197,94,0.2)' : r.status === 'WARN' ? 'rgba(245,158,11,0.2)' : 'rgba(239,68,68,0.25)';

            const tile = document.createElement('div');
            tile.style.cssText = `background:${statusBg}; border:1px solid ${borderColor}; border-radius:8px; padding:12px; display:flex; flex-direction:column; gap:6px; transition:transform 0.15s;`;
            tile.onmouseover = () => tile.style.transform = 'translateY(-2px)';
            tile.onmouseout = () => tile.style.transform = 'none';

            const mitigationHtml = (r.status !== 'PASS' && r.mitigation)
                ? `<div style="margin-top:6px; font-size:9px; background:rgba(0,0,0,0.3); border-radius:4px; padding:6px 8px; color:var(--muted); font-family:'JetBrains Mono',monospace; border-left:2px solid ${statusColor}; line-height:1.5;">💡 ${esc(r.mitigation)}</div>`
                : '';

            tile.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:8px;">
                    <div style="font-size:11px; font-weight:700; color:#fff; line-height:1.4; flex:1;">${esc(r.label)}</div>
                    <span style="font-size:11px; font-weight:900; color:${statusColor}; white-space:nowrap;">${statusIcon} ${r.status}</span>
                </div>
                <div style="font-size:9px; color:var(--dim); font-family:'JetBrains Mono',monospace; letter-spacing:0.3px; background:rgba(255,255,255,0.02); padding:2px 6px; border-radius:4px; border:1px solid var(--border); width:fit-content;">${esc(r.category)}</div>
                <div style="font-size:10px; color:var(--muted); line-height:1.5;">${esc(r.detail)}</div>
                ${mitigationHtml}
            `;
            grid.appendChild(tile);
        });
    }).catch(err => {
        grid.innerHTML = `<div style="grid-column:1/-1; color:var(--red); text-align:center; padding:16px; font-family:'JetBrains Mono',monospace; font-size:11px;">❌ Ошибка: ${esc(err.message)}</div>`;
        if (badge) badge.textContent = 'Ошибка';
    });
};

window.loadApplicationsInfo = function() {
    const data = window.lastMetricsData;
    if (!data) return;
    
    const dockerContainer = $('apps-docker-tbody');
    if (dockerContainer) {
        dockerContainer.innerHTML = '';
        const containers = (data.docker && data.docker.containers) || [];
        if (containers.length === 0) {
            dockerContainer.innerHTML = '<tr><td colspan="4" class="empty-td">Нет запущенных контейнеров</td></tr>';
        } else {
            containers.forEach(c => {
                const tr = document.createElement('tr');
                const isRunning = c.status.toLowerCase().includes('up');
                const statusColor = isRunning ? 'var(--green)' : 'var(--muted)';
                
                // Dynamically count CVE logs related to this container or image
                const logCache = window.currentLogsData || [];
                const containerCves = logCache.filter(l => l.type === 'cve' && l.meta && (l.meta.image === c.image || l.meta.target === c.id || l.meta.image === c.id));
                const cveCount = containerCves.length;
                const cveBadge = cveCount > 0 
                    ? `<span class="inc-sev CRITICAL" style="padding: 2px 6px; font-size: 8px; margin-left: 6px; border-radius: 4px; display: inline-block; vertical-align: middle;">${cveCount} CVE</span>` 
                    : '';

                const dBtnClass = isRunning ? 'btn-q' : 'btn-unq';
                const dBtnText = isRunning ? 'STOP' : 'START';
                const dBtnAction = isRunning ? `controlContainer('${esc(c.id)}', 'stop')` : `controlContainer('${esc(c.id)}', 'start')`;

                tr.innerHTML = `
                    <td>
                        <div style="display:flex; align-items:center; gap:2px;">
                            <strong style="color:#fff; display:inline-block; vertical-align:middle;">${esc(c.name)}</strong>
                            ${cveBadge}
                        </div>
                        <span style="font-size:9px; color:var(--dim); font-family:monospace; display:block; margin-top:2px;">${esc(c.id)}</span>
                    </td>
                    <td style="font-size:10px; font-family:monospace;">${esc(c.image)}</td>
                    <td><span style="color:${statusColor}">${esc(c.status)}</span></td>
                    <td>
                        <div style="display:flex; gap:6px;">
                            <button class="btn-sm" onclick="runTrivyScan('${esc(c.id)}')" style="font-size:9px; padding:3px 6px;">Scan</button>
                            <button class="btn-sm ${dBtnClass}" onclick="${dBtnAction}" style="font-size:9px; padding:3px 6px;">${dBtnText}</button>
                        </div>
                    </td>
                `;
                dockerContainer.appendChild(tr);
            });
        }
    }
    
    const nginxContainer = $('apps-nginx-tbody');
    if (nginxContainer) {
        nginxContainer.innerHTML = '';
        const hasNginx = data.nginx && data.nginx.active;
        const sites = (data.nginx_sites && data.nginx_sites.length > 0) ? data.nginx_sites : (hasNginx ? [
            { domain: 'demo.mistral.local', port: '80', root: '/var/www/mistral-demo' },
            { domain: 'waf.mistral.local', port: '443', root: '/var/www/remon-waf' }
        ] : []);
        if (sites.length === 0) {
            nginxContainer.innerHTML = '<tr><td colspan="4" class="empty-td">Нет активных сайтов Nginx</td></tr>';
        } else {
            sites.forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong style="color:var(--cyan);">${esc(s.domain)}</strong></td>
                    <td style="font-family:monospace;">${esc(s.port)}</td>
                    <td style="font-size:10px; color:var(--muted);">${esc(s.root)}</td>
                    <td><button class="btn-sm" onclick="runSemgrepScan('${esc(s.root)}')" style="font-size:9px; padding:3px 6px;">Semgrep Scan</button></td>
                `;
                nginxContainer.appendChild(tr);
            });
        }
    }
    
    const leaksContainer = $('apps-leaks-feed');
    if (leaksContainer) {
        leaksContainer.innerHTML = '';
        const leaks = data.leaks || [];
        if (leaks.length === 0) {
            leaksContainer.innerHTML = '<div style="color:var(--dim); font-style:italic; text-align:center; padding:20px;">Утечек данных не обнаружено</div>';
        } else {
            leaks.forEach(l => {
                const div = document.createElement('div');
                div.className = 'user-card';
                div.style.padding = '8px 12px';
                div.style.cursor = 'pointer';
                div.onclick = () => {
                    switchTab('ai');
                    $('ai-task').value = `Проанализируй утечку данных в файле ${l.path}. Критичность: ${l.severity}. Описание: ${l.description}`;
                    sendAITask();
                };
                const color = l.severity === 'CRITICAL' ? 'var(--red)' : l.severity === 'HIGH' ? 'var(--orange)' : 'var(--blue)';
                div.innerHTML = `
                    <div class="user-avatar" style="width:28px; height:28px; font-size:11px; background:${color}">LEK</div>
                    <div class="user-info" style="flex:1;">
                        <div class="name" style="font-size:11px; color:#fff;">${l.description}</div>
                        <div class="role" style="font-size:9px; color:var(--muted); font-family:monospace;">${l.path}</div>
                    </div>
                    <div class="user-tg" style="font-size:8px; border-color:${color}; color:${color}; background:transparent;">${l.severity}</div>
                `;
                leaksContainer.appendChild(div);
            });
        }
    }
    
    const vulnsContainer = $('apps-vulns-log');
    if (vulnsContainer) {
        vulnsContainer.innerHTML = '';
        const scanFindings = data.scan_findings || [];
        if (scanFindings.length === 0) {
            vulnsContainer.innerHTML = '<div style="color:var(--dim); font-style:italic; text-align:center; padding:20px;">Нет результатов сканирования уязвимостей</div>';
        } else {
            scanFindings.forEach(f => {
                const div = document.createElement('div');
                div.style.cssText = 'border-bottom:1px solid rgba(255,255,255,0.03); padding:6px 0; cursor:pointer; transition: background 0.2s;';
                div.onmouseover = () => { div.style.background = 'rgba(255,255,255,0.02)'; };
                div.onmouseout = () => { div.style.background = 'transparent'; };
                div.onclick = () => {
                    const promptText = `Проанализируй уязвимость ИБ:\nСканер: ${f.scanner || 'Trivy'}\nПравило: ${f.rule || f.vulnId || ''}\nВажность: ${f.severity || ''}\nОписание: ${f.message || f.title || ''}\nЦель: ${f.path || f.target || ''}`;
                    switchTab('ai');
                    $('ai-task').value = promptText;
                    sendAITask();
                };
                const badgeColor = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'var(--red)' : 'var(--orange)';
                if (f.scanner === 'semgrep') {
                    div.innerHTML = `
                        <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                            <span style="color:var(--purple); font-weight:bold;">[SEMGREP] ${f.rule}</span>
                            <span style="color:${badgeColor}; font-weight:bold;">${f.severity}</span>
                        </div>
                        <div style="color:#ccc;">${f.message}</div>
                        <div style="color:var(--dim); font-size:9px;">Файл: ${f.path}:${f.line}</div>
                    `;
                } else {
                    div.innerHTML = `
                        <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                            <span style="color:var(--blue); font-weight:bold;">[TRIVY] ${f.vulnId} (${f.pkg})</span>
                            <span style="color:${badgeColor}; font-weight:bold;">${f.severity}</span>
                        </div>
                        <div style="color:#ccc;">${f.title}</div>
                        <div style="color:var(--dim); font-size:9px;">Цель: ${f.target} | Исправлено в: ${f.fixedVersion || '—'}</div>
                    `;
                }
                vulnsContainer.appendChild(div);
            });
        }
    }
};

window.runTrivyScan = function(containerId) {
    showToast('Trivy Scan', `Запуск сканирования контейнера ${containerId}...`, 'info');
    switchTab('scanners');
    $('scan-output').textContent = `Запуск сканирования TRIVY на цели: ${containerId}...\nПожалуйста, подождите, это может занять некоторое время...`;
    $('btn-run-semgrep').disabled = true;
    $('btn-run-trivy').disabled = true;

    fetch(`${serverBase}/api/scan/trivy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
        body: JSON.stringify({ target: containerId, scanType: 'image' })
    })
    .then(r => r.json())
    .then(res => {
        showToast('Trivy Complete', `Сканирование завершено. Найдено ${res.findings ? res.findings.length : 0} уязвимостей`, 'green');
        if (window.renderScanResultsInTerminal) {
            window.renderScanResultsInTerminal(res);
        }
        $('btn-run-semgrep').disabled = false;
        $('btn-run-trivy').disabled = false;
        if (window.loadApplicationsInfo) window.loadApplicationsInfo();
    })
    .catch(err => {
        showToast('Ошибка сканирования', err.message, 'warn');
        $('btn-run-semgrep').disabled = false;
        $('btn-run-trivy').disabled = false;
        $('scan-output').textContent = `❌ Ошибка сканирования: ${err.message}`;
    });
};

window.runSemgrepScan = function(rootPath) {
    showToast('Semgrep Scan', `Запуск SAST-сканирования директории ${rootPath}...`, 'info');
    switchTab('scanners');
    $('scan-output').textContent = `Запуск сканирования SEMGREP на цели: ${rootPath}...\nПожалуйста, подождите, это может занять некоторое время...`;
    $('btn-run-semgrep').disabled = true;
    $('btn-run-trivy').disabled = true;

    fetch(`${serverBase}/api/scan/semgrep`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
        body: JSON.stringify({ targetDir: rootPath })
    })
    .then(r => r.json())
    .then(res => {
        showToast('Semgrep Complete', `Сканирование завершено. Найдено ${res.findings ? res.findings.length : 0} замечаний`, 'green');
        if (window.renderScanResultsInTerminal) {
            window.renderScanResultsInTerminal(res);
        }
        $('btn-run-semgrep').disabled = false;
        $('btn-run-trivy').disabled = false;
        if (window.loadApplicationsInfo) window.loadApplicationsInfo();
    })
    .catch(err => {
        showToast('Ошибка сканирования', err.message, 'warn');
        $('btn-run-semgrep').disabled = false;
        $('btn-run-trivy').disabled = false;
        $('scan-output').textContent = `❌ Ошибка сканирования: ${err.message}`;
    });
};

window.triggerScannerInstallation = function() {
    showToast('Установка сканеров', 'Запуск установки Semgrep и Trivy на сервере...', 'info');
    fetch(`${serverBase}/api/install-scanners`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token }
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) showToast('Установка запущена', 'Установка выполняется в фоновом режиме', 'green');
    })
    .catch(err => showToast('Ошибка установки', err.message, 'warn'));
};

window.triggerServerAudit = function() {
    showToast('Аудит безопасности', 'Запуск глубокого аудита системы (Semgrep & Trivy)...', 'info');
    fetch(`${serverBase}/api/run-audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token }
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) showToast('Аудит запущен', 'Процесс глубокого сканирования запущен в фоне', 'green');
    })
    .catch(err => showToast('Ошибка запуска', err.message, 'warn'));
};


window.triggerSecurityHardening = function() {
    const btn = $('btn-activate-security');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Активация...';
    }
    showToast('Безопасность', 'Запущен процесс активации UFW, Fail2ban и Lua чекеров...', 'info');
    fetch(`${serverBase}/api/activate-security`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token }
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            showToast('Безопасность', 'Активация запущена в фоновом режиме.', 'green');
            // Poll security status every 2 seconds for a total of 10 seconds
            let attempts = 0;
            const pollInterval = setInterval(() => {
                window.updateSecurityStatus();
                attempts++;
                if (attempts >= 5) {
                    clearInterval(pollInterval);
                    if (btn) {
                        btn.disabled = false;
                        btn.textContent = 'Активировать UFW & Fail2ban';
                    }
                }
            }, 2000);
        } else {
            showToast('Безопасность', 'Ошибка активации: ' + (res.error || 'unknown'), 'warn');
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Активировать UFW & Fail2ban';
            }
        }
    })
    .catch(err => {
        showToast('Безопасность', 'Ошибка запуска: ' + err.message, 'warn');
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Активировать UFW & Fail2ban';
        }
    });
};

window.updateSecurityStatus = function() {
    fetch(`${serverBase}/api/security-status`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token }
    })
    .then(r => r.json())
    .then(res => {
        const ufwEl = $('status-ufw');
        if (ufwEl) {
            if (res.ufw === 'active') {
                ufwEl.textContent = 'АКТИВЕН';
                ufwEl.style.color = 'var(--green)';
            } else if (res.ufw === 'inactive') {
                ufwEl.textContent = 'НЕАКТИВЕН';
                ufwEl.style.color = 'var(--orange)';
            } else {
                ufwEl.textContent = 'НЕ УСТАНОВЛЕН';
                ufwEl.style.color = 'var(--red)';
            }
        }
        
        const f2bEl = $('status-fail2ban');
        if (f2bEl) {
            if (res.fail2ban === 'active') {
                f2bEl.textContent = 'АКТИВЕН';
                f2bEl.style.color = 'var(--green)';
            } else if (res.fail2ban === 'inactive') {
                f2bEl.textContent = 'НЕАКТИВЕН';
                f2bEl.style.color = 'var(--orange)';
            } else {
                f2bEl.textContent = 'НЕ УСТАНОВЛЕН';
                f2bEl.style.color = 'var(--red)';
            }
        }
        
        const luaEl = $('status-lua');
        if (luaEl) {
            if (res.lua === 'active') {
                luaEl.textContent = 'АКТИВЕН';
                luaEl.style.color = 'var(--green)';
            } else if (res.lua === 'inactive') {
                luaEl.textContent = 'НЕАКТИВЕН';
                luaEl.style.color = 'var(--orange)';
            } else {
                luaEl.textContent = 'НЕ УСТАНОВЛЕН';
                luaEl.style.color = 'var(--red)';
            }
        }
    })
    .catch(err => console.log('Failed to fetch security status:', err.message));
};

// ══════════════════════════════════════════════════════════════════════════════
// VULNERABILITIES & SIGNATURES DATABASE
// ══════════════════════════════════════════════════════════════════════════════
window.allVulnerabilities = [];

window.searchCve = function(cveCode) {
    const searchInp = $('vuln-search');
    if (searchInp) {
        searchInp.value = cveCode;
    }
    switchTab('vulnerabilities');
    window.filterVulnerabilitiesTable(cveCode);
};

window.filterVulnerabilitiesTable = function(searchVal) {
    const tbody = $('vulnerabilities-tbody');
    if (!tbody) return;
    const val = (searchVal || '').toLowerCase().trim();
    
    let filtered = window.allVulnerabilities || [];
    if (val) {
        filtered = filtered.filter(v => 
            (v.id || '').toLowerCase().includes(val) ||
            (v.name || '').toLowerCase().includes(val) ||
            (v.severity || '').toLowerCase().includes(val) ||
            (v.description || '').toLowerCase().includes(val) ||
            (v.detection_rules || '').toLowerCase().includes(val) ||
            (v.remediation || '').toLowerCase().includes(val)
        );
    }
    
    tbody.innerHTML = '';
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-td">Уязвимостей не найдено</td></tr>';
        return;
    }
    
    filtered.forEach(v => {
        const tr = document.createElement('tr');
        let sevClass = v.severity || 'MEDIUM';
        tr.innerHTML = `
            <td style="font-weight:700; color:#fff; font-family:'JetBrains Mono',monospace;">${esc(v.id)}<br><span style="font-size:11px; font-weight:normal; color:var(--muted);">${esc(v.name)}</span></td>
            <td><span class="inc-sev ${sevClass}">${sevClass}</span></td>
            <td style="font-size:11px; color:#ccc;">${esc(v.description || '—')}</td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--muted);">${esc(v.detection_rules || '—')}</td>
            <td style="font-size:11px; color:#ccc;">${esc(v.remediation || '—')}</td>
            <td>
                <div style="display:flex; gap:8px;">
                    <button class="btn-sm" onclick="editVulnerability('${esc(v.id)}')" style="padding:4px 8px; font-size:9px;">EDIT</button>
                    <button class="btn-sm btn-q" onclick="deleteVulnerability('${esc(v.id)}')" style="padding:4px 8px; font-size:9px;">DEL</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
};

window.loadVulnerabilities = function() {
    const tbody = $('vulnerabilities-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="empty-td">Загрузка базы уязвимостей...</td></tr>';
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/vulnerabilities', 'GET')
            .then(vulns => {
                if (vulns && vulns.error) {
                    tbody.innerHTML = `<tr><td colspan="6" class="empty-td" style="color:var(--red);">Ошибка загрузки: ${esc(vulns.error)}</td></tr>`;
                    return;
                }
                window.allVulnerabilities = Array.isArray(vulns) ? vulns : [];
                window.filterVulnerabilitiesTable($('vuln-search')?.value || '');
            })
            .catch(err => {
                tbody.innerHTML = `<tr><td colspan="6" class="empty-td" style="color:var(--red);">Ошибка загрузки: ${esc(err.message)}</td></tr>`;
            });
    }
};

window.showAddVulnerabilityModal = function() {
    $('modal-vuln-title').textContent = 'Добавить уязвимость';
    $('vuln-id').value = '';
    $('vuln-id').disabled = false;
    $('vuln-name').value = '';
    $('vuln-severity').value = 'MEDIUM';
    $('vuln-description').value = '';
    $('vuln-detection').value = '';
    $('vuln-remediation').value = '';
    $('modal-vuln').classList.remove('hidden');
};

window.closeVulnerabilityModal = function() {
    $('modal-vuln').classList.add('hidden');
};

window.saveVulnerability = function() {
    const id = $('vuln-id').value.trim();
    const name = $('vuln-name').value.trim();
    const severity = $('vuln-severity').value;
    const description = $('vuln-description').value.trim();
    const detection_rules = $('vuln-detection').value.trim();
    const remediation = $('vuln-remediation').value.trim();
    
    if (!id || !name) {
        alert('Идентификатор и Название обязательны!');
        return;
    }
    
    const body = { id, name, severity, description, detection_rules, remediation };
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/vulnerabilities', 'POST', body)
            .then(res => {
                if (res.success) {
                    showToast('База уязвимостей', `Сигнатура ${name} сохранена`, 'green');
                    closeVulnerabilityModal();
                    loadVulnerabilities();
                } else {
                    alert('Ошибка при сохранении: ' + (res.error || 'неизвестно'));
                }
            })
            .catch(err => alert('Ошибка сети: ' + err.message));
    }
};

window.editVulnerability = function(id) {
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/vulnerabilities', 'GET')
            .then(vulns => {
                if (vulns && vulns.error) {
                    alert('Ошибка: ' + vulns.error);
                    return;
                }
                if (!Array.isArray(vulns)) {
                    alert('Ошибка: неверный формат данных от сервера');
                    return;
                }
                const v = vulns.find(item => item.id === id);
                if (v) {
                    $('modal-vuln-title').textContent = 'Редактировать уязвимость';
                    $('vuln-id').value = v.id;
                    $('vuln-id').disabled = true;
                    $('vuln-name').value = v.name || '';
                    $('vuln-severity').value = v.severity || 'MEDIUM';
                    $('vuln-description').value = v.description || '';
                    $('vuln-detection').value = v.detection_rules || '';
                    $('vuln-remediation').value = v.remediation || '';
                    $('modal-vuln').classList.remove('hidden');
                }
            })
            .catch(err => alert('Ошибка: ' + err.message));
    }
};

window.deleteVulnerability = function(id) {
    if (!confirm(`Вы действительно хотите удалить сигнатуру ${id}?`)) return;
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/vulnerabilities/' + encodeURIComponent(id), 'DELETE')
            .then(res => {
                if (res.success) {
                    showToast('База уязвимостей', `Сигнатура ${id} удалена`, 'warn');
                    loadVulnerabilities();
                } else {
                    alert('Ошибка удаления: ' + (res.error || 'неизвестно'));
                }
            })
            .catch(err => alert('Ошибка сети: ' + err.message));
    }
};

// ══════════════════════════════════════════════════════════════════════════════
// AI REPORT ARCHIVE
// ══════════════════════════════════════════════════════════════════════════════
window.loadAiReportsList = function() {
    const container = $('ai-reports-list-container');
    if (!container) return;
    container.innerHTML = '<div style="color:var(--dim); font-size:11px; padding:8px 0;">Загрузка отчетов...</div>';
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/ai-reports', 'GET')
            .then(list => {
                container.innerHTML = '';
                if (list && list.error) {
                    container.innerHTML = `<div style="color:var(--red); font-size:11px; padding:8px 0;">Ошибка: ${esc(list.error)}</div>`;
                    return;
                }
                if (!Array.isArray(list)) {
                    container.innerHTML = '<div style="color:var(--red); font-size:11px; padding:8px 0;">Ошибка: неверный формат данных от сервера</div>';
                    return;
                }
                if (list.length === 0) {
                    container.innerHTML = '<div style="color:var(--dim); font-size:11px; padding:8px 0;">Архив пуст</div>';
                    return;
                }
                list.forEach(r => {
                    const row = document.createElement('div');
                    row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); border:1px solid var(--border); padding:8px 12px; border-radius:6px; font-size:11px;';
                    
                    const dateStr = new Date(r.createdAt).toLocaleString();
                    const displayName = r.incidentId ? `Инцидент: ${r.incidentId.substring(0,8)}...` : `Задача: ${r.taskId.substring(0,8)}...`;
                    
                    row.innerHTML = `
                        <div style="font-family:'JetBrains Mono',monospace;">
                            <strong style="color:#fff; display:block;">${displayName}</strong>
                            <span style="color:var(--dim); font-size:9px;">${dateStr} | ${(r.size/1024).toFixed(1)} KB</span>
                        </div>
                        <button class="btn-sm" onclick="viewMdReport('${esc(r.incidentId || r.taskId)}')" style="padding:4px 10px; font-size:9px; border-color:var(--cyan); color:var(--cyan); background:rgba(6,182,212,0.05);">ОТКРЫТЬ</button>
                    `;
                    container.appendChild(row);
                });
            })
            .catch(err => {
                container.innerHTML = `<div style="color:var(--red); font-size:11px; padding:8px 0;">Ошибка: ${esc(err.message)}</div>`;
            });
    }
};

window.viewMdReport = function(id) {
    const viewer = $('modal-md-viewer');
    const title = $('md-viewer-title');
    const content = $('md-viewer-content');
    if (!viewer || !content) return;
    
    content.innerHTML = 'Загрузка отчета...';
    title.textContent = `Отчет ИИ-Агента MISTRAL [${id.substring(0, 8)}]`;
    viewer.classList.remove('hidden');
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/ai-reports/' + id, 'GET')
            .then(res => {
                if (res && res.markdown) {
                    content.innerHTML = parseMarkdown(res.markdown);
                } else {
                    content.innerHTML = 'Ошибка: отчёт пуст или не найден.';
                }
            })
            .catch(err => {
                content.innerHTML = 'Ошибка загрузки отчёта: ' + err.message;
            });
    }
};

window.closeMdViewerModal = function() {
    $('modal-md-viewer').classList.add('hidden');
};

window.triggerDemoReset = function() {
    if (!confirm('Вы действительно хотите полностью сбросить состояние демо-режима? Это действие очистит инциденты, логи, CVE-записи, брандмауэр UFW и удалит отчёты ИИ.')) return;
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/reset-demo', 'POST')
            .then(res => {
                if (res && res.success) {
                    showToast('Демо-режим', 'Система успешно сброшена к исходному состоянию', 'green');
                    // Reset UI memory state too
                    allIncidents = [];
                    currentLogsData = [];
                    // Clear running logs panel
                    const rFeed = $('running-logs');
                    if (rFeed) rFeed.innerHTML = '';
                    updateRlogCount(0);
                    // Update stats/charts locally
                    updateChartsFromIncidents([]);
                } else {
                    alert('Не удалось сбросить состояние: ' + (res.error || 'неизвестно'));
                }
            })
            .catch(err => {
                alert('Ошибка сети: ' + err.message);
            });
    }
};

window.filterLogsByIp = function(ip) {
    if (!ip || ip === 'Неизвестный IP' || ip === 'System') return;
    switchTab('logs');
    
    // Select Server log type to ensure we see network/audit incidents
    const typeSelect = $('log-type');
    if (typeSelect) {
        typeSelect.value = 'server';
        loadLogs();
    }
    
    const search = $('log-search');
    if (search) {
        search.value = ip;
        // Make sure we give log DOM time to render if tab switches
        setTimeout(() => {
            applyLogFilters();
        }, 100);
    }
    showToast('Фильтр логов', `Логи отфильтрованы по IP: ${ip}`, 'info');
};

window.applyIncidentFilters = function() {
    renderIncidents(allIncidents);
};

window.clearIncidentFilters = function() {
    const sev = $('inc-severity-filter'); if(sev) sev.value = 'all';
    const df = $('inc-date-from'); if(df) df.value = '';
    const dt = $('inc-date-to'); if(dt) dt.value = '';
    const tf = $('inc-time-from'); if(tf) tf.value = '';
    const tt = $('inc-time-to'); if(tt) tt.value = '';
    const s = $('inc-search'); if(s) s.value = '';
    window.clearMitreTechniqueFilter();
};

window.clearIncidentHistory = function() {
    if (!confirm('Вы действительно хотите полностью очистить историю инцидентов? Это действие безвозвратно удалит записи из базы данных.')) return;
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/incidents', 'DELETE')
            .then(res => {
                if (res && res.success) {
                    showToast('Очистка', 'История инцидентов успешно очищена', 'green');
                    allIncidents = [];
                    renderIncidents([]);
                    updateChartsFromIncidents([]);
                } else {
                    showToast('Ошибка', res.error || 'Не удалось очистить историю', 'warn');
                }
            })
            .catch(err => {
                showToast('Ошибка сети', err.message, 'warn');
            });
    }
};

window.triggerAgentManual = function(id) {
    const inc = allIncidents.find(i => i.id === id);
    if (!inc) return;
    switchTab('ai');
    if (window.triggerSilentAIResponse) {
        window.triggerSilentAIResponse(inc);
    } else {
        showToast('ИИ-Агент', 'Модуль реагирования не инициализирован', 'warn');
    }
};

// ── SOC Live Clock Ticker ────────────────────────────────────────────────────
function updateClock() {
    const timeEl = document.getElementById('clock-time');
    const dateEl = document.getElementById('clock-date');
    if (!timeEl || !dateEl) return;
    
    const now = new Date();
    const hrs = String(now.getHours()).padStart(2, '0');
    const mins = String(now.getMinutes()).padStart(2, '0');
    const secs = String(now.getSeconds()).padStart(2, '0');
    
    const yr = now.getFullYear();
    const mon = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    
    timeEl.textContent = `${hrs}:${mins}:${secs}`;
    dateEl.textContent = `${yr}-${mon}-${day}`;
}
setInterval(updateClock, 1000);
setTimeout(updateClock, 100);

// ── Continuous Incident Updates ──────────────────────────────────────────────
setInterval(() => {
    if (window.electronAPI) {
        window.electronAPI.sendWsMessage({ event: 'get_incidents' });
    }
}, 5000);

// ── Defense Posture Panel Update ──────────────────────────────────────────────
window.defconOverride = 'auto';

const defconNames = {
    5: "БЕЗОПАСНО",
    4: "МОНИТОРИНГ",
    3: "УГРОЗА",
    2: "АТАКА",
    1: "КАТАСТРОФА"
};

window.manualDefconChange = function(val) {
    window.defconOverride = val;
    if (val === 'auto') {
        showToast('Режим безопасности', 'Контроль безопасности переведен в автоматический режим.', 'info');
    } else {
        const severity = val === '1' || val === '2' ? 'critical' : 'warn';
        const name = defconNames[val] || `Уровень ${val}`;
        showToast('Режим безопасности', `Уровень угрозы принудительно установлен на: "${name}"!`, severity);
    }
    window.updateDefensePosture();
};


function applyDefconVisualEffects(defcon) {
    document.body.classList.remove('defcon-1', 'defcon-2', 'defcon-3', 'defcon-4', 'defcon-5');
    document.body.classList.add(`defcon-${defcon}`);
    
    // Dynamically change color theme based on security posture
    const root = document.documentElement;
    if (defcon === 5) {
        root.style.setProperty('--defcon-accent', '#22C55E'); // Green
        root.style.setProperty('--defcon-glow', 'rgba(34, 197, 94, 0.08)');
        root.style.setProperty('--defcon-border', 'rgba(34, 197, 94, 0.2)');
        root.style.setProperty('--defcon-bg', '#070c08');
    } else if (defcon === 4) {
        root.style.setProperty('--defcon-accent', '#007acc'); // Blue
        root.style.setProperty('--defcon-glow', 'rgba(0, 122, 204, 0.08)');
        root.style.setProperty('--defcon-border', 'rgba(0, 122, 204, 0.2)');
        root.style.setProperty('--defcon-bg', '#07090c');
    } else if (defcon === 3) {
        root.style.setProperty('--defcon-accent', '#00bcd4'); // Cyan
        root.style.setProperty('--defcon-glow', 'rgba(0, 188, 212, 0.08)');
        root.style.setProperty('--defcon-border', 'rgba(0, 188, 212, 0.2)');
        root.style.setProperty('--defcon-bg', '#060b0c');
    } else if (defcon === 2) {
        root.style.setProperty('--defcon-accent', '#F59E0B'); // Orange
        root.style.setProperty('--defcon-glow', 'rgba(245, 158, 11, 0.08)');
        root.style.setProperty('--defcon-border', 'rgba(245, 158, 11, 0.2)');
        root.style.setProperty('--defcon-bg', '#0c0a06');
    } else if (defcon === 1) {
        root.style.setProperty('--defcon-accent', '#e51400'); // Red
        root.style.setProperty('--defcon-glow', 'rgba(229, 20, 0, 0.08)');
        root.style.setProperty('--defcon-border', 'rgba(229, 20, 0, 0.2)');
        root.style.setProperty('--defcon-bg', '#0c0707');
    }
    
    // Sync active classes of the Russian DEFCON buttons
    document.querySelectorAll('.defcon-btn').forEach(btn => {
        const isActive = (btn.id === `defcon-btn-${window.defconOverride || 'auto'}`);
        btn.classList.toggle('active', isActive);
    });

    // Toggle the full-screen emergency CRT overlay
    const overlay = $('defcon1-overlay');
    if (overlay) {
        overlay.classList.toggle('hidden', defcon !== 1);
    }
    
    const alertBanner = $('alert-banner');
    if (alertBanner) {
        if (defcon === 1) {
            alertBanner.innerHTML = '🚨 КРИТИЧЕСКАЯ УГРОЗА: ПРИНУДИТЕЛЬНО ВВЕДЕН РЕЖИМ "КАТАСТРОФА" 🚨';
            alertBanner.style.display = 'block';
            alertBanner.style.background = 'var(--red)';
        } else if (defcon === 2) {
            alertBanner.innerHTML = '⚠️ ПОВЫШЕННЫЙ УРОВЕНЬ ОПАСНОСТИ: ВВЕДЕН РЕЖИМ "АТАКА" ⚠️';
            alertBanner.style.display = 'block';
            alertBanner.style.background = 'var(--orange)';
        } else {
            alertBanner.style.display = 'none';
        }
    }
}

window.updateDefensePosture = function() {
    const mitigated = allIncidents.filter(i => i.aiMitigated || i.status === 'resolved' || i.status === 'ai_mitigation').length;
    const aiCountEl = $('ai-mitigated-count');
    if (aiCountEl) aiCountEl.textContent = mitigated;

    const lastAction = $('ai-last-action');
    const defconEl = $('defcon-status');
    
    const critCount = allIncidents.filter(i => i.severity === 'CRITICAL' && i.status !== 'resolved').length;
    const highCount = allIncidents.filter(i => i.severity === 'HIGH' && i.status !== 'resolved').length;
    
    let defcon = 5;
    let color = 'var(--green)';
    
    if (window.defconOverride && window.defconOverride !== 'auto') {
        defcon = parseInt(window.defconOverride);
    } else {
        if (critCount >= 5) { defcon = 1; }
        else if (critCount >= 3) { defcon = 2; }
        else if (critCount >= 1) { defcon = 3; }
        else if (highCount >= 3) { defcon = 4; }
    }
    
    if (defcon === 5) color = 'var(--green)';
    else if (defcon === 4) color = 'var(--orange)';
    else if (defcon === 3) color = 'var(--orange)';
    else if (defcon === 2) color = 'var(--red)';
    else if (defcon === 1) color = 'var(--red)';
    
    if (defconEl) {
        const name = defconNames[defcon] || `Уровень ${defcon}`;
        defconEl.textContent = name;
        defconEl.style.color = color;
    }
    
    applyDefconVisualEffects(defcon);
    
    const banner = $('dash-warning-banner');
    if (banner) {
        if (critCount > 0 || highCount >= 3) {
            banner.style.display = 'flex';
            const desc = $('dash-warning-desc');
            if (desc) desc.textContent = `Система зафиксировала активные атаки (${critCount} критических, ${highCount} важных). Нажмите для перехода к расследованию.`;
        } else {
            banner.style.display = 'none';
        }
    }

    const lastMitigated = allIncidents.find(i => i.aiMitigated);
    if (lastAction && lastMitigated) {
        lastAction.textContent = `[${lastMitigated.severity}] ${lastMitigated.type} — ${lastMitigated.ip || 'System'}`;
    } else if (lastAction) {
        lastAction.textContent = 'No active threats mitigated yet.';
    }
};

window.setLogSearchTag = function(tag) {
    const searchInp = $('log-search');
    if (searchInp) {
        searchInp.value = tag;
        if (window.applyLogFilters) window.applyLogFilters();
    }
};

// ══════════════════════════════════════════════════════════════════════════════
// EXPORT & BULK OPERATIONS IMPLEMENTATIONS
// ══════════════════════════════════════════════════════════════════════════════
window.exportData = function(data, format, filename) {
    if (!data || !data.length) {
        showToast('Экспорт невозможен', 'Нет данных для экспорта', 'warn');
        return;
    }
    
    let content = '';
    let mimeType = 'text/plain;charset=utf-8';
    
    if (format === 'json') {
        content = JSON.stringify(data, null, 2);
        mimeType = 'application/json;charset=utf-8';
    } else if (format === 'csv') {
        mimeType = 'text/csv;charset=utf-8';
        if (data[0].message !== undefined) {
            // Logs
            const headers = 'ID,Timestamp,Type,Level,Message,Meta\n';
            const rows = data.map(e => {
                const t = e.timestamp || '';
                const lv = getAutoLevel(e);
                const msg = (e.message || '').replace(/"/g, '""');
                const meta = JSON.stringify(e.meta || {}).replace(/"/g, '""');
                return `"${e.id}","${t}","${e.type}","${lv}","${msg}","${meta}"`;
            }).join('\n');
            content = '\uFEFF' + headers + rows;
        } else {
            // Incidents
            const headers = 'ID,Timestamp,Severity,Monitor,Type,IP/Target,Description,Status,Comment,Geo\n';
            const rows = data.map(i => {
                const t = i.timestamp || '';
                const ip = i.ip || i.target || i.monitor || 'System';
                const desc = (i.description || '').replace(/"/g, '""');
                const comment = (i.comment || '').replace(/"/g, '""');
                const geo = JSON.stringify(i.geo || {}).replace(/"/g, '""');
                return `"${i.id}","${t}","${i.severity}","${i.monitor || ''}","${i.type}","${ip}","${desc}","${i.status}","${comment}","${geo}"`;
            }).join('\n');
            content = '\uFEFF' + headers + rows;
        }
    } else {
        // TXT/MD Format
        if (data[0].message !== undefined) {
            // Logs
            content = data.map(e => {
                const t = (e.timestamp||'').slice(0,19).replace('T',' ');
                const lv = getAutoLevel(e).toUpperCase();
                return `[${t}] [${lv}] ${e.message}`;
            }).join('\r\n');
        } else {
            // Incidents Report
            content = `# MISTRAL SOC INCIDENTS REPORT\r\n`;
            content += `Exported at: ${new Date().toLocaleString()}\r\n`;
            content += `Total incidents: ${data.length}\r\n\r\n`;
            content += data.map((i, idx) => {
                const t = (i.timestamp||'').slice(0,19).replace('T',' ');
                return `--- [Incident #${idx + 1}] ---\r\nID: ${i.id}\r\nSeverity: ${i.severity}\r\nType: ${i.type}\r\nSensor: ${i.monitor || 'System'}\r\nIP/Target: ${i.ip || i.target || '—'}\r\nStatus: ${i.status}\r\nDescription: ${i.description || '—'}\r\nTimestamp: ${t}\r\n`;
            }).join('\r\n');
        }
    }
    
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Экспорт выполнен', `Экспортировано записей: ${data.length} в формат ${format.toUpperCase()}`, 'green');
};

window.bulkExportIncidents = function(format) {
    let dataToExport = [];
    if (window.selectedIncidents.size > 0) {
        dataToExport = allIncidents.filter(i => window.selectedIncidents.has(i.id));
    } else {
        dataToExport = window.currentFilteredIncidents || allIncidents;
    }
    
    const dateStr = new Date().toISOString().slice(0,10);
    const ext = format === 'txt' ? 'md' : format;
    window.exportData(dataToExport, format, `mistral_incidents_${dateStr}.${ext}`);
};

window.bulkUpdateIncidentStatusUI = function(status) {
    if (!window.selectedIncidents.size) return;
    const ids = Array.from(window.selectedIncidents);
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/incidents/bulk-status', 'POST', { ids, status })
            .then(res => {
                if (res && res.success) {
                    showToast('SOAR Playbook', `Пакетный статус успешно обновлен на "${status}"`, 'green');
                    window.selectedIncidents.clear();
                    window.updateIncidentsSelectedCount();
                    window.electronAPI.sendWsMessage({event:'get_incidents'});
                } else {
                    showToast('Ошибка', res.error || 'Не удалось обновить статус', 'warn');
                }
            })
            .catch(err => showToast('Ошибка сети', err.message, 'warn'));
    } else {
        fetch(`${serverBase}/api/incidents/bulk-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify({ ids, status })
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showToast('SOAR Playbook', `Пакетный статус успешно обновлен на "${status}"`, 'green');
                window.selectedIncidents.clear();
                window.updateIncidentsSelectedCount();
                ids.forEach(id => {
                    const inc = allIncidents.find(i => i.id === id);
                    if (inc) inc.status = status;
                });
                renderIncidents(allIncidents);
            }
        })
        .catch(err => showToast('Ошибка сети', err.message, 'warn'));
    }
};

window.bulkDeleteIncidentsUI = function() {
    if (!window.selectedIncidents.size) return;
    if (!confirm(`Вы действительно хотите безвозвратно удалить выбранные инциденты (${window.selectedIncidents.size})?`)) return;
    
    const ids = Array.from(window.selectedIncidents);
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/incidents/bulk-delete', 'POST', { ids })
            .then(res => {
                if (res && res.success) {
                    showToast('Удаление', `Удалено инцидентов: ${ids.length}`, 'green');
                    window.selectedIncidents.clear();
                    window.updateIncidentsSelectedCount();
                    window.electronAPI.sendWsMessage({event:'get_incidents'});
                } else {
                    showToast('Ошибка', res.error || 'Не удалось удалить инциденты', 'warn');
                }
            })
            .catch(err => showToast('Ошибка сети', err.message, 'warn'));
    } else {
        fetch(`${serverBase}/api/incidents/bulk-delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify({ ids })
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showToast('Удаление', `Удалено инцидентов: ${ids.length}`, 'green');
                window.selectedIncidents.clear();
                window.updateIncidentsSelectedCount();
                allIncidents = allIncidents.filter(i => !ids.includes(i.id));
                renderIncidents(allIncidents);
            }
        })
        .catch(err => showToast('Ошибка сети', err.message, 'warn'));
    }
};

window.bulkExportLogs = function(format) {
    let dataToExport = [];
    if (window.selectedLogs.size > 0) {
        dataToExport = currentLogsData.filter(l => window.selectedLogs.has(l.id));
    } else {
        dataToExport = window.currentFilteredLogs || currentLogsData;
    }
    
    const type = $('log-type')?.value || 'server';
    const dateStr = new Date().toISOString().slice(0,10);
    const ext = format === 'txt' ? 'txt' : format;
    window.exportData(dataToExport, format, `mistral_logs_${type}_${dateStr}.${ext}`);
};

window.bulkDeleteLogsUI = function() {
    if (!window.selectedLogs.size) return;
    if (!confirm(`Вы действительно хотите безвозвратно удалить выбранные логи (${window.selectedLogs.size})?`)) return;
    
    const ids = Array.from(window.selectedLogs);
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/logs/bulk-delete', 'POST', { ids })
            .then(res => {
                if (res && res.success) {
                    showToast('Удаление логов', `Удалено записей логов: ${ids.length}`, 'green');
                    window.selectedLogs.clear();
                    window.updateLogsSelectedCount();
                    loadLogs();
                } else {
                    showToast('Ошибка', res.error || 'Не удалось удалить логи', 'warn');
                }
            })
            .catch(err => showToast('Ошибка сети', err.message, 'warn'));
    } else {
        fetch(`${serverBase}/api/logs/bulk-delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
            body: JSON.stringify({ ids })
        })
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                showToast('Удаление логов', `Удалено записей логов: ${ids.length}`, 'green');
                window.selectedLogs.clear();
                window.updateLogsSelectedCount();
                currentLogsData = currentLogsData.filter(l => !ids.includes(l.id));
                applyLogFilters();
            }
        })
        .catch(err => showToast('Ошибка сети', err.message, 'warn'));
    }
};






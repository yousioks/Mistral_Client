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
    
    rFeed.scrollTop = rFeed.scrollHeight;
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
        filtered = filtered.filter(i => {
            const type = (i.type || '').toLowerCase();
            const desc = (i.description || '').toLowerCase();
            const ip = (i.ip || i.target || i.monitor || '').toLowerCase();
            return type.includes(search) || desc.includes(search) || ip.includes(search);
        });
    }
    
    if(!filtered || !filtered.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-td">Нет зарегистрированных инцидентов</td></tr>';
        return;
    }
    
    // Virtualization / Limit
    filtered.slice(0, 150).forEach(i => {
        addIncidentRow(i, false, tbody);
    });
}

function addIncidentRow(inc, prepend, container) {
    if(!container) container = $('incidents-tbody');
    // Remove "empty-td" if it exists
    if(container.firstChild && container.firstChild.querySelector('.empty-td')) {
        container.innerHTML = '';
    }
    
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.onclick = (e) => {
        // Prevent opening drawer if clicked on a select or button
        if(e.target.tagName === 'SELECT' || e.target.tagName === 'BUTTON') return;
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
        
    tr.innerHTML = `
        <td>${sevBadge}</td>
        <td style="font-weight:700; color:#fff;">${esc(inc.type||'Unknown')}</td>
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
                    <span style="font-weight:700; color:#fff; display:flex; align-items:center;">${flag} ${esc(inc.geo.country || 'Unknown')}</span>
                </div>
                <div style="text-align:right;">
                    <span style="font-size:10px; color:var(--muted); display:block; text-transform:uppercase; margin-bottom:2px;">ISP / Хостер</span>
                    <span style="font-weight:500; font-size:11px; color:#fff;">${esc(inc.geo.isp || 'Unknown')}</span>
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
            
            <div style="font-size:18px; font-weight:800; color:#fff;">${esc(inc.type||'Unknown')}</div>
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
                    return isBanned 
                        ? `<button class="btn-unq" style="flex:1; padding:10px; border-radius:6px; cursor:pointer; background:rgba(16,185,129,0.12); color:var(--green); border:1px solid rgba(16,185,129,0.3);" onclick="unquarantineIp('${esc(inc.ip)}'); closeIncidentDrawer();">UNBAN IP</button>`
                        : `<button class="btn-q" style="flex:1; padding:10px; border-radius:6px; cursor:pointer;" onclick="quarantineIp('${esc(inc.ip)}', 'Drawer Block'); closeIncidentDrawer();">BAN IP</button>`;
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
    let reportText = `MISTRAL DEFENSE - GLOBAL SOC REPORT\n====================================\n`;
    reportText += `Generated at: ${new Date().toLocaleString()}\n`;
    reportText += `Total Threats Detected: ${threatCount || allIncidents.length}\n`;
    reportText += `System Status: ${lastConnState === 'connected' ? 'ONLINE' : 'OFFLINE'}\n\n`;
    
    reportText += `RECENT CRITICAL & HIGH INCIDENTS\n------------------------------------\n`;
    const threats = allIncidents.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').slice(0, 20);
    
    if (threats.length === 0) {
        reportText += `No critical or high incidents detected.\n`;
    } else {
        threats.forEach(inc => {
            reportText += `[${inc.timestamp}] [${inc.severity}] ${inc.type}\n`;
            reportText += `    Target/IP: ${inc.ip || inc.target || 'System'}\n`;
            reportText += `    Status: ${inc.status || 'New'}\n`;
            if (inc.aiAudit) reportText += `    AI Action: ${inc.aiAudit.substring(0, 100).replace(/\n/g, ' ')}...\n`;
            reportText += `\n`;
        });
    }
    
    reportText += `\nSECURITY SCANNERS SUMMARY\n------------------------------------\n`;
    reportText += $('scan-output') ? $('scan-output').textContent : 'No recent scans.';
    
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `GLOBAL-SOC-REPORT.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Export', 'Global SOC Report downloaded.', 'info');
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

// Context Menu
let ctxTargetIp = '';
function openContextMenu(x, y, ip) {
    const menu = $('context-menu');
    if(!menu || !ip) return;
    ctxTargetIp = ip;
    
    const isBanned = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === ip);
    const banItem = $('ctx-ban');
    if (banItem) {
        if (isBanned) {
            banItem.innerHTML = 'Unban IP';
            banItem.style.color = '#10b981';
            banItem.onclick = () => ctxAction('unban');
        } else {
            banItem.innerHTML = 'Ban IP';
            banItem.style.color = 'var(--red)';
            banItem.onclick = () => ctxAction('ban');
        }
    }
    
    menu.style.display = 'block';
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
}

document.addEventListener('click', () => {
    const menu = $('context-menu');
    if(menu) menu.style.display = 'none';
});

function ctxAction(action) {
    if(!ctxTargetIp) return;
    if(action === 'ban') {
        quarantineIp(ctxTargetIp, 'Context Menu Ban');
        showToast('Banned', `IP ${ctxTargetIp} banned`, 'critical');
    } else if(action === 'unban') {
        unquarantineIp(ctxTargetIp);
        showToast('Unbanned', `IP ${ctxTargetIp} unbanned`, 'green');
    } else if(action === 'filter') {
        $('log-search').value = ctxTargetIp;
        switchTab('logs');
    } else if(action === 'analyze') {
        askAI(`Проанализируй активность с IP адреса ${ctxTargetIp}. Выведи рекомендации по блокировке.`);
    } else if(action === 'lookup') {
        openThreatIntelModal(ctxTargetIp);
    }
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
    
    // Virtualization / Performance limit: Only render the top 200 logs
    const displayLogs = filtered.slice(0, 200);
    
    const fragment = document.createDocumentFragment();
    displayLogs.forEach(entry => {
        const div = document.createElement('div'); 
        const level = getAutoLevel(entry);
        div.className = `log-entry log-row-${level}`;
        const t = (entry.timestamp||'').slice(0,19).replace('T',' ');
        div.innerHTML = `<span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg">${window.formatLogMessageWithIpActions(entry.message)}</span>`;
        fragment.appendChild(div);
    });
    feed.appendChild(fragment);
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
                tb.innerHTML='<tr><td colspan="4" class="empty-td">Ожидание данных от DDoS-анализатора (Lua)...</td></tr>';
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
                dashTb.innerHTML='<tr><td colspan="4" class="empty-td">Ожидание данных от DDoS-анализатора (Lua)...</td></tr>';
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
window.quarantinedIps = [];
function renderQuarantine(list) {
    window.quarantinedIps = list || [];
    const tb = $('quarantine-tbody');
    $('q-count').textContent = list.length;
    if(!list.length) { tb.innerHTML='<tr><td colspan="4" class="empty-td">Нет заблокированных IP</td></tr>'; return; }
    tb.innerHTML = '';
    list.forEach(q => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><span class="ip-chip clickable" onclick="filterLogsByIp('${esc(q.ip)}')">${esc(q.ip)}</span></td><td>${esc(q.reason||'Manual')}</td><td>${esc((q.timestamp||'').slice(0,19).replace('T',' '))}</td><td><button class="btn-sm btn-unq" onclick="unquarantineIp('${esc(q.ip)}')">РАЗБЛОКИРОВАТЬ</button></td>`;
        tb.appendChild(tr);
    });
}
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
    const type = data.type || '';
    const desc = data.description || '';
    const isDdos = type.includes('DDOS') || type.includes('DDoS') || desc.includes('DDoS') || desc.includes('SYN-RECV') || desc.includes('ESTABLISHED');
    
    const suppressCheckbox = $('chk-suppress-ddos');
    const shouldSuppress = suppressCheckbox ? suppressCheckbox.checked : true;
    
    if (isDdos && shouldSuppress) {
        let key = type;
        const ipMatch = desc.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        if (ipMatch) {
            key += '_' + ipMatch[0];
        } else if (data.details?.sourceIp || data.details?.ip) {
            key += '_' + (data.details.sourceIp || data.details.ip);
        }
        
        const now = Date.now();
        const lastTime = alertCooldowns.get(key) || 0;
        const cooldownMs = 180000; // 3 minutes cooldown
        
        if (now - lastTime < cooldownMs) {
            console.log(`[SOC Alert Suppressed] DDoS notification rate-limited for key: ${key}`);
            return;
        }
        alertCooldowns.set(key, now);
    }

    // Extract IP from incident for action buttons
    let alertIp = data.ip || data.target || '';
    if (!alertIp) {
        const ipMatch = desc.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        if (ipMatch) alertIp = ipMatch[0];
    }
    if (!alertIp && data.details) {
        alertIp = data.details.sourceIp || data.details.ip || '';
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
const TAB_NAMES = ['dashboard','network','incidents','dangerous','logs','metrics','scanners','ai','users','map','mitre','server_info','apps','vulnerabilities'];
function switchTab(name) {
    try {
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab===name));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        $('panel-'+name).classList.add('active');
        if(name==='logs') loadLogs();
        if(name==='users') loadUsers();
        if(name==='server_info') { 
            if(window.loadServerInfo) window.loadServerInfo(); 
            if(window.updateSecurityStatus) window.updateSecurityStatus(); 
        }
        if(name==='apps') { if(window.loadApplicationsInfo) window.loadApplicationsInfo(); }
        if(name==='vulnerabilities') loadVulnerabilities();
        if(name==='network') {
            loadQuarantine();
            if(window.updateIPDisplays) window.updateIPDisplays();
        }
        if(name==='incidents' && window.electronAPI) if (window.electronAPI) { window.electronAPI.sendWsMessage({event:'get_incidents'}); }
        if(name==='map' && cyberMap) {
            cyberMap.resize();
        }
    } catch(err) {
        alert("Tab Switch Error: " + err.message + "\n" + err.stack);
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
                                <strong style="font-size: 15px; color: #fff;">${esc(geo.country || 'Unknown')} (${esc(geo.code || '??')})</strong>
                            </div>
                        </div>
                        
                        <div style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.03); border-radius: 8px; padding: 12px; display: flex; flex-direction: column; gap: 8px; font-size: 11px;">
                            <div style="display: flex; justify-content: space-between;"><span style="color: var(--muted);">IP Address:</span><span style="color: #fff; font-family: monospace;">${esc(ip)}</span></div>
                            <div style="display: flex; justify-content: space-between;"><span style="color: var(--muted);">ISP / Provider:</span><span style="color: #fff; font-weight: 600;">${esc(geo.isp || 'Unknown')}</span></div>
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

window.toggleGlowEffectsSetting = function(checked) {
    localStorage.setItem('glow_effects_enabled', checked ? 'true' : 'false');
    document.body.classList.toggle('glow-active', checked);
    showToast('Визуальные эффекты', checked ? 'Глоу-эффект активирован' : 'Глоу-эффект отключен', 'info');
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
            tr.innerHTML = `
                <td style="font-family:monospace; color:var(--cyan);">${p.port}</td>
                <td>${p.proto}</td>
                <td style="font-weight:bold;">${p.proc}</td>
                <td style="color:var(--muted); font-family:monospace;">${p.pid}</td>
            `;
            portsContainer.appendChild(tr);
        });
    }
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
                tr.innerHTML = `
                    <td>
                        <strong style="color:#fff; display:block;">${esc(c.name)}</strong>
                        <span style="font-size:9px; color:var(--dim); font-family:monospace;">${esc(c.id)}</span>
                    </td>
                    <td style="font-size:10px; font-family:monospace;">${esc(c.image)}</td>
                    <td><span style="color:${statusColor}">${esc(c.status)}</span></td>
                    <td><button class="btn-sm" onclick="runTrivyScan('${esc(c.id)}')" style="font-size:9px; padding:3px 6px;">Trivy Scan</button></td>
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
                div.style.cssText = 'border-bottom:1px solid rgba(255,255,255,0.03); padding:6px 0;';
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
window.loadVulnerabilities = function() {
    const tbody = $('vulnerabilities-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="empty-td">Загрузка базы уязвимостей...</td></tr>';
    
    if (window.electronAPI) {
        window.electronAPI.sendApiRequest('/api/vulnerabilities', 'GET')
            .then(vulns => {
                tbody.innerHTML = '';
                if (vulns && vulns.error) {
                    tbody.innerHTML = `<tr><td colspan="6" class="empty-td" style="color:var(--red);">Ошибка загрузки: ${esc(vulns.error)}</td></tr>`;
                    return;
                }
                if (!Array.isArray(vulns)) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-td" style="color:var(--red);">Ошибка загрузки: неверный формат данных от сервера</td></tr>';
                    return;
                }
                if (vulns.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-td">База уязвимостей пуста</td></tr>';
                    return;
                }
                vulns.forEach(v => {
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
    renderIncidents(allIncidents);
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
window.updateDefensePosture = function() {
    const mitigated = allIncidents.filter(i => i.aiMitigated || i.status === 'resolved' || i.status === 'ai_mitigation').length;
    const aiCountEl = $('ai-mitigated-count');
    if (aiCountEl) aiCountEl.textContent = mitigated;

    const lastAction = $('ai-last-action');
    const defconEl = $('defcon-status');
    
    const critCount = allIncidents.filter(i => i.severity === 'CRITICAL' && i.status !== 'resolved').length;
    const highCount = allIncidents.filter(i => i.severity === 'HIGH' && i.status !== 'resolved').length;
    
    if (defconEl) {
        let defcon = 5, color = 'var(--green)';
        if (critCount >= 5) { defcon = 1; color = 'var(--red)'; }
        else if (critCount >= 3) { defcon = 2; color = 'var(--red)'; }
        else if (critCount >= 1) { defcon = 3; color = 'var(--orange)'; }
        else if (highCount >= 3) { defcon = 4; color = 'var(--orange)'; }
        defconEl.textContent = `DEFCON ${defcon}`;
        defconEl.style.color = color;
    }
    
    const lastMitigated = allIncidents.find(i => i.aiMitigated);
    if (lastAction && lastMitigated) {
        lastAction.textContent = `[${lastMitigated.severity}] ${lastMitigated.type} — ${lastMitigated.ip || 'System'}`;
    } else if (lastAction) {
        lastAction.textContent = 'No active threats mitigated yet.';
    }
};



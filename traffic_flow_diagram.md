# Блок-схема потоков трафика — Mistral SOC

> Этот документ описывает **откуда поступает трафик**, **как он проходит через каждый компонент** и **как принимаются решения по реагированию**.

---

## 1. Общая карта потоков трафика

```mermaid
flowchart TD
    INET["🌐 Интернет / Злоумышленник\nВнешний HTTP/HTTPS трафик"]
    DEMO["🔴 Mistral Demo\nСимулятор атак (Python)\nSSH Brute / SQLi / DDoS / Port Scan / Ransomware"]

    INET --> WAF
    DEMO --> WAF
    DEMO -->|"SSH :22"| HOST_SSH["🔐 SSH-демон хоста\n(порт 22)"]

    subgraph TARGET_HOST["🖥️ Целевой хост — Remon (Docker)"]
        WAF["🛡️ WAF: OpenResty / Nginx\nПорт 80 / 443\nLua-скрипты фильтрации"]
        FRONTEND["📄 Frontend\nNext.js — порт 3000"]
        BACKEND["⚙️ Backend API\nNode.js/Express — порт 5000"]
        PGDB[("🗄️ PostgreSQL\nБаза данных Remon")]
        WAF -->|"Разрешённый трафик"| FRONTEND
        FRONTEND -->|"API вызовы"| BACKEND
        BACKEND <-->|"SQL запросы"| PGDB
    end

    subgraph HOST_OS["🐧 ОС Хоста (Linux)"]
        AUTH_LOG["📋 /var/log/auth.log\nSSH события"]
        PROC_LIST["📊 /proc — процессы\nps aux"]
        NET_SOCKS["🔌 Сетевые сокеты\nss -tnp / netstat"]
        FS_FILES["📁 Файловая система\n/etc/passwd, crontab и др."]

        LUA_AUTH["🔍 monitor_auth.lua\nМониторинг SSH попыток"]
        LUA_PROC["🔍 monitor_system.lua\nНесанкционированные процессы"]
        LUA_NET["🔍 monitor_network.lua\nАномалии портов/соединений"]
        LUA_INTEG["🔍 monitor_integrity.lua\nЦелостность файлов"]
        LUA_SEC["🔍 monitor_sec_tools.lua\nСтатус UFW / Fail2ban"]

        AUTH_LOG --> LUA_AUTH
        PROC_LIST --> LUA_PROC
        NET_SOCKS --> LUA_NET
        FS_FILES --> LUA_INTEG
        LUA_SEC
    end

    HOST_SSH --> AUTH_LOG

    WAF -->|"POST /api/attack-detected\n{ip, type, payload, severity}"| MISTRAL_SRV
    LUA_AUTH -->|"POST /api/logs\n{source: auth, level, message}"| MISTRAL_SRV
    LUA_PROC -->|"POST /api/logs\n{source: system, process}"| MISTRAL_SRV
    LUA_NET -->|"POST /api/logs\n{source: network}"| MISTRAL_SRV
    LUA_INTEG -->|"POST /api/logs\n{source: integrity}"| MISTRAL_SRV
    LUA_SEC -->|"POST /api/logs\n{source: sec_tools}"| MISTRAL_SRV

    subgraph MISTRAL_SERVER["🧠 Mistral Server — SOC Core (Node.js :3000)"]
        SRV_RECV["📥 Приём событий\nREST API Endpoint'ы"]
        SRV_PARSE["🔄 Парсинг и нормализация\naddLog() / addIncident()"]
        SRV_DB[("💾 SQLite — mistral.db\nlogs / incidents / cve_logs")]
        SRV_DEFCON["⚠️ Расчёт DEFCON\nИндекс уровня угрозы 1-5"]
        SRV_SOAR["🤖 SOAR-движок\nАвтоматическое реагирование"]
        SRV_AI["🧠 LLM ИИ-Агент\nАнализ инцидентов"]
        SRV_WS["📡 WebSocket Broadcaster\nРеальное время → Client"]
        SRV_TG["📱 Telegram Bot\nОповещение оператора"]
        SRV_UFW["🔥 UFW / iptables\nБлокировка IP"]

        SRV_RECV --> SRV_PARSE
        SRV_PARSE --> SRV_DB
        SRV_PARSE --> SRV_DEFCON
        SRV_DEFCON --> SRV_SOAR
        SRV_SOAR --> SRV_AI
        SRV_SOAR --> SRV_UFW
        SRV_DB --> SRV_WS
        SRV_DEFCON --> SRV_WS
        SRV_AI --> SRV_TG
        SRV_AI --> SRV_WS
    end

    MISTRAL_SRV["MISTRAL_SERVER"]

    SRV_AI -->|"AITunnel REST API\nContextual prompt"| AI_TUNNEL["☁️ AITunnel API Gateway"]
    AI_TUNNEL -->|"Response"| LLM["🤖 LLM\nDeepSeek / Kimi / Claude"]
    LLM --> AI_TUNNEL

    SRV_WS -->|"WS/REST: события, метрики, CVE, инциденты"| CLIENT["💻 Mistral Client\nElectron — Панель оператора"]
    CLIENT -->|"REST: бан IP, настройки SOAR, запуск аудита"| SRV_RECV
    SRV_TG --> OPERATOR["👤 ИБ-Аналитик\nTelegram"]

    style INET fill:#ff4444,color:#fff
    style DEMO fill:#cc2200,color:#fff
    style WAF fill:#ff8800,color:#fff
    style MISTRAL_SERVER fill:#1a1a2e,color:#fff
    style CLIENT fill:#16213e,color:#fff
    style AI_TUNNEL fill:#0f3460,color:#fff
```

---

## 2. Детальная блок-схема: Жизненный цикл одного события атаки

```mermaid
sequenceDiagram
    participant ATK as 🔴 Атакующий
    participant WAF as 🛡️ OpenResty WAF
    participant LUA as 📜 Lua-скрипт (waf.lua)
    participant SRV as 🧠 Mistral Server
    participant DB  as 💾 SQLite DB
    participant AI  as 🤖 ИИ-Агент (LLM)
    participant UFW as 🔥 UFW Firewall
    participant WS  as 📡 WebSocket
    participant CLI as 💻 Mistral Client
    participant TG  as 📱 Telegram

    ATK->>WAF: HTTP GET /api/items?id=1 OR 1=1--
    WAF->>LUA: Передача запроса Lua-хуку
    LUA->>LUA: Поиск паттернов SQLi/XSS<br/>в URI, заголовках, теле
    alt Угроза обнаружена
        LUA->>ATK: HTTP 403 Forbidden
        LUA->>SRV: POST /api/attack-detected<br/>{ip, type:"sqli", payload, severity:"HIGH"}
        SRV->>DB: addLog("attack", "error", ...) → INSERT
        SRV->>DB: addIncident("HIGH", "WAF", "SQLI_ATTACK", ...)
        SRV->>SRV: updateDefconLevel() → пересчёт DEFCON
        SRV->>WS: broadcast({event:"log", data:{...}})
        WS->>CLI: Обновление таблицы логов в реальном времени
        WS->>CLI: Обновление счётчика инцидентов
        SRV->>SRV: checkAutoBlock(ip) → превышен порог?
        alt Порог блокировки превышен
            SRV->>UFW: sudo ufw insert 1 deny from {ip}
            UFW-->>SRV: OK
            SRV->>WS: broadcast({event:"ip_banned", ip:...})
            WS->>CLI: 🚫 Плашка BAN IP на клиенте
        end
        SRV->>SRV: shouldTriggerAI(incident)? → проверка настроек SOAR
        alt ИИ должен сработать
            SRV->>AI: POST AITunnel /v1/chat<br/>{system, context, incident_details}
            AI-->>SRV: {analysis, mitigation_steps, verdict}
            SRV->>DB: Сохранение ИИ-отчёта
            SRV->>WS: broadcast({event:"ai_response", report:...})
            WS->>CLI: Панель ИИ-анализа с шагами выполнения
            SRV->>TG: sendMessage("🚨 КРИТИЧНЫЙ ИНЦИДЕНТ\n[IP] [тип] [вердикт ИИ]")
        end
    else Запрос легитимен
        LUA->>WAF: pass_to_upstream()
        WAF->>ATK: Ответ от Remon Backend
    end
```

---

## 3. Потоки системной телеметрии с хоста

```mermaid
flowchart LR
    subgraph OS_SOURCES["Источники данных ОС"]
        A1["/var/log/auth.log"]
        A2["/proc/&lt;pid&gt;/..."]
        A3["ss -tnp"]
        A4["/etc/passwd\n/etc/crontab"]
        A5["systemctl status\nufw status"]
    end

    subgraph LUA_MONITORS["Lua-зонды (каждые N секунд)"]
        B1["monitor_auth.lua\n→ SSH brute-force детектор"]
        B2["monitor_system.lua\n→ Чёрный список процессов"]
        B3["monitor_network.lua\n→ Аномалии портов"]
        B4["monitor_integrity.lua\n→ Изменения конфигов"]
        B5["monitor_sec_tools.lua\n→ Статус защиты"]
    end

    subgraph SERVER_PROCESSING["Mistral Server обработка"]
        C1["POST /api/logs\nпарсинг payload"]
        C2["addLog() → SQLite"]
        C3["Анализ: порог?"]
        C4["addIncident() → HIGH/MEDIUM"]
        C5["WebSocket broadcast"]
    end

    A1 --> B1
    A2 --> B2
    A3 --> B3
    A4 --> B4
    A5 --> B5

    B1 -->|"HTTP POST"| C1
    B2 -->|"HTTP POST"| C1
    B3 -->|"HTTP POST"| C1
    B4 -->|"HTTP POST"| C1
    B5 -->|"HTTP POST"| C1

    C1 --> C2
    C2 --> C3
    C3 -->|"Порог превышен"| C4
    C4 --> C5
    C3 -->|"Норма"| C5
```

---

## 4. Блок-схема принятия решений SOAR

```mermaid
flowchart TD
    START(["📥 Входящее событие / инцидент"])
    CHECK_WL{"🔍 IP в белом\nсписке CIDR?"}
    CHECK_SSH{"🔐 IP — активная\nSSH-сессия админа?"}
    CHECK_THRESH{"📊 Превышен порог\nавтоблокировки?"}
    CHECK_AI_ON{"🤖 Авто-ИИ\nвключён?"}
    CHECK_CRITICAL{"⚡ Критический\nтип атаки?"}
    CHECK_AI_TYPE{"☑️ Тип атаки\nвыбран в настройках SOAR?"}

    BAN["🔥 sudo ufw insert 1\ndeny from {IP}\n→ Блокировка"]
    SKIP["⏭️ Пропуск\n(защита от lockout)"]
    LOG_ONLY["📝 Только логирование\nв SQLite + WebSocket"]
    TRIGGER_AI["🧠 Запрос к LLM\nчерез AITunnel"]
    APPLY_AUTO["⚙️ Автоприменение\nмитигации на ОС"]
    SHOW_GUIDE["📋 Показ гайда\nоператору в UI"]
    NOTIFY_TG["📱 Telegram-алерт\nоператору"]
    BROADCAST["📡 WebSocket\nbroadcast → Client"]

    START --> CHECK_WL
    CHECK_WL -->|"ДА — доверенный IP"| SKIP
    CHECK_WL -->|"НЕТ"| CHECK_SSH
    CHECK_SSH -->|"ДА — SSH-сессия"| SKIP
    CHECK_SSH -->|"НЕТ"| CHECK_THRESH
    CHECK_THRESH -->|"НЕТ"| LOG_ONLY
    CHECK_THRESH -->|"ДА"| BAN
    BAN --> CHECK_AI_ON
    LOG_ONLY --> CHECK_AI_ON
    CHECK_AI_ON -->|"ВКЛ"| CHECK_AI_TYPE
    CHECK_AI_ON -->|"ВЫКЛ"| CHECK_CRITICAL
    CHECK_CRITICAL -->|"ДА — критический вектор\n(SQLI/SSH/PrivEsc/...)"| TRIGGER_AI
    CHECK_CRITICAL -->|"НЕТ"| BROADCAST
    CHECK_AI_TYPE -->|"Тип выбран"| TRIGGER_AI
    CHECK_AI_TYPE -->|"Тип не выбран"| BROADCAST
    TRIGGER_AI --> NOTIFY_TG
    TRIGGER_AI --> SHOW_GUIDE
    TRIGGER_AI -->|"Автономный режим"| APPLY_AUTO
    SHOW_GUIDE --> BROADCAST
    APPLY_AUTO --> BROADCAST
    NOTIFY_TG --> BROADCAST

    style BAN fill:#cc0000,color:#fff
    style TRIGGER_AI fill:#0055aa,color:#fff
    style SKIP fill:#006600,color:#fff
    style APPLY_AUTO fill:#884400,color:#fff
```

---

## 5. Сетевые порты и протоколы

| Компонент | Порт | Протокол | Направление | Описание |
|---|---|---|---|---|
| OpenResty WAF (Remon) | **80 / 443** | HTTP/HTTPS | ← Внешний трафик | Точка входа всего трафика к Remon |
| Remon Frontend | **3000** | HTTP (internal) | WAF → Frontend | Next.js внутри Docker |
| Remon Backend | **5000** | HTTP (internal) | Frontend → Backend | Node.js/Express REST API |
| PostgreSQL | **5432** | TCP | Backend → DB | База данных Remon |
| Mistral Server | **3000** | HTTP + WS | Lua/WAF/Client → Server | Основной API и WebSocket SOC |
| SSH-демон | **22** | TCP | Атака / Администратор | Мониторится monitor_auth.lua |
| Telegram API | **443** | HTTPS | Server → Telegram | Вебхук оповещений |
| AITunnel API | **443** | HTTPS | Server → Cloud | Запросы к LLM |

---

## 6. Откуда берётся каждый тип лога в интерфейсе Mistral Client

```mermaid
flowchart LR
    subgraph SOURCES["Источники"]
        S1["🌐 WAF (OpenResty Lua)"]
        S2["🔍 monitor_auth.lua"]
        S3["🔍 monitor_system.lua"]
        S4["🔍 monitor_network.lua"]
        S5["🔍 monitor_integrity.lua"]
        S6["🔍 monitor_sec_tools.lua"]
        S7["🤖 ИИ-Агент (LLM)"]
        S8["🔎 Trivy / Semgrep"]
        S9["🐳 Docker Scanner"]
        S10["⚙️ Server Internal Events"]
    end

    subgraph LOG_TABS["Вкладки в интерфейсе"]
        T1["📋 Logs → 'attack'\nАтаки WAF"]
        T2["📋 Logs → 'auth'\nSSH события"]
        T3["📋 Logs → 'system'\nПроцессы ОС"]
        T4["📋 Logs → 'network'\nСетевые аномалии"]
        T5["📋 Logs → 'integrity'\nЦелостность файлов"]
        T6["📋 Logs → 'server'\nСобытия сервера"]
        T7["🛡️ CVE Logs\nУязвимости"]
        T8["🚨 Incidents\nТаблица инцидентов"]
        T9["📊 Dashboard\nDEFCON, метрики"]
    end

    S1 --> T1
    S1 --> T8
    S2 --> T2
    S2 --> T8
    S3 --> T3
    S3 --> T8
    S4 --> T4
    S4 --> T8
    S5 --> T5
    S6 --> T6
    S7 --> T8
    S8 --> T7
    S9 --> T7
    S10 --> T6
    T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8 --> T9
```

---

*Документ сгенерирован для дипломной работы. Версия системы: Mistral SOC v1.4.0*

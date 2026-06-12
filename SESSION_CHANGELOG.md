# MISTRAL DEFENSE — ПОЛНАЯ ДОКУМЕНТАЦИЯ ПРОЕКТА
> Последнее обновление: 2026-06-12 | Статус: актуально | Автор: ИИ-Агент

---

## 🗂️ СТРУКТУРА ПРОЕКТА

```
Диплом/
├── Mistral Server/          — Серверный агент SIEM/SOAR (Node.js, Ubuntu)
├── Mistral Сlient/          — Десктоп-клиент SOC (Electron, Windows)
├── Remon/                   — Защищаемый веб-сайт (Next.js + Express + PostgreSQL)
├── Mistral Demo/            — Симулятор атак для демонстрации (Python)
├── VKR/                     — Материалы для выпускной квалификационной работы
└── SESSION_CHANGELOG.md     — Данный файл
```

---

## 📁 MISTRAL SERVER

**Путь:** `Mistral Server/`  
**Стек:** Node.js ≥ 18, better-sqlite3, ws, express, winston, helmet, openai, bcryptjs, uuid  
**Платформа:** Ubuntu/Debian (Linux), Docker  
**Назначение:** Центральный сервер безопасности — REST API, WebSocket-хаб, SOAR-движок, SIEM-аналитика.

---

### `src/server.js` — 3383 строки — ОСНОВНОЙ МОДУЛЬ

Центральный файл всей системы. Содержит:

#### Инициализация и конфигурация
- Загрузка `.env` переменных: `WSS_SECRET_TOKEN`, `API_PORT` (8080), `WSS_PORT` (8443), `AI_API_KEY`, `TELEGRAM_BOT_TOKEN`
- Инициализация `better-sqlite3` с WAL-режимом
- Настройка `winston` логирования с DailyRotateFile (14 дней ротации)
- Подключение Express с `helmet`, `cors`, rate-limiting (`apiRateLimiter`)
- Поддержка HTTPS/WSS через OpenSSL самоподписанные сертификаты

#### AI-подсистема
- `MODELS` — словарь поддерживаемых моделей: `deepseek-v4-pro`, `gpt-4o`, `claude-3-5-sonnet`, `gemini-2.0-flash`
- `askAI(model, messages, temperature)` — единая функция вызова LLM через OpenAI-совместимое API
- `AI_SAFETY_RULES` — системный промпт с ограничениями: запрет деструктивных команд, ответы только на русском
- `sanitizeAIInput(text)` — защита от prompt-injection (проверка на ключевые слова взлома)
- `activeModel` — текущая активная модель (переключается через WS `switch_model`)

#### Менеджмент инцидентов и логов
- `addIncident(severity, monitor, type, description, details)` — создание инцидента с UUID, геолокацией (mock GeoIP), автоматическим SOAR-ответом
  - Severity уровни: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
  - Автоматический AI-анализ при `severity=CRITICAL` и включённом `aiDefenseEnabled`
  - Автобан IP при DDoS/BruteForce атаках через `banIpInSystem()`
- `addLog(type, level, message, meta)` — запись лога типов `server`, `bot`, `cve`
- `incidents[]`, `serverLogs[]`, `botLogs[]`, `cveLogs[]` — in-memory кэши (до 2000 записей)
- Сохранение инцидентов/логов в SQLite через `db.addIncident()`, `db.addLog()`

#### SOAR (Security Orchestration, Automation and Response)
- `soarSettings` — объект конфигурации:
  - `autoBanDdos` (bool) — автобан при DDoS
  - `autoBanBruteForce` (bool) — автобан при брутфорсе
  - `aiDefenseEnabled` (bool) — включение ИИ-агента
  - `aiMakeChanges` (bool) — разрешение ИИ выполнять команды
  - `aiModel` (string) — модель для автозащиты
  - `aiThreatThreshold` (int) — порог инцидентов для триггера ИИ
  - `aiTriggerOnLeaks` / `aiTriggerOnCritical` (bool)
- `saveSoarSettings()` / `loadSoarSettings()` — персистентность в `data/soar_settings.json`
- `ActiveDefenseEngine` — класс активной защиты:
  - `triggerAutoDefense(incident)` — запуск ИИ-анализа для CRITICAL инцидентов
  - Поиск `[AUTOBAN: ip]` паттерна в ответе ИИ → автоматический бан
- `ThreatIntelWatchdog` — watchdog для проверки IP из threat-intel базы (`data/threat_intel_ips.json`)
  - Запускается каждые 30 минут
  - При совпадении активного соединения с известным C2/Tor → `MALICIOUS_C2_CONNECTION_DETECTED`

#### Система карантина и блокировки IP
- `banIpInSystem(ip, reason)` — блокировка IP:
  - Проверка whitelist (SSH-операторы + ручной список)
  - `db.addQuarantineIp(ip, reason)` — запись в SQLite
  - `sudo ufw insert 1 deny from <ip>` (Linux)
  - `sudo fail2ban-client set sshd banip <ip>` (Linux)
  - Broadcast `quarantine_updated` по WebSocket
- `unbanIpInSystem(ip)` — разблокировка:
  - `sudo ufw delete deny from <ip>`
  - `sudo fail2ban-client set sshd unbanip <ip>`
  - `db.removeQuarantineIp(ip)`
- `WhitelistManager` — управление белым списком:
  - Автоматическое добавление SSH-сессий оператора
  - Файл `data/whitelist.json`

#### REST API эндпоинты
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/auth/login` | Вход (bcrypt + JWT-token = WSS_SECRET_TOKEN) |
| GET | `/api/incidents` | Список инцидентов (с пагинацией, фильтрами) |
| POST | `/api/incidents` | Создать инцидент |
| PATCH | `/api/incidents/:id` | Обновить статус инцидента |
| GET | `/api/logs` | Логи (type, level, limit) |
| POST | `/api/logs` | Добавить лог |
| GET | `/api/quarantine` | Список заблокированных IP (WAF ping point) |
| POST | `/api/quarantine` | Заблокировать IP |
| DELETE | `/api/quarantine/:ip` | Разблокировать IP |
| GET | `/api/stats` | Статистика инцидентов, логов, клиентов |
| POST | `/api/metrics` | Принять метрики от Lua-мониторов |
| POST | `/api/attack-detected` | Принять атаку от Remon WAF |
| GET | `/api/users` | Список пользователей |
| POST | `/api/users` | Создать пользователя |
| DELETE | `/api/users/:id` | Удалить пользователя |
| GET | `/api/geoip/:ip` | Mock-геолокация IP (страна, город, координаты) |
| GET | `/api/vulnerabilities` | База уязвимостей (из JSON-файлов) |
| POST | `/api/vulnerabilities` | Добавить уязвимость |
| DELETE | `/api/vulnerabilities/:id` | Удалить уязвимость |
| POST | `/api/ai/task` | ИИ-задача (с сохранением отчёта в data/reports/) |
| POST | `/api/ai-nlp-search` | NLP-поиск по логам (конвертация запроса в JSON-фильтр) |
| GET | `/api/ai-reports` | Список AI-отчётов |
| GET | `/api/ai-reports/:id` | Получить AI-отчёт по инциденту |
| POST | `/api/execute-ai-script` | Выполнить AI-скрипт митигации (только авторизованным) |
| POST | `/api/scan/semgrep` | Запуск Semgrep сканирования |
| POST | `/api/scan/trivy` | Запуск Trivy сканирования |
| POST | `/api/run-audit` | Запуск комплексного аудита безопасности |
| GET | `/api/security-status` | Статус UFW / Fail2ban / Lua мониторов |
| POST | `/api/activate-security` | Запуск `activate_security.sh` (UFW + Fail2ban + Lua) |
| GET | `/api/hardening-compliance` | OS Hardening Compliance аудит (8 проверок) |
| POST | `/api/reset-demo` | Полный сброс данных демо-стенда |
| DELETE | `/api/process/:pid` | Kill процесс по PID |
| GET | `/api/soar-settings` | Получить настройки SOAR |
| POST | `/api/soar-settings` | Обновить настройки SOAR |
| GET | `/api/whitelist` | Получить whitelist IP |
| POST | `/api/whitelist` | Добавить IP в whitelist |
| DELETE | `/api/whitelist/:ip` | Удалить IP из whitelist |
| GET | `/api/docker` | Список Docker-контейнеров (через `docker ps -a`) |
| POST | `/api/bot-notify` | Broadcast уведомления через WebSocket |
| POST | `/api/install-scanners` | Запуск установки Semgrep + Trivy |

#### WebSocket (WSS `/ws`)
- Аутентификация через `event: auth` + `nonce` (anti-replay)
- Таймаут авторизации 10 секунд → `close(4001, "Auth timeout")`
- События от клиента: `ping`, `get_incidents`, `get_logs`, `get_stats`, `ai_task`, `switch_model`, `run_scan`, `control_container`
- Трансляция ИИ-прогресса: `ai_progress` → пошаговые сообщения с задержкой 1800ms
- Broadcast: `incident`, `log`, `metrics`, `quarantine_updated`, `soar_settings_updated`, `model_changed`
- 7-шаговый прогресс ИИ-анализа с реальными этапами (инициализация → анализ IP → загрузка CVE → синтез → отчёт)

#### OS Hardening Compliance (`GET /api/hardening-compliance`)
8 проверок с результатами `PASS`, `WARN`, `FAIL`:
1. **ASLR** — `/proc/sys/kernel/randomize_va_space` (ожидается `2`)
2. **Yama ptrace_scope** — `/proc/sys/kernel/yama/ptrace_scope` (ожидается `1`+)
3. **UFW** — `sudo ufw status`
4. **Fail2ban** — `sudo fail2ban-client ping`
5. **SSH PermitRootLogin** — `sshd_config` (ожидается `no`)
6. **SSH PasswordAuthentication** — `sshd_config` (ожидается `no`)
7. **Права /etc/passwd** — `stat -c '%a' /etc/passwd` (не должен быть world-writable)
8. **noexec на /tmp** — `findmnt -n -o OPTIONS /tmp`

#### Запуск аудита при старте (`performStartupHardeningAudit`)
- Запускается через 3 сек после старта сервера
- Self-Integrity: хэши SHA-256 для `.env`, `soar_settings.json`, `db.js`, `server.js` → сохраняются в `data/integrity_hashes.json`
- Auto-chmod 0600 для файлов с insecure permissions (Linux)
- CVE Banner Audit: проверка версий SSH (CVE-2024-6387 regreSSHion), Nginx (CVE-2023-44487 HTTP/2 Rapid Reset), Docker (CVE-2024-21626 container breakout), Linux kernel (CVE-2024-1086 LPE netfilter)
- Аудит прослушиваемых портов (сравнение с whitelist)
- Process whitelist enforcement (из `monitors/lua/process_whitelist.txt`)
- Threat Intel Connection scan (сравнение активных соединений с `data/threat_intel_ips.json`)

#### Планировщик автоаудита
- Через 15 сек после старта: первый аудит Trivy + Semgrep
- Каждые 12 часов: повторный аудит
- Docker scan: `trivy image --format json` для всех запущенных контейнеров

#### Локальный фоллбэк метрик
- Каждые 3 сек, если нет данных от Lua-мониторов >8 сек
- Метрики: CPU (через `os.cpus()`), RAM, disk (`df /` или `wmic`), connections (`ss -t -a` или `netstat -ano`)
- `discoverDockerContainers()` — реальный `docker ps -a` с fallback mock-данными
- `discoverNginxSites()` — парсинг `/etc/nginx/sites-enabled/` с fallback

#### Обогащение метрик WAF
- `enrichMetricsWithWaf(payload)` — добавляет статус Remon WAF (pingTime, host, wafActive)
- WAF ping приходит от Remon через `/api/quarantine?waf_ping=true`

---

### `src/db.js` — База данных SQLite

**Таблицы:**
```sql
CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  severity TEXT,           -- CRITICAL / HIGH / MEDIUM / LOW
  monitor TEXT,
  type TEXT,
  description TEXT,
  status TEXT,             -- new / in_progress / resolved / advisory
  details TEXT,            -- JSON
  geo TEXT,                -- JSON {country, city, lat, lon, asn, org}
  ip TEXT,
  aiAudit TEXT,
  createdAt TEXT
);

CREATE TABLE logs (
  id TEXT PRIMARY KEY,
  type TEXT,               -- server / bot / cve
  level TEXT,              -- error / warn / info / debug
  message TEXT,
  meta TEXT,               -- JSON
  createdAt TEXT
);

CREATE TABLE cve_logs (... аналогично logs);
CREATE TABLE bot_logs (... аналогично logs);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT,           -- bcrypt hash
  role TEXT,               -- admin / analyst / operator
  chat_id TEXT,            -- Telegram chat_id для нотификаций
  createdAt TEXT
);

CREATE TABLE quarantine (
  ip TEXT PRIMARY KEY,
  reason TEXT,
  bannedAt TEXT
);
```

**WAL режим:** `PRAGMA journal_mode=WAL` — улучшенная конкурентность записи/чтения.

**Ключевые функции:**
- `addIncident()`, `getIncidents({limit, status, severity})`, `updateIncident()`
- `addLog()`, `getLogs({type, level, limit})`
- `addQuarantineIp()`, `removeQuarantineIp()`, `getQuarantinedIps()`
- `addUser()`, `getUserByUsername()`, `getUsers()`, `deleteUser()`
- `getStats()` — агрегация по severity для дашборда
- `resetDemoData()` — очистка всех таблиц кроме users

---

### `src/scanners.js` — Интеграция сканеров

- `runSemgrep(targetDir, rules)` — запуск `semgrep --config=p/security-audit --json`
- `runTrivy(target, scanType)` — запуск `trivy fs --format json` или `trivy image`
- Возвращают Promise с {success, results, error}
- Обработка таймаутов (120 сек для Docker-образов)

---

### `src/telegram-bot.js` — Telegram Bot

- Библиотека: `node-telegram-bot-api`
- Режим polling (не webhook) — совместим с любой сетью
- Регистрация chat_id в БД при `/start`
- Команды: `/start`, `/status`, `/incidents`, `/quarantine`, `/help`
- Push-уведомления при новых CRITICAL/HIGH инцидентах
- HTTP сервер на `BOT_HTTP_PORT` (8081) для healthcheck

---

### `src/log_forwarder.js` — Log Forwarder

- Чтение системных журналов: journald, `/var/log/syslog`, `/var/log/auth.log`
- Форвардинг в `/api/logs` для централизации в MISTRAL
- Docker события через `docker events`
- Интервал: 5 секунд

---

### `Dockerfile`

```dockerfile
FROM node:20-alpine
RUN apk add iptables iproute2 fail2ban ufw sudo curl
COPY package.json ./ && RUN npm install --production
COPY src/ ./src/ && COPY monitors/ ./monitors/
EXPOSE 8080 8443
CMD ["node", "src/server.js"]
```

Запуск: `docker run --network host --cap-add=NET_ADMIN -v /var/run/fail2ban/fail2ban.sock:/var/run/fail2ban/fail2ban.sock`

---

### `start.sh` — Единый скрипт запуска

5 шагов запуска:
1. **Node.js Server** — REST API + WebSocket → `logs/server.log`
2. **Telegram Bot** — polling → `logs/telegram-bot.log`
3. **Lua Monitors** — через `monitors/run-monitors.sh start`
4. **Log Forwarder** — форвардинг системных логов → `logs/log_forwarder.log`
5. **Honeypot + Audit** — `install_audit.sh` + `start_honeypot.sh`

Выводит публичный IP и URL для подключения клиента.

---

### `monitors/lua/monitor_system.lua` — Системный монитор (Monitor A)

**Интервал:** 5 сек (env `SYSTEM_CHECK_INTERVAL`)

**Собирает:**
- CPU: `top -bn1` → парсинг `%us`/`%sy`
- RAM: `/proc/meminfo`
- Disk: `df -h /`
- Connections: `ss -s`
- Uptime: `/proc/uptime`
- Docker: `docker ps --format` (контейнеры + статусы)
- Systemd: `systemctl list-units --failed`
- Nginx: `systemctl is-active nginx`

**Аномалии:**
- CPU > 90% → `HIGH CPU_SPIKE`
- RAM > 90% → `HIGH RAM_SPIKE`
- Disk > 90% → `CRITICAL DISK_FULL`
- Docker контейнеры с `Exited` статусом → `HIGH CONTAINER_DOWN`
- Systemd failed units → `HIGH SYSTEMD_FAILURE`

---

### `monitors/lua/monitor_auth.lua` — Auth монитор (Monitor B)

**Интервал:** 10 сек (env `AUTH_CHECK_INTERVAL`)

**Собирает:**
- SSH-сессии: `who` → список подключённых пользователей
- sudo-сессии: `journalctl -u sudo --since '5 minutes ago'`
- Неудачные входы: `journalctl _COMM=sshd | grep "Failed password"`
- authorized_keys: размер файла `~/.ssh/authorized_keys`
- Audit logs: `journalctl -t mistral-audit`
- Успешные логины: `journalctl _COMM=sshd | grep "Accepted"`

**Аномалии:**
- Root SSH-сессии → `CRITICAL ROOT_SSH`
- Failed logins > `MAX_FAILED_LOGINS` (5) → `HIGH FAILED_LOGINS`
- sudo-сессий > 3 за 5 мин → `HIGH SUDO_BURST`
- Изменение authorized_keys → `CRITICAL AUTH_KEYS_CHANGED`
- Docker stop/rm в аудит-логах → `HIGH DOCKER_TAMPERING`
- Доступ к `remon_payment_gateway` → `CRITICAL HONEYPOT_TRIGGERED`

---

### `monitors/lua/monitor_network.lua` — Сетевой монитор (Monitor C)

**Интервал:** 8 сек (env `NETWORK_CHECK_INTERVAL`)

**Собирает:**
- TCP-соединения: `ss -tan --processes` → состояния, remote-IP, process
- Listening ports: из TCP-таблицы
- Неизвестные процессы: `ps aux` → фильтрация по `PROCESS_WHITELIST`
- DDoS-индикаторы: подсчёт SYN-RECV, ESTABLISHED, топ-50 IP по количеству соединений

**Port whitelist:** `{22, 80, 443, 5000, 3000, 5432}`

**Process whitelist** (встроенный + динамический из `process_whitelist.txt`):
nginx, node, postgres, dockerd, sshd, systemd, fail2ban, pm2 и 40+ других

**Аномалии:**
- Незнакомые LISTEN-порты → `HIGH UNAUTHORIZED_PORT`
- Неавторизованные процессы → `MEDIUM UNAPPROVED_SYSTEM_PROCESS`
- SYN-RECV > 100 → `HIGH DDOS_SYN`
- ESTABLISHED > 3000 → `HIGH DDOS_ESTAB`
- IP с >200 соединениями → `HIGH DDOS_IP`

---

### `monitors/lua/monitor_integrity.lua` — File Integrity Monitor (Monitor D)

**Интервал:** 30 сек (env `INTEGRITY_CHECK_INTERVAL`)

**Следит за файлами** (env `WATCH_PATHS`):
- По умолчанию: `/root/.ssh/authorized_keys`, `/etc/hosts`

**Проверяет:**
- SHA-256 хэши файлов (через `sha256sum` или `openssl dgst -sha256`)
- Docker images: список через `docker images`
- Git изменения: `git -C /opt/remon status --short`

**Базовый слепок** строится при старте, обновляется после обнаружения изменений.

**Аномалии:**
- Изменение содержимого файла → `CRITICAL FILE_CHANGED`
- Удаление файла → `CRITICAL FILE_DELETED`
- Git uncommitted changes → `HIGH GIT_CHANGES`

---

### `monitors/run-monitors.sh` / `monitors/run-monitors.js`

Bash-скрипт и Node.js-аналог для запуска всех 4 Lua-мониторов:
- `start` — запуск всех в фоне с PID-файлами
- `stop` — останов по PID
- `status` — проверка, запущены ли мониторы (RUNNING/STOPPED)
- `restart` — перезапуск

---

### `monitors/lua/process_whitelist.txt`

Динамический файл белого списка процессов для Monitor C.
Каждая строка — паттерн (подстрока) имени процесса.

---

### Вспомогательные shell-скрипты

| Файл | Назначение |
|------|-----------|
| `stop.sh` | Остановка всех сервисов через `.pids/*.pid` |
| `activate_security.sh` | Включение UFW, Fail2ban, запуск Lua-мониторов |
| `install_semgrep_trivy.sh` | Установка Semgrep и Trivy на Ubuntu |
| `install_audit.sh` | Настройка `auditd` для `mistral-audit` journal |
| `start_honeypot.sh` | Запуск Docker-контейнера ханипота `remon_payment_gateway` |

---

### Конфигурационные данные

| Путь | Содержимое |
|------|------------|
| `.env` | Токены, порты, API-ключи |
| `.env.example` | Шаблон конфигурации |
| `data/soar_settings.json` | Настройки SOAR (автобан, AI-модель, пороги) |
| `data/whitelist.json` | Whitelist IP-адресов |
| `data/threat_intel_ips.json` | База IP репутаций (C2/Tor/Botnet) |
| `data/integrity_hashes.json` | SHA-256 хэши критических файлов |
| `data/vulnerabilities/*.json` | База пользовательских уязвимостей |
| `data/reports/*.md` | AI-отчёты по инцидентам |
| `certs/` | SSL-сертификаты (авто-генерация через openssl) |
| `logs/` | Лог-файлы сервисов (ротация 14 дней) |

---

## 📁 MISTRAL CLIENT

**Путь:** `Mistral Сlient/`  
**Стек:** Electron 30, ws, winston, electron-store, electron-builder  
**Платформа:** Windows (x64), собирается в NSIS installer и Portable .exe  
**Версия:** 1.3.1

---

### `src/main.js` (454 строки) — Electron Main Process

**Окна:**
- `SplashWindow` — загрузочный экран (500×320, frameless, прозрачный, темный фон с логотипом)
- `MainWindow` — основное окно (1600×900, min 1200×700, maximize при старте)

**Безопасность:**
- `will-navigate` → блокировка навигации за пределы `file://`
- `setWindowOpenHandler` → блокировка попапов
- `contextIsolation: true`, `nodeIntegration: false`
- `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` — для самоподписанных SSL-сертификатов

**WebSocket-логика:**
- `connectToServer(host, port, token)` — создание WS/WSS подключения
- Exponential backoff reconnect (до 30 сек максимум)
- Ping каждые 30 сек для keep-alive
- Кэш данных: `cache.{incidents, logs, botLogs, cveLogs, stats, metrics}`
- `trimCache()` — ограничение кэша 5000 записей на тип

**Уведомления Windows:**
- При новом CRITICAL/HIGH инциденте → Native Notification
- Извлечение IP атакующего из `details.sourceIp`, `details.ddos.top_ips[0].ip`, regex из description
- Debounce: минимум 8 секунд между уведомлениями
- Клик по уведомлению → focus окна + highlight инцидента в UI

**System Tray:**
- Иконка `totem.ico` в системном трее
- Меню: "Показать MISTRAL", разделитель, "Выход"

**IPC Handlers:**
| Канал | Описание |
|-------|----------|
| `connect-server` | Логин (POST `/api/auth/login`), запуск WS, возврат token |
| `disconnect-server` | Полное отключение |
| `disconnect-ws` | Отключение только WS |
| `reconnect-server` | Переподключение с сохранёнными параметрами |
| `send-api-request` | Прокси HTTP-запроса к серверу |
| `send-ws-message` | Отправка WS-сообщения |
| `get-app-version` | Версия приложения |
| `set-notifications-enabled` | Включение/отключение нотификаций (сохранение в electron-store) |
| `get-notifications-enabled` | Статус нотификаций |

---

### `src/preload.js` — Electron Preload / Bridge

Экспонирует `window.electronAPI` в renderer-процесс через `contextBridge`:
- `connectServer(config)` → IPC handle
- `disconnectServer()`, `reconnectServer()`
- `sendApiRequest(path, method, body)` → REST-запрос через main process
- `sendWsMessage(msg)` → WS-сообщение через main process
- `onWsMessage(callback)`, `onConnStatus(callback)`, `onInitialCache(callback)`
- `onNotificationClickIp(callback)`, `onNotificationClickIncident(callback)`

---

### `src/templates/index.html` — Главный UI (HTML-шаблон)

Монолитный HTML-файл со всеми вкладками приложения:

**Вкладки (tabs):**
| ID | Название |
|----|---------|
| `dashboard` | Обзор — статистика, графики, карта атак |
| `incidents` | Инциденты — таблица, фильтры, детали |
| `logs` | Логи — сервер/бот/CVE с фильтрацией |
| `map` | Карта атак (CyberMap + миниглобус) |
| `ai` | ИИ-Агент — чат с моделью |
| `reports` | AI-отчёты по инцидентам |
| `soar` | SOAR настройки и управление |
| `hardening` | OS Hardening Compliance |
| `scanner` | Запуск Semgrep/Trivy сканеров |
| `quarantine` | Управление карантином IP |
| `whitelist` | Whitelist IP-адресов |
| `users` | Управление пользователями |
| `settings` | Настройки соединения |
| `vuln-db` | База уязвимостей |

**Login Screen:**
- Поля: host, port, username, password
- NLP-поиск логов (enter в поле поиска → `/api/ai-nlp-search`)
- Auto-session lock через 5 мин неактивности

---

### `src/static/js/core.js` (957 строк) — Основная логика UI

- `handleMessage(msg)` — обработчик всех WS-событий
- `updateStats(stats)` — обновление счётчиков дашборда
- `renderIncidentsList(incidents)` — рендер таблицы инцидентов
- `renderLogsFeed(logs)` — рендер лога событий
- `formatLogMessageWithIpActions(message)` — форматирование лога:
  - Кликабельные IP-чипы с кнопками ЗАБЛОКИРОВАТЬ/РАЗБЛОКИРОВАТЬ
  - Подсветка CVE-номеров (CVE-XXXX-XXXXX)
  - Подсветка источника в `[квадратных скобках]`
  - Подсветка ключевых слов (успешно, атака, заблокировать и т.д.)
- `initCharts()` — инициализация Chart.js графиков:
  - `chartRisk` — Risk Trend (линейный, 24 часа)
  - `chartNet` — Network Activity (столбчатый)
  - `chartType` — Attack Types (круговой)
- `cyberMap`, `miniGlobe` — анимированная карта атак

---

### `src/static/js/ai.js` (312 строк) — ИИ-интерфейс

- `analyzeLog(msgText)` — анализ строки лога через ИИ
- `analyzeContext(incidentId)` — анализ инцидента с шаблоном ПРОТОКОЛ АВТОЗАЩИТЫ MISTRAL:
  - 4 секции: причина активации, триггер, действия, рекомендации
  - Шаблон с плейсхолдерами `{{type}}`, `{{description}}`, `{{context}}`, `{{ip}}`, `{{incident_id}}`
- `appendChatMsg(role, text, isHtml)` — добавление сообщения в чат-историю
- `sendAITask()` — отправка задачи через WS `ai_task`
- Markdown → HTML рендеринг ответов ИИ (заголовки, списки, код)
- Отображение прогресса (7 шагов через `ai_progress` событие)

---

### `src/static/js/auth.js` (140 строк) — Авторизация и пользователи

- `doLogin()` → IPC `connect-server` → показ главного приложения
- `doLogout()` → очистка состояния, показ login-screen
- `loadUsers()` / `addUser()` — управление пользователями через `/api/users`
- `resetIdleTimer()` — сброс таймера неактивности (5 мин)
- `speakAlert(text)` — озвучивание алертов через Web Speech API (ru-RU)
- NLP-поиск логов: длинный запрос (>10 символов) без `=` → `/api/ai-nlp-search`

---

### `src/static/js/` — Прочие JS-модули

| Файл | Назначение |
|------|-----------|
| `incidents.js` | Рендер, фильтрация и детали инцидентов |
| `logs.js` | Фильтрация логов по type/level/IP, экспорт |
| `quarantine.js` | UI карантина: добавление/удаление IP |
| `soar.js` | Управление SOAR-настройками |
| `scanner.js` | Запуск Semgrep/Trivy и отображение результатов |
| `hardening.js` | Отображение OS Hardening Compliance результатов |
| `map.js` | CyberMap + миниглобус (анимация атак) |
| `charts.js` | Chart.js графики риска и сетевой активности |

---

### `src/static/css/style.css` — Дизайн-система

**Цветовая схема (VS Code Dark + MISTRAL акценты):**
```css
--bg-primary: #1e1e1e;
--bg-secondary: #252526;
--bg-panel: #2d2d30;
--red: #e50914;            /* Основной акцент MISTRAL */
--red-glow: rgba(229,9,20,.3);
--green: #22c55e;
--yellow: #eab308;
--blue: #3b82f6;
--text-primary: #f5f5f5;
--text-muted: #999;
```

Элементы: glassmorphism-карточки, анимированные таблицы инцидентов, пульсирующие индикаторы угроз, scan-линии эффекты, gradient severity-бейджи.

---

## 📁 REMON

**Путь:** `Remon/`  
**Назначение:** Защищаемый веб-сайт агентства недвижимости — демонстрирует реальное применение MISTRAL WAF  
**URL:** https://raemon.ru  

---

### `Remon/backend/` — Express API

**Стек:** TypeScript, Express, PostgreSQL (через Prisma/pg), JWT, bcrypt, helmet, compression

**`src/index.ts`** (115 строк) — точка входа:
- Node.js кластеризация (по числу CPU в production)
- Подключение `mistralWAF` middleware **перед** всеми маршрутами
- `sanitizeBody` — DOMPurify-очистка входящих данных
- Rate limiting: 200 req/15 мин (общий), 50 req/15 мин (auth, skipSuccessfulRequests)
- Маршруты: `/api/auth`, `/api/apartments`, `/api/news`, `/api/projects`, `/api/users`, `/api/admin`, `/api/settings`
- Намеренно уязвимый `/api/admin/debug` без авторизации (для демонстрации обнаружения)

**`src/middleware/mistral-waf.ts`** (383 строки) — WAF-агент:

Конфигурация:
- `MISTRAL_SERVER_URL` — адрес Mistral Server для репортинга
- `bannedIps: Set<string>` — список заблокированных IP (обновляется каждые 4 сек из `/api/quarantine?waf_ping=true`)

Паттерны атак (30+ RegExp):
- **SQL Injection:** `UNION SELECT`, `DROP TABLE`, `OR '1'='1`, `--`, etc.
- **XSS:** `<script>`, `javascript:`, `onerror=`, `alert(`, `document.cookie`, etc.
- **Path Traversal:** `../`, `%2e%2e`, `.%00`
- **Command Injection:** `; cat`, `| bash`, `$(...)`, backticks

Чувствительные endpoints (логируются всегда):
- `/api/admin/debug`, `/api/admin/users`, `/api/auth/login`, `/api/auth/register`

Защита от DDoS/Brute-force:
- `ipCounters` — счётчик запросов в 1-минутном окне
- Порог: 300 req/min → тип `DDOS_BRUTEFORCE`

Детекция подозрительной активности:
- Admin endpoints без Bearer token → `ADMIN_ENDPOINT_NO_AUTH`
- PUT/PATCH с полями `role`, `status`, `is_admin` → `MASS_ASSIGNMENT_ATTEMPT`

Алгоритм обработки запроса:
1. Проверка `bannedIps` → 403 если заблокирован
2. `checkAttackPatterns()` → report + block при CRITICAL
3. `checkRateAnomaly()` → report
4. `checkSuspiciousActivity()` → report
5. Логирование чувствительных endpoints
6. `next()` — пропуск запроса

Репортинг в MISTRAL Server через `reportAttack()` (async HTTP POST `/api/attack-detected`).

---

### `Remon/frontend/` — Next.js приложение

**Стек:** Next.js 14, React, TypeScript, Tailwind CSS  
**Страницы:** главная, каталог квартир, новости, проекты, личный кабинет, авторизация

---

### `Remon/docker-compose.yml`

Сервисы:
| Сервис | Образ | Порт |
|--------|-------|------|
| nginx | nginx:alpine | 80, 443 |
| certbot | certbot/certbot | — |
| frontend | Next.js (Dockerfile) | 3000 |
| backend | Express (Dockerfile) | 5000 |
| db | postgres:15-alpine | 5432 |

- Let's Encrypt SSL (certbot авто-обновление каждые 12 часов)
- PostgreSQL healthcheck (pg_isready, 10 попыток)
- Volumes: `postgres_data`, uploads

---

### `Remon/nginx/nginx.conf` — Reverse Proxy

- HTTPS с Let's Encrypt
- Proxy pass `/api/` → backend:5000
- Proxy pass `/` → frontend:3000
- HTTP → HTTPS redirect

---

## 📁 MISTRAL DEMO

**Путь:** `Mistral Demo/`  
**Стек:** Python 3 (без сторонних зависимостей, только stdlib)

---

### `attack_simulator.py` (789 строк) — Симулятор атак v4.0

Интерактивный CLI-симулятор для демонстрации возможностей MISTRAL Defense.

**Сценарии:**
1. **Комплексная атака на raemon.ru** — все фазы одновременно + проверка блокировки WAF
2. **Экспресс APT-атака** — 5 фаз без пауз
3. **Пошаговая APT-атака** — 5 фаз с паузами и подтверждениями
4. **Honeypot Demo** — срабатывание ханипота `remon_payment_gateway`
5. **DDoS Flood** — лавина сетевых логов и скачок метрик
6. **Интерактивная песочница** — ручное управление атакой
7. **Сброс карантина** — разблокировка всех IP

**5 фаз APT-атаки:**
| Фаза | Тип | Severity |
|------|-----|----------|
| 1 | PORT_SCAN | LOW |
| 2 | SSH_BRUTE_FORCE_SUCCESS | HIGH |
| 3 | SQL_INJECTION | HIGH |
| 4 | PRIVILEGE_ESCALATION | CRITICAL |
| 5 | RANSOMWARE_ENCRYPTION | CRITICAL |

**Функции:**
- `send_metric_spike(cpu, ram, disk, connections, ddos)` — генерация метрик нагрузки
- `wait_for_ai_mitigation(incident_id, ip)` — ожидание ответа SOAR (25 сек timeout)
- `is_ip_quarantined(ip)` — проверка бана через `/api/quarantine`
- `website_request(path)` — прямые HTTP-запросы к raemon.ru для тестирования WAF
- `simulate_progress(task, duration)` — анимация прогресс-бара в терминале

---

## 📁 VKR — Материалы ВКР

**Путь:** `VKR/`

Содержит материалы для выпускной квалификационной работы:
- Техническая документация по архитектуре системы
- Описание функционала SIEM/SOAR
- Скриншоты и диаграммы
- Презентационные материалы

---

## 🏗️ АРХИТЕКТУРА СИСТЕМЫ

```
┌─────────────────────────────────────────────────────────────────┐
│                    MISTRAL DEFENSE ARCHITECTURE                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────┐     WebSocket/REST      ┌───────────────────────┐
│  Mistral Client     │◄────────────────────────►│   Mistral Server      │
│  (Electron, Win)    │                          │   (Node.js, Ubuntu)   │
│  ─────────────────  │                          │   ─────────────────── │
│  Dashboard          │                          │   REST API :8080      │
│  Incidents          │                          │   WSS      :8443      │
│  Logs               │                          │   SQLite DB           │
│  AI Chat            │                          │   SOAR Engine         │
│  Quarantine         │                          │   ActiveDefense       │
│  SOAR Settings      │                          │   ThreatIntelWatchdog │
│  OS Hardening       │                          │   AI Integration      │
│  Scanners           │                          │   UFW/Fail2ban mgmt   │
└─────────────────────┘                          └───────────┬───────────┘
                                                              │
                                    ┌─────────────────────────┤
                                    │                         │
                              POST /api/metrics        POST /api/attack-detected
                                    │                         │
                    ┌───────────────▼────┐         ┌──────────▼──────────┐
                    │  Lua Monitors       │         │   Remon WAF         │
                    │  ────────────────── │         │   (TypeScript)      │
                    │  A: System          │         │   ─────────────────  │
                    │  B: Auth            │         │   SQL Injection det. │
                    │  C: Network         │         │   XSS detection      │
                    │  D: Integrity       │         │   Path Traversal det.│
                    └────────────────────┘         │   DDoS detection     │
                                                    │   Quarantine sync   │
                                                    └─────────────────────┘
                                                              │
                                                    ┌─────────▼───────────┐
                                                    │   Remon Website     │
                                                    │   (raemon.ru)       │
                                                    │   Next.js Frontend  │
                                                    │   Express Backend   │
                                                    │   PostgreSQL DB     │
                                                    └─────────────────────┘
```

---

## 🔄 ПОТОК ОБРАБОТКИ ИНЦИДЕНТА

```
Событие → addIncident(severity, monitor, type, description)
  │
  ├─► UUID генерация + timestamp
  ├─► Извлечение IP из описания (regex)
  ├─► Mock GeoIP (страна/город/координаты)
  ├─► db.addIncident() → SQLite
  ├─► broadcast({event: "incident", data: incident}) → все WS-клиенты
  ├─► Telegram уведомление (при HIGH/CRITICAL)
  │
  └─► SOAR Engine:
      ├─► Если autoBanDdos и тип DDoS → banIpInSystem(ip)
      ├─► Если autoBanBruteForce и тип BruteForce → banIpInSystem(ip)
      └─► Если aiDefenseEnabled и severity CRITICAL:
          └─► ActiveDefenseEngine.triggerAutoDefense(incident)
              ├─► Формирование prompt с контекстом
              ├─► askAI(model, messages) → LLM API
              ├─► Поиск [AUTOBAN: IP] в ответе → автобан
              └─► Сохранение отчёта в data/reports/report-{id}.md
```

---

## 📊 СТАТИСТИКА КОДОВОЙ БАЗЫ

| Компонент | Основные файлы | Строк кода |
|-----------|----------------|-----------|
| Mistral Server | server.js, db.js, scanners.js, telegram-bot.js, log_forwarder.js | ~5500 |
| Lua Monitors | monitor_system.lua, monitor_auth.lua, monitor_network.lua, monitor_integrity.lua | ~1000 |
| Shell Scripts | start.sh, stop.sh, activate_security.sh, install_*.sh, start_honeypot.sh | ~450 |
| Mistral Client | main.js, preload.js, core.js, ai.js, auth.js + другие JS | ~3000 |
| Remon Backend | index.ts, mistral-waf.ts + routes + middleware | ~1500 |
| Remon Frontend | Next.js компоненты | ~2000+ |
| Attack Simulator | attack_simulator.py | ~800 |
| **ИТОГО** | | **~14 000+ строк** |

---

## ⚙️ ЗАВИСИМОСТИ

### Mistral Server (`package.json`)
```json
{
  "express": "^4.19.2",
  "ws": "^8.17.0",
  "openai": "^4.52.0",
  "node-telegram-bot-api": "^0.66.0",
  "dotenv": "^16.4.5",
  "cors": "^2.8.5",
  "helmet": "^7.1.0",
  "winston": "^3.13.0",
  "winston-daily-rotate-file": "^5.0.0",
  "better-sqlite3": "^11.5.0",
  "bcryptjs": "^2.4.3",
  "uuid": "^9.0.0"
}
```

### Mistral Client (`package.json`)
```json
{
  "electron-store": "^11.0.2",
  "ws": "^8.17.0",
  "winston": "^3.13.0",
  "winston-daily-rotate-file": "^5.0.0",
  "devDependencies": {
    "electron": "^30.0.0",
    "electron-builder": "^24.13.0"
  }
}
```

### Remon Backend
TypeScript, express, helmet, compression, cors, express-rate-limit, prisma, bcryptjs, jsonwebtoken, multer, DOMPurify

---

## 🔑 КЛЮЧЕВЫЕ ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ (`.env`)

```env
WSS_SECRET_TOKEN=        # Главный секретный токен (auth + SOAR)
API_PORT=8080            # HTTP REST API порт
WSS_PORT=8443            # HTTPS/WSS порт
AI_API_KEY=              # Ключ для LLM API (OpenAI-совместимый)
AI_BASE_URL=             # URL LLM провайдера (deepseek, openai, etc.)
TELEGRAM_BOT_TOKEN=      # Telegram Bot API токен
BOT_HTTP_PORT=8081       # Порт для healthcheck бота
MISTRAL_SERVER_URL=      # URL сервера (для WAF в Remon)
FORCE_HTTPS=false        # Включить HTTPS+WSS
```

---

*Документ сгенерирован автоматически на основе полного анализа кодовой базы проекта MISTRAL Defense.*

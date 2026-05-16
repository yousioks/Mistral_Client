# MISTRAL Defense — Client

Desktop-приложение для оператора информационной безопасности. Работает на Electron, подключается к Mistral Server через WebSocket Secure (WSS), отображает инциденты, логи, CVE, метрики сервера и управляет нейросетями.

## Быстрый старт

```bash
cp .env.example .env
# Отредактируй .env — укажи SERVER_HOST, WSS_SECRET_TOKEN
npm install
npm start
```

Или через `start.bat` на Windows:
```cmd
start.bat
```

## Архитектура

- **main.js** — точка входа Electron, запускает client-server.js перед открытием окна
- **client-server.js** — встроенный Node.js сервер (Express + WebSocket proxy)
- **preload.js** — безопасный IPC-мост между main и renderer
- **templates/index.html** — дашборд (SPA, Chart.js)

## Возможности

- 📊 Дашборд с метриками CPU/RAM/диск/сеть в реальном времени
- 🚨 Инциденты с фильтрацией по severity и статусу
- 📝 Логи сервера, бота и CVE
- 🤖 Управление нейросетями (DeepSeek V4 PRO, Kimi K2.6, Claude Sonnet 4.6)
- 📡 Мониторинг Docker, systemd, nginx
- 📥 Очередь на рассмотрение
- 📈 Генерация отчётов
- ⚙️ Настройки порогов и уведомлений

## Переменные окружения

См. `.env.example` — подключение к серверу, порт клиента, WSS-токен.

## Сборка

```bash
npm run build:win      # NSIS + portable
npm run build:portable # Только portable
```

## Структура

```
.
├── main.js
├── client-server.js
├── preload.js
├── package.json
├── .env.example
├── LICENSE.txt
├── start.bat
├── ssh-tunnel.bat
├── static/
│   ├── icon.png
│   └── logo.svg
└── templates/
    └── index.html
```

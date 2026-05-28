# MISTRAL Defense — Client

Desktop-приложение для оператора информационной безопасности. Работает на Electron, подключается к Mistral Server через WebSocket Secure (WSS), отображает инциденты, логи, CVE, метрики сервера и управляет нейросетями.

## Быстрый старт

```bash
cp .env.example .env
# Отредактируй .env — укажи SERVER_HOST, WSS_SECRET_TOKEN
npm install
npm start
```

Или запустите переносную сборку **MISTRAL-Defense-Portable-1.1.0.exe** из папки `dist/`.

## Архитектура и Нововведения (1.1.0)

- **Новый UI/UX Дизайн**: Улучшенные шрифты, стили, и переработанные иконки. Добавлена новая вкладка для просмотра опасных участков (Dangerous tab).
- **Portable сборка**: Приложение полностью скомпилировано в EXE (NSIS portable) для быстрого запуска на любом Windows-ПК без установки зависимостей.
- **main.js** — точка входа Electron, запускает client-server.js перед открытием окна
- **client-server.js** — встроенный Node.js сервер (Express + WebSocket proxy)
- **preload.js** — безопасный IPC-мост между main и renderer
- **templates/index.html** — дашборд (SPA, Chart.js)

## Возможности

- 📊 Дашборд с метриками CPU/RAM/диск/сеть в реальном времени
- 🚨 Инциденты с фильтрацией по severity и статусу
- 📝 Логи сервера, бота и CVE
- 🤖 Управление нейросетями (Изоляция опасных блоков для ручного выбора ИИ)
- 📡 Мониторинг Docker, systemd, nginx

## Сборка

```bash
npm run build:portable # Создает Portable EXE в папке dist/
```

@echo off
title MISTRAL DEFENSE SYSTEM & REMON - LOCAL ENVIRONMENT STARTER
color 0A
chcp 65001 >nul

echo ==============================================================
echo       MISTRAL DEFENSE SYSTEM + REMON DEVSITE AUTO-LAUNCHER
echo       Запуск всех служб в отдельных консольных окнах...
echo ==============================================================
echo.

set ROOT_DIR=%~dp0
cd /d "%ROOT_DIR%"

echo [1/5] Запуск MISTRAL Server (REST API на http://localhost:8080)...
start "MISTRAL Server" cmd /k "cd /d "%ROOT_DIR%Mistral Server" && npm run dev"
timeout /t 3 /nobreak >nul

echo [2/5] Запуск MISTRAL Telegram Bot (опрос Telegram API)...
start "MISTRAL Telegram Bot" cmd /k "cd /d "%ROOT_DIR%Mistral Server" && npm run bot"
timeout /t 1 /nobreak >nul

echo [3/5] Запуск MISTRAL Client Dashboard (интерфейс управления на порту 3001)...
start "MISTRAL Client Dashboard" cmd /k "cd /d "%ROOT_DIR%Mistral Сlient" && start.bat"
timeout /t 1 /nobreak >nul

echo [4/5] Запуск Remon Backend API (уязвимый сервер на порту 5000)...
start "Remon Backend API" cmd /k "cd /d "%ROOT_DIR%Remon\backend" && npm run dev"
timeout /t 2 /nobreak >nul

echo [5/5] Запуск Remon Frontend Client (веб-сайт Next.js на порту 3000)...
start "Remon Frontend Client" cmd /k "cd /d "%ROOT_DIR%Remon\frontend" && npm run dev"

echo.
echo ==============================================================
echo [OK] Все сервисы запущены!
echo      - Клиент Mistral:  http://localhost:3001
echo      - Сайт Remon (UI): http://localhost:3000
echo      - Backend / API:   http://localhost:5000
echo      - Сервер Mistral:  http://localhost:8080
echo ==============================================================
echo.
pause

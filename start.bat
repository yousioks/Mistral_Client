@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
:: ════════════════════════════════════════════════════════════════════════════
::  MISTRAL Client — Windows Startup Launcher
::  Запускает клиентское приложение на локальной машине Windows
:: ════════════════════════════════════════════════════════════════════════════
title MISTRAL Client Dashboard
color 0C

echo.
echo  ╔═══════════════════════════════════════════════════════════════╗
echo  ║           MISTRAL Defense — Client Dashboard                  ║
echo  ║              Красно-чёрный стиль ^| Real-time                 ║
echo  ╚═══════════════════════════════════════════════════════════════╝
echo.

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

:: Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js не найден! Установите Node.js 18+: https://nodejs.org
    pause
    exit /b 1
)

:: Check .env
if not exist ".env" (
    echo [WARN] .env не найден! Копирую из .env.example...
    copy .env.example .env >nul
    echo [WARN] Отредактируйте .env и укажите правильный SERVER_HOST!
    notepad .env
    pause
)

:: Install deps if needed
if not exist "node_modules" (
    echo [INFO] Установка зависимостей...
    call npm install
    if errorlevel 1 (
        echo [ERROR] Ошибка установки npm пакетов
        pause
        exit /b 1
    )
)

:: Check if server is reachable
for /f "tokens=2 delims==" %%a in ('findstr "^SERVER_HOST=" .env') do set SERVER_HOST=%%a
for /f "tokens=2 delims==" %%a in ('findstr "^SERVER_WSS_PORT=" .env') do set SERVER_WSS=%%a

echo [INFO] Подключение к серверу: %SERVER_HOST%:%SERVER_WSS%
echo [INFO] Клиент будет доступен: http://localhost:3001
echo.

:: Ask for tunnel mode
set /p TUNNEL="Запустить через SSH-туннель? (y/N): "
if /I "%TUNNEL%"=="y" (
    echo [INFO] Запуск SSH-туннеля...
    echo [INFO] Не закрывайте окно туннеля — оно нужно для работы!
    set /p SERVER="Введите адрес сервера (user@ip или домен): "
    if "!SERVER!"=="" (
        echo [ERROR] Адрес сервера не указан!
        pause
        exit /b 1
    )
    echo [INFO] Пробрасываем порты через !SERVER!...
    start "MISTRAL SSH Tunnel" cmd /k "ssh -L 3001:localhost:3001 -L 8080:localhost:8080 -L 8443:localhost:8443 !SERVER!"
    echo [INFO] Ожидание установки туннеля...
    timeout /t 5 /nobreak >nul
)
echo ═══════════════════════════════════════════════════════════════
echo  Запускаю клиентское приложение...
echo ═══════════════════════════════════════════════════════════════
echo.
:: Start client server
start "MISTRAL Client Server" cmd /k "cd /d "%SCRIPT_DIR%" && npm start"

:: Wait and open browser
timeout /t 3 /nobreak >nul
start http://localhost:3001

echo.
echo [OK] Клиент запущен! Браузер откроется автоматически.
echo [INFO] Для остановки закройте окно Node.js или нажмите Ctrl+C
echo.
pause

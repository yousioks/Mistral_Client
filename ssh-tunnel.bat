@echo off
:: ════════════════════════════════════════════════════════════════════════════
::  MISTRAL SSH Tunnel — Windows Launcher
::  Пробрасывает порты сервера на локальную машину через SSH
:: ════════════════════════════════════════════════════════════════════════════

chcp 65001 >nul
title MISTRAL SSH Tunnel

echo.
echo  ╔═══════════════════════════════════════════════════════════════╗
echo  ║              MISTRAL SSH Port Forwarding                      ║
echo  ╚═══════════════════════════════════════════════════════════════╝
echo.
echo  Пробрасываем порты:
echo    • localhost:3001  ->  сервер:3001  (Client Dashboard)
echo    • localhost:8080  ->  сервер:8080  (REST API)
echo    • localhost:8443  ->  сервер:8443  (WebSocket Secure)
echo.

set /p SERVER="Введите адрес сервера (user@ip или домен): "

if "%SERVER%"=="" (
    echo [ERROR] Адрес сервера не указан!
    pause
    exit /b 1
)

echo.
echo [INFO] Подключение к %SERVER% с пробросом портов...
echo [INFO] Не закрывайте это окно — туннель активен!
echo [INFO] Для отключения нажмите Ctrl+C или закройте окно.
echo.

ssh -L 3001:localhost:3001 -L 8080:localhost:8080 -L 8443:localhost:8443 %SERVER%

echo.
echo [INFO] SSH-соединение завершено.
pause

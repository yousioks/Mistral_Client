@echo off
:: ════════════════════════════════════════════════════════════════════════════
::  MISTRAL SSH Tunnel — Windows Launcher
::  Генерирует SSH-ключи, копирует на сервер, пробрасывает порты
:: ════════════════════════════════════════════════════════════════════════════

chcp 65001 >nul
title MISTRAL SSH Tunnel

echo.
echo  ╔═══════════════════════════════════════════════════════════════╗
echo  ║           MISTRAL SSH Tunnel + Key Exchange                   ║
echo  ╚═══════════════════════════════════════════════════════════════╝
echo.

:: ── Проверяем наличие SSH ────────────────────────────────────────────────────
where ssh >nul 2>&1
if errorlevel 1 (
    echo [ERROR] ssh не найден. Установите OpenSSH: Settings - Apps - Optional Features - OpenSSH Client
    pause
    exit /b 1
)

:: ── Генерация ключей если нет ────────────────────────────────────────────────
set KEY_PATH=%USERPROFILE%\.ssh\mistral_rsa
if not exist "%KEY_PATH%" (
    echo [INFO] Генерация SSH-ключей...
    ssh-keygen -t rsa -b 4096 -f "%KEY_PATH%" -N "" -C "mistral-defense-client"
    if errorlevel 1 (
        echo [ERROR] Не удалось сгенерировать ключи!
        pause
        exit /b 1
    )
    echo [OK] Ключи созданы: %KEY_PATH%
) else (
    echo [OK] SSH-ключи уже существуют: %KEY_PATH%
)

:: ── Ввод параметров ──────────────────────────────────────────────────────────
echo.
set /p SERVER_USER="Введите пользователя сервера (например: root): "
set /p SERVER_IP="Введите IP сервера: "
set /p SERVER_PORT_SSH="Введите SSH-порт сервера [22]: "
if "%SERVER_PORT_SSH%"=="" set SERVER_PORT_SSH=22

set SERVER=%SERVER_USER%@%SERVER_IP%

echo.
echo [INFO] Копирование публичного ключа на сервер %SERVER%...
echo [INFO] Введите пароль от сервера (только один раз — потом ключ будет использоваться):
echo.

:: Копируем ключ через ssh-copy-id (если есть) или вручную
where ssh-copy-id >nul 2>&1
if not errorlevel 1 (
    ssh-copy-id -i "%KEY_PATH%.pub" -p %SERVER_PORT_SSH% %SERVER%
) else (
    :: Ручная копия через cat
    type "%KEY_PATH%.pub" | ssh -p %SERVER_PORT_SSH% %SERVER% "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
)

if errorlevel 1 (
    echo [WARN] Не удалось скопировать ключ автоматически.
    echo [WARN] Скопируйте вручную содержимое файла: %KEY_PATH%.pub
    echo [WARN] В файл на сервере: ~/.ssh/authorized_keys
    echo.
) else (
    echo [OK] Ключ успешно скопирован на сервер!
)

:: ── Пробрасываем порты ───────────────────────────────────────────────────────
echo.
echo  Пробрасываем порты:
echo    localhost:8080  -^>  %SERVER_IP%:8080  (REST API)
echo    localhost:8443  -^>  %SERVER_IP%:8443  (WebSocket Secure)
echo.
echo [INFO] Туннель активен. Не закрывайте окно!
echo [INFO] Ctrl+C — остановить туннель.
echo.
echo [INFO] После запуска туннеля в клиенте используйте:
echo         IP: localhost   Порт: 8080
echo.

ssh -i "%KEY_PATH%" -p %SERVER_PORT_SSH% ^
    -L 8080:localhost:8080 ^
    -L 8443:localhost:8443 ^
    -o ServerAliveInterval=30 ^
    -o ServerAliveCountMax=3 ^
    -o StrictHostKeyChecking=no ^
    -N %SERVER%

echo.
echo [INFO] SSH-туннель завершён.
pause

@echo off
title Mistral Defense Demo Simulator
color 0C

echo =======================================================
echo Проверка наличия Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ОШИБКА] Python не установлен или не добавлен в PATH!
    echo Пожалуйста, установите Python с официального сайта.
    pause
    exit /b
)

echo Запуск скрипта атаки...
python attack_simulator.py
pause

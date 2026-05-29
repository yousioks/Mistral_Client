@echo off
chcp 65001 >nul
title Mistral Defense Demo Simulator
color 0C

echo =======================================================
echo Проверка наличия Python...

set PYTHON_CMD=python
%PYTHON_CMD% --version >nul 2>&1
if %errorlevel% neq 0 (
    set PYTHON_CMD=py
    %PYTHON_CMD% --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ОШИБКА] Python не установлен или не добавлен в PATH!
        echo Пожалуйста, установите Python с официального сайта.
        pause
        exit /b
    )
)

echo Запуск скрипта атаки через команду "%PYTHON_CMD%"...
%PYTHON_CMD% attack_simulator.py
pause

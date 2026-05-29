@echo off
title Mistral Defense Demo Simulator
color 0C

echo =======================================================
echo Starting attack simulation...

:: Attempt 1: Standard python command
python attack_simulator.py
if %errorlevel% equ 0 goto end

:: Attempt 2: Windows py launcher
py attack_simulator.py
if %errorlevel% equ 0 goto end

:: Attempt 3: File association (if .py is associated with Python)
attack_simulator.py
if %errorlevel% equ 0 goto end

echo [ERROR] Could not start the script automatically.
echo If Python is installed, please DOUBLE-CLICK the 'attack_simulator.py' file directly in the folder!

:end
pause

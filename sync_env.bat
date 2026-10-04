@echo off
chcp 65001 >nul
title Wazuh SOC Lab - Environment Sync Engine

echo ==============================================================================
echo    Wazuh SOC Lab - Starting Automated Environment Configuration Sync
echo ==============================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in your PATH!
    echo Please install Python 3.8+ or add it to your system PATH.
    pause
    exit /b 1
)

python "%~dp0scripts\sync_env.py" %*

echo.
pause

@echo off
rem ==============================================================================
rem Wazuh Active Response Wrapper for collect-evidence.ps1
rem Receives STDIN JSON from wazuh-execd and passes Alert ID / PID to PowerShell
rem ==============================================================================
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%~dp0collect-evidence.ps1"
exit /b 0

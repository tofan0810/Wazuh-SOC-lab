@echo off
rem ==============================================================================
rem Wazuh Active Response Wrapper for kill-process.ps1
rem Pipes stdin JSON from wazuh-execd to PowerShell engine
rem ==============================================================================
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%~dp0kill-process.ps1"
exit /b 0

# ==============================================================================
# WAZUH SOC LAB - 1-CLICK ENDPOINT MASTER SETUP SCRIPT (WINDOWS 10)
# ==============================================================================
# Automates the complete post-installation provisioning of the Windows 10 Endpoint:
#   1. Applies Sysmon v15.2 configuration (sysmon-config.xml)
#   2. Configures Wazuh Agent (ossec.conf) with Manager IP
#   3. Deploys Active Response scripts (kill-process, collect-evidence)
#   4. Enables Windows Object Access Auditing (SACL Event ID 4663)
#   5. Initializes Deception Grid (Canary Honey-File & Honey-Account)
#   6. Configures Protected WinRM (Port 5985) for SOAR closed-loop remediation
#   7. Restarts and verifies Wazuh Agent service
# ==============================================================================
[CmdletBinding()]
param(
    [string]$WazuhManagerIP = "192.168.71.128"
)

$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Text)
    Write-Host "`n[+] ========================================================" -ForegroundColor Cyan
    Write-Host "[+] $Text" -ForegroundColor Cyan
    Write-Host "[+] ========================================================" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------
# 0. Check Administrator Privilege
# ------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "    Please right-click PowerShell and choose 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "==================================================================" -ForegroundColor Green
Write-Host "  🛡️  WAZUH SOC LAB - 1-CLICK ENDPOINT AUTOMATED PROVISIONING   " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "[*] Script Directory  : $ScriptDir"
Write-Host "[*] Wazuh Manager IP  : $WazuhManagerIP"

# ------------------------------------------------------------------------------
# 1. Configure Microsoft Sysmon v15.2
# ------------------------------------------------------------------------------
Write-Step "BƯỚC 1: Cấu hình Microsoft Sysmon v15.2"
$SysmonConfig = Join-Path $ScriptDir "config\sysmon-config.xml"
$sysmonCmd = Get-Command "Sysmon64.exe" -ErrorAction SilentlyContinue
if (-not $sysmonCmd) {
    $sysmonCmd = Get-Command "Sysmon.exe" -ErrorAction SilentlyContinue
}

if ($sysmonCmd) {
    Write-Host "[*] Found Sysmon executable: $($sysmonCmd.Source)" -ForegroundColor Green
    Write-Host "[*] Applying configuration from: $SysmonConfig"
    & $sysmonCmd.Source -c $SysmonConfig
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Sysmon configuration successfully updated!" -ForegroundColor Green
    }
} else {
    Write-Host "[!] CẢNH BÁO: Không tìm thấy lệnh Sysmon64.exe trong hệ thống!" -ForegroundColor Yellow
    Write-Host "    Nếu bạn chưa cài Sysmon, hãy tải tại https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor Yellow
    Write-Host "    Sau khi cài xong, chạy lệnh: Sysmon64.exe -accepteula -i $SysmonConfig" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# 2. Configure Wazuh Agent (ossec.conf)
# ------------------------------------------------------------------------------
Write-Step "BƯỚC 2: Cập nhật cấu hình Wazuh Agent (ossec.conf)"
$AgentDir = "C:\Program Files (x86)\ossec-agent"
if (-not (Test-Path $AgentDir)) {
    $AgentDir = "C:\Program Files\ossec-agent"
}

if (Test-Path $AgentDir) {
    $AgentOssecConf = Join-Path $AgentDir "ossec.conf"
    $TemplateConf = Join-Path $ScriptDir "config\ossec.conf"
    
    if (Test-Path $TemplateConf) {
        # Backup existing ossec.conf
        if (Test-Path $AgentOssecConf) {
            Copy-Item -Path $AgentOssecConf -Destination "$AgentOssecConf.bak" -Force
            Write-Host "[*] Backed up current ossec.conf -> ossec.conf.bak"
        }
        
        $confContent = Get-Content $TemplateConf -Raw -Encoding UTF8
        $confContent = $confContent -replace "192\.168\.71\.128", $WazuhManagerIP
        [IO.File]::WriteAllText($AgentOssecConf, $confContent, [System.Text.Encoding]::UTF8)
        Write-Host "[+] Successfully deployed agent configuration to: $AgentOssecConf" -ForegroundColor Green
    }
} else {
    Write-Host "[!] CẢNH BÁO: Không tìm thấy thư mục cài đặt Wazuh Agent tại: C:\Program Files (x86)\ossec-agent" -ForegroundColor Yellow
    Write-Host "    Nếu chưa cài Wazuh Agent, vui lòng tải installer chính thức:" -ForegroundColor Yellow
    Write-Host "    https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# 3. Deploy Active Response Scripts
# ------------------------------------------------------------------------------
Write-Step "BƯỚC 3: Triển khai Active Response Scripts (kill-process & collect-evidence)"
if (Test-Path $AgentDir) {
    $ARBinDir = Join-Path $AgentDir "active-response\bin"
    if (-not (Test-Path $ARBinDir)) {
        New-Item -ItemType Directory -Force -Path $ARBinDir | Out-Null
    }
    
    $SourceAR = Join-Path $ScriptDir "active-response"
    Get-ChildItem -Path $SourceAR -Include *.cmd, *.ps1 -File | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $ARBinDir -Force
        Write-Host "[+] Deployed: $($_.Name) -> $ARBinDir" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 4. Enable Object Access Auditing (SACL Event ID 4663)
# ------------------------------------------------------------------------------
Write-Step "BƯỚC 4: Kích hoạt kiểm toán tập tin SACL (Event ID 4663)"
Write-Host "[*] Executing: auditpol /set /subcategory:'File System' /success:enable /failure:enable"
auditpol /set /subcategory:"File System" /success:enable /failure:enable
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] File System Object Access Auditing is ENABLED." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 5. Initialize Deception Grid (Canary Honey-File & Honey-Account)
# ------------------------------------------------------------------------------
Write-Step "BƯỚC 5: Thiết lập mạng lưới bẫy mồi Deception Grid (0% False Positive)"
$CanaryScript = Join-Path $ScriptDir "deception\setup_canary.ps1"
if (Test-Path $CanaryScript) {
    & $CanaryScript
    Write-Host "[+] Deception Grid initialized (Canary File + Honey-Account backup_admin)." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 6. Configure Protected WinRM Port 5985
# ------------------------------------------------------------------------------
Write-Step "BƯỚC 6: Thiết lập kênh điều khiển từ xa an toàn WinRM (Port 5985)"
try {
    Write-Host "[*] Configuring WinRM QuickConfig..."
    winrm quickconfig -q 2>&1 | Out-Null
    Set-Service WinRM -StartupType Automatic
    Start-Service WinRM -ErrorAction SilentlyContinue

    # Configure WinRM settings for Lab Environment
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true -Force -ErrorAction SilentlyContinue
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force -ErrorAction SilentlyContinue
    Set-Item -Path WSMan:\localhost\MaxTimeoutms -Value 1800000 -Force -ErrorAction SilentlyContinue
    Set-Item -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 2048 -Force -ErrorAction SilentlyContinue

    # Ensure Firewall rule for WinRM 5985 is always open
    New-NetFirewallRule -DisplayName "WazuhLab-WinRM-5985" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+] WinRM Port 5985 successfully configured and whitelisted in Firewall." -ForegroundColor Green
} catch {
    Write-Warning "WinRM configuration encountered a non-critical notice: $_"
}

# ------------------------------------------------------------------------------
# 7. Restart Wazuh Agent Service
# ------------------------------------------------------------------------------
Write-Step "BƯỚC 7: Khởi động lại dịch vụ Wazuh Agent"
$wazuhService = Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue
if (-not $wazuhService) {
    $wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
}

if ($wazuhService) {
    Restart-Service -Name $wazuhService.Name -Force
    Start-Sleep -Seconds 2
    $wazuhService.Refresh()
    Write-Host "[+] Wazuh Agent Service Status: $($wazuhService.Status)" -ForegroundColor Green
} else {
    Write-Host "[!] Dịch vụ Wazuh chưa được cài đặt. Hãy cài đặt file MSI trước." -ForegroundColor Yellow
}

Write-Host "`n==================================================================" -ForegroundColor Green
Write-Host "  🎉 THIẾT LẬP MÁY TRẠM ENDPOINT HOÀN TẤT THÀNH CÔNG!             " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "Endpoint đã sẵn sàng kết nối tới Wazuh Manager ($WazuhManagerIP)."
Write-Host "Sysmon, Deception Honey-File, Active Response và WinRM 5985 đã sẵn sàng.`n"

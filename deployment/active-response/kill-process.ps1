# ==============================================================================
# Wazuh Active Response: Automated Malicious Process Termination (kill-process.ps1)
# MITRE ATT&CK: T1003.001 (LSASS Memory Access), T1059.001 (PowerShell Execution)
# ==============================================================================
param()

$LogFile = "C:\Program Files (x86)\ossec-agent\active-responses.log"

function Write-ARLog {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $logEntry = "$timestamp active-response/bin/kill-process.cmd: $Message"
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Fallback if log path is not accessible
    }
}

try {
    # 1. Read input JSON from STDIN passed by wazuh-execd
    $rawInput = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($rawInput)) {
        Write-ARLog "ERROR: Empty STDIN received. No action taken."
        exit 0
    }

    $event = $rawInput | ConvertFrom-Json
    $command = $event.command
    $alert = $event.parameters.alert

    # Only act on "add" command (active response execution)
    if ($command -ne "add") {
        exit 0
    }

    $ruleId = $alert.rule.id
    $ruleDesc = $alert.rule.description
    $eventData = $alert.data.win.eventdata

    # 2. Extract Target PID to terminate
    # For LSASS Memory Access (Sysmon Event 10 - Rule 100005):
    # CRITICAL SAFETY: SourceProcessId is the attacker (e.g. powershell.exe, mimikatz.exe)
    # TargetProcessId is lsass.exe (DO NOT KILL lsass.exe!)
    $targetPid = $null
    $targetImage = $null

    if ($eventData.sourceProcessId) {
        $targetPid = [int]$eventData.sourceProcessId
        $targetImage = $eventData.sourceImage
    } elseif ($eventData.processId) {
        $targetPid = [int]$eventData.processId
        $targetImage = $eventData.image
    }

    if (-not $targetPid -or $targetPid -le 4) {
        Write-ARLog "INFO: Invalid or system PID ($targetPid) for Rule $ruleId. Skipped."
        exit 0
    }

    # 3. Comprehensive Critical System Process Whitelist Protection
    $protectedProcesses = @(
        "lsass", "csrss", "services", "wininit", "smss", "winlogon", 
        "wsmprovhost", "wazuh-agent", "ossec-agent", "explorer", "svchost"
    )

    $procName = "Unknown"
    try {
        $procObj = Get-Process -Id $targetPid -ErrorAction Stop
        $procName = $procObj.ProcessName.ToLower()
    } catch {
        Write-ARLog "INFO: Process with PID $targetPid already terminated or not found."
        exit 0
    }

    if ($protectedProcesses -contains $procName) {
        Write-ARLog "WARNING: Protected system process ($procName, PID: $targetPid) matched whitelist! Termination aborted for system stability."
        exit 0
    }

    # 4. Terminate the Malicious Offending Process
    Stop-Process -Id $targetPid -Force -ErrorAction Stop
    Write-ARLog "SUCCESS: [Rule $ruleId] Malicious process terminated: '$procName' (PID: $targetPid) | Image: '$targetImage'"

} catch {
    Write-ARLog "ERROR: Exception occurred during process termination: $($_.Exception.Message)"
}

exit 0

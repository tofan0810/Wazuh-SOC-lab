# ==============================================================================
# Wazuh Active Response: Automated Forensics Triage & Evidence Preserver (collect-evidence.ps1)
# MITRE ATT&CK: T1083 (File Discovery), T1078 (Valid Accounts), T1046 (Network Service Discovery)
# ==============================================================================
param(
    [string]$AlertId = "",
    [int]$TargetProcessId = 0
)

$OutputDir = "C:\Windows\Temp\Forensics"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-responses.log"

function Write-ARLog {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $logEntry = "$timestamp active-response/bin/collect-evidence.cmd: $Message"
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Fallback if logging fails
    }
}

try {
    $rawInput = $null
    if ([string]::IsNullOrWhiteSpace($AlertId) -and [Console]::IsInputRedirected) {
        try {
            if ([Console]::In.Peek() -ge 0) {
                $rawInput = [Console]::In.ReadToEnd()
            }
        } catch {}
    }
    if (-not [string]::IsNullOrWhiteSpace($rawInput)) {
        try {
            $event = $rawInput | ConvertFrom-Json
            if ($event.command -and $event.command -ne "add") {
                exit 0
            }
            $alert = $event.parameters.alert
            if ($alert) {
                if ($alert.id) { $AlertId = "ALT-$($alert.id)" }
                $eventData = $alert.data.win.eventdata
                if ($eventData.processId) {
                    $TargetProcessId = [int]$eventData.processId
                } elseif ($eventData.sourceProcessId) {
                    $TargetProcessId = [int]$eventData.sourceProcessId
                }
            }
        } catch {
            Write-ARLog "INFO: STDIN was not JSON or parsing failed. Using default parameters."
        }
    }

    if ([string]::IsNullOrWhiteSpace($AlertId)) {
        $AlertId = "TRIPWIRE-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $evidenceFolder = "$OutputDir\Evidence_$AlertId"
    if (Test-Path $evidenceFolder) {
        Remove-Item -Path $evidenceFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $evidenceFolder -Force | Out-Null

    Write-ARLog "START: Preserving digital forensics evidence for Alert: $AlertId..."

    # 2. Process Memory Dump (TargetProcessId) via comsvcs.dll or MiniDump
    if ($TargetProcessId -gt 4) {
        $proc = Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            $dmpPath = "$evidenceFolder\proc_${TargetProcessId}_$($proc.ProcessName).dmp"
            try {
                $dumpCmd = "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $TargetProcessId $dmpPath full"
                cmd.exe /c $dumpCmd | Out-Null
            } catch {
                $err = $_.Exception.Message
                Write-ARLog "WARNING: Could not dump memory for PID ${TargetProcessId}: $err"
            }
        }
    }

    # 3. Live Network Connections & Active Sockets (netstat -ano)
    $netPath = "$evidenceFolder\network_connections.txt"
    netstat -ano > $netPath
    try {
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Format-Table -AutoSize | Out-File -Append -FilePath $netPath
    } catch {}

    # 4. Active User Sessions & Logged-on Accounts
    $sessPath = "$evidenceFolder\active_sessions.txt"
    cmd.exe /c qwinsta > $sessPath

    # 5. Windows Security Log Audit Events (Event 4663, 4624, 4625)
    $evtxPath = "$evidenceFolder\security_audit_trail.evtx"
    try {
        wevtutil epl Security $evtxPath /q:"*[System[(EventID=4663 or EventID=4624 or EventID=4625)]]" /ow:true
    } catch {
        Write-ARLog "WARNING: Could not export security EVTX: $_"
    }

    # 6. Compress Evidence Package into .ZIP
    $zipPath = "$OutputDir\Evidence_${AlertId}.zip"
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    }

    Compress-Archive -Path "$evidenceFolder\*" -DestinationPath $zipPath -CompressionLevel Optimal

    $zipSize = (Get-Item $zipPath).Length
    Write-ARLog "SUCCESS: Forensics package preserved at $zipPath ($zipSize bytes)."

} catch {
    Write-ARLog "ERROR: Exception occurred during evidence collection: $($_.Exception.Message)"
}

exit 0

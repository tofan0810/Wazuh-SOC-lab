# ==============================================================================
# Automated Live Forensics Triage & Evidence Preservation Collector
# Target: Windows Endpoint (192.168.71.129)
# ==============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$TargetProcessId = 0,
    
    [Parameter(Mandatory = $false)]
    [string]$AlertId = "HONEYPOT-ALERT-01",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "C:\Windows\Temp\Forensics"
)

$ErrorActionPreference = "SilentlyContinue"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$evidenceFolder = "$OutputDir\Evidence_$AlertId"
if (Test-Path $evidenceFolder) {
    Remove-Item -Path $evidenceFolder -Recurse -Force
}
New-Item -ItemType Directory -Path $evidenceFolder -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Host "[*] Collecting Incident Forensics Evidence for Alert: $AlertId ($timestamp)..."

# ------------------------------------------------------------------------------
# 1. Process Memory Dump (TargetProcessId) via comsvcs.dll or MiniDump
# ------------------------------------------------------------------------------
if ($TargetProcessId -gt 0) {
    $proc = Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "[*] Preserving RAM memory dump for PID: $TargetProcessId ($($proc.ProcessName))..."
        $dmpPath = "$evidenceFolder\proc_${TargetProcessId}_$($proc.ProcessName).dmp"
        
        # Native Windows user-mode memory dump using rundll32 comsvcs.dll, MiniDump
        try {
            $dumpCmd = "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $TargetProcessId $dmpPath full"
            cmd.exe /c $dumpCmd | Out-Null
            if (-not (Test-Path $dmpPath)) {
                # Fallback to process info snapshot
                $proc | Select-Object Id, ProcessName, Path, StartTime, Handles, VM, WS, CPU | Export-Clixml -Path "$evidenceFolder\process_snapshot.xml"
            }
        } catch {
            Write-Warning "Could not dump memory via comsvcs: $_"
        }
    }
}

# ------------------------------------------------------------------------------
# 2. Live Network Connections & Active Sockets (netstat -ano)
# ------------------------------------------------------------------------------
Write-Host "[*] Preserving live active network connections..."
$netPath = "$evidenceFolder\network_connections.txt"
netstat -ano > $netPath
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Format-Table -AutoSize | Out-File -Append -FilePath $netPath

# ------------------------------------------------------------------------------
# 3. Active User Sessions & Logged-on Accounts
# ------------------------------------------------------------------------------
Write-Host "[*] Preserving active user sessions..."
$sessPath = "$evidenceFolder\active_sessions.txt"
qwinsta > $sessPath

# ------------------------------------------------------------------------------
# 4. Windows Security Log Audit Events (Event 4663, 4624, 4625)
# ------------------------------------------------------------------------------
Write-Host "[*] Exporting Windows Security Log Audit Trail..."
$evtxPath = "$evidenceFolder\security_audit_trail.evtx"
try {
    wevtutil epl Security $evtxPath /q:"*[System[(EventID=4663 or EventID=4624 or EventID=4625)]]" /ow:true
} catch {
    Write-Warning "Could not export evtx: $_"
}

# ------------------------------------------------------------------------------
# 5. Compress Evidence Package into .ZIP
# ------------------------------------------------------------------------------
$zipPath = "$OutputDir\Evidence_${AlertId}.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

Write-Host "[*] Compressing all forensics artifacts into $zipPath..."
Compress-Archive -Path "$evidenceFolder\*" -DestinationPath $zipPath -CompressionLevel Optimal

# Output result as JSON for automated SOAR consumption
$result = [PSCustomObject]@{
    status         = "success"
    alert_id       = $AlertId
    zip_path       = $zipPath
    zip_size_bytes = (Get-Item $zipPath).Length
    files_included = (Get-ChildItem $evidenceFolder | Select-Object -ExpandProperty Name)
}

$result | ConvertTo-Json -Compress

# ==============================================================================
# Network Service Decoy / Low-Interaction Honeypot (Port 21 FTP) & Deception Sensor
# Pure PowerShell / .NET Implementation (Zero External Dependencies)
# ==============================================================================
param(
    [int]$Port = 21
)

$ErrorActionPreference = "SilentlyContinue"
$logFile = "C:\Windows\Temp\honeypot_ftp.log"
$wazuhLog = "C:\Program Files (x86)\ossec-agent\active-responses.log"
$collectorScript = "C:\Program Files (x86)\ossec-agent\active-response\bin\collect-evidence.ps1"

function Trigger-EvidenceCollector([string]$alertId, [int]$procId = 0) {
    Start-Job -ScriptBlock {
        param($script, $aid, $pid)
        & $script -AlertId $aid -TargetProcessId $pid
    } -ArgumentList $collectorScript, $alertId, $procId | Out-Null
}

function Write-DecoyLog([string]$msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "[$ts] [FTP-DECOY] $msg"
    try {
        Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    } catch {}
    
    try {
        $wazuhDir = Split-Path $wazuhLog
        if (Test-Path $wazuhDir) {
            $arEntry = "$ts active-response/bin/decoy.cmd: $msg"
            Add-Content -Path $wazuhLog -Value $arEntry -ErrorAction SilentlyContinue
        }
    } catch {}

    # Write to Windows Application Event Log so Wazuh Agent eventchannel captures it (Rule 100016)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("WazuhDecoy")) {
            [System.Diagnostics.EventLog]::CreateEventSource("WazuhDecoy", "Application")
        }
        [System.Diagnostics.EventLog]::WriteEntry("WazuhDecoy", "[FTP-DECOY] $msg", [System.Diagnostics.EventLogEntryType]::Warning, 1016)
    } catch {}
}

# Ensure Firewall rule allows Port 21
try {
    if (-not (Get-NetFirewallRule -DisplayName "FTP-Decoy-Port-21" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "FTP-Decoy-Port-21" -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow | Out-Null
    }
} catch {}

# Start background thread to watch for Canary File (4663) and Honey-Account (4625)
$jobWatcher = Start-Job -ScriptBlock {
    param($collectorScript)
    $last4663 = 0
    $last4625 = 0
    try {
        $e1 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 1 -ErrorAction SilentlyContinue
        $e2 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($e1) { $last4663 = $e1.RecordId }
        if ($e2) { $last4625 = $e2.RecordId }
    } catch {}

    while ($true) {
        Start-Sleep -Seconds 1
        try {
            $evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4663, 4625)} -MaxEvents 10 -ErrorAction SilentlyContinue
            foreach ($e in $evts) {
                if ($e.Id -eq 4663 -and $e.RecordId -gt $last4663) {
                    $last4663 = $e.RecordId
                    if ($e.Message -match "IT_Admin_Credentials\.xlsx") {
                        & $collectorScript -AlertId "ALT-CANARY-$($e.RecordId)" -TargetProcessId $e.ProcessId
                    }
                }
                if ($e.Id -eq 4625 -and $e.RecordId -gt $last4625) {
                    $last4625 = $e.RecordId
                    if ($e.Message -match "backup_admin") {
                        & $collectorScript -AlertId "ALT-HONEYACC-$($e.RecordId)" -TargetProcessId $e.ProcessId
                    }
                }
            }
        } catch {}
    }
} -ArgumentList $collectorScript

$ip = [System.Net.IPAddress]::Any
$listener = New-Object System.Net.Sockets.TcpListener($ip, $Port)

try {
    $listener.Start()
    Write-DecoyLog "Decoy listener started on 0.0.0.0:$Port"
} catch {
    Write-DecoyLog "Failed to bind port $Port : $_"
    exit 1
}

while ($true) {
    try {
        $client = $listener.AcceptTcpClient()
        $remoteEndpoint = $client.Client.RemoteEndPoint
        $srcIp = $remoteEndpoint.Address.ToString()
        $srcPort = $remoteEndpoint.Port
        Write-DecoyLog "TRIPWIRE_TRIGGERED: Unauthorized probe from ${srcIp}:${srcPort}"

        # Trigger Forensics Evidence Preservation instantly
        $alertId = "ALT-PORT21-$(Get-Date -Format 'HHmmss')"
        Trigger-EvidenceCollector $alertId 0

        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII)
        $writer.AutoFlush = $true
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)

        # Send banner
        $writer.WriteLine("220 Microsoft FTP Service Ready.")

        $client.ReceiveTimeout = 5000
        $data = $reader.ReadLine()
        if ($data) {
            Write-DecoyLog "PROBE_PAYLOAD from ${srcIp}: $data"
            $writer.WriteLine("530 User cannot log in.")
        }
        $client.Close()
    } catch {
        Start-Sleep -Milliseconds 200
    }
}

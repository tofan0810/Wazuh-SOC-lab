# 🚀 Remote Execution Cheat-Sheet

Guide on executing commands directly from **PowerShell on the Windows Host machine** into the **3 VMware virtual machines** without switching console windows.

---

## 📌 Network Information & Lab Credentials

| Virtual Machine | IP Address | Protocol | Account / SSH Alias |
| :--- | :--- | :--- | :--- |
| **Kali Linux** (Attacker) | `192.168.71.130` | SSH (Port 22) | Host: `kali-vm` (User: `kali`) |
| **Ubuntu Wazuh** (Manager) | `192.168.71.128` | SSH (Port 22) | Host: `wazuh-vm` (User: `nguyentoan`) |
| **Windows 10** (Victim) | `192.168.71.129` | WinRM (Port 5985) | User: `socrunner` |

---

## 1. ⚔️ KALI LINUX (Attacker Machine)

### Run a quick command from Host:
```powershell
# View IP and user:
ssh kali-vm "hostname; whoami; ip -br a"

# Check running attack processes (xfreerdp / curl):
ssh kali-vm "ps aux | grep -E 'xfreerdp|curl'"
```

### Open an interactive terminal (SSH session into Kali):
```powershell
ssh kali-vm
# Exit: type 'exit'
```

---

## 2. 🛡️ UBUNTU WAZUH MANAGER (SIEM Server)

### Run a quick command from Host:
```powershell
# Check status of the 3 Docker containers (Manager, Indexer, Dashboard):
ssh wazuh-vm "cd ~/wazuh-docker/single-node && docker compose ps"

# Check RAM / CPU usage on the Wazuh server:
ssh wazuh-vm "free -m; docker stats --no-stream"

# View 10 newest Wazuh alerts:
ssh wazuh-vm "sudo tail -n 10 /var/ossec/logs/alerts/alerts.json"

# Restart the Wazuh service inside the Manager container:
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart"
```

### Open an interactive terminal:
```powershell
ssh wazuh-vm
# Exit: type 'exit'
```

---

## 3. 🎯 WINDOWS 10 VICTIM (Target Endpoint)

*On Host PowerShell, store the credential in a temporary variable once per session:*
```powershell
$cred = Get-Credential -UserName socrunner
```

### Method A: Run a quick command or script block (`Invoke-Command`)
```powershell
# 1. Check Wazuh Agent service status:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-Service WazuhSvc
}

# 2. Check Apache port 80 (XAMPP):
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    netstat -ano | Select-String ":80\s+.*LISTENING"
}

# 3. View firewall rules automatically created by Wazuh Active Response:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*WAZUH*"} | Select-Object DisplayName, Action, Enabled
}

# 4. View the 10 most recent Active Response log lines:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 10
}

# 5. Restart Wazuh Agent service:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Restart-Service WazuhSvc
}
```

### Method B: Open an interactive shell into Windows 10 (`Enter-PSSession`)
```powershell
Enter-PSSession -ComputerName 192.168.71.129 -Credential $cred
```
*The prompt switches to `[192.168.71.129]: PS C:\...>` — execute commands directly on the virtual machine. Type `exit` to quit.*

---

## 4. ⚡ Quick Health Check Across All 3 Machines (Health 1-Liner)

Run this one-liner on Host PowerShell to test connectivity across all 3 machines:
```powershell
Write-Host "--- KALI ---"; ssh -o BatchMode=yes kali-vm "hostname; whoami"; Write-Host "--- WAZUH ---"; ssh -o BatchMode=yes wazuh-vm "hostname; docker ps --format '{{.Names}}: {{.Status}}'"; Write-Host "--- WINDOWS 10 ---"; Test-WSMan 192.168.71.129
```
Or use the lab's built-in Python script:
```powershell
python tests/e2e/lab_health.py
```

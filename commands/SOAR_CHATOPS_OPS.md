# 🤖 SOAR n8n, ChatOps Telegram & Jira Cloud Operations Guide

Guide for orchestrating, maintaining, monitoring logs, and troubleshooting the security orchestration, automation, and response (SOAR) engine.

---

## 📌 Service Ports & Access URLs

| Service | URL / Port | Credentials / Notes |
| :--- | :--- | :--- |
| **n8n Web Editor** | `http://192.168.71.128:5678` | Visualize and debug the 3 workflow canvases |
| **Wazuh Dashboard** | `https://192.168.71.128:443` | `admin` / `SecretPassword123!` |
| **Telegram Bot** | `https://t.me/my_wazuh_soc_alert_bot` | `@my_wazuh_soc_alert_bot` |
| **Jira Cloud Board** | `https://tn421015.atlassian.net` | Project Key: `KAN` |

---

## 1. ⚙️ Managing the n8n SOAR Engine Container (`wazuh-vm`)

### Check n8n container status:
```powershell
ssh wazuh-vm "docker ps --filter name=n8n-soar-engine --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
```

### View real-time n8n logs (Realtime Debugging):
```powershell
# View the 50 most recent log lines:
ssh wazuh-vm "docker logs --tail 50 n8n-soar-engine"

# Follow logs in real-time:
ssh wazuh-vm "docker logs -f --tail 20 n8n-soar-engine"
# (Press Ctrl+C to exit)
```

### Restart or stop the n8n cluster:
```powershell
# Restart:
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose restart"

# Reload configuration from updated .env:
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose up -d"

# Stop container:
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose down"
```

---

## 2. 📡 Managing the Telegram Callback Bridge (`telegram_bridge.py`)

Because the Lab server resides in an internal private network without a public IP, the `telegram_bridge.py` Python process uses **Telegram Long-Polling** to receive interactive button-click callback queries from Telegram and forward them to n8n webhooks.

### Verify running process:
```powershell
ssh wazuh-vm "ps aux | grep telegram_bridge | grep -v grep"
```

### View callback button reception logs:
```powershell
ssh wazuh-vm "tail -n 25 /home/nguyentoan/n8n-docker/telegram_bridge.log"
```
*Sample log on successful callback delivery:*
```text
2026-10-04 21:38:43,497 [INFO] Starting Telegram -> n8n ChatOps Callback Bridge...
2026-10-04 21:38:43,499 [INFO] Target n8n Webhook: http://127.0.0.1:5678/webhook/telegram-callback
2026-10-04 21:40:02,120 [INFO] Received Callback Query from @Khanh Toan: action:jira:100005:192.168.71.129:1791103745
2026-10-04 21:40:02,185 [INFO] Forwarded callback 456583364 to n8n -> HTTP 200
```

### Manually restart the Telegram Bridge process:
```powershell
ssh wazuh-vm "/home/nguyentoan/n8n-docker/restart_bridge.sh"
```

---

## 3. 🛡️ Firewall Rule Verification & Rollback (Containment Verification)

When an Analyst clicks the **`[🚫 Block IP 24h]`** button on Telegram:

### Check created blocking rules on Windows 10:
```powershell
$cred = Get-Credential -UserName socrunner
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WAZUH*" -or $_.DisplayName -like "*SOAR*" } | Select-Object Name, DisplayName, Direction, Action, Enabled
}
```

### Remove (Rollback) isolation rules to restore connectivity for testing:
```powershell
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WAZUH*" -or $_.DisplayName -like "*SOAR*" } | Remove-NetFirewallRule
    Write-Host "✅ All experimental firewall blocking rules have been removed."
}
```

---

## 4. 🎫 Jira Cloud REST API Integration Testing

### Validate Atlassian Token credentials from Host machine:
```powershell
# Run synchronous test script for immediate validation:
python -c "
import urllib.request, base64, os
from dotenv import load_dotenv
load_dotenv()
domain = os.getenv('JIRA_DOMAIN', '').replace('https://', '').strip('/')
auth = base64.b64encode(f\"{os.getenv('JIRA_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}\".encode()).decode()
req = urllib.request.Request(f'https://{domain}/rest/api/3/myself', headers={'Authorization': f'Basic {auth}', 'Accept': 'application/json'})
with urllib.request.urlopen(req) as resp:
    print('✅ Jira Status:', resp.status, 'User OK')
"
```

### View created tickets directly on Jira Web:
Browse to: `https://tn421015.atlassian.net/jira/software/projects/KAN/boards/2`
Or query a specific ticket: `https://tn421015.atlassian.net/browse/KAN-15`

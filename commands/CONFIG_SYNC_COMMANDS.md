# 🔄 Configuration & Environment Variables (.env) Synchronization Guide

Guide on updating and synchronizing configuration from the `.env` file across the entire Wazuh SIEM, n8n SOAR, Telegram Bridge, and Jira Cloud ecosystem.

---

## 🚀 Method 1: Using the 1-Click Automation Tool (Recommended)

Whenever you modify the `.env` file (updating Telegram Token, Chat ID, Jira Token, VirusTotal / AbuseIPDB API Keys, or changing VM IP addresses):

### 1. Double-Click:
Simply double-click the [`sync_env.bat`](../../sync_env.bat) file located at the project root directory.

### 2. Or run from Terminal (PowerShell / CMD):
```powershell
# Run the Python orchestration script:
python scripts/sync_env.py

# Or run the batch file:
.\sync_env.bat
```

---

## ⚙️ Automated Actions Performed by the Script

1. **Pre-flight API Key Validation:**
   - Sends verification requests to the Telegram API (`/getMe`).
   - Sends Basic Auth verification requests to the Jira Cloud API (`/rest/api/3/myself`).
   - Checks AbuseIPDB quota status (`/api/v2/check`).
2. **Local Configuration Updates:**
   - Updates the `<integration>` blocks in [`deployment/ossec.conf`](../../deployment/ossec.conf).
   - Updates workflow templates in [`integrations/n8n/workflows/`](../../integrations/n8n/workflows/).
3. **Deployment to Wazuh Server via SSH/SCP:**
   - Deploys `.env` to `/home/nguyentoan/n8n-docker/.env`.
   - Injects the updated `ossec.conf` into the `single-node-wazuh.manager-1` container.
   - Synchronizes workflow JSON files to the n8n Docker directory.
4. **Service Restart & Application:**
   - Automatically invokes `/var/ossec/bin/wazuh-control restart`.
   - Automatically refreshes the `n8n-soar-engine` container (`docker compose up -d`).
   - Automatically restarts the background daemon `telegram_bridge.py`.
5. **Displays a visual Health Check Report table.**

---

## 🛠️ Method 2: Step-by-Step Manual Update Process (Manual Fallback)

If Python is unavailable or if individual component operations are required:

### Step 1: Copy `.env` to `wazuh-vm`
```powershell
scp .env wazuh-vm:/home/nguyentoan/n8n-docker/.env
```

### Step 2: Load Configuration into Wazuh Manager Container
```powershell
scp deployment/ossec.conf wazuh-vm:/tmp/ossec.conf
ssh wazuh-vm "docker cp /tmp/ossec.conf single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf"
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart"
```

### Step 3: Restart n8n Container
```powershell
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose up -d"
```

### Step 4: Restart the Telegram Bridge Daemon
```powershell
ssh wazuh-vm "/home/nguyentoan/n8n-docker/restart_bridge.sh"
```

---

## 🔍 Troubleshooting

### 1. `Cannot connect via SSH to wazuh-vm` error:
- Verify that the Ubuntu Wazuh VM has booted in VMware.
- Check the SSH alias configuration in `C:\Users\<User>\.ssh\config`:
   ```text
   Host wazuh-vm
       HostName 192.168.71.128
       User nguyentoan
   ```

### 2. Telegram Bot does not respond to button callbacks:
- Check the daemon bridge logs:
   ```powershell
   ssh wazuh-vm "tail -n 20 /home/nguyentoan/n8n-docker/telegram_bridge.log"
   ```
- If an `Unauthorized` message appears $\rightarrow$ the bot token in `.env` is invalid; update it and run `.\sync_env.bat`.

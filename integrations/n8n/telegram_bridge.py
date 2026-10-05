#!/usr/bin/env python3
"""
Telegram Long-Polling to n8n Webhook Bridge & Closed-Loop Containment Engine
Continuously listens for Telegram callback query clicks (Khóa IP, Rollback, Diệt Process, Dọn Persistence, Jira)
1. Executes direct endpoint containment / rollback actions on Windows 10 via WinRM (pywinrm)
2. Forwards callback queries to n8n Workflow 02 (telegram-callback webhook) for ChatOps state update
"""

import os
import sys
import json
import time
import logging
import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("telegram_bridge")

# Load .env if present
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
if not os.path.exists(env_path):
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
N8N_WEBHOOK_URL = os.getenv("N8N_CALLBACK_URL", "http://127.0.0.1:5678/webhook/telegram-callback")
TELEGRAM_API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"

WINRM_HOST = os.getenv("LAB_WINDOWS_IP", "192.168.71.129")
WINRM_USER = os.getenv("LAB_WINDOWS_USER", "socrunner")
WINRM_PASS = os.getenv("LAB_WINDOWS_PASSWORD", "")


def execute_winrm_action(action_type, target):
    """Executes closed-loop containment / rollback on Windows 10 Endpoint via WinRM."""
    try:
        import winrm
    except ImportError:
        logger.warning("pywinrm not installed, skipping direct endpoint execution")
        return False

    ps_cmd = ""
    if action_type in ["block", "isolate"]:
        if target == WINRM_HOST or target == "192.168.71.129" or action_type == "isolate":
            # Safe Host Isolation: Block attacker (Kali) & external networks while preserving Wazuh & WinRM management
            ps_cmd = (
                "$ProgressPreference = 'SilentlyContinue'; "
                'New-NetFirewallRule -DisplayName "SOAR-ISOLATE-Kali-In" -Direction Inbound -Action Block -RemoteAddress 192.168.71.130 -ErrorAction SilentlyContinue; '
                'New-NetFirewallRule -DisplayName "SOAR-ISOLATE-Kali-Out" -Direction Outbound -Action Block -RemoteAddress 192.168.71.130 -ErrorAction SilentlyContinue; '
                'New-NetFirewallRule -DisplayName "SOAR-ISOLATE-Ext-In" -Direction Inbound -Action Block -RemoteAddress "0.0.0.0-192.168.70.255","192.168.72.0-255.255.255.255" -ErrorAction SilentlyContinue; '
                'New-NetFirewallRule -DisplayName "SOAR-ISOLATE-Ext-Out" -Direction Outbound -Action Block -RemoteAddress "0.0.0.0-192.168.70.255","192.168.72.0-255.255.255.255" -ErrorAction SilentlyContinue; '
                "exit 0"
            )
        else:
            # Block specific malicious IP (e.g. Remote attacker)
            ps_cmd = (
                f'New-NetFirewallRule -DisplayName "SOAR-BLOCK-{target}" -Direction Inbound -Action Block -RemoteAddress {target} -ErrorAction SilentlyContinue; '
                f'New-NetFirewallRule -DisplayName "SOAR-BLOCK-Out-{target}" -Direction Outbound -Action Block -RemoteAddress {target} -ErrorAction SilentlyContinue; '
                "exit 0"
            )
    elif action_type in ["unblock", "unisolate"]:
        # Rollback firewall block & host isolation
        ps_cmd = (
            f'Remove-NetFirewallRule -DisplayName "SOAR-BLOCK-{target}*" -ErrorAction SilentlyContinue; '
            'Remove-NetFirewallRule -DisplayName "SOAR-ISOLATE-*" -ErrorAction SilentlyContinue; '
            "exit 0"
        )
    elif action_type == "killproc":
        # Force terminate malicious process
        clean_target = target.replace(".exe", "").strip()
        ps_cmd = (
            "$ProgressPreference = 'SilentlyContinue'; "
            f"Get-Process -Name '{clean_target}' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; "
            "exit 0"
        )
    elif action_type == "cleanpersist":
        # Clean persistence Registry Run key & UAC ms-settings hijack
        ps_cmd = (
            "$ProgressPreference = 'SilentlyContinue'; "
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WazuhLabPersistenceTest' -Force -ErrorAction SilentlyContinue; "
            "if (Test-Path 'HKCU:\\Software\\Classes\\ms-settings') { Remove-Item -Path 'HKCU:\\Software\\Classes\\ms-settings' -Recurse -Force -ErrorAction SilentlyContinue }; "
            "exit 0"
        )

    if not ps_cmd:
        return False

    try:
        session = winrm.Session(
            f"http://{WINRM_HOST}:5985/wsman",
            auth=(WINRM_USER, WINRM_PASS),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=15,
            operation_timeout_sec=10,
        )
        logger.info(f"Executing WinRM command on {WINRM_HOST} for action: {action_type} (target: {target})...")
        r = session.run_ps(ps_cmd)
        logger.info(f"WinRM execution finished. Exit code: {r.status_code}")
        if r.std_err:
            logger.warning(f"WinRM stderr: {r.std_err.decode(errors='replace').strip()}")
        return r.status_code == 0
    except Exception as e:
        logger.error(f"WinRM command failed on {WINRM_HOST}: {e}")
        return False


def poll_updates(offset=None):
    url = f"{TELEGRAM_API_BASE}/getUpdates?timeout=20"
    if offset:
        url += f"&offset={offset}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Wazuh-SOAR-Telegram-Bridge"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return data.get("result", [])
    except Exception as e:
        logger.warning(f"Error fetching updates from Telegram: {e}")
    return []


def forward_to_n8n(callback_query):
    try:
        payload = json.dumps({"callback_query": callback_query}).encode("utf-8")
        req = urllib.request.Request(
            N8N_WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Wazuh-SOAR-Bridge"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"Forwarded callback {callback_query.get('id')} to n8n -> HTTP {resp.status}")
            return True
    except Exception as e:
        logger.error(f"Failed to forward callback to n8n: {e}")
        return False


def main():
    logger.info("Starting Telegram -> n8n ChatOps Callback & WinRM Containment Bridge...")
    logger.info(f"Target n8n Webhook: {N8N_WEBHOOK_URL}")
    logger.info(f"Target WinRM Endpoint: {WINRM_USER}@{WINRM_HOST}:5985")
    offset = None

    while True:
        try:
            updates = poll_updates(offset)
            for update in updates:
                update_id = update.get("update_id")
                offset = update_id + 1

                if "callback_query" in update:
                    cb = update["callback_query"]
                    cb_data = cb.get("data", "")
                    sender = cb.get("from", {}).get("username") or cb.get("from", {}).get("first_name")
                    logger.info(f"Received Callback Query from @{sender}: {cb_data}")

                    # Execute closed-loop WinRM action on Windows 10 Endpoint if applicable
                    parts = cb_data.split(":")
                    if len(parts) >= 3 and parts[0] == "action":
                        action_type = parts[1]
                        target = parts[2] if action_type != "jira" else (parts[3] if len(parts) > 3 else "")
                        if action_type in ["block", "unblock", "isolate", "unisolate", "killproc", "cleanpersist"]:
                            logger.info(f"Triggering endpoint containment/rollback: {action_type} on {target}")
                            execute_winrm_action(action_type, target)

                    forward_to_n8n(cb)

            time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Bridge stopped by user.")
            break
        except Exception as e:
            logger.error(f"Unexpected loop error: {e}")
            time.sleep(3)


if __name__ == "__main__":
    main()

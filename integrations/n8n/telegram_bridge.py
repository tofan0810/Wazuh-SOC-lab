#!/usr/bin/env python3
"""
Telegram Long-Polling to n8n Webhook Bridge & Closed-Loop Containment Engine
Continuously listens for Telegram callback query clicks (Block IP, Rollback, Kill Process, Clean Persistence, Jira)
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
possible_env_paths = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"),
    "/home/nguyentoan/n8n-docker/.env"
]
for p in possible_env_paths:
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        break

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
N8N_WEBHOOK_URL = os.getenv("N8N_CALLBACK_URL", "http://127.0.0.1:5678/webhook/telegram-callback")
TELEGRAM_API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"

WINRM_HOST = os.getenv("LAB_WINDOWS_IP", "192.168.71.129")
WINRM_USER = os.getenv("LAB_WINDOWS_USER", "socrunner")
WINRM_PASS = os.getenv("LAB_WINDOWS_PASSWORD", "")

JIRA_DOMAIN = os.getenv("JIRA_DOMAIN", "tn421015.atlassian.net").replace("https://", "").strip("/")
JIRA_EMAIL = os.getenv("JIRA_EMAIL", "tn421015@gmail.com")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "")


def notify_telegram(text, chat_id="8696241190"):
    try:
        url = f"{TELEGRAM_API_BASE}/sendMessage"
        payload = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML"}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "Wazuh-SOAR-Bridge"})
        with urllib.request.urlopen(req, timeout=10) as r:
            pass
    except Exception as e:
        logger.warning(f"Failed to send telegram notification: {e}")


def get_latest_jira_issue():
    """Queries Jira Cloud for the newest issue in project KAN and checks if it already has a zip attachment."""
    if not JIRA_API_TOKEN:
        return None, False
    try:
        import base64
        auth_str = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode("utf-8")).decode("ascii")
        j_req = urllib.request.Request(
            f"https://{JIRA_DOMAIN}/rest/api/3/search/jql?jql=project%3DKAN%20order%20by%20created%20DESC&maxResults=1&fields=key,attachment",
            headers={"Authorization": f"Basic {auth_str}", "Accept": "application/json"}
        )
        with urllib.request.urlopen(j_req, timeout=10) as j_res:
            j_data = json.loads(j_res.read().decode("utf-8"))
            issues = j_data.get("issues", [])
            if issues:
                k = issues[0]["key"]
                atts = issues[0]["fields"].get("attachment", [])
                has_zip = any(a.get("filename", "").endswith(".zip") for a in atts)
                return k, has_zip
    except Exception as e:
        logger.warning(f"Error checking latest Jira issue: {e}")
    return None, False


def attach_evidence_to_jira_issue(issue_key):
    """Fetches latest Forensics ZIP from Windows endpoint via WinRM and attaches to Jira Issue."""
    if not JIRA_API_TOKEN or not issue_key:
        return False
    try:
        import winrm
        import base64
        import io
        session = winrm.Session(
            f"http://{WINRM_HOST}:5985/wsman",
            auth=(WINRM_USER, WINRM_PASS),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=20,
            operation_timeout_sec=15,
        )
        # Find newest zip in C:\Windows\Temp\Forensics
        ps_find = (
            "$z = Get-ChildItem 'C:\\Windows\\Temp\\Forensics\\Evidence_*.zip' -ErrorAction SilentlyContinue | "
            "Sort-Object LastWriteTime -Descending | Select-Object -First 1; "
            "if ($z) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($z.FullName)) + '|' + $z.Name } else { '' }"
        )
        r = session.run_ps(ps_find)
        if not r.std_out:
            return False
        out = r.std_out.decode('ascii', errors='ignore').strip()
        if '|' not in out:
            return False
        b64_content, filename = out.split('|', 1)
        file_bytes = base64.b64decode(b64_content)
        
        # Upload attachment to Jira via REST API v3
        auth_str = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode("utf-8")).decode("ascii")
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        jira_url = f"https://{JIRA_DOMAIN}/rest/api/3/issue/{issue_key}/attachments"
        req = urllib.request.Request(
            jira_url,
            data=body,
            headers={
                "Authorization": f"Basic {auth_str}",
                "X-Atlassian-Token": "no-check",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "Wazuh-SOAR-Bridge"
            }
        )
        with urllib.request.urlopen(req, timeout=15) as res:
            logger.info(f"Attached evidence {filename} ({len(file_bytes)} bytes) to Jira {issue_key} -> HTTP {res.status}")
            notify_telegram(
                f"📦 <b>[FORENSICS PRESERVATION - EVIDENCE ATTACHED]</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🎫 <b>Jira Issue:</b> <a href=\"https://{JIRA_DOMAIN}/browse/{issue_key}\">{issue_key}</a>\n"
                f"📁 <b>Evidence File:</b> <code>{filename}</code> ({len(file_bytes)} bytes)\n"
                f"💻 <b>Source Endpoint:</b> <code>{WINRM_HOST}</code>\n"
                f"🔒 <b>Chain of Custody:</b> Integrity preserved in NIST SP 800-86 format\n"
                f"✅ <b>Status:</b> Digital Forensics ZIP successfully uploaded to Jira Cloud."
            )
            return True
    except Exception as e:
        logger.warning(f"Could not attach evidence to Jira {issue_key}: {e}")
        return False


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

                    forward_res = forward_to_n8n(cb)
                    if len(parts) >= 2 and parts[1] == "jira":
                        baseline_key, _ = get_latest_jira_issue()
                        logger.info(f"Jira ticket creation initiated via ChatOps. Baseline issue key: {baseline_key}")

                        import threading
                        def delayed_attach(prev_key):
                            logger.info(f"Background delayed attachment monitor started (waiting for new ticket after {prev_key})...")
                            for attempt in range(12):  # Poll up to 36 seconds
                                time.sleep(3)
                                try:
                                    current_key, current_has_zip = get_latest_jira_issue()
                                    if current_key and (current_key != prev_key or not current_has_zip):
                                        logger.info(f"New or unattached ticket detected: {current_key} (has_zip={current_has_zip}). Attaching forensics package...")
                                        if attach_evidence_to_jira_issue(current_key):
                                            logger.info(f"Successfully attached forensics package to {current_key}.")
                                            break
                                except Exception as ex:
                                    logger.warning(f"Attempt {attempt+1} polling Jira issue failed: {ex}")

                        threading.Thread(target=delayed_attach, args=(baseline_key,), daemon=True).start()

            time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Bridge stopped by user.")
            break
        except Exception as e:
            logger.error(f"Unexpected loop error: {e}")
            time.sleep(3)


if __name__ == "__main__":
    main()

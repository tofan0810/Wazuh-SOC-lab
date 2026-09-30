#!/usr/bin/env python3
"""
Custom Telegram ChatOps Integration for Wazuh SIEM
Sends rich, formatted SOC alerts to a Telegram Channel or Group.

Parameters passed by Wazuh:
    sys.argv[1]: Path to the temporary alert JSON file
    sys.argv[2]: API Key (Telegram Bot Token)
    sys.argv[3]: Hook URL (Telegram Chat ID or full webhook URL)
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

LOG_FILE = "/var/ossec/logs/integrations.log"


def log_debug(message: str) -> None:
    try:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} custom-telegram: {message}\n")
    except Exception:
        pass


def format_soc_message(alert: dict) -> str:
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "N/A")
    rule_level = rule.get("level", 0)
    rule_desc = rule.get("description", "Security Alert Detected")
    groups = rule.get("groups", [])

    agent = alert.get("agent", {})
    agent_name = agent.get("name", "Unknown Agent")
    agent_ip = agent.get("ip", "N/A")

    timestamp = alert.get("timestamp", datetime.utcnow().isoformat())
    data = alert.get("data", {})

    # Extract Attacker IP
    src_ip = (
        data.get("srcip")
        or data.get("win", {}).get("eventdata", {}).get("ipAddress")
        or alert.get("srcip")
        or "N/A"
    )

    # Extract Target User
    target_user = (
        data.get("win", {}).get("eventdata", {}).get("targetUserName")
        or data.get("dstuser")
        or alert.get("dstuser")
        or "N/A"
    )

    # Extract MITRE Information
    mitre = rule.get("mitre", {})
    mitre_ids = mitre.get("id", [])
    mitre_tactics = mitre.get("tactic", [])
    mitre_techniques = mitre.get("technique", [])

    mitre_str = ", ".join(mitre_ids) if isinstance(mitre_ids, list) else str(mitre_ids)
    tactic_str = ", ".join(mitre_tactics) if isinstance(mitre_tactics, list) else str(mitre_tactics)
    technique_str = ", ".join(mitre_techniques) if isinstance(mitre_techniques, list) else str(mitre_techniques)

    # Severity Icon & Tag
    if int(rule_level) >= 12:
        severity_header = "🚨 [SOC ALERT - CRITICAL / HIGH SEVERITY]"
    elif int(rule_level) >= 8:
        severity_header = "⚠️ [SOC ALERT - MEDIUM SEVERITY]"
    else:
        severity_header = "ℹ️ [SOC ALERT - INFORMATIONAL]"

    lines = [
        f"<b>{severity_header}</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🎯 <b>Rule ID:</b> <code>{rule_id}</code> (Level: <b>{rule_level}</b>)",
        f"📋 <b>Cảnh báo:</b> {rule_desc}",
    ]

    if mitre_str:
        lines.append(f"⚔️ <b>MITRE ATT&CK:</b> <code>{mitre_str}</code>")
        if technique_str:
            lines.append(f"📌 <b>Kỹ thuật:</b> {technique_str}")
        if tactic_str:
            lines.append(f"🛡️ <b>Chiến thuật:</b> {tactic_str}")

    lines.append(f"⏰ <b>Thời gian:</b> <code>{timestamp}</code>")
    lines.append("──────────────────────────")
    lines.append(f"📍 <b>Endpoint:</b> <code>{agent_name}</code> (<code>{agent_ip}</code>)")

    if src_ip != "N/A":
        lines.append(f"🛑 <b>IP Kẻ tấn công:</b> <code>{src_ip}</code>")

    if target_user != "N/A":
        lines.append(f"👤 <b>Tài khoản mục tiêu:</b> <code>{target_user}</code>")

    # Scenario-specific Details
    if str(rule_id) == "100001":
        lines.append("⚡ <b>Vector:</b> RDP Brute Force (Port 3389)")
        lines.append("🛡️ <b>Phản ứng tự động:</b> <b>ĐÃ KHÓA IP KALI QUA FIREWALL (600s)</b>")
    elif str(rule_id) == "100002":
        url = data.get("url", "N/A")
        status_code = data.get("id", "N/A")
        lines.append(f"🌐 <b>Vector:</b> Web LFI / Path Traversal (HTTP {status_code})")
        lines.append(f"🔗 <b>URL Payload:</b> <code>{url}</code>")
        lines.append("🛡️ <b>Phản ứng tự động:</b> <b>ĐÃ KHÓA IP KALI QUA FIREWALL (600s)</b>")
    elif str(rule_id) == "87105":
        vt = alert.get("virustotal", {})
        positives = vt.get("positives", "N/A")
        file_path = vt.get("source", {}).get("file", "N/A")
        lines.append(f"🦠 <b>VirusTotal:</b> <b>{positives}</b> Antivirus Engines phát hiện độc hại!")
        lines.append(f"📁 <b>Tệp tin mã độc:</b> <code>{file_path}</code>")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("🔍 <i>Wazuh SIEM Security Operations Center</i>")

    return "\n".join(lines)


def send_telegram_notification(bot_token: str, chat_id: str, message: str) -> None:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Wazuh-Telegram-Integrator/1.0"},
    )

    # Prepare standard SSL context, fallback to unverified context if CA bundle fails
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            if response.status == 200:
                log_debug(f"Alert successfully sent to Telegram chat {chat_id}")
            else:
                log_debug(f"Telegram API responded with HTTP {response.status}")
    except (ssl.SSLError, urllib.error.URLError) as ssl_err:
        err_str = str(ssl_err).lower()
        if "certificate verify failed" in err_str or "self-signed" in err_str:
            try:
                unverified_ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, timeout=10, context=unverified_ctx) as response:
                    if response.status == 200:
                        log_debug(f"Alert successfully sent to Telegram chat {chat_id} (via fallback unverified SSL)")
                    else:
                        log_debug(f"Telegram API responded with HTTP {response.status} (via fallback unverified SSL)")
            except Exception as retry_err:
                log_debug(f"Exception sending alert with unverified SSL context: {retry_err}")
        else:
            log_debug(f"URLError/SSLError calling Telegram API: {ssl_err}")
    except urllib.error.HTTPError as error:
        err_body = error.read().decode("utf-8", errors="replace")
        log_debug(f"HTTPError {error.code} calling Telegram API: {err_body}")
    except Exception as error:
        log_debug(f"Exception sending alert to Telegram: {error}")


def main():
    if len(sys.argv) < 4:
        log_debug(f"Error: Missing required arguments. Received: {sys.argv}")
        sys.exit(1)

    alert_file = sys.argv[1]
    bot_token = sys.argv[2].strip()
    chat_id = sys.argv[3].strip()

    # Support full URL in hook_url if user configured it that way
    if "api.telegram.org" in chat_id:
        try:
            parsed = urllib.parse.urlparse(chat_id)
            params = urllib.parse.parse_qs(parsed.query)
            if "chat_id" in params:
                chat_id = params["chat_id"][0]
        except Exception:
            pass

    if not os.path.exists(alert_file):
        log_debug(f"Error: Alert file not found: {alert_file}")
        sys.exit(1)

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as error:
        log_debug(f"Error parsing alert JSON: {error}")
        sys.exit(1)

    message = format_soc_message(alert)
    send_telegram_notification(bot_token, chat_id, message)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Telegram Alert Test Tool for Wazuh SOC Lab
Sends a simulated SOC Alert (RDP Brute Force, Web LFI, or VirusTotal) to verify your Telegram Bot.

Usage:
    python integrations/telegram/test_telegram_alert.py
    python integrations/telegram/test_telegram_alert.py --scenario rdp
    python integrations/telegram/test_telegram_alert.py --scenario lfi
    python integrations/telegram/test_telegram_alert.py --scenario virustotal
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime


def load_env_file():
    paths = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"),
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip("'\"")
                            if k and k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass
            break


def get_mock_alert(scenario: str) -> dict:
    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    if scenario == "lfi":
        return {
            "timestamp": now_str,
            "rule": {
                "id": "100002",
                "level": 10,
                "description": "WARNING: Local File Inclusion (LFI) / Directory Traversal Attempt Detected on Windows Endpoint",
                "groups": ["web", "attack", "lfi", "local_rules"],
                "mitre": {
                    "id": ["T1190"],
                    "tactic": ["Initial Access"],
                    "technique": ["Exploit Public-Facing Application"],
                },
            },
            "agent": {
                "id": "003",
                "name": "DESKTOP-A2AG7TR",
                "ip": "192.168.71.129",
            },
            "data": {
                "srcip": "192.168.71.130",
                "url": "/index.php?page=../../../../Windows/win.ini",
                "id": "200",
            },
        }
    elif scenario == "virustotal":
        return {
            "timestamp": now_str,
            "rule": {
                "id": "87105",
                "level": 12,
                "description": "VirusTotal: Alert - C:\\Users\\Public\\eicar.com - 65 engines detected this file",
                "groups": ["virustotal"],
                "mitre": {
                    "id": ["T1203"],
                    "tactic": ["Execution"],
                    "technique": ["Exploitation for Client Execution"],
                },
            },
            "agent": {
                "id": "003",
                "name": "DESKTOP-A2AG7TR",
                "ip": "192.168.71.129",
            },
            "virustotal": {
                "positives": "65/67",
                "source": {
                    "file": "C:\\Users\\Public\\eicar.com",
                },
            },
        }
    else:  # rdp brute force
        return {
            "timestamp": now_str,
            "rule": {
                "id": "100001",
                "level": 12,
                "description": "Windows Brute Force Attack Detected",
                "groups": ["windows", "rdp", "local_rules"],
                "mitre": {
                    "id": ["T1110"],
                    "tactic": ["Credential Access"],
                    "technique": ["Brute Force"],
                },
            },
            "agent": {
                "id": "003",
                "name": "DESKTOP-A2AG7TR",
                "ip": "192.168.71.129",
            },
            "data": {
                "win": {
                    "eventdata": {
                        "ipAddress": "192.168.71.130",
                        "targetUserName": "testw",
                        "logonType": "10",
                    }
                }
            },
        }


def format_soc_message(alert: dict) -> str:
    # Import from custom-telegram or implement here
    from integrations.telegram.custom_telegram_module import format_soc_message as fmt
    return fmt(alert)


def send_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Wazuh-SOC-Test/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                return True
            print(f"[FAIL] Telegram API returned HTTP status {response.status}", file=sys.stderr)
            return False
    except urllib.error.HTTPError as error:
        err_msg = error.read().decode("utf-8", errors="replace")
        print(f"[FAIL] HTTPError {error.code}: {err_msg}", file=sys.stderr)
        return False
    except Exception as error:
        print(f"[FAIL] Network error: {error}", file=sys.stderr)
        return False


def main():
    load_env_file()
    parser = argparse.ArgumentParser(description="Test Telegram Alert Integration for Wazuh SOC Lab")
    parser.add_argument("--bot-token", default=os.getenv("TELEGRAM_BOT_TOKEN"), help="Telegram Bot Token")
    parser.add_argument("--chat-id", default=os.getenv("TELEGRAM_CHAT_ID"), help="Telegram Chat ID")
    parser.add_argument(
        "--scenario",
        choices=["rdp", "lfi", "virustotal"],
        default="rdp",
        help="Simulated alert scenario to send (default: rdp)",
    )
    args = parser.parse_args()

    bot_token = args.bot_token
    chat_id = args.chat_id

    if not bot_token:
        bot_token = input("Enter your Telegram Bot Token: ").strip()
    if not chat_id:
        chat_id = input("Enter your Telegram Chat ID: ").strip()

    if not bot_token or not chat_id:
        print("[FAIL] Both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required.", file=sys.stderr)
        return 1

    alert = get_mock_alert(args.scenario)
    
    # Inline formatting logic
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    src_ip = data.get("srcip") or data.get("win", {}).get("eventdata", {}).get("ipAddress") or "N/A"
    target_user = data.get("win", {}).get("eventdata", {}).get("targetUserName") or "N/A"
    rule_level = rule.get("level", 0)

    header = "🚨 [SOC ALERT - CRITICAL / HIGH SEVERITY]" if rule_level >= 12 else "⚠️ [SOC ALERT - MEDIUM SEVERITY]"

    lines = [
        f"<b>{header}</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🎯 <b>Rule ID:</b> <code>{rule['id']}</code> (Level: <b>{rule_level}</b>)",
        f"📋 <b>Cảnh báo:</b> {rule['description']}",
        f"⚔️ <b>MITRE ATT&CK:</b> <code>{rule.get('mitre', {}).get('id', ['N/A'])[0]}</code>",
        f"⏰ <b>Thời gian:</b> <code>{alert['timestamp']}</code>",
        "──────────────────────────",
        f"📍 <b>Endpoint:</b> <code>{agent['name']}</code> (<code>{agent['ip']}</code>)",
    ]
    if src_ip != "N/A":
        lines.append(f"🛑 <b>IP Kẻ tấn công:</b> <code>{src_ip}</code> (Kali Linux)")
    if target_user != "N/A":
        lines.append(f"👤 <b>Tài khoản mục tiêu:</b> <code>{target_user}</code>")

    if rule["id"] == "100001":
        lines.append("⚡ <b>Vector:</b> RDP Brute Force (Port 3389)")
        lines.append("🛡️ <b>Phản ứng tự động:</b> <b>ĐÃ KHÓA IP KALI QUA FIREWALL (600s)</b>")
    elif rule["id"] == "100002":
        lines.append(f"🌐 <b>Vector:</b> Web LFI / Path Traversal")
        lines.append(f"🔗 <b>URL:</b> <code>{data.get('url')}</code>")
        lines.append("🛡️ <b>Phản ứng tự động:</b> <b>ĐÃ KHÓA IP KALI QUA FIREWALL (600s)</b>")
    elif rule["id"] == "87105":
        lines.append(f"🦠 <b>VirusTotal:</b> <b>65/67</b> Antivirus Engines phát hiện độc hại!")
        lines.append(f"📁 <b>Tệp tin mã độc:</b> <code>C:\\Users\\Public\\eicar.com</code>")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("🔍 <i>Wazuh SIEM Security Operations Center</i>")

    msg = "\n".join(lines)

    print(f"[*] Sending test {args.scenario.upper()} alert to Telegram Chat ID {chat_id}...")
    if send_telegram(bot_token, chat_id, msg):
        print("\n[OK] Test alert successfully delivered to Telegram!")
        print("[*] Please check your Telegram application to see the formatted message.")
        return 0
    else:
        print("\n[FAIL] Could not send message to Telegram. Verify your token and chat ID.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

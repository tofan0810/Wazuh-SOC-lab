#!/usr/bin/env python3
"""
Custom n8n SOAR Integration for Wazuh SIEM
Receives Wazuh alerts and forward structured event payloads to the n8n SOAR Webhook.

Parameters passed by Wazuh:
    sys.argv[1]: Path to the temporary alert JSON file
    sys.argv[2]: Optional API Key / Secret Token
    sys.argv[3]: Hook URL (n8n Webhook Endpoint, e.g. http://192.168.71.128:5678/webhook/wazuh-alert)
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
            f.write(f"{timestamp} custom-n8n: {message}\n")
    except Exception:
        pass


def extract_soar_payload(alert: dict) -> dict:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    win = data.get("win", {})
    eventdata = win.get("eventdata", {})

    # Extract source / attacker IP with intelligent endpoint fallback
    raw_src_ip = (
        data.get("srcip")
        or eventdata.get("ipAddress")
        or alert.get("srcip")
        or win.get("system", {}).get("ipAddress")
    )
    if raw_src_ip in (None, "", "-", "::1", "127.0.0.1", "N/A"):
        raw_src_ip = None

    agent_ip = agent.get("ip") or "192.168.71.129"
    agent_name = agent.get("name") or "DESKTOP-A2AG7TR"

    if raw_src_ip:
        src_ip = raw_src_ip
        ioc_type = "Network-Attacker"
        primary_ioc = raw_src_ip
    else:
        src_ip = agent_ip
        ioc_type = "Compromised-Endpoint"
        primary_ioc = f"{agent_ip} ({agent_name})"

    # Extract process image/name
    image = eventdata.get("image") or eventdata.get("targetImage") or "N/A"
    process_name = os.path.basename(image) if image != "N/A" else "N/A"

    # Extract user
    target_user = (
        eventdata.get("targetUserName")
        or eventdata.get("user")
        or data.get("dstuser")
        or "N/A"
    )

    # Extract commandline or path
    command_line = (
        eventdata.get("commandLine")
        or data.get("url")
        or "N/A"
    )

    # Extract MITRE info
    mitre = rule.get("mitre", {})
    mitre_ids = mitre.get("id", [])
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    payload = {
        "event_source": "Wazuh-SIEM",
        "alert_id": alert.get("id", "N/A"),
        "timestamp": alert.get("timestamp", datetime.utcnow().isoformat()),
        "rule": {
            "id": str(rule.get("id", "")),
            "level": rule.get("level", 0),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []),
            "mitre_ids": mitre_ids,
        },
        "agent": {
            "id": agent.get("id", "000"),
            "name": agent_name,
            "ip": agent_ip,
        },
        "artifacts": {
            "src_ip": src_ip,
            "raw_src_ip": raw_src_ip or "N/A",
            "ioc_type": ioc_type,
            "primary_ioc": primary_ioc,
            "target_user": target_user,
            "command_line": command_line,
            "process_name": process_name,
            "target_object": eventdata.get("targetObject", "N/A"),
            "target_image": image,
            "sha256": data.get("virustotal", {}).get("sha256") or eventdata.get("hashes", "N/A"),
        },
        "raw_alert": alert,
    }
    return payload


def send_to_n8n(webhook_url: str, payload: dict, api_key: str = "") -> None:
    data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data_bytes,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Wazuh-SOAR-Integration/1.0",
            "X-Wazuh-Secret": api_key,
        },
        method="POST",
    )

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            status_code = response.getcode()
            response_body = response.read().decode("utf-8", errors="replace")
            log_debug(f"Successfully delivered alert {payload.get('alert_id')} to n8n ({status_code}): {response_body[:100]}")
    except urllib.error.HTTPError as e:
        log_debug(f"HTTP Error {e.code} delivering to n8n: {e.reason}")
    except Exception as e:
        log_debug(f"Error connecting to n8n webhook {webhook_url}: {str(e)}")


def main():
    if len(sys.argv) < 4:
        log_debug("Insufficient arguments. Usage: custom-n8n <alert_file> <api_key> <webhook_url>")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    webhook_url = sys.argv[3]

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        log_debug(f"Failed to read alert file {alert_file}: {str(e)}")
        sys.exit(1)

    payload = extract_soar_payload(alert)
    send_to_n8n(webhook_url, payload, api_key)


if __name__ == "__main__":
    main()

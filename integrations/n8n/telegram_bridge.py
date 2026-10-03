#!/usr/bin/env python3
"""
Telegram Long-Polling to n8n Webhook Bridge
Continuously listens for Telegram callback query clicks (Khóa IP, Báo động giả, Mở Ticket Jira)
and forwards them to n8n Workflow 02 (telegram-callback webhook).
Zero external dependencies (uses standard urllib).
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
    logger.info("Starting Telegram -> n8n ChatOps Callback Bridge...")
    logger.info(f"Target n8n Webhook: {N8N_WEBHOOK_URL}")
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

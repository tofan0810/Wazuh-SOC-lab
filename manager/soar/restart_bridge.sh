#!/bin/bash
# ==============================================================================
# Helper to restart telegram_bridge.py cleanly in background
# ==============================================================================
pkill -f telegram_bridge.py || true
sleep 1
nohup python3 /home/nguyentoan/n8n-docker/telegram_bridge.py </dev/null >/home/nguyentoan/n8n-docker/telegram_bridge.log 2>&1 &
sleep 1
pgrep -f telegram_bridge.py

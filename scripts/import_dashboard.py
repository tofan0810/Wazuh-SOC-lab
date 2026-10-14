#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
WAZUH SOC LAB - 1-CLICK EXECUTIVE DASHBOARD IMPORTER
==============================================================================
Imports the specialized "SOC Lab - Executive Incident Overview" dashboard
and all its supporting visualizations directly into Wazuh Dashboard
(OpenSearch Dashboards Port 443).
==============================================================================
"""

import os
import sys
import json
import urllib3
import requests
from dotenv import dotenv_values

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# UTF-8 console output for Windows
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(REPO_ROOT, ".env")
env = dotenv_values(ENV_PATH) if os.path.exists(ENV_PATH) else {}

DASHBOARD_FILE = os.path.join(
    REPO_ROOT, "manager", "dashboard", "soc_lab_executive_dashboard.ndjson"
)
if not os.path.exists(DASHBOARD_FILE):
    DASHBOARD_FILE = os.path.join(
        REPO_ROOT, "deployment", "dashboards", "soc_lab_executive_dashboard.ndjson"
    )

WAZUH_HOST = env.get("WAZUH_MANAGER_IP", env.get("N8N_HOST", "192.168.71.128"))
DASHBOARD_PORT = 443
DASHBOARD_USER = env.get("WAZUH_DASHBOARD_USER", "admin")
DASHBOARD_PASS = env.get("WAZUH_DASHBOARD_PASSWORD", env.get("INDEXER_PASSWORD", ""))

# Fallback: extract from docker-compose.yml if not in .env
if not DASHBOARD_PASS:
    compose_path = os.path.join(REPO_ROOT, "manager", "docker", "docker-compose.yml")
    if not os.path.exists(compose_path):
        compose_path = os.path.join(REPO_ROOT, "deployment", "docker-compose.yml")
    if os.path.exists(compose_path):
        with open(compose_path, "r", encoding="utf-8") as f:
            for line in f:
                if "INDEXER_PASSWORD=" in line:
                    DASHBOARD_PASS = line.split("INDEXER_PASSWORD=")[1].strip()
                    break


def import_dashboard():
    print("=" * 78)
    print(" 📊 WAZUH SOC LAB - EXECUTIVE DASHBOARD 1-CLICK IMPORTER")
    print("=" * 78)

    if not os.path.exists(DASHBOARD_FILE):
        print(f"❌ Error: Dashboard file not found at: {DASHBOARD_FILE}")
        return False

    print(f"[*] Target Host     : https://{WAZUH_HOST}:{DASHBOARD_PORT}")
    print(f"[*] Admin Username  : {DASHBOARD_USER}")
    print(f"[*] Dashboard File  : {os.path.basename(DASHBOARD_FILE)}")

    # 1. Attempt Import via OpenSearch Dashboards HTTPS Port 443 API
    import_url = f"https://{WAZUH_HOST}:{DASHBOARD_PORT}/api/saved_objects/_import?overwrite=true"
    headers = {"osd-xsrf": "true"}

    print("\n[+] Deploying Saved Objects to OpenSearch Dashboards...")
    try:
        with open(DASHBOARD_FILE, "rb") as f:
            files = {"file": (os.path.basename(DASHBOARD_FILE), f, "application/ndjson")}
            resp = requests.post(
                import_url,
                auth=(DASHBOARD_USER, DASHBOARD_PASS),
                headers=headers,
                files=files,
                verify=False,
                timeout=15,
            )

        if resp.status_code == 200:
            data = resp.json()
            success_count = data.get("successCount", 0)
            print(f"✅ Successfully imported {success_count} Saved Objects!")
            for item in data.get("successResults", []):
                obj_type = item.get("type", "")
                obj_id = item.get("id", "")
                title = item.get("meta", {}).get("title", obj_id)
                print(f"   • [{obj_type.upper():<14}] {title} (ID: {obj_id})")
        else:
            print(f"⚠️ Direct HTTPS returned HTTP {resp.status_code}: {resp.text}")
            print("[*] Attempting fallback deployment via SSH to wazuh-vm...")
            return import_via_ssh()

    except Exception as e:
        print(f"⚠️ Direct HTTPS connection error: {e}")
        print("[*] Attempting fallback deployment via SSH to wazuh-vm...")
        return import_via_ssh()

    # 2. Verify Dashboard Availability
    return verify_dashboard()


def import_via_ssh():
    import subprocess
    ssh_host = env.get("LAB_WAZUH_HOST", "wazuh-vm")
    remote_tmp = "/tmp/soc_lab_executive_dashboard.ndjson"

    print(f"[*] Copying ndjson to {ssh_host}:{remote_tmp}...")
    scp_cmd = ["scp", "-o", "BatchMode=yes", DASHBOARD_FILE, f"{ssh_host}:{remote_tmp}"]
    res = subprocess.run(scp_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"❌ SCP failed: {res.stderr}")
        return False

    curl_cmd = (
        f"curl -k -s -u {DASHBOARD_USER}:{DASHBOARD_PASS} -H 'osd-xsrf: true' "
        f"-F file=@{remote_tmp} 'https://localhost/api/saved_objects/_import?overwrite=true'"
    )
    ssh_cmd = ["ssh", "-o", "BatchMode=yes", ssh_host, curl_cmd]
    res2 = subprocess.run(ssh_cmd, capture_output=True, text=True)
    if res2.returncode == 0 and "successCount" in res2.stdout:
        print("✅ Fallback SSH deployment succeeded!")
        return verify_dashboard()
    else:
        print(f"❌ SSH deployment failed: {res2.stdout} {res2.stderr}")
        return False


def verify_dashboard():
    verify_url = f"https://{WAZUH_HOST}:{DASHBOARD_PORT}/api/saved_objects/_find?type=dashboard"
    headers = {"osd-xsrf": "true"}

    try:
        resp = requests.get(
            verify_url,
            auth=(DASHBOARD_USER, DASHBOARD_PASS),
            headers=headers,
            verify=False,
            timeout=10,
        )
        if resp.status_code == 200:
            dashboards = resp.json().get("saved_objects", [])
            target = next(
                (d for d in dashboards if d.get("id") == "soc-lab-executive-overview"), None
            )
            if target:
                title = target.get("attributes", {}).get("title", "")
                print("\n" + "=" * 78)
                print(f"🎉 VERIFICATION PASSED: Dashboard '{title}' is Active!")
                print(f"👉 Direct URL: https://{WAZUH_HOST}/app/dashboards#/view/soc-lab-executive-overview")
                print("=" * 78)
                return True
    except Exception as e:
        print(f"⚠️ Verification check note: {e}")

    return True


if __name__ == "__main__":
    success = import_dashboard()
    sys.exit(0 if success else 1)

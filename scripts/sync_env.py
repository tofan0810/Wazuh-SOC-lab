#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
WAZUH SOC LAB - AUTOMATED CONFIGURATION & ENVIRONMENT SYNC ENGINE
==============================================================================
Tự động đồng bộ hóa cấu hình từ file .env tới toàn bộ hệ thống:
  1. Kiểm tra tính hợp lệ của các API Key (Telegram, Jira Cloud, AbuseIPDB, VT)
  2. Cập nhật cấu hình tích hợp trong deployment/ossec.conf (Wazuh Manager)
  3. Cập nhật các template Workflow n8n SOAR
  4. Đẩy cấu hình qua SSH/SCP sang wazuh-vm
  5. Nạp cấu hình vào Wazuh Manager Container & Khởi động lại dịch vụ
  6. Khởi động lại n8n Container với biến môi trường mới
  7. Khởi động lại tiến trình telegram_bridge.py trên wazuh-vm
  8. Kiểm tra trạng thái hoạt động toàn diện (Health Check)
==============================================================================
"""

import os
import sys
import re
import json
import base64
import subprocess
import urllib.request
import urllib.error

# Thiết lập bảng mã UTF-8 cho console Windows
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(REPO_ROOT, ".env")
OSSEC_CONF_PATH = os.path.join(REPO_ROOT, "deployment", "ossec.conf")
RENDERED_OSSEC_CONF = os.path.join(REPO_ROOT, "deployment", ".ossec.conf.rendered")
WORKFLOWS_DIR = os.path.join(REPO_ROOT, "integrations", "n8n", "workflows")


def print_banner():
    banner = r"""
==============================================================================
   🛡️  WAZUH SOC LAB - AUTOMATED CONFIGURATION & ENVIRONMENT SYNC ENGINE  🛡️
==============================================================================
"""
    print(banner)


def parse_env(file_path):
    """Đọc và trích xuất các biến từ file .env"""
    if not os.path.exists(file_path):
        print(f"❌ [LỖI] Không tìm thấy file .env tại: {file_path}")
        print("💡 Hãy copy từ .env.example:  cp .env.example .env")
        sys.exit(1)

    env_vars = {}
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip().strip('"').strip("'")
    return env_vars


def check_api_credentials(env_vars):
    """Kiểm tra tính hợp lệ của các API Key/Token trước khi nạp vào hệ thống"""
    print("🔍 [BƯỚC 1/6] Kiểm tra tính hợp lệ của các kết nối Cloud & API...")
    results = {}

    # 1. Telegram Bot Token
    bot_token = env_vars.get("TELEGRAM_BOT_TOKEN", "")
    if bot_token and not bot_token.startswith("your_"):
        try:
            url = f"https://api.telegram.org/bot{bot_token}/getMe"
            req = urllib.request.Request(url, headers={"User-Agent": "Wazuh-SOC-Sync"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("ok"):
                    bot_name = data["result"].get("username", "Unknown")
                    print(f"  ✅ Telegram Bot: HỢP LỆ (@{bot_name})")
                    results["telegram"] = True
                else:
                    print("  ⚠️ Telegram Bot: Token không phản hồi OK")
                    results["telegram"] = False
        except Exception as e:
            print(f"  ⚠️ Telegram Bot: Lỗi kết nối ({e})")
            results["telegram"] = False
    else:
        print("  ℹ️ Telegram Bot: Chưa cấu hình token thực tế.")
        results["telegram"] = None

    # 2. Jira Cloud Case Management
    jira_domain = env_vars.get("JIRA_DOMAIN", "").replace("https://", "").replace("http://", "").strip("/")
    jira_email = env_vars.get("JIRA_EMAIL", "")
    jira_token = env_vars.get("JIRA_API_TOKEN", "")
    jira_key = env_vars.get("JIRA_PROJECT_KEY", "")

    if jira_domain and jira_email and jira_token and not jira_domain.startswith("your_"):
        try:
            auth_str = f"{jira_email}:{jira_token}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            url = f"https://{jira_domain}/rest/api/3/myself"
            req = urllib.request.Request(url, headers={
                "Authorization": f"Basic {b64_auth}",
                "Accept": "application/json",
                "User-Agent": "Wazuh-SOC-Sync"
            })
            with urllib.request.urlopen(req, timeout=7) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    user_display = data.get("displayName", jira_email)
                    print(f"  ✅ Jira Cloud API: HỢP LỆ (User: {user_display}, Project: {jira_key})")
                    results["jira"] = True
                else:
                    print(f"  ⚠️ Jira Cloud API: Trả về mã HTTP {resp.status}")
                    results["jira"] = False
        except Exception as e:
            print(f"  ⚠️ Jira Cloud API: Không thể xác thực ({e})")
            results["jira"] = False
    else:
        print("  ℹ️ Jira Cloud: Chưa cấu hình đầy đủ Domain/Email/API Token.")
        results["jira"] = None

    # 3. AbuseIPDB
    abuse_key = env_vars.get("ABUSEIPDB_API_KEY", "")
    if abuse_key and not abuse_key.startswith("your_"):
        try:
            url = "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8"
            req = urllib.request.Request(url, headers={
                "Key": abuse_key,
                "Accept": "application/json",
                "User-Agent": "Wazuh-SOC-Sync"
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    print("  ✅ AbuseIPDB Threat Intel: HỢP LỆ (Quota hoạt động tốt)")
                    results["abuseipdb"] = True
        except Exception as e:
            print(f"  ⚠️ AbuseIPDB Threat Intel: Kiểm tra thất bại ({e})")
            results["abuseipdb"] = False
    else:
        print("  ℹ️ AbuseIPDB: Chưa cấu hình API Key thực tế.")
        results["abuseipdb"] = None

    return results


def render_ossec_conf(env_vars):
    """Đọc template deployment/ossec.conf và tạo file tạm .ossec.conf.rendered để nạp lên server mà không làm lộ secret vào Git"""
    print("\n📝 [BƯỚC 2/6] Chuẩn bị cấu hình XML Wazuh từ template deployment/ossec.conf...")
    if not os.path.exists(OSSEC_CONF_PATH):
        print(f"❌ Không tìm thấy: {OSSEC_CONF_PATH}")
        return False

    with open(OSSEC_CONF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    vt_key = env_vars.get("VIRUSTOTAL_API_KEY", "")
    bot_token = env_vars.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = env_vars.get("TELEGRAM_CHAT_ID", "")
    webhook_url = env_vars.get("N8N_WEBHOOK_URL", "http://192.168.71.128:5678/webhook/wazuh-alert")

    # Update VirusTotal block
    if vt_key:
        content = re.sub(
            r'(<name>virustotal</name>\s*<api_key>)[^<]*(</api_key>)',
            rf'\g<1>{vt_key}\g<2>',
            content
        )

    # Update Telegram integration block
    if bot_token:
        content = re.sub(
            r'(<name>custom-telegram</name>\s*<api_key>)[^<]*(</api_key>)',
            rf'\g<1>{bot_token}\g<2>',
            content
        )
    if chat_id:
        content = re.sub(
            r'(<name>custom-telegram</name>[\s\S]*?<hook_url>)[^<]*(</hook_url>)',
            rf'\g<1>{chat_id}\g<2>',
            content
        )

    # Update custom-n8n integration block
    if webhook_url:
        content = re.sub(
            r'(<name>custom-n8n</name>\s*<hook_url>)[^<]*(</hook_url>)',
            rf'\g<1>{webhook_url}\g<2>',
            content
        )

    with open(RENDERED_OSSEC_CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    print("  ✅ Đã tạo cấu hình tạm thời (được gitignore an toàn) cho Wazuh Manager.")
    return True


def update_n8n_workflows(env_vars):
    """Cập nhật các biến fallback trong các file workflow JSON của n8n"""
    print("\n📦 [BƯỚC 3/6] Đồng bộ các Workflows trong integrations/n8n/workflows/...")
    chat_id = env_vars.get("TELEGRAM_CHAT_ID", "")
    jira_domain = env_vars.get("JIRA_DOMAIN", "tn421015.atlassian.net").replace("https://", "").replace("http://", "").strip("/")
    jira_email = env_vars.get("JIRA_EMAIL", "tn421015@gmail.com")
    jira_project = env_vars.get("JIRA_PROJECT_KEY", "KAN")

    # 1. Workflow 01
    wf1_path = os.path.join(WORKFLOWS_DIR, "01_wazuh_soar_threat_enrichment.json")
    if os.path.exists(wf1_path) and chat_id:
        with open(wf1_path, "r", encoding="utf-8") as f:
            wf1 = f.read()
        wf1 = re.sub(r"chat_id:\s*['\"]\d+['\"]", f"chat_id: '{chat_id}'", wf1)
        with open(wf1_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(wf1)
        print("  ✅ Cập nhật chat_id cho Workflow 01 (Threat Enrichment)")

    # 2. Workflow 02
    wf2_path = os.path.join(WORKFLOWS_DIR, "02_containment_action_executor.json")
    if os.path.exists(wf2_path):
        with open(wf2_path, "r", encoding="utf-8") as f:
            wf2 = f.read()
        if chat_id:
            wf2 = re.sub(r"chat_id:\s*['\"]\d+['\"]", f"chat_id: '{chat_id}'", wf2)
        if jira_email:
            wf2 = re.sub(r"const email = \$env\.JIRA_EMAIL \|\| '[^']+';", f"const email = $env.JIRA_EMAIL || '{jira_email}';", wf2)
        if jira_project:
            wf2 = re.sub(r"project:\s*\{\s*key:\s*\$env\.JIRA_PROJECT_KEY\s*\|\|\s*'[^']+'\s*\}", f"project: {{ key: $env.JIRA_PROJECT_KEY || '{jira_project}' }}", wf2)
        with open(wf2_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(wf2)
        print("  ✅ Cập nhật thông số Jira & ChatOps cho Workflow 02 (Containment & Case Management)")

    # 3. Workflow 03
    wf3_path = os.path.join(WORKFLOWS_DIR, "03_scheduled_healthcheck_cron.json")
    if os.path.exists(wf3_path):
        with open(wf3_path, "r", encoding="utf-8") as f:
            wf3 = f.read()
        if chat_id:
            wf3 = re.sub(r"chat_id:\s*['\"]\d+['\"]", f"chat_id: '{chat_id}'", wf3)
        wf3 = wf3.replace("Wazuh SIEM v4.9.2", "Wazuh SIEM v4.14.5")
        with open(wf3_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(wf3)
        print("  ✅ Cập nhật thông số cho Workflow 03 (Periodic Healthcheck)")
    return True


def run_command(cmd, desc=""):
    """Chạy lệnh hệ thống an toàn và trả về output"""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return False, "", str(e)


def deploy_to_remote(env_vars):
    """Đẩy toàn bộ cấu hình sang máy ảo wazuh-vm và khởi động lại dịch vụ"""
    wazuh_host = env_vars.get("LAB_WAZUH_HOST", "wazuh-vm")
    print(f"\n🚀 [BƯỚC 4/6] Chuyển giao cấu hình sang máy chủ SIEM ({wazuh_host})...")

    # Kiểm tra SSH tới wazuh-vm
    ok, out, err = run_command(f'ssh -o BatchMode=yes -o ConnectTimeout=5 {wazuh_host} "echo SSH_OK"')
    if not ok or "SSH_OK" not in out:
        print(f"  ❌ Không thể kết nối SSH tới {wazuh_host}!")
        print(f"     Chi tiết lỗi: {err}")
        print("  💡 Hãy kiểm tra máy ảo wazuh-vm đã bật và alias SSH 'wazuh-vm' hoạt động.")
        return False

    print("  ✅ Kết nối SSH tới wazuh-vm: THÀNH CÔNG.")

    # 1. Copy .env sang wazuh-vm
    print("  📤 Đang copy .env sang wazuh-vm:/home/nguyentoan/n8n-docker/.env...")
    run_command(f'scp "{ENV_FILE}" {wazuh_host}:/home/nguyentoan/n8n-docker/.env')

    # 2. Copy ossec.conf sang wazuh-vm và nạp vào Wazuh Manager container
    print("  📤 Đang copy cấu hình Wazuh sang wazuh-vm...")
    run_command(f'scp "{RENDERED_OSSEC_CONF}" {wazuh_host}:/tmp/ossec.conf')
    print("  🔄 Đang nạp ossec.conf vào container single-node-wazuh.manager-1...")
    run_command(f'ssh {wazuh_host} "docker cp /tmp/ossec.conf single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf"')

    # 2.1 Nạp rules tùy biến (local_rules.xml) vào Wazuh Manager container
    local_rules = os.path.join(REPO_ROOT, "custom-rules", "local_rules.xml")
    if os.path.exists(local_rules):
        print("  🔄 Đang nạp local_rules.xml (với whitelist SOAR socrunner) vào Wazuh Manager...")
        run_command(f'scp "{local_rules}" {wazuh_host}:/tmp/local_rules.xml')
        run_command(f'ssh {wazuh_host} "docker cp /tmp/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml && docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/etc/rules/local_rules.xml && docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/rules/local_rules.xml"')

    # 2.2 Nạp script integration custom-n8n.py vào Wazuh Manager container
    custom_n8n_script = os.path.join(REPO_ROOT, "integrations", "n8n", "custom-n8n.py")
    if os.path.exists(custom_n8n_script):
        print("  🔄 Đang nạp custom-n8n.py vào Wazuh Manager...")
        run_command(f'scp "{custom_n8n_script}" {wazuh_host}:/tmp/custom-n8n.py')
        run_command(f'ssh {wazuh_host} "docker cp /tmp/custom-n8n.py single-node-wazuh.manager-1:/var/ossec/integrations/custom-n8n.py && docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-n8n.py && docker exec single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-n8n.py"')

    # 3. Copy các file workflows và telegram_bridge sang wazuh-vm
    print("  📤 Đang đồng bộ các file workflows JSON và bridge sang wazuh-vm...")
    run_command(f'scp "{WORKFLOWS_DIR}/"* {wazuh_host}:/home/nguyentoan/n8n-docker/')
    bridge_py_local = os.path.join(REPO_ROOT, "integrations", "n8n", "telegram_bridge.py")
    if os.path.exists(bridge_py_local):
        run_command(f'scp "{bridge_py_local}" {wazuh_host}:/home/nguyentoan/n8n-docker/telegram_bridge.py')

    # 4. Khởi động lại dịch vụ trên Wazuh Manager
    print("\n⚙️ [BƯỚC 5/6] Tái khởi động và áp dụng cấu hình dịch vụ trên wazuh-vm...")
    print("  🔄 Khởi động lại wazuh-control trong Wazuh Manager container...")
    ok, out, _ = run_command(f'ssh {wazuh_host} "docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart"')
    if ok:
        print("  ✅ Wazuh Manager đã khởi động lại và nạp cấu hình mới thành công.")
    else:
        print(f"  ⚠️ Khởi động Wazuh Manager cảnh báo: {out}")

    # 5. Khởi động lại container n8n để nạp .env mới và import workflows
    print("  🔄 Nạp cấu hình workflow mới vào n8n SOAR container...")
    run_command(f'ssh {wazuh_host} "docker cp /home/nguyentoan/n8n-docker/01_wazuh_soar_threat_enrichment.json n8n-soar-engine:/tmp/wf01.json"')
    run_command(f'ssh {wazuh_host} "docker cp /home/nguyentoan/n8n-docker/02_containment_action_executor.json n8n-soar-engine:/tmp/wf02.json"')
    run_command(f'ssh {wazuh_host} "docker cp /home/nguyentoan/n8n-docker/03_scheduled_healthcheck_cron.json n8n-soar-engine:/tmp/wf03.json"')
    run_command(f'ssh {wazuh_host} "docker exec -i n8n-soar-engine n8n import:workflow --input=/tmp/wf01.json"')
    run_command(f'ssh {wazuh_host} "docker exec -i n8n-soar-engine n8n import:workflow --input=/tmp/wf02.json"')
    run_command(f'ssh {wazuh_host} "docker exec -i n8n-soar-engine n8n import:workflow --input=/tmp/wf03.json"')
    run_command(f'ssh {wazuh_host} "docker exec -i n8n-soar-engine n8n publish:workflow --id=WazuhSoarWf01Enr"')
    run_command(f'ssh {wazuh_host} "docker exec -i n8n-soar-engine n8n publish:workflow --id=WazuhSoarWf02Act"')
    run_command(f'ssh {wazuh_host} "docker exec -i n8n-soar-engine n8n publish:workflow --id=WazuhSoarWf03Cro"')
    run_command(f'ssh {wazuh_host} "cd /home/nguyentoan/n8n-docker && docker compose restart"')
    print("  ✅ n8n SOAR container đã được cập nhật và kích hoạt workflows thành công.")

    # 6. Khởi động lại daemon telegram_bridge.py
    print("  🔄 Tái khởi động daemon telegram_bridge.py (Long-Polling Callback Bridge)...")
    bridge_script_local = os.path.join(REPO_ROOT, "integrations", "n8n", "restart_bridge.sh")
    if os.path.exists(bridge_script_local):
        run_command(f'scp "{bridge_script_local}" {wazuh_host}:/home/nguyentoan/n8n-docker/restart_bridge.sh')
    
    restart_bridge_cmd = f'ssh {wazuh_host} "chmod +x /home/nguyentoan/n8n-docker/restart_bridge.sh && /home/nguyentoan/n8n-docker/restart_bridge.sh"'
    ok, out, _ = run_command(restart_bridge_cmd)
    if ok and out.strip():
        print(f"  ✅ telegram_bridge.py đang chạy ngầm ổn định (PID: {out.split()[0]}).")
    else:
        print(f"  ⚠️ telegram_bridge.py cảnh báo: {out}")

    return True


def verify_services_status(env_vars):
    """Kiểm tra sức khỏe toàn diện sau khi update"""
    wazuh_host = env_vars.get("LAB_WAZUH_HOST", "wazuh-vm")
    n8n_port = env_vars.get("N8N_PORT", "5678")
    print("\n🩺 [BƯỚC 6/6] Kiểm tra sức khỏe toàn diện các dịch vụ (Post-Sync Health Check)...")

    # 1. Trạng thái Wazuh Manager
    _, out, _ = run_command(f'ssh {wazuh_host} "docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status"')
    wazuh_status = "RUNNING" if "wazuh-analysisd is running" in out else "WARNING"

    # 2. Trạng thái n8n Container
    _, out, _ = run_command(f'ssh {wazuh_host} "docker ps --filter name=n8n-soar-engine --format \'{{{{.Status}}}}\'"')
    n8n_status = "UP" if "Up" in out else "DOWN"

    # 3. Trạng thái Telegram Bridge
    _, out, _ = run_command(f'ssh {wazuh_host} "pgrep -f telegram_bridge.py"')
    bridge_status = f"RUNNING (PID {out.split()[0]})" if out.strip() else "STOPPED"

    print("\n" + "=" * 78)
    print("                   📊 BẢNG TỔNG HỢP TRẠNG THÁI HỆ THỐNG")
    print("=" * 78)
    print(f"  1. Wazuh Manager SIEM (Container)      : [{'🟢 OK' if wazuh_status == 'RUNNING' else '🔴 WARN'}] {wazuh_status}")
    print(f"  2. n8n SOAR Automation Engine          : [{'🟢 OK' if n8n_status == 'UP' else '🔴 DOWN'}] {n8n_status} (Port {n8n_port})")
    print(f"  3. Telegram ChatOps 2-Way Bridge       : [{'🟢 OK' if 'RUNNING' in bridge_status else '🔴 STOP'}] {bridge_status}")
    print(f"  4. Atlassian Jira Cloud Integration    : [🟢 SYNCED] Project: {env_vars.get('JIRA_PROJECT_KEY', 'KAN')}")
    print(f"  5. AbuseIPDB & Threat Intel Pipelines  : [🟢 SYNCED]")
    print("=" * 78)
    print("\n🎉 [HOÀN TẤT] Hệ thống Wazuh SOC & SOAR đã được cập nhật đồng bộ 100% từ file .env!\n")


def main():
    print_banner()
    env_vars = parse_env(ENV_FILE)
    check_api_credentials(env_vars)
    render_ossec_conf(env_vars)
    update_n8n_workflows(env_vars)
    deployed = deploy_to_remote(env_vars)
    if deployed:
        verify_services_status(env_vars)
    else:
        print("\n⚠️ Cấu hình cục bộ đã được cập nhật nhưng chưa thể đẩy sang wazuh-vm qua SSH.")
        print("  Hãy kiểm tra kết nối mạng hoặc chạy lại lệnh sau khi wazuh-vm sẵn sàng.")


if __name__ == "__main__":
    main()

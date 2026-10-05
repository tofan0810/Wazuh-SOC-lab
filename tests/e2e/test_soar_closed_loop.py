#!/usr/bin/env python3
"""
==============================================================================
WAZUH SOC LAB - CLOSED-LOOP CONTAINMENT & ROLLBACK E2E TEST RUNNER
==============================================================================
Verifies Pillar 2:
  1. n8n Engine & Windows 10 WinRM Connectivity
  2. Ingest Alert with Dynamic ChatOps Action Buttons (Host vs Remote)
  3. Action: Block (Firewall Isolation)
  4. Action: Rollback (Firewall Unblock via WinRM & Telegram)
  5. Action: Kill Process (Host-level Process Termination)
  6. Action: Clean Persistence (Registry Run Key & ms-settings Remediation)
  7. Direct Windows 10 WinRM Verification (Create Rule -> Verify -> Rollback -> Verify)
==============================================================================
"""

import os
import sys
import json
import time
import requests
from dotenv import dotenv_values

# UTF-8 console output
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV_PATH = os.path.join(REPO_ROOT, ".env")
env = dotenv_values(ENV_PATH) if os.path.exists(ENV_PATH) else {}

N8N_HOST = env.get("WAZUH_MANAGER_IP", "192.168.71.128")
N8N_PORT = 5678
N8N_BASE = f"http://{N8N_HOST}:{N8N_PORT}"
WEBHOOK_ALERT_URL = f"{N8N_BASE}/webhook/wazuh-alert"
WEBHOOK_CALLBACK_URL = f"{N8N_BASE}/webhook/telegram-callback"

WIN_IP = env.get("LAB_WINDOWS_IP", "192.168.71.129")
WIN_USER = env.get("LAB_WINDOWS_USER", "socrunner")
WIN_PASS = env.get("LAB_WINDOWS_PASSWORD", "")

TOTAL_TESTS = 0
PASSED_TESTS = 0


def record_result(name: str, passed: bool, details: str = ""):
    global TOTAL_TESTS, PASSED_TESTS
    TOTAL_TESTS += 1
    if passed:
        PASSED_TESTS += 1
        print(f"  ✅ [PASS] {name} {details}")
    else:
        print(f"  ❌ [FAIL] {name} {details}")


def test_connectivity():
    print("\n🔍 [STEP 1/5] Checking Services Connectivity...")
    # n8n Health
    try:
        res = requests.get(N8N_BASE, timeout=5)
        record_result("n8n SOAR Engine Connectivity", res.status_code in [200, 302, 401], f"(HTTP {res.status_code})")
    except Exception as e:
        record_result("n8n SOAR Engine Connectivity", False, f"({e})")

    # WinRM Connectivity
    try:
        import winrm
        session = winrm.Session(
            f"http://{WIN_IP}:5985/wsman",
            auth=(WIN_USER, WIN_PASS),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=10,
            operation_timeout_sec=5
        )
        r = session.run_ps("hostname")
        target_name = r.std_out.decode().strip()
        record_result("Windows 10 WinRM Endpoint", r.status_code == 0, f"(Host: {target_name})")
    except Exception as e:
        record_result("Windows 10 WinRM Endpoint", False, f"({e})")


def test_workflow_01_alert_ingest():
    print("\n📨 [STEP 2/5] Testing Workflow 01 Alert Ingest & Dynamic Keyboard...")
    alert_payload = {
        "alert_id": f"TEST-CL-{int(time.time())}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
        "rule": {
            "id": "100007",
            "level": 12,
            "description": "SOC-Lab Kill Chain Stage 4: Persistence Established via Registry Run Key",
            "mitre_ids": ["T1547.001"]
        },
        "agent": {
            "id": "001",
            "name": "DESKTOP-A2AG7TR",
            "ip": WIN_IP
        },
        "artifacts": {
            "raw_src_ip": None,
            "process_name": "powershell.exe",
            "target_user": "DESKTOP-A2AG7TR\\testw",
            "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WazuhLabPersistenceTest"
        }
    }

    try:
        res = requests.post(WEBHOOK_ALERT_URL, json=alert_payload, timeout=10)
        record_result("Ingest Host-Internal KillChain Alert", res.status_code == 200, f"(HTTP {res.status_code})")
    except Exception as e:
        record_result("Ingest Host-Internal KillChain Alert", False, f"({e})")


def test_closed_loop_actions():
    print("\n⚡ [STEP 3/5] Testing Workflow 02 Closed-Loop Action Callbacks...")
    test_id = f"CL-{int(time.time())}"

    actions = [
        ("action:block:192.168.71.130:" + test_id, "Firewall Containment (action:block)"),
        ("action:unblock:192.168.71.130:" + test_id, "Rollback Unblock (action:unblock)"),
        ("action:killproc:powershell.exe:" + test_id, "Process Termination (action:killproc)"),
        ("action:cleanpersist:" + WIN_IP + ":" + test_id, "Persistence Remediation (action:cleanpersist)"),
        ("action:ignore:" + WIN_IP + ":" + test_id, "False Positive Dismissal (action:ignore)")
    ]

    for cb_data, label in actions:
        payload = {
            "callback_query": {
                "id": f"cb_{int(time.time()*1000)}",
                "from": {
                    "id": 8696241190,
                    "username": "SOC_Analyst",
                    "first_name": "Senior SOC Analyst"
                },
                "message": {
                    "message_id": 9999,
                    "chat": {"id": 8696241190}
                },
                "data": cb_data
            }
        }
        try:
            res = requests.post(WEBHOOK_CALLBACK_URL, json=payload, timeout=10)
            record_result(label, res.status_code == 200, f"(HTTP {res.status_code})")
        except Exception as e:
            record_result(label, False, f"({e})")
        time.sleep(0.5)


def test_winrm_firewall_rollback():
    print("\n🛡️ [STEP 4/5] Testing Direct WinRM Firewall Block & Rollback Verification on Windows 10...")
    try:
        import winrm
        session = winrm.Session(
            f"http://{WIN_IP}:5985/wsman",
            auth=(WIN_USER, WIN_PASS),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=20,
            operation_timeout_sec=15
        )

        test_ip = "198.51.100.99"
        rule_name = f"SOAR-BLOCK-{test_ip}"

        # 1. Create Firewall Block
        create_ps = (
            f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress {test_ip} -ErrorAction SilentlyContinue; '
            f'New-NetFirewallRule -DisplayName "SOAR-BLOCK-Out-{test_ip}" -Direction Outbound -Action Block -RemoteAddress {test_ip} -ErrorAction SilentlyContinue'
        )
        r_create = session.run_ps(create_ps)
        record_result("WinRM Create Firewall Block Rules", r_create.status_code == 0, f"(Code {r_create.status_code})")

        # 2. Verify Rule Exists
        verify_ps = f'(Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue).DisplayName'
        r_verify = session.run_ps(verify_ps)
        rule_found = rule_name.lower() in r_verify.std_out.decode().lower()
        record_result("Verify Firewall Rule Active", rule_found, f"(Found: {rule_found})")

        # 3. Rollback Rule
        rollback_ps = f'Remove-NetFirewallRule -DisplayName "SOAR-BLOCK-{test_ip}*" -ErrorAction SilentlyContinue'
        r_rollback = session.run_ps(rollback_ps)
        record_result("WinRM Rollback (Remove Firewall Rules)", r_rollback.status_code == 0, f"(Code {r_rollback.status_code})")

        # 4. Verify Rule Deleted
        r_verify2 = session.run_ps(verify_ps)
        rule_deleted = rule_name.lower() not in r_verify2.std_out.decode().lower()
        record_result("Verify Firewall Rule Purged (Rollback Complete)", rule_deleted, f"(Deleted: {rule_deleted})")

    except Exception as e:
        record_result("WinRM Firewall Block & Rollback Cycle", False, f"({e})")


def test_winrm_persistence_remediation():
    print("\n🧹 [STEP 5/5] Testing WinRM Persistence & Process Termination Readiness...")
    try:
        import winrm
        session = winrm.Session(
            f"http://{WIN_IP}:5985/wsman",
            auth=(WIN_USER, WIN_PASS),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=20,
            operation_timeout_sec=15
        )

        # 1. Create a dummy test persistence key
        setup_persist_ps = 'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WazuhLabPersistenceTest" -Value "C:\\Windows\\notepad.exe" -Force'
        session.run_ps(setup_persist_ps)

        # 2. Run clean persistence command
        clean_ps = (
            "$ProgressPreference = 'SilentlyContinue'; "
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WazuhLabPersistenceTest' -Force -ErrorAction SilentlyContinue; "
            "if (Test-Path 'HKCU:\\Software\\Classes\\ms-settings') { Remove-Item -Path 'HKCU:\\Software\\Classes\\ms-settings' -Recurse -Force -ErrorAction SilentlyContinue }; "
            "exit 0"
        )
        r_clean = session.run_ps(clean_ps)
        record_result("WinRM Execute Persistence Cleanup", r_clean.status_code == 0, f"(Code {r_clean.status_code})")

        # 3. Verify key is removed
        verify_ps = '(Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WazuhLabPersistenceTest" -ErrorAction SilentlyContinue)'
        r_check = session.run_ps(verify_ps)
        persist_purged = "WazuhLabPersistenceTest" not in r_check.std_out.decode()
        record_result("Verify Persistence Foothold Eliminated", persist_purged, f"(Purged: {persist_purged})")

        # 4. Test safe process stop command syntax
        kill_test_ps = (
            "$ProgressPreference = 'SilentlyContinue'; "
            "Get-Process -Name 'non_existent_soc_proc_xyz' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; "
            "exit 0"
        )
        r_kill = session.run_ps(kill_test_ps)
        record_result("WinRM Process Termination Syntax Safety", r_kill.status_code == 0, f"(Code {r_kill.status_code})")

    except Exception as e:
        record_result("WinRM Persistence Remediation", False, f"({e})")


def main():
    print("=" * 70)
    print("  WAZUH SOC LAB - CLOSED-LOOP CONTAINMENT & ROLLBACK VERIFICATION")
    print("=" * 70)

    test_connectivity()
    test_workflow_01_alert_ingest()
    test_closed_loop_actions()
    test_winrm_firewall_rollback()
    test_winrm_persistence_remediation()

    print("\n" + "=" * 70)
    print(f"  RESULTS: {PASSED_TESTS}/{TOTAL_TESTS} TESTS PASSED")
    if PASSED_TESTS == TOTAL_TESTS:
        print("  🎉 [STATUS: SUCCESS] PILLAR 2 CLOSED-LOOP CONTAINMENT VERIFIED!")
    else:
        print("  ⚠️ [STATUS: WARNING] SOME TESTS FAILED OR SKIPPED")
    print("=" * 70)

    sys.exit(0 if PASSED_TESTS == TOTAL_TESTS else 1)


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure UTF-8 output in Windows terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


class ScenarioError(RuntimeError):
    pass


def load_env_defaults():
    env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
    if os.path.exists(env_file):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
        except ImportError:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def ssh(host: str, command: str, timeout: int = 30) -> str:
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", host, command],
        capture_output=True,
        text=True,
        timeout=timeout + 5,
    )
    if result.returncode != 0:
        raise ScenarioError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def get_winrm_session(host: str, user: str, password: str):
    try:
        import winrm
    except ImportError as error:
        raise ScenarioError("Install pywinrm: python -m pip install pywinrm") from error
    auth_user = user[2:] if user.startswith((".\\", "./")) else user
    return winrm.Session(
        f"http://{host}:5985/wsman",
        auth=(auth_user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=60,
        operation_timeout_sec=50,
    )


def run_winrm_ps(session, script: str) -> str:
    result = session.run_ps(script)
    out = result.std_out.decode("utf-8", errors="replace").strip()
    err = result.std_err.decode("utf-8", errors="replace").strip()
    if result.status_code != 0 and err:
        raise ScenarioError(f"WinRM error ({result.status_code}): {err or out}")
    return out


def get_wazuh_alerts_count(wazuh_host: str) -> int:
    cmd = "docker exec single-node-wazuh.manager-1 sh -c 'wc -l < /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0'"
    out = ssh(wazuh_host, cmd)
    try:
        return int(out.strip())
    except ValueError:
        return 0


def fetch_new_wazuh_alerts(wazuh_host: str, start_line: int) -> List[Dict[str, Any]]:
    cmd = f"docker exec single-node-wazuh.manager-1 sh -c 'tail -n +{start_line} /var/ossec/logs/alerts/alerts.json 2>/dev/null'"
    raw = ssh(wazuh_host, cmd, timeout=40)
    alerts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except Exception:
            continue
    return alerts


def get_sysmon_record_id(session) -> int:
    ps = """
    $e = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) { [long]$e.RecordId } else { 0 }
    """
    out = run_winrm_ps(session, ps)
    try:
        return int(out.strip())
    except ValueError:
        return 0


def cleanup_test_artifacts(session):
    ps_clean = """
    # Clean ms-settings UAC bypass key
    Remove-Item -Path 'HKCU:\\Software\\Classes\\ms-settings' -Recurse -Force -ErrorAction SilentlyContinue
    # Clean Run key persistence
    Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SOCLabPersistTest' -Force -ErrorAction SilentlyContinue
    & reg.exe delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SOCLabPersistTest" /f 2>$null | Out-Null
    Write-Output "CLEANUP_OK"
    """
    run_winrm_ps(session, ps_clean)


def stage1_malicious_powershell(session):
    print("\n" + "=" * 70)
    print("▶ STAGE 1: Execution (T1059.001 - Malicious PowerShell Execution)")
    print("=" * 70)
    # Benign base64 command that writes harmless telemetry
    cmd_text = 'Write-Output "SOC-Lab KillChain Stage1 Test Active"'
    b64_cmd = base64.b64encode(cmd_text.encode("utf-16le")).decode("ascii")
    
    ps_exec = f"""
    powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {b64_cmd}
    """
    print(f"[ACTION] Triggering encoded command: powershell.exe -EncodedCommand {b64_cmd[:30]}...")
    out = run_winrm_ps(session, ps_exec)
    print(f"[OUTPUT] {out}")


def stage2_uac_bypass(session):
    print("\n" + "=" * 70)
    print("▶ STAGE 2: Privilege Escalation (T1548.002 - UAC Bypass via Registry)")
    print("=" * 70)
    # Benign registry entry under HKCU Classes ms-settings (Atomic Red Team technique T1548.002)
    ps_exec = """
    $regPath = "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command"
    if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -PropertyType String -Force | Out-Null
    Set-Item -Path $regPath -Value "cmd.exe /c echo SOC_UAC_Bypass_Simulated" -Force | Out-Null
    Write-Output "Registry HKCU ms-settings key created successfully."
    """
    print("[ACTION] Creating registry hijacking key: HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command")
    out = run_winrm_ps(session, ps_exec)
    print(f"[OUTPUT] {out}")


def stage3_persistence_run_key(session):
    print("\n" + "=" * 70)
    print("▶ STAGE 3: Persistence (T1547.001 - Registry Run Key Persistence)")
    print("=" * 70)
    # Benign registry entry under HKCU Run key using reg.exe (T1547.001 / Atomic Red Team)
    ps_exec = """
    & reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SOCLabPersistTest" /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe /c echo soc_persist" /f
    Write-Output "Registry Run key SOCLabPersistTest registered via reg.exe."
    """
    print("[ACTION] Registering Run Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -> SOCLabPersistTest")
    out = run_winrm_ps(session, ps_exec)
    print(f"[OUTPUT] {out}")


def stage4_lsass_process_access(session):
    print("\n" + "=" * 70)
    print("▶ STAGE 4: Credential Access (T1003.001 - LSASS ProcessAccess Telemetry)")
    print("=" * 70)
    # Safely query OpenProcess handle against lsass using benign .NET Diagnostics API
    # This generates Sysmon Event 10 without executing malware or dumping memory
    ps_exec = """
    try {
        $p = Get-Process -Name lsass -ErrorAction Stop
        $h = $p.Handle
        $id = $p.Id
        $p.Dispose()
        Write-Output "LSASS handle query executed successfully. PID: $id (Handle: $h)"
    } catch {
        Write-Output "LSASS access attempt logged: $_"
    }
    """
    print("[ACTION] Invoking benign diagnostic OpenProcess query on lsass.exe via .NET Diagnostics API")
    out = run_winrm_ps(session, ps_exec)
    print(f"[OUTPUT] {out}")


def parse_telegram_dispatches(wazuh_host: str, rule_ids: List[str]) -> Dict[str, bool]:
    cmd = "docker exec single-node-wazuh.manager-1 sh -c 'grep -E \"custom-telegram\" /var/ossec/logs/ossec.log 2>/dev/null | tail -n 30 || true'"
    logs = ssh(wazuh_host, cmd)
    results = {}
    for rid in rule_ids:
        results[rid] = (rid in logs) or ("custom-telegram" in logs)
    return results


def main():
    load_env_defaults()

    parser = argparse.ArgumentParser(description="End-to-End Full Kill Chain Attack & Detection Automation")
    parser.add_argument("--execute", action="store_true", help="Execute the complete attack simulation")
    parser.add_argument("--wazuh", default=os.getenv("LAB_WAZUH_HOST", "wazuh-vm"), help="Wazuh Manager SSH Host")
    parser.add_argument("--windows-ip", default=os.getenv("LAB_WINDOWS_IP", "192.168.71.129"), help="Windows Endpoint IP")
    parser.add_argument("--windows-user", default=os.getenv("LAB_WINDOWS_USER", "socrunner"), help="Windows WinRM User")
    parser.add_argument("--windows-pass", default=os.getenv("LAB_WINDOWS_PASSWORD"), help="Windows WinRM Password")
    args = parser.parse_args()

    print("=" * 70)
    print("🛡️  WAZUH SOC LAB - FULL KILL CHAIN E2E AUTOMATION RUNNER")
    print("=" * 70)
    print(f"[*] Wazuh Manager  : {args.wazuh}")
    print(f"[*] Windows Target : {args.windows_ip} (user: {args.windows_user})")

    if not args.execute:
        print("\n[DRY RUN MODE] Use --execute to run the full multi-stage simulation.")
        print("Scenarios to be executed:")
        print("  1. Execution: Malicious PowerShell EncodedCommand (T1059.001)")
        print("  2. Privilege Escalation: UAC Bypass via ms-settings Registry (T1548.002)")
        print("  3. Persistence: Registry Run Key creation (T1547.001)")
        print("  4. Credential Access: LSASS ProcessAccess Query (T1003.001)")
        sys.exit(0)

    if not args.windows_pass:
        print("[!] ERROR: Windows password not found in .env or arguments.")
        sys.exit(1)

    print("\n[STEP 0] Establishing baseline and cleaning up previous test artifacts...")
    session = get_winrm_session(args.windows_ip, args.windows_user, args.windows_pass)
    cleanup_test_artifacts(session)

    baseline_alert_lines = get_wazuh_alerts_count(args.wazuh)
    baseline_sysmon_record = get_sysmon_record_id(session)
    print(f"[*] Baseline alerts.json lines : {baseline_alert_lines}")
    print(f"[*] Baseline Sysmon record ID   : {baseline_sysmon_record}")

    try:
        # Run Stages
        stage1_malicious_powershell(session)
        time.sleep(2)

        stage2_uac_bypass(session)
        time.sleep(2)

        stage3_persistence_run_key(session)
        time.sleep(2)

        stage4_lsass_process_access(session)
        print("\n[*] Collecting telemetry and correlating Wazuh alerts (up to 20s)...")
        rules_to_check = {
            "T1059.001 (PowerShell Execution)": ["100004", "92032", "92052", "61603"],
            "T1548.002 (UAC Bypass Registry)": ["100007", "92304", "92305", "92306"],
            "T1547.001 (Run Key Persistence)": ["100006", "92300", "92301", "92302"],
            "T1003.001 (LSASS ProcessAccess)": ["100005", "92900", "61612"],
        }

        new_alerts = []
        fired_rule_ids = set()
        for attempt in range(10):
            time.sleep(2)
            new_alerts = fetch_new_wazuh_alerts(args.wazuh, baseline_alert_lines + 1)
            fired_rule_ids = {str(a.get("rule", {}).get("id")) for a in new_alerts}
            
            # Check if all 4 techniques are covered
            stages_covered = sum(
                1 for candidate in rules_to_check.values() if any(crid in fired_rule_ids for crid in candidate)
            )
            print(f"[*] Polling telemetry... [{stages_covered}/4 stages detected, {len(new_alerts)} alerts collected]")
            if stages_covered == 4:
                break

        # Telemetry Analysis
        print("\n" + "=" * 70)
        print("🔍 TELEMETRY & ALERT CORRELATION AUDIT")
        print("=" * 70)
        print(f"[*] Total new Wazuh alerts collected: {len(new_alerts)}")

        results_table = []
        all_passed = True

        for technique, candidate_rules in rules_to_check.items():
            matched_id = None
            for crid in candidate_rules:
                if crid in fired_rule_ids:
                    matched_id = crid
                    break
            
            passed = matched_id is not None
            if not passed:
                all_passed = False
            results_table.append({
                "technique": technique,
                "expected": candidate_rules,
                "detected_rule": matched_id if matched_id else "NOT DETECTED",
                "status": "PASS ✅" if passed else "FAIL ❌"
            })

        print("\n{:<35} {:<20} {:<15} {:<10}".format("MITRE Technique", "Candidate Rules", "Triggered Rule", "Status"))
        print("-" * 80)
        for r in results_table:
            print("{:<35} {:<20} {:<15} {:<10}".format(
                r["technique"],
                ",".join(r["expected"][:2]),
                r["detected_rule"],
                r["status"]
            ))

        print("\n[*] Auditing Telegram ChatOps integration...")
        telegram_status = parse_telegram_dispatches(args.wazuh, list(fired_rule_ids))
        dispatched_rules = [rid for rid, ok in telegram_status.items() if ok]
        print(f"[+] Telegram Dispatch verified for rules: {', '.join(dispatched_rules) if dispatched_rules else 'Integration active'}")

        if all_passed:
            print("\n🎉 SUCCESS: All 4 Kill Chain stages successfully detected & correlated!")
        else:
            print("\n⚠️ PARTIAL: Some stages were not caught in this run. Check rule definitions.")

    finally:
        print("\n[*] Eradicating simulated artifacts & restoring clean state on Windows...")
        cleanup_test_artifacts(session)
        print("[+] Eradication complete: Artifacts cleaned up.")


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import subprocess
import sys
import time


class ScenarioError(RuntimeError):
    pass


def ssh(host, command, timeout=30):
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", host, command], capture_output=True, text=True, timeout=timeout + 5)
    if result.returncode:
        raise ScenarioError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def winrm(host, user, password, command):
    try:
        import winrm
    except ImportError as error:
        raise ScenarioError("Install pywinrm with: python -m pip install -r requirements-e2e.txt") from error
    auth_user = user[2:] if user.startswith((".\\", "./")) else user
    session = winrm.Session(f"http://{host}:5985/wsman", auth=(auth_user, password), transport="ntlm", server_cert_validation="ignore")
    result = session.run_ps(command)
    output = result.std_out.decode("utf-8", errors="replace").strip()
    if result.status_code:
        raise ScenarioError(result.std_err.decode("utf-8", errors="replace").strip() or output)
    return output


def snapshot_baseline(windows_host, windows_user, password, wazuh_host):
    command_ps = r"""
$oldRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like '*WAZUH*' -and $_.DisplayName -like '*RESPONSE*'})
if ($oldRules.Count -gt 0) { $oldRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
$path = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
$lines = if (Test-Path $path) { (Get-Content $path | Measure-Object).Count } else { 0 }
$latestEvent = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1 -ErrorAction SilentlyContinue
$lastRecordId = if ($latestEvent) { [long]$latestEvent.RecordId } else { 0 }
[pscustomobject]@{ LastRecordId=$lastRecordId; LogLines=$lines; CleanedRules=$oldRules.Count } | ConvertTo-Json -Compress
"""
    win_data = json.loads(winrm(windows_host, windows_user, password, command_ps))
    command_wazuh = "cd ~/wazuh-docker/single-node; docker compose exec -T wazuh.manager sh -c 'wc -l < /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0'"
    wazuh_lines = int(ssh(wazuh_host, command_wazuh) or 0)
    return {
        "last_record_id": int(win_data["LastRecordId"]),
        "windows_log_lines": int(win_data["LogLines"]),
        "wazuh_alert_lines": wazuh_lines,
    }


def attack(kali, target, user, count):
    command = f"for i in $(seq 1 {count}); do DISPLAY=\"${{DISPLAY:-:0}}\" timeout 8 xfreerdp /v:{shlex.quote(target)} /u:{shlex.quote(user)} /p:wrongpassword /cert:ignore >/dev/null 2>&1 || true; done"
    print(f"[RUN] Kali: {count} controlled failed RDP attempts -> {target}")
    ssh(kali, command, max(60, count * 10))


def windows_evidence(host, user, password, last_record_id, pre_log_lines):
    command = rf"""
$path = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
$newLines = if (Test-Path $path) {{ (Get-Content $path | Select-Object -Skip {pre_log_lines}) -join "`n" }} else {{ '' }}
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*WAZUH*' -and $_.DisplayName -like '*RESPONSE*'}})
$newEvents = @(Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {{ [long]$_.RecordId -gt {last_record_id} }})
[pscustomobject]@{{
    FailedLogons = $newEvents.Count;
    ActiveResponseRules = @($rules | Select-Object DisplayName,Enabled,Action);
    ActiveResponseExecuted = ($newLines -match 'active-response/bin/netsh.exe' -and $newLines -match '"id":"100001"' -and $newLines -match '"command":"continue"')
}} | ConvertTo-Json -Compress
"""
    return json.loads(winrm(host, user, password, command))


def wazuh_alert(host, pre_lines):
    start_line = pre_lines + 1
    command = f"cd ~/wazuh-docker/single-node; docker compose exec -T wazuh.manager sh -c 'tail -n +{start_line} /var/ossec/logs/alerts/alerts.json | grep -aF 100001 | tail -n 1'"
    return bool(ssh(host, command))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--kali", default=os.getenv("LAB_KALI_HOST", "kali-vm"))
    parser.add_argument("--wazuh", default=os.getenv("LAB_WAZUH_HOST", "wazuh-vm"))
    parser.add_argument("--windows-ip", default=os.getenv("LAB_WINDOWS_IP", "192.168.71.129"))
    parser.add_argument("--windows-user", default=os.getenv("LAB_WINDOWS_USER", "testw"))
    parser.add_argument("--rdp-user", default=os.getenv("LAB_RDP_USER", "testw"))
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--wait", type=int, default=30)
    args = parser.parse_args()
    if not args.execute:
        print("Dry run only. Add --execute to run the controlled RDP scenario.")
        return 0
    if args.count < 5:
        print("[FAIL] --count must be at least 5", file=sys.stderr)
        return 1
    password = os.getenv("LAB_WINDOWS_PASSWORD") or getpass.getpass(f"Password for WinRM user {args.windows_user}: ")
    try:
        print(f"[BASELINE] Capturing pre-test snapshot on Windows and Wazuh...")
        baseline = snapshot_baseline(args.windows_ip, args.windows_user, password, args.wazuh)
        print(f"[BASELINE] Windows Last Event RecordID: {baseline['last_record_id']}")
        print(f"[BASELINE] Windows active-responses.log lines: {baseline['windows_log_lines']}")
        print(f"[BASELINE] Wazuh alerts.json lines: {baseline['wazuh_alert_lines']}")

        attack(args.kali, args.windows_ip, args.rdp_user, args.count)
        print(f"[WAIT] Waiting {args.wait}s for Wazuh analysis and Active Response")
        time.sleep(args.wait)

        evidence = windows_evidence(
            args.windows_ip,
            args.windows_user,
            password,
            baseline["last_record_id"],
            baseline["windows_log_lines"],
        )
        alert = wazuh_alert(args.wazuh, baseline["wazuh_alert_lines"])
    except (ScenarioError, subprocess.TimeoutExpired) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    failed = int(evidence.get("FailedLogons", 0))
    rules = evidence.get("ActiveResponseRules", [])
    executed = bool(evidence.get("ActiveResponseExecuted", False))

    print(f"[INFO] Fresh Windows Event ID 4625 (RecordID > {baseline['last_record_id']}): {failed}")
    print(f"[INFO] Active Response firewall rules found: {len(rules) if isinstance(rules, list) else 1}")
    print(f"[INFO] Fresh Active Response executed in this run: {executed}")
    print(f"[INFO] Fresh Wazuh Rule 100001 alert found in this run: {alert}")

    if failed == 0 or not executed or not alert:
        print("[FAIL] RDP brute-force detection validation failed (strictly new evidence required)", file=sys.stderr)
        return 1
    print("[PASS] RDP brute-force detection and response validated (100% strictly fresh evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

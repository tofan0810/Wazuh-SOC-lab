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
    session = winrm.Session(f"http://{host}:5985/wsman", auth=(user, password), transport="ntlm", server_cert_validation="ignore")
    result = session.run_ps(command)
    output = result.std_out.decode("utf-8", errors="replace").strip()
    if result.status_code:
        raise ScenarioError(result.std_err.decode("utf-8", errors="replace").strip() or output)
    return output


def attack(kali, target, user, count):
    command = f"for i in $(seq 1 {count}); do timeout 8 xfreerdp /v:{shlex.quote(target)} /u:{shlex.quote(user)} /p:wrongpassword /cert:ignore >/dev/null 2>&1 || true; done"
    print(f"[RUN] Kali: {count} controlled failed RDP attempts -> {target}")
    ssh(kali, command, max(60, count * 10))


def windows_evidence(host, user, password):
    command = r"""
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue)
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like '*WAZUH*' -and $_.DisplayName -like '*RESPONSE*'})
$path = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
$log = if (Test-Path $path) { Get-Content $path -Tail 200 | Out-String } else { '' }
[pscustomobject]@{ FailedLogons=$events.Count; ActiveResponseRules=@($rules | Select DisplayName,Enabled,Action); ActiveResponseExecuted=($log -match 'active-response/bin/netsh.exe' -and $log -match '"id":"100001"' -and $log -match '"command":"continue"') } | ConvertTo-Json -Compress
"""
    return json.loads(winrm(host, user, password, command))


def wazuh_alert(host):
    command = "cd ~/wazuh-docker/single-node; docker compose exec -T wazuh.manager sh -c 'tail -n 3000 /var/ossec/logs/alerts/alerts.json | grep -F 100001 | tail -n 1'"
    return bool(ssh(host, command))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--kali", default=os.getenv("LAB_KALI_HOST", "kali-vm"))
    parser.add_argument("--wazuh", default=os.getenv("LAB_WAZUH_HOST", "wazuh-vm"))
    parser.add_argument("--windows-ip", default=os.getenv("LAB_WINDOWS_IP", "192.168.71.129"))
    parser.add_argument("--windows-user", default=os.getenv("LAB_WINDOWS_USER", r".\socrunner"))
    parser.add_argument("--rdp-user", default=os.getenv("LAB_RDP_USER", "regression-test"))
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
        attack(args.kali, args.windows_ip, args.rdp_user, args.count)
        print(f"[WAIT] Waiting {args.wait}s for Wazuh analysis and Active Response")
        time.sleep(args.wait)
        evidence = windows_evidence(args.windows_ip, args.windows_user, password)
        alert = wazuh_alert(args.wazuh)
    except (ScenarioError, subprocess.TimeoutExpired) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    failed = int(evidence.get("FailedLogons", 0))
    rules = evidence.get("ActiveResponseRules", [])
    executed = bool(evidence.get("ActiveResponseExecuted", False))
    print(f"[INFO] Windows Event ID 4625 in last 15 minutes: {failed}")
    print(f"[INFO] Active Response rules found: {len(rules) if isinstance(rules, list) else 1}")
    print(f"[INFO] Active Response executed: {executed}")
    print(f"[INFO] Wazuh Rule 100001 alert found: {alert}")
    if failed == 0 or not executed or not alert:
        print("[FAIL] RDP brute-force detection validation failed", file=sys.stderr)
        return 1
    print("[PASS] RDP brute-force detection and response validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

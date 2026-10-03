from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import subprocess
import sys
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class ScenarioError(RuntimeError):
    pass


def ssh(host, command, timeout=30):
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", host, command],
        capture_output=True,
        text=True,
        timeout=timeout + 5,
    )
    if result.returncode:
        raise ScenarioError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def winrm(host, user, password, command):
    try:
        import winrm
    except ImportError as error:
        raise ScenarioError("Install pywinrm with: python -m pip install -r requirements-e2e.txt") from error
    auth_user = user[2:] if user.startswith((".\\", "./")) else user
    session = winrm.Session(
        f"http://{host}:5985/wsman",
        auth=(auth_user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=60,
        operation_timeout_sec=50,
    )
    result = session.run_ps(command)
    output = result.std_out.decode("utf-8", errors="replace").strip()
    if result.status_code:
        raise ScenarioError(result.std_err.decode("utf-8", errors="replace").strip() or output)
    return output


def snapshot_baseline(windows_host, windows_user, password, wazuh_host):
    command_ps = r"""
$oldRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like '*WAZUH*' -and $_.DisplayName -like '*RESPONSE*'})
if ($oldRules.Count -gt 0) { $oldRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }

$apachePort = (netstat -ano | Select-String ":80\s+.*LISTENING") -ne $null

$accessPath = 'C:\xampp\apache\logs\access.log'
$accessLines = if (Test-Path $accessPath) { @(Get-Content $accessPath).Count } else { 0 }

$arPath = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
$arLines = if (Test-Path $arPath) { @(Get-Content $arPath).Count } else { 0 }

[pscustomobject]@{
    ApacheListening = $apachePort;
    AccessLines = $accessLines;
    ArLines = $arLines;
    CleanedRules = $oldRules.Count
} | ConvertTo-Json -Compress
"""
    win_data = json.loads(winrm(windows_host, windows_user, password, command_ps))
    if not win_data.get("ApacheListening"):
        raise ScenarioError(
            f"Apache Web Server is not running on {windows_host}:80.\n"
            f"Please open XAMPP Control Panel on the Windows victim machine and start the Apache service."
        )

    command_wazuh = "cd ~/wazuh-docker/single-node; docker compose exec -T wazuh.manager sh -c 'wc -l < /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0'"
    wazuh_lines = int(ssh(wazuh_host, command_wazuh) or 0)
    return {
        "access_lines": int(win_data["AccessLines"]),
        "windows_log_lines": int(win_data["ArLines"]),
        "wazuh_alert_lines": wazuh_lines,
    }


def attack(kali, target_ip):
    # Send both standard traversal and double-encoded traversal payloads from Kali
    payloads = [
        f"curl -s -G --connect-timeout 5 'http://{target_ip}/index.php' --data-urlencode 'page=../../../../Windows/win.ini'",
        f"curl -s --connect-timeout 5 'http://{target_ip}/index.php?page=..%252f..%252f..%252f..%252fWindows/win.ini'",
        f"curl -s --connect-timeout 5 'http://{target_ip}/index.php?page=../boot.ini'",
    ]
    print(f"[RUN] Kali: Executing controlled LFI exploit payloads -> http://{target_ip}/index.php")
    for payload in payloads:
        out = ssh(kali, f"{payload} || true", timeout=10)
        if "[fonts]" in out or "[extensions]" in out or "for 16-bit app support" in out:
            print("[INFO] Attacker confirmation: Target win.ini content successfully retrieved via LFI!")


def windows_evidence(host, user, password, pre_access_lines, pre_ar_lines):
    command = rf"""
$accessPath = 'C:\xampp\apache\logs\access.log'
$newAccess = if (Test-Path $accessPath) {{ @(Get-Content $accessPath | Select-Object -Skip {pre_access_lines}) -join "`n" }} else {{ '' }}

$arPath = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
$newAr = if (Test-Path $arPath) {{ @(Get-Content $arPath | Select-Object -Skip {pre_ar_lines}) -join "`n" }} else {{ '' }}

$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*WAZUH*' -and $_.DisplayName -like '*RESPONSE*'}})

[pscustomobject]@{{
    LfiLogInAccess = ($newAccess -match 'win\.ini' -or $newAccess -match '%252f' -or $newAccess -match 'page=');
    ActiveResponseRules = @($rules | Select-Object DisplayName,Enabled,Action);
    ActiveResponseExecuted = ($newAr -match 'active-response/bin/netsh.exe' -and $newAr -match '"id":"100002"' -and ($newAr -match '"command":"continue"' -or $newAr -match '"command":"add"')) -or ($rules.Count -gt 0);
    NewAccessSnippet = if ($newAccess.Length -gt 150) {{ $newAccess.Substring(0, 150) }} else {{ $newAccess }};
    NewArSnippet = if ($newAr.Length -gt 150) {{ $newAr.Substring(0, 150) }} else {{ $newAr }}
}} | ConvertTo-Json -Compress
"""
    return json.loads(winrm(host, user, password, command))


def wazuh_alert(host, pre_lines):
    start_line = pre_lines + 1
    command = f"cd ~/wazuh-docker/single-node; docker compose exec -T wazuh.manager sh -c 'tail -n +{start_line} /var/ossec/logs/alerts/alerts.json | grep -aF 100002 | tail -n 1'"
    return bool(ssh(host, command))


def main():
    parser = argparse.ArgumentParser(description="End-to-End Automated Test for Scenario 2: Web LFI / Directory Traversal (T1190)")
    parser.add_argument("--execute", action="store_true", help="Execute the real attack and validation")
    parser.add_argument("--kali", default=os.getenv("LAB_KALI_HOST", "kali-vm"), help="Kali SSH host")
    parser.add_argument("--wazuh", default=os.getenv("LAB_WAZUH_HOST", "wazuh-vm"), help="Wazuh SSH host")
    parser.add_argument("--windows-ip", default=os.getenv("LAB_WINDOWS_IP", "192.168.71.129"), help="Windows victim IP")
    parser.add_argument("--windows-user", default=os.getenv("LAB_WINDOWS_USER", "socrunner"), help="WinRM local user")
    parser.add_argument("--wait", type=int, default=15, help="Seconds to wait for Wazuh analysis and Active Response")
    args = parser.parse_args()

    if not args.execute:
        print("Dry run only. Add --execute to run the controlled Web LFI (T1190) scenario.")
        return 0

    password = os.getenv("LAB_WINDOWS_PASSWORD") or getpass.getpass(f"Password for WinRM user {args.windows_user}: ")

    try:
        print("[BASELINE] Capturing pre-test snapshot on Windows and Wazuh...")
        baseline = snapshot_baseline(args.windows_ip, args.windows_user, password, args.wazuh)
        print(f"[BASELINE] Windows Apache access.log lines: {baseline['access_lines']}")
        print(f"[BASELINE] Windows active-responses.log lines: {baseline['windows_log_lines']}")
        print(f"[BASELINE] Wazuh alerts.json lines: {baseline['wazuh_alert_lines']}")

        attack(args.kali, args.windows_ip)
        print(f"[WAIT] Waiting {args.wait}s for Wazuh log ingestion, decoding, rule matching, and Active Response...")
        time.sleep(args.wait)

        evidence = windows_evidence(
            args.windows_ip,
            args.windows_user,
            password,
            baseline["access_lines"],
            baseline["windows_log_lines"],
        )
        alert = wazuh_alert(args.wazuh, baseline["wazuh_alert_lines"])
    except (ScenarioError, subprocess.TimeoutExpired) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    lfi_logged = bool(evidence.get("LfiLogInAccess", False))
    rules = evidence.get("ActiveResponseRules", [])
    executed = bool(evidence.get("ActiveResponseExecuted", False))

    print(f"[INFO] Fresh Apache access.log LFI record captured: {lfi_logged}")
    print(f"[INFO] Fresh Wazuh Rule 100002 (T1190) alert found in this run: {alert}")
    print(f"[INFO] Fresh Active Response executed in this run: {executed}")
    print(f"[INFO] Active Response firewall rules found on Windows: {len(rules) if isinstance(rules, list) else 1}")

    if not lfi_logged or not alert or not executed:
        if not lfi_logged:
            print(f"[DEBUG] New access.log content: {evidence.get('NewAccessSnippet', '')!r}")
        if not executed:
            print(f"[DEBUG] New active-responses.log content: {evidence.get('NewArSnippet', '')!r}")
        print("[FAIL] Web LFI detection validation failed (strictly fresh evidence required)", file=sys.stderr)
        return 1

    print("[PASS] Web LFI (T1190) attack detection and automated response validated (100% strictly fresh evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

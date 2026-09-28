from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Hosts:
    kali: str
    wazuh: str


class HealthError(RuntimeError):
    pass


def ssh(host, command, timeout=15):
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", host, command], capture_output=True, text=True, timeout=timeout + 5)
    if result.returncode:
        raise HealthError(f"{host}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def local_powershell(command):
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise HealthError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kali", default=os.getenv("LAB_KALI_HOST", "kali-vm"))
    parser.add_argument("--wazuh", default=os.getenv("LAB_WAZUH_HOST", "wazuh-vm"))
    parser.add_argument("--windows-ip", default=os.getenv("LAB_WINDOWS_IP", "192.168.71.129"))
    args = parser.parse_args()
    try:
        print(f"[OK] Kali SSH: {ssh(args.kali, 'hostname')}")
        local_powershell(f"Test-WSMan -ComputerName '{args.windows_ip}'")
        print(f"[OK] Windows WinRM: {args.windows_ip}:5985")
        print(f"[OK] Ubuntu Wazuh SSH: {ssh(args.wazuh, 'hostname')}")
        services = set(ssh(args.wazuh, "cd ~/wazuh-docker/single-node; docker compose ps --services --filter status=running").splitlines())
        required = {"wazuh.manager", "wazuh.indexer", "wazuh.dashboard"}
        if not required <= services:
            raise HealthError(f"missing services: {sorted(required - services)}")
        print("[OK] Wazuh containers: wazuh.manager, wazuh.indexer, wazuh.dashboard")
        status = ssh(args.wazuh, "curl -k -sS -o /dev/null -w '%{http_code}' https://localhost")
        if status not in {"200", "302"}:
            raise HealthError(f"Dashboard HTTP {status}")
        print(f"[OK] Dashboard HTTPS: HTTP {status}")
        logs = ssh(args.wazuh, "cd ~/wazuh-docker/single-node; docker compose logs --since=6h wazuh.manager")
        if "Connection to backoff(elasticsearch(https://wazuh.indexer:9200)) established" not in logs:
            raise HealthError("Manager-to-Indexer connection not found")
        print("[OK] Manager connected to Indexer")
        print("[PASS] Three-VM Wazuh lab health check")
        return 0
    except (HealthError, subprocess.TimeoutExpired, FileNotFoundError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

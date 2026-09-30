#!/usr/bin/env python3
"""
VirusTotal API v3 Verification Tool for Wazuh SOC Lab
Tests the VirusTotal API connection and queries a sample hash (EICAR / Mimikatz).

Usage:
    python integrations/virustotal/test_virustotal_lookup.py --api-key <YOUR_KEY>
    python integrations/virustotal/test_virustotal_lookup.py --hash <SHA256>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# Default test hash: EICAR Standard Antivirus Test File (SHA256)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def load_env_file():
    """Lightweight .env loader without third-party dependencies."""
    paths = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"),
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip("'\"")
                            if k and k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass
            break


def check_virustotal_hash(api_key: str, file_hash: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "Wazuh-SOC-Lab/1.0",
    }
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                return data
            raise RuntimeError(f"Unexpected HTTP status: {response.status}")
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise RuntimeError("Invalid VirusTotal API Key (HTTP 401 Unauthorized)") from error
        if error.code == 404:
            raise RuntimeError(f"Hash not found in VirusTotal database: {file_hash}") from error
        if error.code == 429:
            raise RuntimeError("VirusTotal API quota exceeded (HTTP 429 Too Many Requests)") from error
        raise RuntimeError(f"HTTP Error {error.code}: {error.reason}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Network error connecting to VirusTotal: {error.reason}") from error


def main():
    load_env_file()
    parser = argparse.ArgumentParser(description="Verify VirusTotal API Key and query file reputation.")
    parser.add_argument("--api-key", default=os.getenv("VIRUSTOTAL_API_KEY"), help="VirusTotal v3 API Key")
    parser.add_argument("--hash", default=EICAR_SHA256, help="File SHA256/MD5 hash to lookup (default: EICAR test file)")
    args = parser.parse_args()

    api_key = args.api_key
    if not api_key:
        api_key = input("Enter your VirusTotal API Key: ").strip()

    if not api_key:
        print("[FAIL] VirusTotal API key is required.", file=sys.stderr)
        return 1

    print(f"[*] Querying VirusTotal for hash: {args.hash}...")
    try:
        result = check_virustotal_hash(api_key, args.hash)
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless

        print("\n[OK] VirusTotal API Key is VALID and ACTIVE!")
        print(f"[*] Detection Summary: {malicious}/{total} security vendors flagged this hash as malicious.")
        print(f"    - Malicious:  {malicious}")
        print(f"    - Suspicious: {suspicious}")
        print(f"    - Harmless:   {harmless}")
        print(f"    - Undetected: {undetected}")
        print(f"[*] Meaning Name: {attributes.get('meaningful_name', 'N/A')}")
        print(f"[*] Permalink:    https://www.virustotal.com/gui/file/{args.hash}")

        if malicious > 0:
            print("\n[ALERT] This hash is confirmed MALICIOUS. Wazuh Rule 87105 will trigger Level 12 Alert!")
        else:
            print("\n[INFO] This hash is CLEAN or UNKNOWN. Wazuh Rule 87104 will record as harmless.")
        return 0
    except RuntimeError as err:
        print(f"[FAIL] {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

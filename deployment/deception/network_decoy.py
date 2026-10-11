"""
Deception Technology & Active Defense Sensor Daemon
==============================================================================
Runs on Windows Endpoint (192.168.71.129):
1. Port 21 FTP Decoy Honeypot (Network Service Discovery Tripwire - T1046)
2. Canary Honey-File Access Watcher (Event 4663 - T1083 / T1005)
3. Honey-Account Tripwire Logon Watcher (Event 4625 - T1078 / T1110)
4. Automated Instant Forensics Evidence Preserver (Generates Evidence_*.zip in C:\\Windows\\Temp\\Forensics\\)
==============================================================================
"""

import socket
import sys
import os
import time
import subprocess
import threading
from datetime import datetime

PORT = int(os.getenv("DECOY_PORT", "21"))
HOST = "0.0.0.0"
LOG_FILE = r"C:\Windows\Temp\honeypot_ftp.log"
WAZUH_AR_LOG = r"C:\Program Files (x86)\ossec-agent\active-responses.log"
COLLECTOR_SCRIPT = r"C:\Program Files (x86)\ossec-agent\active-response\bin\collect-evidence.ps1"

last_evidence_time = 0
evidence_lock = threading.Lock()

def log_event(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] [FTP-DECOY] {msg}\n"
    print(entry.strip())
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass

    try:
        if os.path.exists(os.path.dirname(WAZUH_AR_LOG)):
            with open(WAZUH_AR_LOG, "a", encoding="utf-8") as f:
                f.write(f"{ts} active-response/bin/decoy.cmd: {msg}\n")
    except Exception:
        pass

def trigger_evidence_collection(alert_id, target_pid=0):
    global last_evidence_time
    now = time.time()
    with evidence_lock:
        if now - last_evidence_time < 3:
            return  # Debounce within 3 seconds
        last_evidence_time = now

    def _run():
        try:
            cmd = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-NoProfile",
                "-NonInteractive",
                "-File", COLLECTOR_SCRIPT,
                "-AlertId", alert_id,
                "-TargetProcessId", str(target_pid)
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Evidence collection error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

def watch_windows_security_events():
    """Background thread watching for Event 4663 (Honey-File) and Event 4625 (backup_admin)."""
    print("[*] Security Event Watcher thread started.")
    last_record_4663 = 0
    last_record_4625 = 0

    # Initialize last record IDs
    try:
        ps_init = '''
        $e4663 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 1 -ErrorAction SilentlyContinue
        $e4625 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1 -ErrorAction SilentlyContinue
        "$($e4663.RecordId)|$($e4625.RecordId)"
        '''
        res = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command", ps_init]).decode().strip()
        parts = res.split("|")
        if len(parts) == 2:
            last_record_4663 = int(parts[0]) if parts[0].isdigit() else 0
            last_record_4625 = int(parts[1]) if parts[1].isdigit() else 0
    except Exception:
        pass

    while True:
        try:
            time.sleep(1)
            # Query recent 4663 events
            ps_query = f'''
            $events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=@(4663, 4625)}} -MaxEvents 10 -ErrorAction SilentlyContinue
            foreach ($e in $events) {{
                if ($e.Id -eq 4663 -and $e.RecordId -gt {last_record_4663}) {{
                    if ($e.Message -match "IT_Admin_Credentials\\.xlsx") {{
                        "4663|$($e.RecordId)|$($e.ProcessId)"
                    }}
                }}
                if ($e.Id -eq 4625 -and $e.RecordId -gt {last_record_4625}) {{
                    if ($e.Message -match "backup_admin") {{
                        "4625|$($e.RecordId)|$($e.ProcessId)"
                    }}
                }}
            }}
            '''
            out = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command", ps_query], stderr=subprocess.DEVNULL).decode().strip()
            if out:
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    tokens = line.split("|")
                    if len(tokens) >= 3:
                        evt_id = tokens[0]
                        rec_id = int(tokens[1]) if tokens[1].isdigit() else 0
                        proc_id = int(tokens[2]) if tokens[2].isdigit() else 0

                        if evt_id == "4663":
                            if rec_id > last_record_4663:
                                last_record_4663 = rec_id
                            print(f"[!] CANARY FILE ACCESSED! Triggering Evidence Collection for Record {rec_id}...")
                            trigger_evidence_collection(f"ALT-CANARY-{rec_id}", proc_id)

                        elif evt_id == "4625":
                            if rec_id > last_record_4625:
                                last_record_4625 = rec_id
                            print(f"[!] HONEY-ACCOUNT ACCESSED! Triggering Evidence Collection for Record {rec_id}...")
                            trigger_evidence_collection(f"ALT-HONEYACC-{rec_id}", proc_id)
        except Exception:
            time.sleep(2)

def start_server():
    # Start background event watcher thread
    t = threading.Thread(target=watch_windows_security_events, daemon=True)
    t.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(5)
        log_event(f"Decoy listener started on {HOST}:{PORT}")
    except Exception as e:
        log_event(f"Failed to bind port {PORT}: {e}")
        sys.exit(1)

    while True:
        try:
            client, addr = server.accept()
            src_ip, src_port = addr
            log_event(f"TRIPWIRE_TRIGGERED: Unauthorized probe from {src_ip}:{src_port}")
            
            # Immediately trigger digital forensics preservation on decoy interaction
            trigger_evidence_collection(f"ALT-PORT21-{int(time.time())}")

            # Send fake Microsoft banner
            banner = b"220 Microsoft FTP Service Ready.\r\n"
            client.sendall(banner)
            
            client.settimeout(5.0)
            try:
                data = client.recv(1024)
                if data:
                    req = data.decode("utf-8", errors="ignore").strip()
                    log_event(f"PROBE_PAYLOAD from {src_ip}: {req}")
                    client.sendall(b"530 User cannot log in.\r\n")
            except Exception:
                pass
            finally:
                client.close()
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_event(f"Error handling connection: {e}")
            time.sleep(1)

if __name__ == "__main__":
    start_server()

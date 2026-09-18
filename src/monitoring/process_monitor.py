import time
import psutil
from datetime import datetime
import subprocess
import re
import socket
import hashlib
import os

from src.core.event_store import add_event
from src.detection.rule_engine import analyze


SYSTEM_KEYWORDS = [
    "systemd", "kworker", "kthreadd", "rcu",
    "migration", "ksoftirqd", "watchdog",
    "kswapd", "kcompactd", "irq",
    "dbus", "NetworkManager"
]


def is_system_process(name):
    name = (name or "").lower()
    return any(kw in name for kw in SYSTEM_KEYWORDS)


def get_process_sha256(pid):
    """Calculates the SHA-256 hash of the running process executable binary."""
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        if os.path.exists(exe_path) and os.path.isfile(exe_path):
            hasher = hashlib.sha256()
            with open(exe_path, 'rb') as f:
                # Read file in blocks to minimize memory utilization
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
    except Exception:
        pass
    # Baseline simulation hash for dynamic UI components
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def get_automatic_network_details():
    """
    Independent helper that dynamically reads the active Linux interface configuration.
    It automatically finds if the device is connected via Wired (eth0) or Wireless (wlan0)
    and extracts the live IP and MAC address.
    """
    ip_address = "127.0.0.1"
    mac_address = "00:00:00:00:00:00"
    
    try:
        route_cmd = subprocess.check_output("ip route get 8.8.8.8", shell=True, text=True)
        iface_match = re.search(r"dev\s+(\S+)", route_cmd)
        ip_match = re.search(r"src\s+(\S+)", route_cmd)
        
        if ip_match:
            ip_address = ip_match.group(1)
            
        if iface_match:
            interface_name = iface_match.group(1)
            with open(f"/sys/class/net/{interface_name}/address", "r") as f:
                mac_address = f.read().strip().upper()
                
    except Exception:
        try:
            import socket
            ip_address = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass
            
    return ip_address, mac_address


def start_process_monitor(logger, interval=3):
    print("🟢 Process monitor started...")

    seen = set()

    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or "unknown"

                unique = f"{pid}:{name}"

                if unique in seen:
                    continue
                seen.add(unique)

                if is_system_process(name):
                    continue

                source_ip, source_mac = get_automatic_network_details()
                
                # NEW: Gather Cryptographic Process Fingerprint
                process_hash = get_process_sha256(pid)

                # =========================
                # ANALYSIS
                # =========================
                event_data = {
                    "type": "process",
                    "path": name
                }

                result = analyze(event_data)
                severity = result.get("severity", "LOW")

                msg = f"🧠 Process: {name} (PID:{pid}) | IP: {source_ip} | MAC: {source_mac} | Hash: {process_hash[:10]}... | {severity}"

                # =========================
                # DASHBOARD DATA PACKET INJECTION
                # =========================
                add_event(
                    event_type="process",
                    path=name,
                    severity=severity,
                    extra={
                        "pid": pid, 
                        "type": "process",
                        "source_ip": source_ip,
                        "source_mac": source_mac,
                        "sha256": process_hash
                    },
                )

                if severity in ["HIGH", "MEDIUM"]:
                    print(msg)
                    logger.info(msg)

                # =========================
                # AUTO RESPONSE
                # =========================
                if severity == "HIGH":
                    try:
                        psutil.Process(pid).terminate()
                        logger.warning(f"🚨 Killed: {name} (PID:{pid})")
                    except Exception as e:
                        logger.error(f"Kill failed: {e}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(interval)

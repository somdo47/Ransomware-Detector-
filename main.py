import psutil
import os
import time
import threading
import subprocess
from collections import defaultdict
import numpy as np
from datetime import datetime

# Config
MONITOR_DIR = r'C:\Users'  # Monitor user directories; adjust for your OS
SCAN_INTERVAL = 5  # Seconds between scans
ENTROPY_THRESHOLD = 7.0  # High entropy indicates encryption (text ~4-5, encrypted ~7-8)
MOD_RATE_THRESHOLD = 10  # Max file mods per minute (heuristic for rapid encryption)
VSS_CMD = 'vssadmin list shadows'  # Windows VSS check

def shannon_entropy(data):
    """Calculate Shannon entropy of file content (0-8 scale)."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * np.log2(p_x)
    return entropy

def check_vss_deletion():
    """Detect if ransomware deleted shadow copies (common tactic)."""
    try:
        result = subprocess.run(VSS_CMD, shell=True, capture_output=True, text=True)
        if 'No items found' in result.stdout:
            return True, "Shadow copies deleted - potential ransomware!"
    except:
        pass
    return False, "VSS check failed or normal."

def monitor_file_changes(monitor_dir, interval):
    """Monitor file modifications and entropy in directory."""
    file_mods = defaultdict(list)  # {filepath: [timestamps]}
    alerts = []
    while True:
        for root, _, files in os.walk(monitor_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    stat = os.stat(filepath)
                    mtime = stat.st_mtime
                    size = stat.st_size
                    if size > 0 and size < 10**7:  # Skip large files
                        if filepath in file_mods:
                            recent = [t for t in file_mods[filepath] if time.time() - t < 60]
                            if len(recent) > MOD_RATE_THRESHOLD:
                                alerts.append(f"High mod rate: {filepath} ({len(recent)} in 60s)")
                            # Entropy check on recent mods
                            if len(recent) > 1 and time.time() - recent[-1] < interval:
                                with open(filepath, 'rb') as f:
                                    content = f.read(1024)  # Sample first KB
                                entropy = shannon_entropy(content)
                                if entropy > ENTROPY_THRESHOLD:
                                    alerts.append(f"High entropy ({entropy:.2f}): {filepath} - encrypted?")
                        file_mods[filepath].append(mtime)
                        # Keep last 100 mods
                        if len(file_mods[filepath]) > 100:
                            file_mods[filepath] = file_mods[filepath][-100:]
                except (OSError, PermissionError):
                    pass
        if alerts:
            print(f"[FILE ALERT {datetime.now()}] {', '.join(alerts[-5:])}")  # Last 5
            alerts = alerts[-10:]  # Rolling alerts
        time.sleep(interval)

def detect_suspicious_processes():
    """Scan for ransomware-like processes (e.g., high I/O, suspicious names)."""
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'io_counters']):
        try:
            info = proc.info
            if 'ransom' in (info['name'] or '').lower() or any('encrypt' in arg.lower() for arg in info['cmdline'] or []):
                suspicious.append({'pid': info['pid'], 'name': info['name'], 'note': 'Keyword match'})
            else:
                io = info['io_counters']
                if io and (io.write_bytes / 1024 / 1024) > 100:  # >100MB write burst
                    suspicious.append({'pid': info['pid'], 'name': info['name'], 'note': f'High write ({io.write_bytes/1024/1024:.1f}MB)'})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return suspicious

def monitor_processes(interval):
    """Real-time process monitoring."""
    while True:
        susp = detect_suspicious_processes()
        if susp:
            print(f"[PROC ALERT {datetime.now()}] Found {len(susp)} suspicious:")
            for p in susp:
                print(f"- PID {p['pid']}: {p['name']} - {p['note']}")
        time.sleep(interval)

def main():
    print("Ransomware Detection Starting...")
    vss_deleted, vss_msg = check_vss_deletion()
    if vss_deleted:
        print(f"[VSS ALERT] {vss_msg}")
    
    # Start threads
    threading.Thread(target=monitor_file_changes, args=(MONITOR_DIR, SCAN_INTERVAL), daemon=True).start()
    threading.Thread(target=monitor_processes, args=(SCAN_INTERVAL, ), daemon=True).start()
    
    print(f"Monitoring {MONITOR_DIR} for changes. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)  # Main loop heartbeat
    except KeyboardInterrupt:
        print("Stopping. Review alerts above.")

if __name__ == "__main__":
    main()

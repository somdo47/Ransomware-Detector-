# Ransomware Detection System

## Overview

The **Ransomware Detection System** is a Python-based cybersecurity tool designed for educational and defensive purposes. It monitors systems for ransomware-like behavior, such as rapid file modifications, high-entropy file changes (indicative of encryption), suspicious process I/O, and Volume Shadow Copy (VSS) deletions on Windows. Built for ethical use, it helps researchers and security enthusiasts study ransomware patterns in controlled environments like virtual machines.

**Purpose**: Detect and alert on potential ransomware activity in real-time.  
**Intended Use**: Educational, research, or personal system monitoring (with explicit permission).  
**Disclaimer**: This is not a production-grade antivirus. Use responsibly on systems you own. Not liable for misuse.

**Version**: 1.0  
**License**: MIT  
**Last Updated**: September 13, 2025

## Features

- **File Monitoring**: Detects rapid file changes and high-entropy content (encrypted files).  
- **Process Scanning**: Flags processes with high I/O writes or suspicious names (e.g., "ransom", "encrypt").  
- **VSS Deletion Check**: Alerts on deleted Windows shadow copies, a common ransomware tactic.  
- **Real-Time Operation**: Uses multi-threading for continuous monitoring with minimal overhead.  
- **Lightweight**: Minimal dependencies; runs offline.  
- **Configurable**: Adjustable thresholds for entropy, modification rates, and directories.

## Requirements

- **Python**: 3.8+ (tested on 3.12)
- **Operating System**: Windows (VSS checks); partial Linux/macOS support (adapt paths)
- **Dependencies**:
  ```
  pip install psutil numpy
  ```
  - `psutil`: System and process utilities
  - `numpy`: Entropy calculations
- **Permissions**: Run as Administrator for VSS/process access
- **No Internet**: Fully offline operation

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/ransomware-detection-system.git
   cd ransomware-detection-system
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Create `requirements.txt`:
   ```
   psutil
   numpy
   ```

3. **Verify Setup**:
   ```bash
   python -c "import psutil, numpy; print('Setup complete!')"
   ```

## Usage

1. **Run the Script**:
   ```bash
   python ransomware_detector.py
   ```
   - Monitors `C:\Users` (edit `MONITOR_DIR` for custom paths).
   - Outputs alerts to console (e.g., `[FILE ALERT] High entropy (7.5): suspicious.txt`).
   - Press `Ctrl+C` to stop.

2. **Configuration**:
   Edit variables in `ransomware_detector.py`:
   ```python
   MONITOR_DIR = r'C:\Users'  # Directory to watch
   SCAN_INTERVAL = 5          # Seconds between scans
   ENTROPY_THRESHOLD = 7.0    # High entropy for encrypted files
   MOD_RATE_THRESHOLD = 10    # Max file mods per minute
   ```

3. **Test in a VM**:
   - Simulate ransomware (e.g., encrypt a file with AES or delete VSS via `vssadmin delete shadows`).
   - Example test script (ethical use only):
     ```python
     with open('test.txt', 'wb') as f:
         f.write(os.urandom(1024))  # High-entropy content
     ```
   - Run detector to see alerts.

## How It Works

| Component | Description | Detection Logic |
|-----------|-------------|-----------------|
| **File Monitoring** | Watches directories for rapid mods and encryption. | Tracks mtimes; flags >10 mods/min or entropy >7 (encrypted files). |
| **Process Scanning** | Identifies high I/O or keyword matches. | Uses `psutil.io_counters`; checks for "ransom"/"encrypt". |
| **VSS Check** | Detects shadow copy deletions. | Runs `vssadmin list shadows`; alerts if none found. |
| **Threading** | Parallel scans for real-time alerts. | Threads for file/process monitoring every 5s. |

See inline code comments for technical details.

## Limitations

- **Windows-Centric**: VSS checks are Windows-only; adapt for Linux (`/proc` monitoring).
- **False Positives**: Legit backups or compression tools may trigger; tune thresholds.
- **Basic Detection**: Misses kernel-mode or obfuscated ransomware; consider YARA for signatures.
- **Performance**: High file counts may increase CPU load; adjust `SCAN_INTERVAL`.
- **No GUI**: Console-based; extend with Tkinter for visuals.

## Future Enhancements

- Add ML (e.g., IsolationForest) for better anomaly detection.
- Integrate email alerts (`smtplib`) or logging to file.
- Port to Linux with `/proc` or `/dev` monitoring.
- Add YARA rules for known ransomware signatures.
- Build a web dashboard with Flask/Dash.

## Contributing

1. Fork the repo and create a branch: `git checkout -b feature-name`.
2. Submit a pull request with clear descriptions.
3. Ideas: ML models, GUI, cross-platform support, or blockchain logging.

## Troubleshooting

- **Permission Errors**: Run as admin (`right-click → Run as Administrator`).
- **No Alerts**: Ensure `MONITOR_DIR` exists; test with simulated files.
- **Module Not Found**: Verify `pip list | grep psutil`.
- **Linux/macOS**: Comment VSS code; set `MONITOR_DIR='/home'`.

## License

This project is licensed under the MIT License. See `LICENSE` file for details.

## Acknowledgments

- Inspired by open-source cybersecurity tools and academic research.
- Libraries: [psutil](https://psutil.readthedocs.io), [numpy](https://numpy.org).
- Community: Thanks to ethical hacking resources like GeeksforGeeks and GitHub.

---

*Star this repo if you find it useful! Issues and feedback welcome.*

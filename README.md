# WTM-IDS: Windows Traffic Monitor - Intrusion Detection System

WTM-IDS is a simple network monitoring and intrusion detection tool for Windows. It uses packet sniffing to detect suspicious network activity and displays visited websites in a GUI. The tool is designed for educational and demonstration purposes.

## Features
- Monitors DNS, TCP, UDP, and ICMP traffic
- Detects potential scanning/malicious activity based on traffic patterns
- Displays visited websites in a GUI
- Alerts with a popup and sound on suspicious activity

## Requirements
- Windows OS
- Python 3.7+
- Administrator privileges (for packet sniffing)
- **Npcap** (must be installed manually, see below)

## Installation
1. **Download and install Npcap:**
   - Go to [https://nmap.org/npcap/](https://nmap.org/npcap/)
   - Download the installer and run it.
   - **During installation, check the box for "Install Npcap in WinPcap API-compatible Mode".**
2. Clone this repository or download the code.
3. Install the required Python packages:

```bash
pip install -r requirements.txt
```

4. (Optional) If you encounter issues with `tkinter` or `winsound`, ensure you are using the standard Python distribution for Windows.

## Usage
Run the program with administrator privileges:

```bash
python WTMIDS.py
```

- Click "Start Monitoring" to begin network monitoring.
- Visited websites will appear in the list.
- If suspicious activity is detected, you will receive a popup and a sound alert.

## Notes
- This tool is for educational use only. Do not use it for unauthorized network monitoring.
- Requires admin rights to capture packets on Windows.
- **Npcap is required for packet sniffing.**

## License
MIT License 
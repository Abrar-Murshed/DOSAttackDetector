# 🛡️ DOS Attack Detector - Blue Team Defensive Tool

Description: A real-time network monitoring tool that detects Denial of Service (DOS) attack focused primarily on SYN packets’ patterns by analyzing traffic signatures and alerting on suspicious activity.


## 🎯 Features

- **Real-time Packet Analysis**: Captures and analyzes network packets as they arrive
- **SYN Flood Detection**: Identifies excessive SYN packets indicating SYN flood attacks
- **High Traffic Detection**: Monitors packet rates and detects abnormal volumes
- **Configurable Thresholds**: Customize detection sensitivity
- **Live Monitoring Dashboard**: Terminal-based status display
- **Alert System**: Immediate notifications when attacks are detected

## 📋 Requirements

- Python 3.6+
- Linux-based system (Kali Linux, Ubuntu, etc.)
- Root/sudo privileges (required for packet capture)
- Network interface (eth0, wlan0, etc.)

## 🚀 Installation

### 1. Install Python dependencies

```bash
sudo pip3 install scapy

```

### 2. Make scripts executable

```bash
chmod +x launcher.sh
chmod +x dos_detector.py
chmod +x test_dos.py

```

## 💻 Usage

### Basic Usage

Run the detector on your default network interface:

```bash
sudo ./monitor.sh

```

### Specify Network Interface

Run on a specific interface (e.g., wlan0):

```bash
sudo ./monitor.sh wlan0

```

Or directly with Python:

```bash
sudo python3 monitor.py eth0

```

### Finding Your Network Interface

List available interfaces:

```bash
ip link show

```

Common interfaces:

- `eth0` - Wired Ethernet
- `wlan0` - Wireless
- `lo` - Loopback (localhost)

## ⚙️ Configuration

Edit `monitor.py` to adjust detection thresholds:

```python
self.SYN_THRESHOLD = 100      # SYN packets per second
self.PACKET_THRESHOLD = 200   # Total packets per second
self.TIME_WINDOW = 10         # Time window in seconds

```

### Threshold Tuning Guidelines

**For High-Security Networks:**

```python
self.SYN_THRESHOLD = 50
self.PACKET_THRESHOLD = 100

```

**For High-Traffic Networks:**

```python
self.SYN_THRESHOLD = 200
self.PACKET_THRESHOLD = 500

```

## 🔍 How It Works

### Detection Methodology

1. **Packet Capture**: Uses Scapy to capture TCP and ICMP packets
2. **IP Tracking**: Monitors traffic from each source IP
3. **Pattern Analysis**:
    - Counts SYN packets (potential SYN flood)
    - Calculates packet rate over time window
4. **Threshold Comparison**: Triggers alerts when thresholds exceeded
5. **Alert Generation**: Displays real-time warnings with details

### Attack Signatures Detected

**SYN Flood Attack:**

- Excessive TCP SYN packets without ACK
- Indicates attacker attempting to exhaust server resources
- Detection: Count SYN-only packets per IP

**High Traffic Volume:**

- Abnormally high packet rate from single source
- Could indicate various DOS attack types
- Detection: Packets per second calculation

## 📊 Data Structures

```python
syn_count = {
    "192.168.1.50": 125,
    "10.0.0.5": 15
}

timestamps = {
    "192.168.1.50": deque([t1, t2, t3, ...]),  # Recent packet times
}

```

## 🛠️ Troubleshooting

### "Permission denied" error

```bash
# Must run with sudo/root
sudo python3 dos_detector_kali.py

```

### "No module named 'scapy'" error

```bash
# Install Scapy
sudo pip3 install scapy

```

### No packets captured

```bash
# Check interface is active
ip link show

# Verify interface name
ifconfig

# Try different interface
sudo ./monitor.sh wlan0

```

### Too many false positives

- Increase thresholds in `monitor.py`
- Adjust `TIME_WINDOW` for longer averaging

## 🔒 Security Notes

- **Testing**: Only test on networks you own or have explicit permission
- **Legal**: Unauthorized testing may violate laws (CFAA, etc.)
- **Production**: Fine-tune thresholds for your environment
- **Logging**: Consider adding log file output for forensics

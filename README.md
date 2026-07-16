# 🌐 Advanced Network Traffic Monitor

A sophisticated Python-based network traffic monitoring and analysis tool that captures, analyzes, and visualizes real-time network packets with protocol detection, anomaly detection, and bandwidth monitoring.

## ✨ Features

### Real-time Monitoring
- **Live Packet Capture**: Monitor network traffic in real-time
- **Protocol Detection**: Identify HTTP, HTTPS, DNS, TCP, UDP, ICMP, ARP
- **Bandwidth Analysis**: Track per-interface and per-application bandwidth
- **Connection Tracking**: Monitor active connections and sessions

### Advanced Analytics
- **Anomaly Detection**: Identify suspicious traffic patterns
- **Network Statistics**: Packet counts, bytes transferred, protocol distribution
- **Geolocation Tracking**: Map IP addresses to geographic locations (with MaxMind GeoIP2)
- **Port Analysis**: Identify open ports and services

### Visualization & Reporting
- **Real-time Dashboard**: Color-coded terminal UI
- **Traffic Graphs**: ASCII-based bandwidth visualization
- **Export Reports**: Generate JSON, CSV, and HTML reports
- **Alert System**: Anomaly and threshold-based alerts

### Security Features
- **DDoS Detection**: Identify potential DDoS attacks
- **Port Scanning Detection**: Monitor for reconnaissance activity
- **Suspicious Pattern Detection**: Unusual traffic patterns
- **IP Filtering**: Whitelist/blacklist IP addresses

## 📋 Requirements

- Python 3.8+
- Linux/macOS (Windows with WSL recommended)
- Root/Administrator privileges (for packet capture)
- `libpcap` library

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/IlanT-hub/network-traffic-monitor.git
cd network-traffic-monitor
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libpcap-dev python3-dev
```

**macOS:**
```bash
brew install libpcap
```

### 4. Install Python Dependencies
```bash
pip install -r requirements.txt
```

## 🎯 Quick Start

### Basic Usage
```bash
# Run with sudo for packet capture privileges
sudo python main.py
```

### Monitor Specific Interface
```bash
sudo python main.py --interface eth0
```

### Live Dashboard
```bash
sudo python main.py --interface eth0 --dashboard
```

### Packet Capture with Filters
```bash
# Monitor only HTTP traffic
sudo python main.py --interface eth0 --filter "tcp port 80"

# Monitor DNS traffic
sudo python main.py --interface eth0 --filter "udp port 53"

# Monitor HTTPS traffic
sudo python main.py --interface eth0 --filter "tcp port 443"
```

### Anomaly Detection Mode
```bash
sudo python main.py --interface eth0 --anomaly-detection
```

### Export Network Statistics
```bash
sudo python main.py --interface eth0 --export json
```

### DDoS Attack Simulation Detection
```bash
sudo python main.py --interface eth0 --ddos-detection
```

### Run Analysis on Packet Capture File
```bash
sudo python main.py --pcap capture.pcap --analyze
```

## 📊 Features in Detail

### Real-time Dashboard
Displays:
- Active connections
- Top bandwidth consumers
- Protocol distribution
- Packets per second
- Live alerts

### Protocol Detection
Supported protocols:
- **TCP**: Connection-oriented communication
- **UDP**: Connectionless communication
- **ICMP**: Ping and error messages
- **DNS**: Domain name resolution (Port 53)
- **HTTP/HTTPS**: Web traffic (Ports 80/443)
- **ARP**: Address resolution
- **SSH**: Secure shell (Port 22)
- **FTP**: File transfer (Port 21)

### Anomaly Detection
Detects:
- Unusual packet sizes
- Abnormal connection rates
- Unexpected protocols
- Suspicious port activity
- Traffic pattern changes
- Potential port scanning

### Geolocation Tracking
- Map IP addresses to countries/regions
- Display IP reputation
- Track international traffic

## 🔧 Configuration

Edit `config.py` to customize:
- Packet capture settings
- Alert thresholds
- Anomaly detection sensitivity
- Report generation options
- Interface settings

## 📁 Project Structure

```
network-traffic-monitor/
├── main.py                 # Entry point
├── config.py              # Configuration settings
├── requirements.txt       # Python dependencies
├── packet_sniffer.py      # Packet capture module
├── protocol_analyzer.py   # Protocol detection & parsing
├── network_analyzer.py    # Traffic analysis & statistics
├── anomaly_detector.py    # Anomaly detection engine
├── dashboard.py           # Terminal UI dashboard
├── alerts.py              # Alert system
├── geoip_tracker.py       # Geolocation tracking
├── report_generator.py    # Report generation
├── filters.py             # IP/Port filtering
├── utils.py               # Utility functions
├── README.md              # This file
├── LICENSE
├── .gitignore
├── .env.example
└── data/
    ├── captures/          # Saved PCAP files
    ├── reports/           # Generated reports
    └── logs/              # Application logs
```

## 🔐 Security Considerations

- **Requires Root**: Packet capture requires elevated privileges
- **Privacy**: Only capture on networks you own or have permission to monitor
- **Legal**: Ensure compliance with local network monitoring laws
- **Data Storage**: Securely handle captured data

## 📈 Example Output

```
╔════════════════════════════════════════════════════════════════╗
║          🌐 NETWORK TRAFFIC MONITOR - LIVE DASHBOARD 🌐         ║
╚════════════════════════════════════════════════════════════════╝

📊 INTERFACE: eth0 (192.168.1.100)
⏱️  Uptime: 00:15:42 | Packets: 45,234 | Bytes: 123.4 MB

┌─ ACTIVE CONNECTIONS ─────────────────────────────────────────┐
│ Source IP          Dest IP            Protocol  State   Speed  │
│ 192.168.1.50 → 8.8.8.8            TCP      ESTAB   2.1 MB/s   │
│ 192.168.1.75 → 142.251.41.14      HTTPS    ESTAB   1.5 MB/s   │
│ 192.168.1.100 → 1.1.1.1           DNS      REQ     45.2 KB/s  │
└──────────────────────────────────────────────────────────────┘

┌─ PROTOCOL DISTRIBUTION ──────────────────────────────────────┐
│ TCP:    45% ████████████████████████░░░░░░░░░░░░░░░░░░░░░░ │
│ UDP:    35% ████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
│ ICMP:   12% ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
│ ARP:     8% ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
└──────────────────────────────────────────────────────────────┘

🚨 ALERTS:
   ⚠️  Anomaly detected: Unusual traffic from 192.168.1.200
   ✓ All systems normal

💾 Packets captured: 1,234 | Data transferred: 45.6 MB
```

## 🐛 Troubleshooting

**Permission Denied Error**
```bash
# Solution: Run with sudo
sudo python main.py
```

**No Packets Captured**
- Check interface name: `ip link show`
- Verify network activity
- Try different interface: `--interface lo`

**Import Errors**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## 📚 Advanced Usage

### Custom Packet Analysis
```python
from packet_sniffer import PacketSniffer
from protocol_analyzer import ProtocolAnalyzer

sniffer = PacketSniffer(interface='eth0')
analyzer = ProtocolAnalyzer()

for packet in sniffer.capture():
    protocol_info = analyzer.analyze(packet)
    print(protocol_info)
```

### Anomaly Detection Integration
```python
from anomaly_detector import AnomalyDetector

detector = AnomalyDetector(sensitivity=0.8)
anomalies = detector.detect(traffic_data)
```

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Make your changes
4. Submit pull request

## 📄 License

MIT License - see LICENSE file

## 🙏 Acknowledgments

- Scapy library for packet manipulation
- Maxmind GeoIP2 for geolocation
- Built with Python and community libraries

## 📞 Support

For issues or questions, open a GitHub issue.

---

**Made with ❤️ by IlanT-hub**

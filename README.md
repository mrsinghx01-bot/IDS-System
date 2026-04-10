# 🛡 Network Intrusion Detection System (IDS)

This project is a simple real-time **Network Intrusion Detection System (IDS)** built using Python. It captures live network traffic, analyzes packets, and detects suspicious activities like flooding, port scans, DDoS attacks, and malicious DNS queries.

The backend is implemented using Flask and Scapy, and the frontend provides a dashboard to monitor traffic and alerts.


Features

- 📡 Real-time packet sniffing using Scapy  
- ⚠️ Detection of:
  - TCP/UDP/ICMP Flood attacks  
  - Port scanning attempts  
  - DDoS attacks (multiple sources targeting one system)  
  - Suspicious DNS queries  
- 📊 Live traffic monitoring (packets, bytes, devices)  
- 🌐 DNS query tracking  
- 📁 CSV file analysis for offline traffic data  
- 🔁 Auto-refresh dashboard  



How it Works

The system continuously captures network packets and processes them using a central packet handler function.

Each packet is analyzed based on:
- Source and destination IP  
- Protocol (TCP, UDP, ICMP)  
- Packet rate (packets per second)  
- Destination ports  
- DNS queries  

Based on this, different detection logics are applied such as:
- Rate-based detection for floods  
- Port counting for scans  
- Multi-source tracking for DDoS  
- Keyword matching for suspicious domains  

Detected threats are stored as alerts and marked against devices.

---

Tech Stack

- **Backend:** Python, Flask  
- **Packet Analysis:** Scapy  
- **Frontend:** HTML, CSS, JavaScript  
- **Other Libraries:** threading, datetime, collections  

---

Setup & Run

### 1. Install dependencies
```bash
pip install flask flask-cors scapy
```

### 2. Run the backend
```bash
python app.py
```

Server will start at:
```
http://localhost:5000
```

### 3. Open frontend
Open `index.html` in your browser.

---

API Endpoints

- `/devices` → device-wise stats  
- `/traffic` → overall traffic info  
- `/alerts` → detected attacks  
- `/domains` → DNS queries  
- `/packet_stats` → detailed analytics  
- `/analyze_csv` → analyze uploaded CSV  
- `/debug` → debugging info  

---

Limitations

- Cannot inspect encrypted traffic (HTTPS)  
- Only metadata is analyzed, not full payload  
- Rule-based detection may generate false positives  
- Cannot monitor all devices fully in standard Wi-Fi networks  

---

Future Improvements

- Machine learning-based detection  
- Better visualization dashboard  
- Deployment on router/gateway for full network visibility  
- Advanced anomaly detection  

---

Conclusion

This project demonstrates how real-time packet analysis can be used to detect common network attacks using simple rule-based logic. It provides a practical understanding of network security concepts and IDS design.

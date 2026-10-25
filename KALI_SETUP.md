# 🐉 Kali Linux Setup & Execution Guide

Step-by-step instructions to set up, run, and test the Network Intrusion Detection System (IDS) on **Kali Linux** inside a folder named `final` on your Desktop.

---

## 📋 Step 1: Clone or Navigate to Desktop Folder

Open your terminal in Kali Linux:

```bash
cd ~/Desktop
```

### Option A: If cloning directly from GitHub
```bash
git clone https://github.com/mrsinghx01-bot/IDS-System.git final
cd final
```

### Option B: If the folder already exists on your Desktop
```bash
cd ~/Desktop/final
```

---

## 📦 Step 2: Install Dependencies

Kali Linux uses Debian package management. You can install all required packages via `apt` (recommended) or using a Python virtual environment.

### Recommended: Install via apt
```bash
sudo apt update
sudo apt install -y python3-flask python3-flask-cors python3-scapy
```

### Alternative: Install via pip & venv
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Step 3: Run the IDS Backend (Requires `sudo`)

Packet sniffing requires root privileges to capture packets in promiscuous mode.

```bash
sudo python3 app.py
```

### Expected Output:
```text
[*] Starting packet capture on interface: 'any'
[*] Promiscuous mode: ON
[*] Flood threshold: 50 pkt/s over 2s window
[*] Burst threshold: 20 pkts in 1s
[*] Port scan threshold: 15 ports in 5s window
[*] DDoS threshold: 3 sources @ 20 pkt/s each
[*] Debug mode: ON
[*] IDS Backend running at http://0.0.0.0:5000
[*] Debug endpoint: http://localhost:5000/debug
```
> **Keep this terminal running.**

---

## 🌐 Step 4: Open the Web Dashboard

Open a **new terminal tab** (`Ctrl + Shift + T`) and launch the dashboard:

```bash
cd ~/Desktop/final
firefox index.html &
```

Or open `index.html` manually in your browser. The dashboard refreshes every 4 seconds and connects to `http://localhost:5000`.

---

## ⚔️ Step 5: Simulate Attacks to Test the IDS

Open another terminal tab to run tests:

### 1. UDP Flood Test
```bash
sudo hping3 --udp -p 80 --flood 127.0.0.1
```
*Stop after 2–3 seconds with `Ctrl + C`.*  
**Expected:** High severity alert popup `UDP_FLOOD` on the dashboard.

### 2. TCP SYN Flood Test
```bash
sudo hping3 -S -p 80 --flood 127.0.0.1
```
*Stop after 2–3 seconds with `Ctrl + C`.*  
**Expected:** High severity alert popup `TCP_FLOOD` on the dashboard.

### 3. Port Scan Test
```bash
nmap -p 1-100 127.0.0.1
```
**Expected:** Medium severity alert `PORT_SCAN` on the dashboard.

### 4. Suspicious DNS Domain Query Test
```bash
nslookup phish-test-bank.xyz
```
**Expected:** Low severity alert under the **DNS Domains** tab.

---

## ⚙️ Configuration & Troubleshooting

- **Check Network Interfaces:**
  ```bash
  ip a
  ```
- **Change Sniff Interface:**
  If `'any'` doesn't capture packets on your specific adapter, edit line 39 in `app.py`:
  ```python
  SNIFF_INTERFACE = "eth0"   # or "wlan0" / "lo"
  ```
- **Live Debug Endpoint:**
  Visit `http://localhost:5000/debug` in your browser to verify packet counts and tracked devices.

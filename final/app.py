from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf
import threading
import time
import csv
import io
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)
CORS(app)

SNIFF_INTERFACE = "any"
DEBUG = True

# Flood / Rate-based thresholds 

# hping3 easily sends 1000+ pps; 50 pps is clearly abnormal for normal traffic.
PACKETS_PER_SECOND_THRESHOLD = 50  

# Even if Scapy misses some packets, a burst of 20 in 1 second is still caught.
BURST_THRESHOLD    = 20     
BURST_WINDOW_SEC   = 1 
RATE_WINDOW_SEC = 2        

# ── Port scan threshold
PORT_SCAN_THRESHOLD = 20   
PORT_SCAN_WINDOW_SEC = 5   

# ── DDoS detection thresholds 
DDOS_SOURCE_THRESHOLD = 3          
DDOS_PPS_PER_SOURCE   = 20        

# ── Alert cooldown
ALERT_COOLDOWN_SEC = 10           

# ── Suspicious domain keywords ────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = ["malware", "phish", "hack", ".ru", ".xyz", ".tk"]

devices = {}
alerts = []
total_packets = 0
total_bytes   = 0

packet_times = defaultdict(list)

device_ports = defaultdict(dict)

ddos_tracker = defaultdict(lambda: defaultdict(list))

alert_cooldown = {}

lock = threading.Lock()

_debug_pkt_counter = 0

def now_str():
    """Return current timestamp as a readable string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def dbg(msg):
    """NEW: Print a debug message only when DEBUG mode is on."""
    if DEBUG:
        print(f"[DBG] {msg}")


def ensure_device(ip):
    """Initialize a device entry if it doesn't exist yet."""
    if ip not in devices:
        devices[ip] = {
            "ip":         ip,
            "packets":    0,
            "bytes":      0,
            "domains":    [],
            "last_seen":  now_str(),
            "suspicious": False,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "first_seen": now_str()
        }
#ALERT SYSTEM

def can_alert(ip, alert_type):
    """
    Cooldown check — returns True only if enough time has passed
    since the last alert of this (ip, alert_type) combination.
    This prevents duplicate alert spam during sustained floods.
    """
    key = (ip, alert_type)
    last = alert_cooldown.get(key, 0)
    if time.time() - last >= ALERT_COOLDOWN_SEC:
        alert_cooldown[key] = time.time()
        return True
    return False


def add_alert(alert_type, source_ip, message):
    """
    Create and store a new alert.
    Now uses can_alert() cooldown — multiple alerts allowed per device,
    but not more than once per ALERT_COOLDOWN_SEC per (ip, type).
    Also marks the device as suspicious.
    """
    if not can_alert(source_ip, alert_type):
        return  # Still within cooldown window — skip duplicate

    alert = {
        "type":      alert_type,
        "source_ip": source_ip,
        "message":   message,
        "timestamp": now_str()
    }
    alerts.append(alert)

    # Mark device suspicious on any alert
    if source_ip in devices:
        devices[source_ip]["suspicious"] = True

    print(f"[ALERT] {alert_type} from {source_ip}: {message}")

def check_flood(ip, protocol):
    now = time.time()
    packet_times[ip] = [t for t in packet_times[ip] if now - t <= RATE_WINDOW_SEC]
    packet_times[ip].append(now)

    count_in_window = len(packet_times[ip])

    # ── Calculate packets per second ──
    # Divide by window size to get average rate.
    pps = count_in_window / RATE_WINDOW_SEC

    # ── Burst check: packets in last 1 second ──
    burst_count = sum(1 for t in packet_times[ip] if now - t <= BURST_WINDOW_SEC)

    # ── Debug output ──
    if count_in_window > 5:   # Only log when there's notable activity
        dbg(f"{ip} | {protocol} | window={count_in_window} pkts/{RATE_WINDOW_SEC}s "
            f"| pps={pps:.1f} | burst={burst_count}")

    # ── Fire alert if threshold crossed ──
    alert_type = f"{protocol}_FLOOD"   # NEW: e.g., "UDP_FLOOD" or "TCP_FLOOD"

    if pps >= PACKETS_PER_SECOND_THRESHOLD:
        add_alert(
            alert_type,
            ip,
            f"{protocol} flood detected: {pps:.0f} pkt/s (threshold={PACKETS_PER_SECOND_THRESHOLD})"
        )

    elif burst_count >= BURST_THRESHOLD:
        add_alert(
            alert_type,
            ip,
            f"{protocol} burst spike: {burst_count} packets in 1 second"
        )

def check_ddos(src_ip, dst_ip, protocol):

    now = time.time()

    # Keep only recent timestamps for this (dst, src) pair
    ddos_tracker[dst_ip][src_ip] = [
        t for t in ddos_tracker[dst_ip][src_ip] if now - t <= RATE_WINDOW_SEC
    ]
    ddos_tracker[dst_ip][src_ip].append(now)

    # Count how many sources are sending at high rate to this destination
    active_attackers = 0
    for attacker_ip, timestamps in ddos_tracker[dst_ip].items():
        pps = len(timestamps) / RATE_WINDOW_SEC
        if pps >= DDOS_PPS_PER_SOURCE:
            active_attackers += 1

    if active_attackers >= DDOS_SOURCE_THRESHOLD:
        # Alert is keyed to the target IP, not the source
        if can_alert(dst_ip, "DDOS"):
            alert = {
                "type":      "DDOS",
                "source_ip": dst_ip,   # dst_ip is the victim here
                "message":   (f"DDoS attack on {dst_ip}: "
                              f"{active_attackers} sources sending {protocol} flood"),
                "timestamp": now_str()
            }
            alerts.append(alert)
            print(f"[ALERT] DDOS targeting {dst_ip} from {active_attackers} sources")

            # Mark the victim device as suspicious too
            ensure_device(dst_ip)
            devices[dst_ip]["suspicious"] = True


def check_port_scan(ip, port):
    now = time.time()
    
    # Clean old ports outside the window
    device_ports[ip] = {
        p: t for p, t in device_ports[ip].items() 
        if now - t <= PORT_SCAN_WINDOW_SEC
    }
    
    # If this is a new port, record the timestamp
    if port not in device_ports[ip]:
        device_ports[ip][port] = now
    
    # Count how many ports were discovered recently (in this window)
    ports_in_window = len(device_ports[ip])
    
    # Only alert if many ports appeared within the scanning window
    if ports_in_window >= PORT_SCAN_THRESHOLD:
        add_alert(
            "PORT_SCAN",
            ip,
            f"Port scan detected: {ports_in_window} unique ports in {PORT_SCAN_WINDOW_SEC}s window"
        )


def check_suspicious_domain(ip, domain):

    domain_lower = domain.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain_lower:
            add_alert(
                "SUSPICIOUS_DOMAIN",
                ip,
                f"Suspicious domain queried: {domain} (matched keyword: '{keyword}')"
            )
            break


def handle_packet(pkt):

    global total_packets, total_bytes, _debug_pkt_counter

    if not pkt.haslayer(IP):
        return

    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst    # NEW: needed for DDoS detection
    pkt_len = len(pkt)
    _debug_pkt_counter += 1
    if DEBUG and _debug_pkt_counter % 100 == 0:
        print(f"[DBG] Captured {_debug_pkt_counter} packets so far | "
              f"latest: {src_ip} → {dst_ip}")

    with lock:
        total_packets += 1
        total_bytes   += pkt_len

        ensure_device(src_ip)
        devices[src_ip]["packets"]  += 1
        devices[src_ip]["bytes"]    += pkt_len
        devices[src_ip]["last_seen"] = now_str()

        # ── Determine protocol and run flood detection ──
        if pkt.haslayer(UDP):
            # UPDATED: Pass "UDP" so alert type becomes "UDP_FLOOD"
            devices[src_ip]["udp_packets"] += 1
            check_flood(src_ip, "UDP")
            check_port_scan(src_ip, pkt[UDP].dport)
            check_ddos(src_ip, dst_ip, "UDP")    # NEW

        elif pkt.haslayer(TCP):
            # UPDATED: Pass "TCP" so alert type becomes "TCP_FLOOD"
            devices[src_ip]["tcp_packets"] += 1
            check_flood(src_ip, "TCP")
            check_port_scan(src_ip, pkt[TCP].dport)
            check_ddos(src_ip, dst_ip, "TCP")    # NEW

        else:
            # Generic IP traffic (ICMP, etc.) — still check flood rate
            devices[src_ip]["icmp_packets"] += 1
            check_flood(src_ip, "ICMP")

        # ── DNS query detection ──
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                domain = ""
            if domain:
                if domain not in devices[src_ip]["domains"]:
                    devices[src_ip]["domains"].append(domain)
                    devices[src_ip]["domains"] = devices[src_ip]["domains"][-10:]
                check_suspicious_domain(src_ip, domain)

def start_sniffing():
 
    conf.sniff_promisc = True

    print(f"[*] Starting packet capture on interface: '{SNIFF_INTERFACE}'")
    print(f"[*] Promiscuous mode: ON")
    print(f"[*] Flood threshold: {PACKETS_PER_SECOND_THRESHOLD} pkt/s "
          f"over {RATE_WINDOW_SEC}s window")
    print(f"[*] Burst threshold: {BURST_THRESHOLD} pkts in {BURST_WINDOW_SEC}s")
    print(f"[*] Port scan threshold: {PORT_SCAN_THRESHOLD} ports in {PORT_SCAN_WINDOW_SEC}s")
    print(f"[*] DDoS threshold: {DDOS_SOURCE_THRESHOLD} sources "
          f"@ {DDOS_PPS_PER_SOURCE} pkt/s each")
    print(f"[*] Debug mode: {'ON' if DEBUG else 'OFF'}")

    try:
        # FIXED: iface parameter added; filter broadened to catch UDP flood
        sniff(
            iface=SNIFF_INTERFACE,
            filter="ip",           
            prn=handle_packet,
            store=False            
        )
    except Exception as e:
        print(f"[ERROR] Sniffing failed on '{SNIFF_INTERFACE}': {e}")
        print("[*] Retrying on default interface...")
        
        sniff(filter="ip", prn=handle_packet, store=False)

@app.route("/devices")
def get_devices():
    """Return per-device statistics."""
    with lock:
        return jsonify(list(devices.values()))


@app.route("/traffic")
def get_traffic():
    """Return global traffic totals."""
    with lock:
        return jsonify({
            "total_packets":    total_packets,
            "total_bytes":      total_bytes,
            "total_devices":    len(devices),
            "total_alerts":     len(alerts),
            "suspicious_count": sum(1 for d in devices.values() if d["suspicious"])
        })


@app.route("/alerts")
def get_alerts():
    """Return all alerts, latest first."""
    with lock:
        return jsonify(list(reversed(alerts)))


@app.route("/domains")
def get_domains():
    """Return recent DNS queries from all devices."""
    with lock:
        all_domains = []
        for ip, data in devices.items():
            for domain in data["domains"]:
                all_domains.append({"ip": ip, "domain": domain})
        return jsonify(all_domains[-50:])


@app.route("/packet_stats")
def get_packet_stats():
    with lock:
        stats = []
        current_time = time.time()
        
        for ip, data in devices.items():
            # Calculate packet rate (packets per second)
            first_seen = datetime.strptime(data["first_seen"], "%Y-%m-%d %H:%M:%S")
            last_seen = datetime.strptime(data["last_seen"], "%Y-%m-%d %H:%M:%S")
            duration = (last_seen - first_seen).total_seconds()
            pps = data["packets"] / duration if duration > 0 else 0
            
            stats.append({
                "ip": ip,
                "total_packets": data["packets"],
                "tcp_packets": data.get("tcp_packets", 0),
                "udp_packets": data.get("udp_packets", 0),
                "icmp_packets": data.get("icmp_packets", 0),
                "bytes": data["bytes"],
                "pps": round(pps, 2),
                "domains_accessed": len(data["domains"]),
                "last_seen": data["last_seen"],
                "suspicious": data["suspicious"]
            })
        
        # Sort by packet count (descending)
        stats.sort(key=lambda x: x["total_packets"], reverse=True)
        return jsonify(stats)


@app.route("/analyze_csv", methods=["POST"])
def analyze_csv():
   
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file    = request.files["file"]
    content = file.read().decode("utf-8", errors="ignore")

    results = []
    try:
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            byte_val = 0
            for col in ["bytes", "Bytes", "total_bytes", "size", "Size"]:
                if col in row:
                    try:
                        byte_val = int(float(row[col]))
                    except ValueError:
                        pass
                    break

            pkt_val = 0
            for col in ["packets", "Packets", "count", "Count"]:
                if col in row:
                    try:
                        pkt_val = int(float(row[col]))
                    except ValueError:
                        pass
                    break

            status = "Suspicious" if (byte_val > 1_000_000 or pkt_val > 500) else "Normal"
            results.append({**row, "status": status})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify(results)

@app.route("/debug")
def debug_info():
    """NEW: Returns live capture stats for debugging. Hit this in browser to verify."""
    with lock:
        top_talkers = sorted(
            devices.values(),
            key=lambda d: d["packets"],
            reverse=True
        )[:5]
        return jsonify({
            "raw_packets_seen_by_handler": _debug_pkt_counter,
            "total_packets_counted":       total_packets,
            "total_devices_tracked":       len(devices),
            "top_5_talkers": [
                {"ip": d["ip"], "packets": d["packets"]} for d in top_talkers
            ],
            "recent_alerts": [a["type"] for a in alerts[-10:]],
            "interface":     SNIFF_INTERFACE,
            "thresholds": {
                "pps":            PACKETS_PER_SECOND_THRESHOLD,
                "burst":          BURST_THRESHOLD,
                "burst_window_s": BURST_WINDOW_SEC,
                "rate_window_s":  RATE_WINDOW_SEC,
                "cooldown_s":     ALERT_COOLDOWN_SEC,
                "port_scan_ports": PORT_SCAN_THRESHOLD,
                "port_scan_window_s": PORT_SCAN_WINDOW_SEC,
                "ddos_sources":   DDOS_SOURCE_THRESHOLD,
            }
        })

# MAIN 
if __name__ == "__main__":
    # Start sniffer in a background daemon thread
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

    print("[*] IDS Backend running at http://0.0.0.0:5000")
    print("[*] Debug endpoint: http://localhost:5000/debug")
    app.run(host="0.0.0.0", port=5000, debug=False)

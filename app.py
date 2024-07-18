from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP
import threading
import time
from collections import defaultdict

app = Flask(__name__)

# Dictionaries to store captured packets and alerts
packet_count = defaultdict(int)
ip_count = defaultdict(int)
alerts = []

# Port scan detection
def detect_port_scan(packet):
    if TCP in packet or UDP in packet:
        ip_src = packet[IP].src
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        packet_count[(ip_src, port)] += 1

        # If more than 10 packets from the same IP to different ports within a minute
        if packet_count[(ip_src, port)] > 10:
            alert = f"Alert: Possible port scan detected from {ip_src}"
            alerts.append(alert)
            print(alert)

# DDoS detection
def detect_ddos(packet):
    ip_src = packet[IP].src
    ip_count[ip_src] += 1

    # If more than 100 packets from the same IP within a minute
    if ip_count[ip_src] > 100:
        alert = f"Alert: Possible DDoS attack detected from {ip_src}"
        alerts.append(alert)
        print(alert)

# Callback function for packet capture
def packet_callback(packet):
    if IP in packet:
        detect_port_scan(packet)
        detect_ddos(packet)
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Packet: {ip_src} -> {ip_dst}")

# Reset counters every minute
def reset_counters():
    global packet_count, ip_count
    while True:
        time.sleep(60)
        packet_count = defaultdict(int)
        ip_count = defaultdict(int)

# Start packet capture in a separate thread
def start_sniffing():
    sniff(prn=packet_callback, store=0)

# Start the packet capture thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Start the counter reset thread
reset_thread = threading.Thread(target=reset_counters)
reset_thread.daemon = True
reset_thread.start()

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def get_alerts():
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True)



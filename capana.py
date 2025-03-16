import pyshark
from collections import defaultdict
import time
import os

# Initialize a dictionary to store packet count by source IP
packet_count = defaultdict(int)

# Set threshold for abnormal packet count (this depends on your network)
THRESHOLD = 1000  # Adjust this threshold according to your needs
DURATION = 60  # Time window in seconds for monitoring

def analyze_packets(pkt):
    """
    Analyze each captured packet for DDoS behavior.
    A simple approach here is to count packets from each source IP.
    """
    if hasattr(pkt, 'ip'):  # Check if the packet has an IP layer
        src_ip = pkt.ip.src
        packet_count[src_ip] += 1

def detect_ddos():
    """
    Detect DDoS attacks based on packet count exceeding threshold.
    """
    global packet_count
    potential_ddos = []

    # Check if any IP has crossed the threshold
    for ip, count in packet_count.items():
        if count > THRESHOLD:
            potential_ddos.append((ip, count))

    if potential_ddos:
        print("Possible DDoS attack detected:")
        for ip, count in potential_ddos:
            print(f"Source IP: {ip}, Packets: {count}")
    else:
        print("No DDoS attack detected.")

def capture_packets(interface='wlan0'):
    """
    Capture network packets and analyze them for potential DDoS attacks.
    """
    print(f"Starting packet capture on interface {interface}...")
    try:
        # Check if user has sufficient privileges
        if os.geteuid() != 0:
            print("You need to run this script as root or with sudo!")
            return
        
        # List available interfaces
        interfaces = pyshark.LiveCapture.list_interfaces()
        if interface not in interfaces:
            print(f"Invalid interface {interface}. Available interfaces: {interfaces}")
            return

        # Capture packets for the given duration (use sniff() for more control)
        cap = pyshark.LiveCapture(interface=interface)

        # Set capture duration
        start_time = time.time()
        while time.time() - start_time < DURATION:
            for pkt in cap.sniff_packets(timeout=1):  # Sniff for 1 second intervals
                analyze_packets(pkt)

        detect_ddos()  # After capture duration, check for DDoS

    except Exception as e:
        print(f"Error during capture: {e}")

if __name__ == "__main__":
    # Replace 'eth0' with your correct network interface
    capture_packets(interface='wlan0')


from scapy.all import sniff, IP, TCP, UDP, Raw
import os

# Where to save the .pcap file
save_dir = "/root/NetworkSniff/sniffer_logs"
os.makedirs(save_dir, exist_ok=True)   # Create folder if it doesn't exist
pcap_file = os.path.join(save_dir, "capture.pcap")

captured_packets = []

def packet_callback(packet):
        # Check if the packet has an IP layer
        if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto

                # Identify protocol
                if proto == 6:
                        protocol = "TCP"
                elif proto == 17:
                        protocol = "UDP"
                else:
                        protocol = str(proto)

                print(f"[+] {src_ip} -> {dst_ip} | Protocol:{protocol}")

                # Show payload if available
                if Raw in packet:
                        payload = packet[Raw].load
                        try:
                                payload_text = payload.decode(errors="ignore")
                                print(f"  Payload:{payload_text[:100]}")    # Show first 100 chars
                        except:
                                print("   Payload: (binary data)")

try:
	# Capture packets (requires root/administrator privileges)
	print("Starting packet capture... Press Ctrl+C to stop.")
	sniff(filter="tcp port 80", prn=packet_callback, store=False)
except KeyboardInterrupt:
	print(f"\nSaving {len(captured_packets)} packets to {pcap_file}...")
	wrpcap(pcap_file, captured_packets)
	print("File saved. Open it in Wireshark to analyze.")

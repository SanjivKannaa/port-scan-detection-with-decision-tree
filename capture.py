from scapy.all import sniff, wrpcap
import time
from datetime import datetime


def capture_packets():
    capture_duration = 10 #5 * 60  # 5 minutes
    start_time = time.time()
    packets = sniff(filter="tcp or udp", timeout=capture_duration)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"./capture/capture_{timestamp}.pcap"
    wrpcap(pcap_filename, packets)
    print(f"Saved {len(packets)} packets to {pcap_filename}")
    return pcap_filename
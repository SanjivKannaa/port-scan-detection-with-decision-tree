from scapy.all import sniff, IP
import json
from ml import detect

# Mapping for protocol and flag values
protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
flag_map = {0: 'SF', 1: 'S0', 2: 'REJ', 3: 'RSTR', 4: 'RSTO', 5: 'SH', 
            6: 'S1', 7: 'S2', 8: 'RSTOS0', 9: 'S3', 10: 'OTH'}

# Function to extract features and print as JSON
def extract_features(packet):
    features = {}

    # Extract IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        # protocol_name = protocol_map.get(protocol, 'unknown')
        
        # Features
        features['duration'] = packet.time
        features['protocol_type'] = protocol #protocol_name
        features['flag'] = int(packet[IP].flags)
        features['src_bytes'] = len(packet)
        features['dst_bytes'] = len(packet)
        features['land'] = 0  # Placeholder (requires custom logic)
        
        # Additional placeholder features, can be customized based on packet inspection
        features['wrong_fragment'] = 0
        features['urgent'] = 0
        features['hot'] = 0
        features['num_failed_logins'] = 0
        features['logged_in'] = 0
        features['num_compromised'] = 0
        features['root_shell'] = 0
        features['su_attempted'] = 0
        features['num_file_creations'] = 0
        features['num_shells'] = 0
        features['num_access_files'] = 0
        features['is_guest_login'] = 0
        features['count'] = 0
        features['srv_count'] = 0
        features['serror_rate'] = 0
        features['rerror_rate'] = 0
        features['same_srv_rate'] = 0
        features['diff_srv_rate'] = 0
        features['srv_diff_host_rate'] = 0
        features['dst_host_count'] = 0
        features['dst_host_srv_count'] = 0
        features['dst_host_diff_srv_rate'] = 0
        features['dst_host_same_src_port_rate'] = 0
        features['dst_host_srv_diff_host_rate'] = 0

        # Convert features to JSON (dict)
        return features

# Capture live traffic and extract features
def capture_live_traffic():
    print("Starting packet capture...")
    results = []
    # Capture 10 packets (you can change this number or set it to `None` for unlimited capture)
    sniff(prn=lambda packet: detect(extract_features(packet))) #, count 100)
    # sniff(prn=lambda packet: print(packet.json())) #, count 100)
    print(results)

# Call the function to start capturing
capture_live_traffic()

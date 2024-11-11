from ml import detect

# Mapping for protocol and flag values
protocol_map = {'icmp': 1, 'tcp': 6, 'udp': 17}
flag_map = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5, 
            'S1': 6, 'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10}

# Function to parse a CSV-style input string into features
def parse_input(input_str):
    # Split the input string by commas
    data = input_str.strip().split(',')
    
    # Map CSV fields to feature dictionary
    features = {
        'duration': int(data[0]),
        'protocol_type': protocol_map.get(data[1], 6),  # Default to TCP if unknown
        'service': data[2],
        'flag': flag_map.get(data[3], 0),  # Default to SF if unknown
        'src_bytes': int(data[4]),
        'dst_bytes': int(data[5]),
        'land': int(data[6]),
        'wrong_fragment': int(data[7]),
        'urgent': int(data[8]),
        'hot': int(data[9]),
        'num_failed_logins': int(data[10]),
        'logged_in': int(data[11]),
        'num_compromised': int(data[12]),
        'root_shell': int(data[13]),
        'su_attempted': int(data[14]),
        'num_file_creations': int(data[15]),
        'num_shells': int(data[16]),
        'num_access_files': int(data[17]),
        'is_guest_login': int(data[18]),
        'count': int(data[22]),
        'srv_count': int(data[23]),
        'serror_rate': float(data[24]),
        'rerror_rate': float(data[25]),
        'same_srv_rate': float(data[26]),
        'diff_srv_rate': float(data[27]),
        'srv_diff_host_rate': float(data[28]),
        'dst_host_count': int(data[29]),
        'dst_host_srv_count': int(data[30]),
        'dst_host_diff_srv_rate': float(data[31]),
        'dst_host_same_src_port_rate': float(data[32]),
        'dst_host_srv_diff_host_rate': float(data[33]),
    }
    
    return features

# Example CSV input (without the attack label at the end)
csv_input = "0,icmp,ecr_i,SF,520,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,456,456,0.00,0.00,0.00,0.00,1.00,0.00,0.00,255,255,1.00,0.00,1.00,0.00,0.00,0.00,0.00,0.00"

# Parse the input and extract features
features = parse_input(csv_input)

# Predict the attack type using the model
result = detect(features)

# Print the result
print(f"Prediction: {result}, Features: {features}")

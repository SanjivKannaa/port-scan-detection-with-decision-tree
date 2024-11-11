import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from scapy.all import IP, rdpcap

# Ensure correct file paths
data_path = "./input/kdd-cup-1999-data/kddcup.data_10_percent.gz"
attack_types_path = "./input/kdd-cup-1999-data/training_attack_types"

# Column names
cols = """
duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment,
urgent, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted,
num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds,
is_host_login, is_guest_login, count, srv_count, serror_rate, srv_serror_rate,
rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate,
dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate,
dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate
"""

# features that are shortlisted after training (input should be in this format)
# Index(['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land',
#        'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
#        'num_compromised', 'root_shell', 'su_attempted', 'num_file_creations',
#        'num_shells', 'num_access_files', 'is_guest_login', 'count',
#        'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
#        'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
#        'dst_host_srv_count', 'dst_host_diff_srv_rate',
#        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate'],
#       dtype='object')

columns = [c.strip() for c in cols.split(",") if c.strip()]
columns.append("target")

# Attack types mapping
attacks_types = {
    'normal': 'normal', 'back': 'dos', 'buffer_overflow': 'u2r', 'ftp_write': 'r2l',
    'guess_passwd': 'r2l', 'imap': 'r2l', 'ipsweep': 'probe', 'land': 'dos',
    'loadmodule': 'u2r', 'multihop': 'r2l', 'neptune': 'dos', 'nmap': 'probe',
    'perl': 'u2r', 'phf': 'r2l', 'pod': 'dos', 'portsweep': 'probe', 'rootkit': 'u2r',
    'satan': 'probe', 'smurf': 'dos', 'spy': 'r2l', 'teardrop': 'dos', 'warezclient': 'r2l',
    'warezmaster': 'r2l',
}

# Load dataset
df = pd.read_csv(data_path, names=columns, compression='gzip')
df['Attack Type'] = df.target.apply(lambda r: attacks_types.get(r[:-1], 'unknown'))

# Data preprocessing
df.dropna(inplace=True)
df = df[[col for col in df if df[col].nunique() > 1]]
df = df.drop(['num_root', 'srv_serror_rate', 'srv_rerror_rate', 'dst_host_srv_serror_rate',
              'dst_host_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
              'dst_host_same_srv_rate'], axis=1)

# Mapping protocol and flag
pmap = {'icmp': 0, 'tcp': 1, 'udp': 2}
fmap = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5, 'S1': 6,
        'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10}
df['protocol_type'] = df['protocol_type'].map(pmap)
df['flag'] = df['flag'].map(fmap)
df.drop('service', axis=1, inplace=True)

# print(df.drop(['target', 'Attack Type'], axis=1).columns)


# Model training data setup
Y = df[['Attack Type']]
X = df.drop(['target', 'Attack Type'], axis=1)
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, Y_train, Y_test = train_test_split(X_scaled, Y, test_size=0.33, random_state=42)

def train():
    # Naive Bayes Model
    if os.path.exists('./model/naive_bayes_model.pkl'):
        model1 = joblib.load('./model/naive_bayes_model.pkl')
    else:
        model1 = GaussianNB()
        model1.fit(X_train, Y_train.values.ravel())
        joblib.dump(model1, './model/naive_bayes_model.pkl')
    print("Naive Bayes Test Score:", model1.score(X_test, Y_test))

    # Decision Tree Model
    if os.path.exists('./model/decision_tree_model.pkl'):
        model2 = joblib.load('./model/decision_tree_model.pkl')
    else:
        model2 = DecisionTreeClassifier(criterion="entropy", max_depth=4)
        model2.fit(X_train, Y_train.values.ravel())
        joblib.dump(model2, './model/decision_tree_model.pkl')
    print("Decision Tree Test Score:", model2.score(X_test, Y_test))

    # Random Forest Model
    if os.path.exists('./model/random_forest_model.pkl'):
        model3 = joblib.load('./model/random_forest_model.pkl')
    else:
        model3 = RandomForestClassifier(n_estimators=30)
        model3.fit(X_train, Y_train.values.ravel())
        joblib.dump(model3, './model/random_forest_model.pkl')
    print("Random Forest Test Score:", model3.score(X_test, Y_test))
    scaler = MinMaxScaler()
    scaler.fit(X_train)  # Fit scaler on the training data
    joblib.dump(scaler, './model/scaler.pkl')  # Save the scaler for later use


# Function to parse PCAP and detect attacks
def detect(packet):
    if not packet:
        return {
            'time': 0,  # 'time' is assumed to be 'duration' in the input
            'fromip': "None",  # Ensure the 'src_ip' is part of the input
            'toip': "None",    # Ensure the 'dst_ip' is part of the input
            'attacktype': "normal"
        }
    # try:
    # print(packet[IP])
    # except:
    #     pass
    # return 
    # Load the model and scaler
    model = joblib.load('./model/random_forest_model.pkl')
    scaler = joblib.load('./model/scaler.pkl')  # Load the scaler saved during training
    
    # Ensure the input dictionary has the correct feature values
    features = [
        packet['duration'],                  # 'duration'
        packet['protocol_type'],             # 'protocol_type'
        packet['flag'],                      # 'flag'
        packet['src_bytes'],                 # 'src_bytes'
        packet['dst_bytes'],                 # 'dst_bytes'
        packet['land'],                      # 'land'
        packet['wrong_fragment'],            # 'wrong_fragment'
        packet['urgent'],                    # 'urgent'
        packet['hot'],                       # 'hot'
        packet['num_failed_logins'],         # 'num_failed_logins'
        packet['logged_in'],                 # 'logged_in'
        packet['num_compromised'],           # 'num_compromised'
        packet['root_shell'],                # 'root_shell'
        packet['su_attempted'],              # 'su_attempted'
        packet['num_file_creations'],        # 'num_file_creations'
        packet['num_shells'],                # 'num_shells'
        packet['num_access_files'],          # 'num_access_files'
        packet['is_guest_login'],            # 'is_guest_login'
        packet['count'],                     # 'count'
        packet['srv_count'],                 # 'srv_count'
        packet['serror_rate'],               # 'serror_rate'
        packet['rerror_rate'],               # 'rerror_rate'
        packet['same_srv_rate'],             # 'same_srv_rate'
        packet['diff_srv_rate'],             # 'diff_srv_rate'
        packet['srv_diff_host_rate'],        # 'srv_diff_host_rate'
        packet['dst_host_count'],            # 'dst_host_count'
        packet['dst_host_srv_count'],        # 'dst_host_srv_count'
        packet['dst_host_diff_srv_rate'],    # 'dst_host_diff_srv_rate'
        packet['dst_host_same_src_port_rate'],  # 'dst_host_same_src_port_rate'
        packet['dst_host_srv_diff_host_rate']   # 'dst_host_srv_diff_host_rate'
    ]
    
    # Scale the features using the loaded scaler (same as during training)
    features_scaled = scaler.transform([features])
    
    # Predict the attack type
    attack_type = model.predict(features_scaled)[0]  # Only take the first prediction
    
    # Return the result in the requested format
    return {
        'time': packet['duration'],  # 'time' is assumed to be 'duration' in the input
        'fromip': packet.get("src_ip", 'unknown'),  # Ensure the 'src_ip' is part of the input
        'toip': packet.get('dst_ip', 'unknown'),    # Ensure the 'dst_ip' is part of the input
        'attacktype': attack_type
    }








train()
# detect(rdpcap("./capture/capture.pcap"))
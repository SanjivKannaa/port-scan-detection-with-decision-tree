import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from flask import Flask, request, jsonify

# Ensure correct file paths
data_path = "./input/kdd-cup-1999-data/kddcup.data_10_percent.gz"
attack_types_path = "./input/kdd-cup-1999-data/training_attack_types"

# Column names for the dataset
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

# Feature columns
columns = [c.strip() for c in cols.split(",") if c.strip()]
columns.append("target")

# Attack type mapping
attacks_types = {
    'normal': 'normal', 'back': 'dos', 'buffer_overflow': 'u2r', 'ftp_write': 'r2l',
    'guess_passwd': 'r2l', 'imap': 'r2l', 'ipsweep': 'probe', 'land': 'dos',
    'loadmodule': 'u2r', 'multihop': 'r2l', 'neptune': 'dos', 'nmap': 'probe',
    'perl': 'u2r', 'phf': 'r2l', 'pod': 'dos', 'portsweep': 'probe', 'rootkit': 'u2r',
    'satan': 'probe', 'smurf': 'dos', 'spy': 'r2l', 'teardrop': 'dos', 'warezclient': 'r2l',
    'warezmaster': 'r2l',
}

# Load dataset and preprocess
df = pd.read_csv(data_path, names=columns, compression='gzip')
df['Attack Type'] = df.target.apply(lambda r: attacks_types.get(r[:-1], 'unknown'))
df.dropna(inplace=True)
df = df[[col for col in df if df[col].nunique() > 1]]
df.drop(['num_root', 'srv_serror_rate', 'srv_rerror_rate', 'dst_host_srv_serror_rate',
         'dst_host_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
         'dst_host_same_srv_rate'], axis=1, inplace=True)

# Mapping protocol and flag
pmap = {'icmp': 0, 'tcp': 1, 'udp': 2}
fmap = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5, 'S1': 6,
        'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10}
df['protocol_type'] = df['protocol_type'].map(pmap)
df['flag'] = df['flag'].map(fmap)
df.drop('service', axis=1, inplace=True)

# Model training data setup
Y = df[['Attack Type']]
X = df.drop(['target', 'Attack Type'], axis=1)
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, Y_train, Y_test = train_test_split(X_scaled, Y, test_size=0.33, random_state=42)

def train():
    # Train Random Forest model
    if not os.path.exists('./model/random_forest_model.pkl'):
        model = RandomForestClassifier(n_estimators=30)
        model.fit(X_train, Y_train.values.ravel())
        joblib.dump(model, './model/random_forest_model.pkl')
    else:
        model = joblib.load('./model/random_forest_model.pkl')
    
    # Save scaler
    joblib.dump(scaler, './model/scaler.pkl')

train()

# Flask API setup
app = Flask(__name__)

# Load model and scaler
model = joblib.load('./model/random_forest_model.pkl')
scaler = joblib.load('./model/scaler.pkl')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    features = [
        data.get('duration'), data.get('protocol_type'), data.get('flag'),
        data.get('src_bytes'), data.get('dst_bytes'), data.get('land'),
        data.get('wrong_fragment'), data.get('urgent'), data.get('hot'),
        data.get('num_failed_logins'), data.get('logged_in'),
        data.get('num_compromised'), data.get('root_shell'), data.get('su_attempted'),
        data.get('num_file_creations'), data.get('num_shells'),
        data.get('num_access_files'), data.get('is_guest_login'),
        data.get('count'), data.get('srv_count'), data.get('serror_rate'),
        data.get('rerror_rate'), data.get('same_srv_rate'),
        data.get('diff_srv_rate'), data.get('srv_diff_host_rate'),
        data.get('dst_host_count'), data.get('dst_host_srv_count'),
        data.get('dst_host_diff_srv_rate'), data.get('dst_host_same_src_port_rate'),
        data.get('dst_host_srv_diff_host_rate')
    ]
    
    # Scale input features
    features_scaled = scaler.transform([features])
    
    # Predict the attack type
    attack_type = model.predict(features_scaled)[0]
    
    return jsonify({
        'attack_type': attack_type
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

from capture import capture_packets
from ml import detect
from datetime import datetime


while True:
    print("starting new capture")
    fname = capture_packets()
    # for i in fname:
    #     post_process = detect(extract_features(i, fname))
    post_process = detect(fname)
    exit()
    if post_process['status'] == 1:
        print("port scan detected!")
        current_time = datetime.now()
        formatted_time = current_time.strftime("%d-%m-%Y %H-%M-%S")
        attacker_ip = "attacker ip"
        #sending sms
        
        message_body += f"Port scan detected from {attacker_ip} at {formatted_time}!"
            
        

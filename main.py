from capture import capture_packets
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime


# set env variables
env = {
    "twilio_phone_number": 9566250207,
    "account_sid": "",
    "auth_token": "",
    "emailid": "jsanjiv2003@gmail.com",
    "fromemail": "",
    "sendgrid_api_key": ""
}


try:
    client = Client(env[account_sid], env[auth_token])
    print("TWILLIO CONNECTION SUCCESSFULLY")
except:
    print("TWILLIO CONNECTION FAILED")
    exit()


def send_email(to_email, subject, content):
    # Set up the sender and recipient details
    from_email = "your_verified_sender@example.com"
    global env
    message = Mail(
        from_email=from_email,
        to_emails=env["emailid"],
        subject=subject,
        plain_text_content=content
    )

    try:
        # Initialize SendGrid client with your API key
        sendgrid_client = SendGridAPIClient("YOUR_SENDGRID_API_KEY")  # Replace with your actual API key
        response = sendgrid_client.send(message)
        print(f"Email sent with status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending email: {e}")

while True:
    fname = capture()
    post_process = process(fname)
    if post_process['status'] == 1:
        print("port scan detected!")
        current_time = datetime.now()
        formatted_time = current_time.strftime("%d-%m-%Y %H-%M-%S")
        attacker_ip = "attacker ip"
        #sending sms
        try:
            message_body += f"Port scan detected from {attacker_ip} at {formatted_time}!"
            message = client.messages.create(
                body=message_body,
                from_=env[twilio_phone_number],
                to=env[to_phone_number]
            )
            print("sms sent")
        except Exception as e:
            print("twillio error: ", e)
        #send email
        message = Mail(
            from_email=env["fromemail"],
            to_emails=env["emailid"],
            subject=subject,
            plain_text_content=content
        )
        try:
            # Initialize SendGrid client with your API key
            sendgrid_client = SendGridAPIClient(env["sendgrid_api_key"])  # Replace with your actual API key
            response = sendgrid_client.send(message)
            print(f"Email sent with status code: {response.status_code}")
        except Exception as e:
            print(f"Error sending email: {e}")
import os
import json
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Define default configuration path
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def load_or_create_config():
    """Loads configuration details, auto-creating a template if missing."""
    default_config = {
        "email": {
            "enabled": True,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "your_email@gmail.com",
            "sender_password": "your_smtp_app_password",
            "recipient_email": "owner_email@gmail.com"
        },
        "twilio": {
            "enabled": False,
            "account_sid": "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "auth_token": "your_auth_token",
            "from_number": "+1234567890",
            "to_number": "+1234567890"
        }
    }
    
    if not os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=4)
            print(f"[OTP] Generated default configuration template at '{CONFIG_PATH}'", flush=True)
        except Exception as e:
            print(f"[WARNING] Failed to write default config: {e}", flush=True)
        return default_config
        
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read config.json: {e}", flush=True)
        return default_config

def generate_otp():
    """Generates a cryptographically secure 6-digit OTP code."""
    # Use SystemRandom for cryptographic security
    rng = random.SystemRandom()
    return f"{rng.randint(100000, 999999)}"

def send_email_otp(otp, config):
    """Sends the OTP code to the owner via SMTP."""
    mail_conf = config.get("email", {})
    if not mail_conf.get("enabled", False):
        return False
        
    sender = mail_conf.get("sender_email")
    password = mail_conf.get("sender_password")
    recipient = mail_conf.get("recipient_email")
    server_addr = mail_conf.get("smtp_server")
    port = mail_conf.get("smtp_port", 587)
    
    # Skip if credentials are placeholders
    if "your_email" in sender or "your_smtp" in password:
        print("[OTP] [WARNING] SMTP credentials are not configured in config.json. Skipping email dispatch.", flush=True)
        return False
        
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = "SECURE ALERT: Behavioral Anomaly Detected!"
    
    body = f"""\
<h3>Security Alert Notification</h3>
<p>Our Behavioral Security system has detected anomalous dynamics on your desktop.</p>
<p><strong>Verification Code:</strong> <span style="font-size: 20px; font-family: monospace; color: red;">{otp}</span></p>
<p>If this is you, enter this OTP on the verification prompt to authenticate and auto-calibrate the system models.</p>
<p>If you are not currently using your computer, an unauthorized session is active. Take immediate precautions.</p>
"""
    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP(server_addr, port)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()
        print(f"[OTP] OTP email successfully dispatched to {recipient}", flush=True)
        return True
    except Exception as e:
        print(f"[OTP] [ERROR] Failed to send OTP email: {e}", flush=True)
        return False

def send_twilio_otp(otp, config):
    """Sends the OTP code to the owner via Twilio SMS."""
    sms_conf = config.get("twilio", {})
    if not sms_conf.get("enabled", False):
        return False
        
    sid = sms_conf.get("account_sid")
    token = sms_conf.get("auth_token")
    from_num = sms_conf.get("from_number")
    to_num = sms_conf.get("to_number")
    
    if "ACXX" in sid or "your_auth" in token:
        print("[OTP] [WARNING] Twilio API credentials are not configured in config.json. Skipping SMS dispatch.", flush=True)
        return False
        
    try:
        # Import Twilio inside function to make it optional
        from twilio.rest import Client
        client = Client(sid, token)
        message = client.messages.create(
            body=f"SECURITY ALERT: Behavioral anomaly detected on your computer! Enter OTP {otp} to verify identity.",
            from_=from_num,
            to=to_num
        )
        print(f"[OTP] OTP SMS successfully sent via Twilio (Message SID: {message.sid})", flush=True)
        return True
    except Exception as e:
        print(f"[OTP] [ERROR] Failed to send Twilio SMS: {e}", flush=True)
        return False

def dispatch_otp(otp):
    """Coordinates OTP generation and dispatch based on config settings."""
    config = load_or_create_config()
    
    email_success = send_email_otp(otp, config)
    sms_success = send_twilio_otp(otp, config)
    
    return email_success or sms_success

if __name__ == "__main__":
    code = generate_otp()
    print(f"Generated test code: {code}")
    dispatch_otp(code)

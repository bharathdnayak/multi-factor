import os
import sys
import json
import random
import time
import ssl
import smtplib
import requests
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def parse_env_file(filepath=ENV_PATH):
    """Parses key-value pairs from .env file directly."""
    env_vars = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        env_vars[key.strip()] = val.strip().strip('"').strip("'")
        except Exception as e:
            print(f"[OTP] [WARNING] Could not read .env: {e}", flush=True)
    return env_vars


def get_alert_config():
    """Merges configurations from .env and config.json with priority to .env."""
    env_vars = parse_env_file()
    
    sender_pwd = env_vars.get("SMTP_APP_PASSWORD", "")
    if not sender_pwd and os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                json_cfg = json.load(f)
                sender_pwd = json_cfg.get("email", {}).get("sender_password", "")
        except Exception:
            pass

    # Clean password of any spaces
    clean_pwd = sender_pwd.replace(" ", "").strip()
    
    sender_email = env_vars.get("SMTP_EMAIL", "jd444583@gmail.com")
    recipient_email = env_vars.get("ALERT_EMAIL", sender_email)
    
    config = {
        "email": {
            "enabled": True,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 465,
            "sender_email": sender_email,
            "sender_password": clean_pwd,
            "recipient_email": recipient_email
        },
        "telegram": {
            "enabled": bool(env_vars.get("TELEGRAM_BOT_TOKEN")),
            "bot_token": env_vars.get("TELEGRAM_BOT_TOKEN", ""),
            "chat_id": env_vars.get("TELEGRAM_CHAT_ID", "")
        }
    }
    return config


def generate_otp():
    """Generates a cryptographically secure 6-digit OTP code."""
    rng = random.SystemRandom()
    return f"{rng.randint(100000, 999999)}"


def send_email_otp(otp, photo_path=None, threat_info=None):
    """Sends the OTP code and captured intruder evidence to the owner via SMTP (Gmail)."""
    config = get_alert_config()
    mail_conf = config.get("email", {})
    
    sender = mail_conf.get("sender_email")
    password = mail_conf.get("sender_password")
    recipient = mail_conf.get("recipient_email")
    
    if not sender or not password or "your_email" in sender:
        print("[OTP] [INFO] SMTP credentials not fully configured. Skipping email dispatch.", flush=True)
        return False
        
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_text = f"{threat_info.get('risk_score', 0.85):.2f}" if threat_info else "0.88 (HIGH ANOMALY)"
    app_text = threat_info.get('active_app', 'Unknown Desktop Session') if threat_info else 'Active Desktop Session'

    msg = MIMEMultipart("mixed")
    msg['From'] = f"Behavioral Security <{sender}>"
    msg['To'] = recipient
    msg['Subject'] = f"🚨 SECURITY ALERT: Intrusion Detected on Desktop [OTP: {otp}]"
    
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background-color: #1e293b; border-radius: 10px; padding: 25px; border: 1px solid #ef4444;">
          <h2 style="color: #ef4444; margin-top: 0;">⚠️ Security Anomaly Detected!</h2>
          <p style="color: #cbd5e1; font-size: 15px;">
            Our continuous biometric authentication engine detected an unauthorized session or sudden behavioral drift on your desktop.
          </p>
          
          <table style="width: 100%; margin: 15px 0; color: #e2e8f0; font-size: 14px;">
            <tr><td><strong>Timestamp:</strong></td><td>{now_str}</td></tr>
            <tr><td><strong>Threat Risk Score:</strong></td><td style="color: #f87171; font-weight: bold;">{risk_text}</td></tr>
            <tr><td><strong>Active Application:</strong></td><td>{app_text}</td></tr>
          </table>

          <div style="background-color: #0f172a; border-radius: 8px; padding: 15px; text-align: center; margin: 20px 0; border: 1px dashed #38bdf8;">
            <p style="margin: 0; color: #94a3b8; font-size: 13px;">SESSION VERIFICATION OTP</p>
            <span style="font-size: 32px; font-family: monospace; font-weight: bold; color: #38bdf8; letter-spacing: 6px;">{otp}</span>
          </div>

          <p style="color: #94a3b8; font-size: 13px;">
            • If this is you, enter this OTP on the Verification Lock Screen to restore normal operation.<br>
            • If someone else is at your computer, the deception sandbox is actively isolating their activity.
          </p>
          
          {"<p style='color: #f59e0b; font-size: 13px;'>📷 <em>Intruder snapshot captured via webcam attached below.</em></p>" if photo_path and os.path.exists(photo_path) else ""}
        </div>
      </body>
    </html>
    """
    msg.attach(MIMEText(html_body, 'html'))
    
    if photo_path and os.path.exists(photo_path):
        try:
            with open(photo_path, "rb") as img_f:
                image_part = MIMEImage(img_f.read(), name=os.path.basename(photo_path))
                image_part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(photo_path))
                msg.attach(image_part)
        except Exception as e:
            print(f"[OTP] [WARNING] Could not attach photo to email: {e}", flush=True)

    try:
        context = ssl.create_default_context()
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=15)
        server.login(sender, password)
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()
        print(f"[OTP] [SUCCESS] Alert email with OTP {otp} successfully delivered to {recipient}", flush=True)
        return True
    except Exception as e:
        print(f"[OTP] [ERROR] SMTP delivery error: {e}", flush=True)
        return False


def get_latest_telegram_chat_id(bot_token):
    """Auto-discovers the user's chat ID from the bot's latest messages if misconfigured."""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
        resp = requests.get(url, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("result", [])
            if results:
                for item in reversed(results):
                    msg = item.get("message", item.get("my_chat_member", {}))
                    chat = msg.get("chat", {})
                    chat_id = chat.get("id")
                    if chat_id and str(chat_id) != bot_token.split(":")[0]:
                        return str(chat_id)
    except Exception:
        pass
    return None


def send_telegram_alert(otp, photo_path=None, threat_info=None):
    """Sends real-time alert message and intruder photo directly to owner's Telegram."""
    config = get_alert_config()
    tg_conf = config.get("telegram", {})
    
    bot_token = tg_conf.get("bot_token")
    chat_id = tg_conf.get("chat_id")
    
    if not bot_token:
        return False

    bot_id = bot_token.split(":")[0]
    if str(chat_id) == str(bot_id) or not chat_id:
        auto_chat_id = get_latest_telegram_chat_id(bot_token)
        if auto_chat_id:
            chat_id = auto_chat_id
        else:
            print(f"[OTP] [NOTICE] Telegram Chat ID '{chat_id}' is the Bot's ID. Message your bot on Telegram to receive alerts there too.", flush=True)
            return False

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_val = f"{threat_info.get('risk_score', 0.85):.2f}" if threat_info else "0.88"
    app_val = threat_info.get('active_app', 'Active Session') if threat_info else 'Active Desktop Session'
    
    caption = (
        f"🚨 <b>SECURITY BREACH ALERT!</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ <b>Behavioral Drift / Unauthorized Takeover Detected!</b>\n\n"
        f"🔑 <b>Verification OTP:</b> <code>{otp}</code>\n"
        f"📊 <b>Threat Risk Score:</b> <code>{risk_val}</code>\n"
        f"🖥️ <b>Active App:</b> <code>{app_val}</code>\n"
        f"🕒 <b>Time:</b> <code>{now_str}</code>\n\n"
        f"<i>Enter the 6-digit OTP on the Desktop Lock Screen to restore access.</i>"
    )
    
    try:
        if photo_path and os.path.exists(photo_path):
            url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
            with open(photo_path, "rb") as photo_file:
                resp = requests.post(
                    url,
                    data={"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"},
                    files={"photo": photo_file},
                    timeout=10
                )
        else:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            resp = requests.post(
                url,
                json={"chat_id": chat_id, "text": caption, "parse_mode": "HTML"},
                timeout=10
            )
            
        if resp.status_code == 200:
            print(f"[OTP] [SUCCESS] Live Telegram alert + evidence dispatched to chat ID {chat_id}", flush=True)
            return True
        else:
            return False
    except Exception as e:
        return False


def dispatch_otp(otp, photo_path=None, threat_info=None):
    """Dispatches OTP across all enabled communication channels (Email + Telegram + SMS)."""
    print(f"[ALERT-DISPATCHER] Initiating multi-channel security alerts for OTP: {otp}...", flush=True)
    email_ok = send_email_otp(otp, photo_path=photo_path, threat_info=threat_info)
    tg_ok = send_telegram_alert(otp, photo_path=photo_path, threat_info=threat_info)
    return email_ok or tg_ok


if __name__ == "__main__":
    test_otp = generate_otp()
    print(f"=== TESTING LIVE REAL-TIME ALERTING (OTP: {test_otp}) ===")
    
    forensics_dir = os.path.join(PROJECT_ROOT, "data", "forensics")
    test_photo = None
    if os.path.exists(forensics_dir):
        for f in os.listdir(forensics_dir):
            if f.endswith(".jpg") or f.endswith(".png"):
                test_photo = os.path.join(forensics_dir, f)
                break
                
    success = dispatch_otp(test_otp, photo_path=test_photo, threat_info={"risk_score": 0.94, "active_app": "cmd.exe"})
    print(f"\n[RESULT] Live Alert Dispatch: {'SUCCESSFUL' if success else 'FAILED'}")

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

FROM_EMAIL = os.getenv("SMTP_USER", "varshaa32004@gmail.com")
PASSWORD = os.getenv("SMTP_PASS")
TO_EMAIL = "svar22040.cb@rmkec.ac.in"


def send_soc_alert(device_id: str, action: str, trust_score: float, attack_type: str = "Unknown"):
    """
    Sends a real-time SOC alert email when a device's trust score drops below critical thresholds.
    """
    if not PASSWORD:
        print("[EmailAlert] Skipping SOC alert email: SMTP_PASS environment variable is not set.")
        return False

    subject = f"[CRITICAL] Guardient Incident Alert: Device {device_id[:8]}"
    
    body = f"""
Guardient Security Orchestration & Automated Response (SOAR)
============================================================

CRITICAL INCIDENT DETECTED

Device ID:    {device_id}
Attack Type:  {attack_type}
Trust Score:  {trust_score:.1f} / 100.0
Action Taken: {action.upper().replace('_', ' ')}

Please investigate immediately via the Guardient Dashboard:
http://localhost:3000/simulation

--
Guardient Automated Response Engine
    """

    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(FROM_EMAIL, PASSWORD)
        server.sendmail(FROM_EMAIL, TO_EMAIL, msg.as_string())
        server.quit()
        print(f"[EmailAlert] ✅ SOC alert sent successfully to {TO_EMAIL} for device {device_id[:8]}")
        return True
    except Exception as e:
        print(f"[EmailAlert] ❌ Failed to send SOC alert email: {e}")
        return False

if __name__ == "__main__":
    # Test execution
    print("Testing Guardient Email Alert...")
    send_soc_alert("dev_test123456", "isolate_device", 12.5, "C2 Beaconing")

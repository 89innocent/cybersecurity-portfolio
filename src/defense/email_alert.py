import smtplib
import os
from email.mime.text import MIMEText


EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

TO_EMAIL = os.getenv("TO_EMAIL")


def send_alert(subject, body):

    try:

        msg = MIMEText(body, "plain", "utf-8")

        msg["Subject"] = subject
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = TO_EMAIL

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:

            server.starttls()

            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

            server.send_message(msg)

        print("📧 Email alert sent!")

    except Exception as e:

        print(f"[EMAIL ERROR] {e}")

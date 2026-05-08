import os
import smtplib
from email.mime.text import MIMEText

import requests


def send_slack_alert(webhook_url, message):
    try:
        requests.post(webhook_url, json={"text": message}, timeout=10)
        print("Slack alert sent.")
    except requests.exceptions.Timeout:
        print("Failed to send Slack alert: request timed out after 10s.")
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")


def send_email_alert(smtp_config, sender, recipients, subject, body):
    """Send an email alert via SMTP.

    SMTP credentials are read from environment variables:
      SMTP_USERNAME — overrides smtp_config['username'] if set
      SMTP_PASSWORD — required; never pass the password through smtp_config
    """
    username = os.environ.get("SMTP_USERNAME") or smtp_config.get("username", "")
    password = os.environ.get("SMTP_PASSWORD")
    if not password:
        print("Failed to send email alert: SMTP_PASSWORD environment variable is not set.")
        return

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)

        with smtplib.SMTP(smtp_config["host"], smtp_config["port"]) as server:
            server.starttls()
            server.login(username, password)
            server.sendmail(sender, recipients, msg.as_string())
        print("Email alert sent.")
    except Exception as e:
        print(f"Failed to send email alert: {e}")

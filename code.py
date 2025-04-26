from fastapi import FastAPI, Request
from dotenv import load_dotenv
import os, re, requests, smtplib
from email.message import EmailMessage

load_dotenv()
app = FastAPI()

# Load ENV variables
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")

# Secret patterns
patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
}

def notify_slack(msg):
    if SLACK_WEBHOOK:
        requests.post(SLACK_WEBHOOK, json={"text": msg})

def notify_email(subject, body):
    if EMAIL_USER and EMAIL_PASS:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_TO
        msg.set_content(body)

        try:
            with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
                server.starttls()
                server.login(EMAIL_USER, EMAIL_PASS)
                server.send_message(msg)
        except Exception as e:
            print("Email failed:", e)

@app.post("/webhook")
async def scan_commits(request: Request):
    data = await request.json()
    commits = data.get("commits", [])
    for commit in commits:
       msg = commit.get("message", "")
        for name, regex in patterns.items():
            if re.search(regex, msg):
                alert = f"🚨 Leak Detected: {name}\n🔎 Commit Message: {msg}"
                notify_slack(alert)
                notify_email("Leak Detected!", alert)
    return {"status": "scanned"}

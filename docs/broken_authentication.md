Broken Authentication

Demos Included
- Brute Force Login
- Weak Password Policy at Registration
- Weak / Uncontrolled Session Cookies

https://tryhackme.com/room/owasptop102021 (Identification and Authentication Failures Section)

- Brute Force Login

The login endpoint in this application allows unlimited authentication attempts.
This enables an attacker to perform a brute force attack to guess user passwords.

I prepared everthing necessary so you can perform a brute force attack on our app, by following these steps:
1. Run the app
2. Register a new user with username: tester and choose your own password
3. Run the brute_force_test.py script under attack-demos/broken_authentication (you may need to install the requests package with "pip install requests")
4. This script will try to guess your password using a common password list obtained from kaggle (*)
5. It will display the passwords it tries, how many attempts it took, and how much time was spent, like this:

(venv) seckin@seckins-mbp broken_authentication % python3 brute_force_test.py 
[-] Tried: 123456
[-] Tried: 12345
[-] Tried: 123456789
[-] Tried: password
[-] Tried: iloveyou
[-] Tried: princess
[-] Tried: 1234567
[-] Tried: rockyou
[-] Tried: 12345678

[+] Password FOUND: abc123
[✓] Attempts: 10
[✓] Time taken: 0.03 seconds

(*) https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt/data 
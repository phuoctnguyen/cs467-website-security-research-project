Broken Authentication

Demos Included
- Brute Force Login
- Weak Password Policy at Registration (skipped for now, since it conflicts with the brute force demo)
- Weak / Uncontrolled Session Cookies

https://tryhackme.com/room/owasptop102021 (Identification and Authentication Failures Section)

- Brute Force Login

The login endpoint in this application allows unlimited authentication attempts.
This enables an attacker to perform a brute force attack to guess user passwords.

I prepared everthing necessary so you can perform a brute force attack on our app, by following these steps:
1. Run the app
2. Register a new user with username: tester and choose your own (make sure you pick one from the 100 passwords listed in attack-demos/broken_authentication/passwords.txt file) password.
3. In the attack-demos/broken_authentication folder (you may need to pip install requests first), run: python3 brute_force_test.py vulnerable
4. The script will try to guess your password using a common password list from Kaggle (*), showing each attempt as it goes.
5. Once it guesses correctly, it will display your password, the number of attempts, and the time taken. For example:

(venv) seckin@seckins-mbp broken_authentication % python3 brute_force_test.py vulnerable
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

In order to see our defense in action, do the following:

1. Run the script in secure mode: python3 brute_force_test.py secure
2. It will stop automatically because our app begins returning the HTTP 429 Too Many Requests error once it detects more than five failed login attempts from the same IP within a 60 second window.

(venv) seckin@seckins-mbp broken_authentication % python3 brute_force_test.py secure    
[-] Tried: 123456
[-] Tried: 12345
[-] Tried: 123456789
[-] Tried: password
[-] Tried: iloveyou

[!] Rate limit hit. Brute force attack stopped.
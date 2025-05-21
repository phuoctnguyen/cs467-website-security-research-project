
# Security Misconfiguration Vulnerabilty/Mitigation

## Overview

This update enhances the security of the Capstone Bank application by enforcing strong password policies during user registration and adding secure HTTP headers in **secure mode**. These additions help prevent weak user credentials and common browser-based attacks such as XSS, clickjacking, and MIME-type sniffing.

---

## Summary of Changes

### 1. Password Strength Validation

A new password validation function has been implemented to enforce minimum complexity rules. This validation is only applied in **Secure Mode** to mirror a realistic security toggle scenario for educational purposes.

**Requirements:**
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character (e.g., `!`, `@`, `#`, `$`, etc.)

```python
def validate_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True
```

### 2. Registration Improvements

- The `register` route was updated to:
  - Reject mismatched passwords.
  - Reject weak passwords (in secure mode).
  - Show meaningful flash messages to the user.

- Flash messages now include:
  - "Passwords do not match."
  - "Username already exists."
  - "Password must be at least 8 characters..."
  - "Registration successful! Please log in."

- The registration HTML (`register.html`) was updated to:
  - Show only the most recent flash message.
  - Display password requirement hints if password validation fails.

### 3. Secure HTTP Headers

Secure HTTP headers are added in **Secure Mode** only, via the `@app.after_request` decorator:

```python
@app.after_request
def add_security_headers(response):
    if session.get('secure_mode'):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
        response.headers['Referrer-Policy'] = 'no-referrer'
    return response
```

These headers are commonly recommended for production web applications and align with security best practices.

---

## Testing Instructions

### Registration (Secure Mode)

1. Go to `/register`
2. Select `Secure` mode from the dropdown.
3. Try creating accounts using:
   - Passwords without special characters → Should be rejected
   - Passwords under 8 characters → Should be rejected
   - Passwords without uppercase/lowercase/numbers → Should be rejected
   - Strong password → Should succeed

### HTTP Header Verification

**Method 1: Browser DevTools**
1. Log in using `Secure` mode.
2. Open DevTools → Network tab.
3. Refresh `/dashboard` or another page.
4. Click on the request and view **Response Headers**.
5. Confirm presence of the following:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `X-XSS-Protection: 1; mode=block`
   - `Content-Security-Policy: default-src 'self'`
   - `Strict-Transport-Security`
   - `Referrer-Policy`

**Method 2: Frame Blocking Test**
1. Create a file with the following (test-iframe.html included in repo):
   ```html
   <iframe src="http://127.0.0.1:5000/dashboard" width="600" height="400"></iframe>
   ```
2. Load it in a browser while logged into the app in Secure Mode.
3. The iframe should be blocked with a browser error.

---

## Secure HTTP Header Reference Table

| Header                      | Purpose                                               |
|-----------------------------|--------------------------------------------------------|
| X-Content-Type-Options      | Prevents MIME-type sniffing                          |
| X-Frame-Options             | Prevents clickjacking via iframes                    |
| X-XSS-Protection            | Enables XSS filtering (legacy support)               |
| Content-Security-Policy     | Restricts sources of scripts, styles, etc.           |
| Strict-Transport-Security   | Enforces HTTPS with max-age + preload                |
| Referrer-Policy             | Hides referrer headers for privacy and security      |

---

## Notes

- These improvements are **only activated in Secure Mode**, allowing comparison between vulnerable and hardened implementations for learning and testing purposes.

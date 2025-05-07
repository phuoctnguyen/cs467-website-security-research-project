# XML External Entity (XXE) Attack Demonstration

## Overview
This demonstration showcases how an XML External Entity (XXE) vulnerability can be exploited in a Flask-based web application, and how it can be mitigated using secure XML parsing. The application allows users to upload an XML file to update account balances. In vulnerable mode, XML input is parsed with external entities enabled, making the app susceptible to XXE attacks.

In secure mode, external entity resolution is disabled to prevent exploitation.

---

## Setting up and Running the Application

### Prerequisites
- Python 3
- Flask and required dependencies
- Application code running on `http://127.0.0.1:5000`

### Start the Flask app
```bash
python3 app.py
```

---

## Vulnerable Mode

### Code Behavior
In vulnerable mode, the app uses:
```python
parser = etree.XMLParser(resolve_entities=True)
```
This allows injected XML entities to be parsed and resolved by the server, including local file disclosure.

### Attack Setup
1. Log in to the app at `/login` with:
   - Username: `tester`
   - Password: `abc123`
   - Mode: **Vulnerable**
2. Navigate to the **Import** page.
3. Upload a malicious XML file such as:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <root>
       <checking>1000</checking>
       <savings>&xxe;</savings>
   </root>
   ```
4. Observe that the contents of `/etc/passwd` are displayed, confirming a successful XXE attack.

---

## Secure Mode

### Mitigation Code
In secure mode, external entity resolution is explicitly disabled:
```python
parser = etree.XMLParser(resolve_entities=False)
```

### Updated Code
```python
secure_mode = session.get('secure_mode', False)
parser = etree.XMLParser(resolve_entities=not secure_mode)
```

### Attack Attempt in Secure Mode
1. Log in to the app with:
   - Username: `tester`
   - Password: `abc123`
   - Mode: **Secure**
2. Upload the same malicious XML payload from earlier.
3. The app either:
   - Rejects the entity, or
   - Displays a parsing error.
4. No sensitive file contents are revealed.

---

## Test Cases

| Mode       | Payload Used                     | Expected Behavior                      |
|------------|----------------------------------|----------------------------------------|
| Vulnerable | XXE loading /etc/passwd          | Server returns contents of the file    |
| Secure     | XXE loading /etc/passwd          | XXE is blocked or rejected             |
| Vulnerable | Well-formed balance XML          | Account balances are updated           |
| Secure     | Well-formed balance XML          | Account balances are updated           |

---

## Resources

1. [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
2. [PortSwigger on XXE](https://portswigger.net/web-security/xxe)
3. [lxml XMLParser Docs](https://lxml.de/api/lxml.etree.XMLParser-class.html)


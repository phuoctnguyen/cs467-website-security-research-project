# Insufficient Logging and Monitoring

## Overview

Insufficient logging and monitoring is one of the OWASP Top 10 vulnerabilities. It occurs when applications fail to record security-relevant events, making it difficult to detect, respond to, or recover from attacks. Without proper logging, organizations may miss signs of intrusion, exfiltration, or abuse until after damage has occurred.

## Secure Mode

- All login attempts (successful or failed) are logged, including IP address, username, and role.
- Registration attempts are logged.
- Logging is handled by Python's built-in `logging` library with a rotating file handler.
- Logs are written to `logs/app.log` and retained up to 5 rotating files.

## Vulnerable Mode

- No event correlation or real-time alerting.
- Insufficient logging here represents a realistic lack of visibility in insecure deployments.

## Implementation Details

### Logging Configuration

Located near the top of `app.py`, below the Flask app initialization:

```python
import logging
from logging.handlers import RotatingFileHandler

LOG_FILE = 'logs/app.log'
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
handler.setFormatter(formatter)

app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)
```

### Logging Events

Added logging statements to:
- `@app.route("/login")`:
  - Log all login attempts.
  - Log success and failure separately.
- `@app.route("/register")`:
  - Log all registration attempts.

Example log output:
```
[2025-06-01 23:52:10] INFO in app: Login attempt by user: tester in secure mode from IP: 127.0.0.1
[2025-06-01 23:52:11] WARNING in app: Failed login for user: tester from IP: 127.0.0.1
[2025-06-01 23:52:20] INFO in app: Successful login for user: tester (Role: user) from IP: 127.0.0.1
[2025-06-01 23:53:05] INFO in app: New registration attempt for username: newuser in secure mode
```

## How to Test

1. Run the app in secure mode.
2. Attempt a successful and failed login.
3. Register a new user.
4. Open the log file at `logs/app.log`.
5. Confirm that actions were logged, including:
   - Timestamp
   - Event type (INFO or WARNING)
   - Module name
   - Description of the action

To simulate insufficient logging:
- Switch to vulnerable mode and observe how log entries are limited or not emphasized.
- No interface is available for viewing logs in the browser.

## Notes

- Log file is kept locally and should not be served through Flask routes.
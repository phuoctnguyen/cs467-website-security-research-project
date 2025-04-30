# SQL Injection Demonstration with Secure/Vulnerable Toggle

## Overview

This feature adds a toggle-able login mechanism that allows the app to operate in either **secure** or **vulnerable** mode. It was developed to demonstrate how a basic SQL injection attack works and how to properly mitigate it using safe query practices.

The secure mode uses SQLAlchemy's `filter_by()` method, while the vulnerable mode executes a raw SQL string using `text()` with user input.

---

## Implementation Details

- A dropdown was added to the login form to allow users to select "Secure" or "Vulnerable" mode at runtime.
- The Flask backend reads the selection from `request.form.get('secure')`.
- In vulnerable mode, a raw SQL string is constructed using user input and executed directly.
- In secure mode, SQLAlchemy’s ORM is used with safe parameterization.
- Flash messages indicate which mode is active.

---

## Test Instructions

Test at `http://127.0.0.1:5000/login`

### Case 1: Secure Mode — Valid Credentials  
- Username: `tester`  
- Password: `abc123`  
- Expected: Login succeeds

### Case 2: Secure Mode — Invalid Credentials  
- Username: `tester`  
- Password: `wrongpass`  
- Expected: Login fails

### Case 3: Secure Mode — SQL Injection Attempt  
- Username: any  
- Password: `' OR '1'='1' --`  
- Expected: Login fails (injection blocked)

### Case 4: Vulnerable Mode — SQL Injection Bypass  
- Username: any  
- Password: `' OR '1'='1' --`  
- Expected: Login succeeds (unauthorized access)

### Case 5: Vulnerable Mode — Wrong Password Without Injection  
- Username: `tester`  
- Password: `wrongpass`  
- Expected: Login fails (normal behavior)

---

## Resources

- [TryHackMe: SQL Injection Lab](https://tryhackme.com/room/sqlinjectionlm)  
- [Flask Mega-Tutorial by Miguel Grinberg (Part I)](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)

---

## Notes

- This feature was developed and tested as part of Sprint 1 but aligns with the SQL Injection task assigned in Sprint 2.

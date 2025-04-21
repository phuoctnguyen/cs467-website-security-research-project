# SQL Injection Vulnerability Plan

## Goal
Create a login system with two versions:
- A vulnerable version that can be tricked using SQL injection
- A secure version that is protected from SQL injection

## How It Will Work
- Add a switch called SECURE_MODE that is either True or False
- If it’s False, the app will run insecure code using raw SQL strings
- If it’s True, the app will run safe code using SQLAlchemy’s filter_by

## Tasks
- Add SECURE_MODE at the top of the app
- Change the login route to check if SECURE_MODE is True or False
- If False: use raw SQL to check username and password
- If True: use filter_by to check login
- Test both modes by trying to log in normally and by using a SQL injection input like:
  - username: anything
  - password: ' OR '1'='1

## Notes
I will try writing both versions and test how the injection works when the app is in vulnerable mode.

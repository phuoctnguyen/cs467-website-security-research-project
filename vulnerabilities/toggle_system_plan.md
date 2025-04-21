# Toggle System Plan

## Purpose
Allow the web app to run in either secure or vulnerable mode by switching one variable in the backend.

## Toggle Variable
SECURE_MODE = True or False

## Where It Will Go
- At the top of app.py
- Used in the login() route to choose between secure and insecure login logic

## What It Affects
- The login logic for SQL Injection demo
- Later: probably for other routes

## Future Plans
We can eventually:
- Read the toggle value from an environment variable
- Add a dropdown in the UI to switch modes
- Display which mode is active somewhere on the dashboard

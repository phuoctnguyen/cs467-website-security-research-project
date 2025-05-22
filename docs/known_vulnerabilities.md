# Using Components with Known Vulnerabilities Demonstration: Pillow Decompression Bomb

Attention: Do not try to open the decompression_bomb.gif file under attack-demos/known_vulnerabilities. 

## 1. Overview

This document presents our attempt to demonstrate a Denial of Service (DoS) vulnerability in Pillow 8.2.0 using decompression bomb images.

Although we aimed to crash the application using TIFF/PNG bombs, Pillow’s internal checks (even in 8.2.0) raised catchable exceptions instead. As a result, our demo shifted focus:

1. Confirm Pillow ≥11.2.1 flags suspicious images.
2. Show how unhandled exceptions in app code (“Vulnerable Mode”) can still cause a DoS.
3. Compare with a safely-handled version (“Secure Mode”).

## 2. Background

* **Pillow < 8.3.0 Vulnerability:** Older versions were vulnerable to DoS via crafted images (e.g., TIFF/PNG) that triggered excessive memory allocation.

Both Pillow 8.2.0 and 11.2.1 raised Image.DecompressionBombError when tested with known bomb files.

## 3. Setup & Method

### 3.1. Application Feature

A Flask profile image upload endpoint using Pillow to process images.

### 3.2. Demonstration Logic (`app.py`)

* **"Secure Mode":** Catches Image.DecompressionBombError with try-except.
* **"Vulnerable Mode":** Omits error handling, simulating a DoS condition.

### 3.3. Test File
* **Bomb File:** `decompression_bomb.gif` (Source: Pillow test suite - `https://github.com/python-pillow/Pillow/blob/main/Tests/images/decompression_bomb.gif`)
* **Observed Behavior with Pillow 8.2.0 and 11.2.1:** In both Pillow versions, raises DecompressionBombError.
---

## 4. Testing Guide

**Prerequisites**

* Install pillow library (pip install pillow).
* Have the test bomb image file ready ('decompression_bomb.gif` under attack-demos/known_vulnerabilities).
* Remove existing DB: rm users.sqlite3 (note: this deletes test data).

**Test 1: Vulnerable Mode**

1.  Start app and log in as vulnerable user.
2.  Go to the profile page and upload the bomb image.
3.  **Expected:**
    * **Browser:** App crashes.
    * **Terminal:** Shows a full traceback.

**Test 2: Latest Pillow with Application in "Secure Mode"**

1.  Restart Flask app.
2.  Log in as secure user.
3.  Go to the profile page and upload the same bomb image.
4.  **Expected Outcome:**
    * **Browser:** Friendly error message shown. App remains stable.
    * **Terminal:** Logs handled exception.

## 5. Key Learnings

Reproducing known vulnerabilities is harder than expected. Installing old, vulnerable packages often fails due to outdated dependencies or incompatible environments.

# Insecure Deserialization Demonstration: Python Pickle Vulnerability

Attention: The malicious .dat file generated for this demo (deface_admin_dashboard.dat) is designed to perform actions on your local server environment when used with the application in "Vulnerable Mode." Understand what they do before using them. Be prepared to restore the modified file (admin-dashboard.html) after the defacement demo.

## 1. Overview

This document details the demonstration of an Insecure Deserialization vulnerability using Python's pickle module within the Capstone Bank application. The vulnerability is present in the "Import a User" admin feature when the application is in "Vulnerable Mode."

The demonstration showcases how pickle.loads() on untrusted data can lead to Remote Code Execution, specifically by defacing a web page.

This vulnerability is mitigated in "Secure Mode" by using a safe data format (JSON) and parser for the same import functionality, rendering it immune to these pickle based attacks.

## 2. Background

**Serialization & Deserialization:** Serialization converts an object into a storable/transmittable format. Deserialization reconstructs the object from this format.

**Insecure Deserialization:** Occurs when an application deserializes data from an untrusted source without sufficient validation or using an inherently unsafe deserializer.

**Python pickle:** A Python module for serializing and deserializing Python object structures. However, it is not secure against maliciously constructed data. Deserializing a pickle stream from an untrusted source can execute arbitrary code. This is because pickle is designed to reconstruct not just data, but complex object states, and can be instructed to run arbitrary functions during this process. The official Python documentation explicitly warns against unpickling data from untrusted sources.

## 3. Setup & Method

### 3.1. Application Feature

To facilitate this demonstration, new functionalities for "Import a User" and "Export a User" were developed for the admin portal. The "Import a User" feature allows administrators to upload a file to create new users, serving as the entry point for the deserialization vulnerability. The "Export a User" feature provides context by allowing admins to generate user data files in formats relevant to both secure (JSON) and vulnerable (Pickle) modes of the application.

### 3.2. Demonstration

**"Secure Mode":**
The application expects a .json file for user import.
It uses json.loads(uploaded_file_content) to parse the data.
Validation is performed on the parsed JSON data (required fields, data types, username uniqueness).
New users are created safely using validated data, with passwords handled as bcrypt hashes (no plaintext passwords in the JSON file).
If a .dat (pickle) file is uploaded, json.loads() will fail safely (with a JSONDecodeError), and no malicious code will execute.

**"Vulnerable Mode":**
The application expects a .dat file for user import.
It directly uses pickle.loads(uploaded_file_content) to deserialize the file content.
If a legitimate pickled User object is uploaded, a new user is created based on its attributes.
If a maliciously crafted pickle payload is uploaded, the code embedded in the payload (via __reduce__) will execute on the server with the application's privileges.

### 3.3. Test Files

**Malicious RCE Payload (Defacement):** `deface_admin_dashboard.dat` (created by running the dat_generator.py in attack-demos/insecure_deserialization)
**Legitimate JSON Import File:** 'Ethan_export.json' (created by using the export function of the app)

## 4. Testing Guide

**Test 1: Vulnerable Mode**

1. Start the application.
2. Log in as an administrator (admin-tester) and in Vulnerable Mode.
3. Navigate to the admin dashboard and click "Import a User".
4. Upload the Malicious RCE Payload file.

Expected Outcome & Verification:
Browser: Navigate to the admin dashboard. The page should now be defaced, showing the message injected by the payload ("PWNED").
Restore your original frontend/pages/admin-dashboard.html file.

**Test 2: Secure Mode**

1. Start the application.
2. Log in as an administrator (admin-tester) and in Secure Mode.
3. Navigate to the admin dashboard and click "Import a User".
4. Upload the Malicious RCE Payload file.

Expected Outcome & Verification:
The import should fail safely. You should see a flashed error message about the file type. The admin dashboard should remain normal.

5. While still in Secure Mode as an admin, navigate to "Import a User".
6. Upload the Legitimate JSON Import File.

Expected Outcome & Verification:
The user "Ethan Hunt" should be created, check it by listing all users.

## 5. Key Learnings

Deserializing data from untrusted sources usingmodules like Python's pickle is extremely dangerous and can easily lead to Remote Code Execution or Denial of Service.

Always prefer safe, data only serialization formats like JSON for data interchange with external or untrusted sources.
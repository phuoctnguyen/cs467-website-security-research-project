# Sensitive Data Exposure

## Testing
The following is a demonstration on how to set up the app and show sensitive data exposure in secure and vulnerable mode.
In vulnerable mode, the user is able to see sensitive data with no restrictions. In secure mode, the sensitive data is hidden from the users. 

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
1. Log in to the app at `/login` with:
   - Username: `tester`
   - Password: `abc123`
   - Mode: **Vulnerable**
2. Once on the dashboard page, right-click on the page and select the web inspector tool. 
3. Navigate to Sources
4. Select the users.js file
5. The following JSON user data will be displayed: 
``` 
[{
    "id": 1,
    "role": "user",
    "name": "tester",
    "email": "tester@capstone.com",
    "password": "abc123",
    "checking": 1000.0,
    "savings": 5000.0
}, {
    "id": 2,
    "role": "admin",
    "name": "admin-tester",
    "email": "admin@capstone.com",
    "password": "abc123",
    "checking": 1000.0,
    "savings": 5000.0
}]; 
```
6. Exit out of the web inspector tool and navigate to the 'Profile' page
7. Observe that the password is exposed.
8. Navigate back to the Dashboard and logout

---

## Secure Mode
1. Log in to the app at `/login` with:
   - Username: `tester`
   - Password: `abc123`
   - Mode: **Secure**
2. Once on the dashboard page, right-click on the page and select the web inspector tool. 
3. Navigate to Sources
4. Select the users.js file
5. The following JSON user data will be displayed: 
``` 
[{"id": 1, "name": "tester"}];
```
6. Exit out of the web inspector tool and navigate to the 'Profile' page
7. Observe that the password is masked.
8. Check the 'Show Password' button
9. Observe the password is now shown
10. Uncheck the 'Show Password' button and observe the password is masked again.

---

## Mitigations
To secure the application, the user is restricted to only seeing their own information in the users.js file. Passwords are considered sensitive data so a masking was 
added to protect the user from potential over the shoulder looking. 

## Resources

1. [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
2. [Password Toggle](https://www.w3schools.com/howto/howto_js_toggle_password.asp)


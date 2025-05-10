from flask import flash, Flask, redirect, render_template, request, session, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_wtf import CSRFProtect      # CSRF Protection
from backend.forms import TransferForm      # CSRF Protection
from backend.helpers import execute_transfer
from lxml import etree
import os
import json
import time

# Brute Force Mitigation Variables
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS   = 5
WINDOW_SECONDS = 60

app = Flask(__name__,
            template_folder='frontend/pages',
            static_folder='frontend')
app.secret_key = '467'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
db = SQLAlchemy(app)

# WTF_CSRF-related logic & code adapted from:
# https://flask-wtf.readthedocs.io/en/0.15.x/csrf/#exclude-views-from-protection
# disable default CSRF protection on all endpoints; activate by endpoint when needed; better for testing.
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

csrf = CSRFProtect(app)     # enable CSRF protection

DEFAULT_CHECKING = 1000.00
DEFAULT_SAVINGS = 5000.00


# User model
class User(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    role = db.Column("role", db.String(8))
    name = db.Column("name", db.String(100))
    email = db.Column("email", db.String(320))
    password = db.Column("password", db.String(100))
    checking = db.Column("checking", db.Float, default=DEFAULT_CHECKING)
    savings = db.Column("savings", db.Float, default=DEFAULT_SAVINGS)

    def __init__(self, role, name, password, email, checking=DEFAULT_CHECKING, savings=DEFAULT_SAVINGS):
        self.role = role
        self.name = name
        self.email = email
        self.password = password
        self.checking = checking
        self.savings = savings

    def get_id(self):
        return self._id


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        secure_mode = request.form.get('secure') == 'true'

        if secure_mode:

            # This is a note for my project partners and "future me":
            # The following code creates key-value pairs in the LOGIN_ATTEMPS 
            # dictionary where keys are ip numbers and values are lists for 
            # the timestamps of login attempts.

            ip  = request.remote_addr or 'unknown'
            now = time.time()

            if ip not in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[ip] = []

            # This gets rid of timestamps outside our WINDOW_SECONDS
            valid = []
            for timestamp in LOGIN_ATTEMPTS[ip]:
                if now - timestamp < WINDOW_SECONDS:
                    valid.append(timestamp)
            LOGIN_ATTEMPTS[ip] = valid

            if len(LOGIN_ATTEMPTS[ip]) >= MAX_ATTEMPTS:
                return make_response("Too many requests", 429)
            
            user = User.query.filter_by(name=username, password=password).first()

        else:
            # Vulnerable version
            query = text(f"SELECT * FROM user WHERE name = '{username}' AND password = '{password}'")
            print(f"[DEBUG] Running raw query: {query}")
            result = db.session.execute(query).fetchone()
            user = None
            if result:
                user_id = result[0]  # first column is "id"
                user = User.query.filter_by(_id=user_id).first()

        if user:

            if secure_mode:
                LOGIN_ATTEMPTS[ip] = []

            session['username'] = user.name
            session['secure_mode'] = secure_mode
            flash(f"Hello, {username} ({'Secure' if secure_mode else 'Vulnerable'} Mode)")
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:

            if secure_mode:
                LOGIN_ATTEMPTS[ip].append(now)

            flash(f"Invalid username or password ({'Secure' if secure_mode else 'Vulnerable'} Mode)")
            return render_template('login.html')

    return render_template('login.html')


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(name=username).first()
        if existing_user:
            flash("Username already exists")
            return redirect(url_for('register'))

        new_user = User(role='user', name=username, password=password, email=None)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route("/dashboard")
def dashboard():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"
    return render_template("dashboard.html", user=user, mode=mode)


@app.route("/accounts")
def accounts():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    return render_template("accounts.html", user=user, mode=mode)


@app.route("/profile")
def profile():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    return render_template("profile.html", user=user, mode=mode)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    secure_mode = session.get('secure_mode', False)     # SET VULNERABILITY MODE HERE
    mode = "secure" if secure_mode else "vulnerable"    # to be displayed in form
    message = ""

    if secure_mode:     # secure mode
        csrf.protect()  # protect this endpoint only
        transfer_form = TransferForm()

        if transfer_form.validate_on_submit():  # POST request
            from_account = transfer_form.from_account.data
            to_account = transfer_form.to_account.data
            amount_str = transfer_form.amount.data

            transfer_success, message = execute_transfer(user, from_account, to_account, amount_str)
            if transfer_success:
                db.session.commit()  # update user

        elif request.method == "POST":  # and form didn't validate
            print("Likely CSRF Attack intercepted.")

        # only send FlaskForm if in secure mode
        return render_template("transfer.html", user=user, mode=mode, message=message, transfer_form=transfer_form)

    # vulnerable mode
    if request.method == "POST":
        from_account = request.form.get('from_account')
        to_account = request.form.get('to_account')
        amount_str = request.form.get('amount')

        transfer_success, message = execute_transfer(user, from_account, to_account, amount_str)
        if transfer_success:
            db.session.commit()     # update user

    return render_template("transfer.html", user=user, mode=mode, message=message)


@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"
    message = ""

    if request.method == "POST":
        amount_str = request.form.get('amount')
        to_account = request.form.get('to_account')

        if not amount_str or not to_account:
            message = "All fields are required."
        else:
            try:
                amount = float(amount_str)
                if amount <= 0:
                    message = "Deposit amount must be greater than zero."
                else:
                    if to_account == "checking":
                        user.checking += amount
                    elif to_account == "savings":
                        user.savings += amount
                    else:
                        message = "Invalid account selection."
                        return render_template("deposit.html", user=user, mode=mode, message=message)

                    db.session.commit()
                    message = f"Successfully deposited ${amount:.2f} into {to_account} account."

            except ValueError:
                message = "Invalid amount. Please enter a number."

    return render_template("deposit.html", user=user, mode=mode, message=message)


@app.route("/admin")
def admin_dashboard():
    adminname = session.get('username')
    if not adminname:
        flash("Please log in first.")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    return render_template('admin-dashboard.html', mode=mode, admin=admin)


@app.route('/list-users')
def list_users():
    adminname = session.get('username')
    if not adminname:
        flash("Please log in first.")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    if secure_mode:
        if admin.role != "admin":   # check listing is performed by an admin
            print("Likely Broken Access Control attack intercepted.")
            return redirect(url_for('login'))

    users = User.query.filter_by(role='user')

    return render_template('list-users.html', mode=mode, admin=admin, users=users)


@app.route('/add-user', methods=['GET', 'POST'])
def add_user():
    adminname = session.get('username')
    if not adminname:
        flash("Please log in first.")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    message = ""
    if request.method == 'POST':
        role = request.form.get('role')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        checking = request.form.get('checking', 0)
        savings = request.form.get('savings', 0)
        if not (role and username and password and email):
            message = "Invalid request. Required info is missing."
        else:
            try:
                added_user = User(role='user', name=username, password=password,
                                  email=email, checking=float(checking), savings=float(savings))
                db.session.add(added_user)
                db.session.commit()

                added_user_id = added_user.get_id()
                if added_user_id is not None:
                    message = f"New user with ID: {added_user_id} added!"
                else:
                    message = "Failed to add user."
            except Exception as e:
                message = f"Error adding user: {str(e)}"

    return render_template('add-user.html', mode=mode, admin=admin, message=message)


@app.route('/edit-user', methods=['GET', 'POST'])
def edit_user():
    adminname = session.get('username')
    if not adminname:
        flash("Please log in first.")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    users = User.query.filter_by(role='user').all()
    selected_user = None
    message = ""

    if request.method == 'POST':
        # if select user form submitted
        if 'load_user' in request.form:
            user_id = int(request.form.get('edit_userid'))
            selected_user = User.query.filter_by(_id=user_id).first()

        # if update form submitted
        elif 'update_user' in request.form:
            user_id = request.form.get('userid')
            user = User.query.filter_by(_id=user_id).first()
            if user:
                # update db
                try:
                    user.name = request.form.get('name')
                    user.email = request.form.get('email')
                    user.password = request.form.get('password')

                    if user.role == "user":
                        checking = request.form.get('checking')
                        savings = request.form.get('savings')
                        user.checking = float(checking)
                        user.savings = float(savings)

                    db.session.commit()

                    message = f"User with ID {user.get_id()} and username {user.name} updated."
                    selected_user = user
                except Exception as e:
                    message = f"Error updating user: {str(e)}"

    return render_template('edit-user.html', mode=mode, admin=admin, users=users,
                           selected_user=selected_user, message=message)


@app.route('/delete-user', methods=['GET', 'POST'])
def delete_user():
    adminname = session.get('username')
    if not adminname:
        flash("Please log in first.")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    if secure_mode:
        if admin.role != "admin":   # check deletion is performed by an admin
            print("Likely Broken Access Control attack intercepted.")
            return redirect(url_for('login'))

    users = User.query.filter_by(role='user').all()
    message = ""
    if request.method == 'POST':
        try:
            delete_userid = int(request.form.get('delete_userid'))
            user_to_delete = User.query.filter_by(_id=delete_userid).first()
            delete_username = user_to_delete.name

            db.session.delete(user_to_delete)
            db.session.commit()
            message = f"User with ID {delete_userid} and username {delete_username} deleted."

        except Exception as e:
            message = f"Error deleting the user: {str(e)}"

    return render_template('delete-user.html', mode=mode, admin=admin,
                           users=users, message=message)


@app.route("/import-data", methods=["GET", "POST"])
def import_data():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    message = ""

    if request.method == "POST":
        uploaded_file = request.files.get("xmlfile")
        if not uploaded_file or uploaded_file.filename == "":
            message = "No file selected."
        else:
            try:
                xml_content = uploaded_file.read()

                parser = etree.XMLParser(resolve_entities=not secure_mode)
                root = etree.fromstring(xml_content, parser)

                checking_str = root.findtext("checking", default="0")
                savings_elem = root.find("savings")
                savings_str = savings_elem.text if savings_elem is not None else "0"

                if not secure_mode and savings_str and "##" in savings_str:
                    lines = savings_str.strip().split("\n")
                    parsed_rows = []
                    for line in lines:
                        if not line.strip().startswith("#") and ":" in line:
                            parts = line.split(":")
                            if len(parts) >= 7:
                                parsed_rows.append({
                                    "username": parts[0],
                                    "uid": parts[2],
                                    "gid": parts[3],
                                    "description": parts[4],
                                    "home": parts[5],
                                    "shell": parts[6],
                                })
                    return render_template("passwd_view.html", rows=parsed_rows)

                try:
                    user.savings = float(savings_str)
                except ValueError:
                    message += f"Non-numeric savings value detected: {savings_str}\n"

                db.session.commit()

                if not message:
                    message = f"Imported balances: Checking = ${user.checking:.2f}, Savings = ${user.savings:.2f}"

            except Exception as e:
                message = f"Error parsing XML: {str(e)}"

    return render_template("import-data.html", mode=mode, message=message)


@app.route("/logout")
def logout():
    session.pop('username', None)
    return render_template("logout.html")


# Utility functions

# generate json with list of users and user data
@app.route("/users.js")
def generate_user_list():
    secure_mode = session.get('secure_mode')
    username = session.get('username')

    user = User.query.all()
    current_user = User.query.filter_by(name=username).first()
    
    if secure_mode:
        user_data = [
            {
                "id": current_user._id,
                "name": current_user.name,
            }
        ]
    else: 
        user_data = [
            {
                "id": user._id,
                "role": user.role,
                "name": user.name,
                "email": user.email,
                "password": user.password,
                "checking": user.checking,
                "savings": user.savings
            }
            for user in user
        ]

    json_user_data = f"const exposedUserData = {json.dumps(user_data)};\n"

    return json_user_data, 200, {"Content-Type": "application/javascript"}


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add a test non-admin user
        if not User.query.filter_by(name='tester').first():
            new_nonadmin_user = User(role='user', name='tester', password='abc123', email='tester@capstone.com')
            db.session.add(new_nonadmin_user)
            db.session.commit()
        # Add a second test non-admin user to use as Broken Access Control deletion target
        if not User.query.filter_by(name='qwer').first():
            new_nonadmin_user = User(role='user', name='qwer', password='qwer', email='qwer@capstone.com')
            db.session.add(new_nonadmin_user)
            db.session.commit()
        # Add a test admin
        if not User.query.filter_by(name='admin-tester').first():
            new_admin_user = User(role='admin', name='admin-tester', password='abc123', email='admin@capstone.com')
            db.session.add(new_admin_user)
            db.session.commit()

    app.run(debug=True)

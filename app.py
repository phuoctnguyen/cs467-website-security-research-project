from flask import abort, flash, Flask, redirect, render_template, request, session, url_for, make_response, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_wtf import CSRFProtect      # CSRF Protection
from backend.forms import TransferForm      # CSRF Protection
from backend.helpers import execute_transfer
from lxml import etree
import os
import bcrypt   # Password Hashing
import hashlib  # Password Hashing
import json
import time
import re
import io
import pickle
from markupsafe import Markup
from PIL import Image, ImageFile, UnidentifiedImageError
from werkzeug.utils import secure_filename
import logging
from logging.handlers import RotatingFileHandler

# Brute Force Mitigation Variables
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60

app = Flask(__name__,
            template_folder='frontend/pages',
            static_folder='frontend')
app.secret_key = '467'

LOG_FILE = 'logs/app.log'
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Rotating handler: 1MB per file, keep 5 backups
handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
handler.setFormatter(formatter)

app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
db = SQLAlchemy(app)

# WTF_CSRF-related logic & code adapted from:
# https://flask-wtf.readthedocs.io/en/0.15.x/csrf/#exclude-views-from-protection
# disable default CSRF protection on all endpoints; activate by endpoint when needed; better for testing.
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

csrf = CSRFProtect(app)     # enable CSRF protection

DEFAULT_CHECKING = 1000.00
DEFAULT_SAVINGS = 5000.00

# Image upload variables
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads/profile_pics')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'tiff'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Helper for image checking
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Secure Headers (only in secure mode)
@app.after_request
def add_security_headers(response):
    if session.get('secure_mode'):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
        response.headers['Referrer-Policy'] = 'no-referrer'
    return response


def validate_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


# User model
class User(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    role = db.Column("role", db.String(8))
    name = db.Column("name", db.String(100))
    email = db.Column("email", db.String(320))
    password = db.Column("password", db.String(128))    # plaintext password to be used in vulnerable mode
    checking = db.Column("checking", db.Float, default=DEFAULT_CHECKING)
    savings = db.Column("savings", db.Float, default=DEFAULT_SAVINGS)
    profile_picture = db.Column(db.String(255), nullable=True)

    # salts & password hashes to store
    md5_salt = db.Column("pwd_salt_md5", db.String(16))
    pwd_hash_md5_unsalted = db.Column("pwd_hash_md5_unsalted", db.String(32))
    pwd_hash_md5_salted = db.Column("pwd_hash_md5_salted", db.String(32))
    pwd_hash_bcrypt = db.Column("pwd_hash_bcrypt", db.String(128))  # to be used in secure mode

    def __init__(self, role, name, password, email,
                 checking=DEFAULT_CHECKING, savings=DEFAULT_SAVINGS, profile_picture=None):
        self.role = role
        self.name = name
        self.email = email
        self.password = password    # plaintext password
        self.checking = checking
        self.savings = savings
        self.profile_picture = profile_picture

        # create salt and password hash attributes and store them in database
        password_to_bytes = password.encode('utf-8')  # convert password to array of bytes

        self.pwd_hash_md5_unsalted = hashlib.md5(password_to_bytes).hexdigest()

        self.md5_salt = os.urandom(1)   # generate & store 1-byte salt to add to plaintext before hashing
        self.pwd_hash_md5_salted = hashlib.md5(self.md5_salt + password_to_bytes).hexdigest()

        # bcrypt password hash will be used in the secure version of the app
        # code adapted from: https://geekpython.medium.com/easy-password-hashing-using-bcrypt-in-python-3a706a26e4bf
        bcrypt_salt = bcrypt.gensalt()  # generate salt to add to plaintext before hashing; stored within hash
        self.pwd_hash_bcrypt = bcrypt.hashpw(password_to_bytes, bcrypt_salt).decode()

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

            ip = request.remote_addr or 'unknown'
            now = time.time()

            if ip not in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[ip] = []

            # This gets rid of timestamps outside our WINDOW_SECONDS
            valid = [t for t in LOGIN_ATTEMPTS[ip] if now - t < WINDOW_SECONDS]
            LOGIN_ATTEMPTS[ip] = valid 

            LOGIN_ATTEMPTS[ip].append(now)
            if len(LOGIN_ATTEMPTS[ip]) >= MAX_ATTEMPTS:
                return make_response("Too many requests", 429)

            user = User.query.filter_by(name=username).first()  # get user with matching username from DB
            app.logger.info(f"Login attempt by user: {username} in secure mode from IP: {request.remote_addr}")

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
                app.logger.info(f"Successful login for user: {username} (Role: {user.role}) from IP: {request.remote_addr}")


            if secure_mode:
                # check password hashes match
                # code adapted from:
                # https://geekpython.medium.com/easy-password-hashing-using-bcrypt-in-python-3a706a26e4bf
                password_bytes = password.encode('utf-8')   # change entered password to bytes
                pwd_hash_bcrypt_in_db = user.pwd_hash_bcrypt.encode()     # get bcrypt password hash from db
                password_check = bcrypt.checkpw(password_bytes, pwd_hash_bcrypt_in_db)   # check match
                if not password_check:
                    flash("Invalid username or password.")
                    print("Invalid username or password (hash doesn't match).")
                    return render_template('login.html')
                
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
                app.logger.warning(f"Failed login for user: {username} from IP: {request.remote_addr}")

            flash(f"Invalid username or password ({'Secure' if secure_mode else 'Vulnerable'} Mode)")
            return render_template('login.html')

    else:
        if session.pop('just_logged_out', None):
            session.pop('_flashes', None)  # only clear if logging out

        if session.pop('just_registered', None):
            flash("Registration successful! Please log in.")

    return render_template('login.html')


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm-password')
        secure_mode = request.form.get('secure') == 'true'
        session['secure_mode'] = secure_mode  # Store this to persist for flash logic

        if secure_mode:
            if password != confirm_password:
                flash("Passwords do not match.")
                return redirect(url_for('register'))

            if not validate_password_strength(password):
                flash("Password must be at least 8 characters long "
                      "and include uppercase, lowercase, digits, and special characters.")
                return redirect(url_for('register'))
            
            app.logger.info(f"New registration attempt for username: {username} in {'secure' if secure_mode else 'vulnerable'} mode")

        existing_user = User.query.filter_by(name=username).first()
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for('register'))

        new_user = User(role='user', name=username, password=password, email=None)
        db.session.add(new_user)
        db.session.commit()
        session['just_registered'] = True
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


@app.route("/profile", methods=["GET", "POST"])
def profile():
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"

    if secure_mode:
        username = session.get('username')  # set username from session only
        if request.args and 'username' in request.args and username != request.args.get('username'):
            print("Horizontal Broken Access Control Attack intercepted.")
            abort(403)
    else:
        username = request.args.get('username')

    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()

    if not user:
        flash(f"User '{username}' not found.")
        return redirect(url_for('login'))

    if request.method == "POST":
        if 'profile_pic' not in request.files:
            flash('No file part in request.')
            return redirect(request.url)

        file = request.files['profile_pic']
        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            unique_filename = f"{user.get_id()}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            file.save(filepath)

            if mode == "secure":

                print("SECURE MODE: Attempting to process image with error handling.")

                try:
                    img = Image.open(filepath)
                    img.load()
                    user.profile_picture = os.path.join('uploads/profile_pics', unique_filename)
                    db.session.commit()
                    flash('Profile picture uploaded successfully! (Secure Mode)')

                except Image.DecompressionBombError as dbe:
                    print(f"SECURE: Caught Image.DecompressionBombError: {type(dbe).__name__} - {str(dbe)}")
                    flash("Image is too large or is a decompression bomb. Upload failed. (Secure Mode)")
                    if os.path.exists(filepath):
                        os.remove(filepath)

                except UnidentifiedImageError as uie:
                    print(f"SECURE: Caught UnidentifiedImageError: {type(uie).__name__} - {str(uie)}")
                    flash("Cannot identify image file. (Secure Mode)")
                    if os.path.exists(filepath):
                        os.remove(filepath)

                except ValueError as ve:
                    print(f"SECURE: Caught ValueError: {type(ve).__name__} - {str(ve)}")
                    flash(f"A ValueError occurred: {str(ve)}. Upload failed. (Secure Mode)")
                    if os.path.exists(filepath):
                        os.remove(filepath)

                except Exception as e:
                    print(f"SECURE: Caught generic Exception: {type(e).__name__} - {str(e)}")
                    flash(f"An unexpected error occurred: {type(e).__name__}. (Secure Mode)")
                    if os.path.exists(filepath):
                        os.remove(filepath)

            else:   # VULNERABLE

                print("VULNERABLE MODE: Processing image without specific bomb error handling.")
                img = Image.open(filepath)
                img.load()

                user.profile_picture = os.path.join('uploads/profile_pics', unique_filename)
                db.session.commit()
                flash('Profile picture uploaded successfully! (Vulnerable Mode)')   # this line won't be reached

            return redirect(url_for('profile', username=user.name if not secure_mode else None))

        else:

            flash('File type not allowed. Allowed types: png, jpg, jpeg, gif, tiff.')
            return redirect(request.url)

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
        return render_template("transfer.html", user=user, mode=mode, message=message,
                               transfer_form=transfer_form, secure_mode=True)

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

@app.route("/admin/logs")
def admin_logs():
    adminname = session.get('username')
    if not adminname:
        flash("Please log in first.")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    if not admin or admin.role != "admin":
        app.logger.warning(f"Unauthorized log viewer access attempt by '{adminname}'")
        abort(403)

    log_path = 'logs/app.log'
    log_lines = []

    try:
        with open(log_path, 'r') as f:
            log_lines = f.readlines()[-100:]  # show last 100 lines
    except Exception as e:
        log_lines = [f"[ERROR] Unable to read log file: {str(e)}"]

    return render_template("admin-logs.html", logs=log_lines, mode="secure" if session.get('secure_mode') else "vulnerable")


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
        if admin.role != "admin":   # check user requesting the users list is an admin
            print("Broken Access Control attack intercepted.")
            abort(403)

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
        if admin.role != "admin":   # check user requesting the deletion is an admin
            print("Horizontal Broken Access Control attack intercepted.")
            abort(403)

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


@app.route("/account-activity")
def account_activity():
    secure_mode = session.get('secure_mode', False)
    mode = "secure" if secure_mode else "vulnerable"
    # list of example activities
    activities = [
        {"name": "Deposit", "amount": "$500.00", "date": "2025-05-17"},
        {"name": "Withdrawal", "amount": "$100.00", "date": "2025-05-16"},
        {"name": "Transfer", "amount": "$250.00", "date": "2025-05-15"},
    ]

    # search query for search field
    raw_query = request.args.get('query', '')
    query_lower = raw_query.lower()
    if query_lower:
        activities = [act for act in activities if query_lower in act["name"].lower()]

    # use markup in vulnerable mode to handle the raw input as safe html
    # in secure mode, flask automatically escapes the input when rendering preventing xss
    if secure_mode:
        safe_query = raw_query
    else:
        safe_query = Markup(raw_query)

    return render_template(
        'account-activity.html',
        mode=mode,
        activities=activities,
        query=safe_query,
    )


@app.route('/export-user', methods=['GET', 'POST'])
def admin_export_user_page():
    adminname = session.get('username')

    if not adminname:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    if not admin or admin.role != 'admin':
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard')) 

    secure_mode = session.get('secure_mode', False)
    current_mode_string = "secure" if secure_mode else "vulnerable"
    
    message = ""

    if request.method == 'POST':
        if request.form.get('action') == 'export_selected_user':
            user_id_to_export_str = request.form.get('export_user_id')

            if not user_id_to_export_str:
                message = "No user selected for export. Please select a user from the dropdown."

            else:
                try:
                    user_id_to_export = int(user_id_to_export_str)
                    user_to_export = User.query.filter_by(_id=user_id_to_export, role='user').first() 

                    if not user_to_export:
                        message = f"User with ID {user_id_to_export} not found or cannot be exported."
                    else:
                        format_type = 'json' if secure_mode else 'pickle'
                        
                        return redirect(url_for('admin_export_user_file', 
                                                user_id=user_id_to_export, 
                                                format_type=format_type))
                except ValueError:
                    message = "Invalid user ID format selected."
                except Exception as e:
                    message = f"An error occurred during export preparation: {str(e)}"
                    print(f"Export Prep Error: {str(e)}") 

        else:
            message = "Invalid export action."

    users_for_dropdown = User.query.filter_by(role='user').all() 

    return render_template('export-user.html',
                           mode=current_mode_string, 
                           admin=admin,
                           users_for_dropdown=users_for_dropdown,
                           message=message)


@app.route('/admin/export_user_file/<int:user_id>/<string:format_type>')
def admin_export_user_file(user_id, format_type):
    adminname = session.get('username')

    if not adminname:
        flash("Please log in first to download files.", "warning")
        return redirect(url_for('login')) 

    admin = User.query.filter_by(name=adminname).first()
    if not admin or admin.role != 'admin':
        flash("Admin access required to download user files.", "danger")
        return redirect(url_for('admin_export_user_page'))

    user_to_export = User.query.filter_by(_id=user_id, role='user').first()
    if not user_to_export:
        user_to_export = User.query.get(user_id) 
        if not user_to_export or (user_to_export.role != 'user' and format_type != 'pickle_admin_special_case'): 
            flash("User not found or cannot be exported with this role.", "danger")
            return redirect(url_for('admin_export_user_page'))

    filename_base = "".join(c if c.isalnum() else "_" for c in user_to_export.name)

    if format_type == 'pickle':
        try:
            pickled_data = pickle.dumps(user_to_export)
            filename = f"{filename_base}_export.dat"
            
            return send_file(
                io.BytesIO(pickled_data),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            flash(f"Error exporting user as pickle: {str(e)}", "danger")
            print(f"[PICKLE_EXPORT_ERROR] In admin_export_user_file: {type(e).__name__}: {str(e)}")
            return redirect(url_for('admin_export_user_page'))

    elif format_type == 'json':
        try:
            user_data_dict = {
                "role": user_to_export.role,
                "name": user_to_export.name,
                "email": user_to_export.email,
                "pwd_hash_bcrypt": user_to_export.pwd_hash_bcrypt 
            }
            json_data_string = json.dumps(user_data_dict, indent=4)
            filename = f"{filename_base}_export.json"
            
            return send_file(
                io.BytesIO(json_data_string.encode('utf-8')),
                mimetype='application/json',
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            flash(f"Error exporting user as JSON: {str(e)}", "danger")
            print(f"[JSON_EXPORT_ERROR] In admin_export_user_file: {type(e).__name__}: {str(e)}")
            return redirect(url_for('admin_export_user_page'))
    
    else:
        flash("Invalid export format specified for download.", "danger")
        return redirect(url_for('admin_export_user_page'))
    

@app.route('/import-user', methods=['GET', 'POST'])
def admin_import_user_page():
    adminname = session.get('username')
    
    if not adminname:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    admin = User.query.filter_by(name=adminname).first()
    if not admin or admin.role != 'admin':
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard'))

    secure_mode = session.get('secure_mode', False)
    current_mode_string = "secure" if secure_mode else "vulnerable"
    page_message_get = "Upload a file to create a new user." 

    if request.method == 'POST':
        if 'user_file' not in request.files:
            flash('No file part in request.', 'danger')
            return redirect(url_for('admin_import_user_page'))

        file = request.files['user_file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('admin_import_user_page'))

        if file:
            try:
                file_content = file.read()

                if not secure_mode:
                    try:
                        deserialized_object = pickle.loads(file_content)
                        
                        if isinstance(deserialized_object, User):
                            existing_user_check = User.query.filter_by(name=deserialized_object.name).first()
                            if existing_user_check:
                                flash(f"Vulnerable Mode: User '{deserialized_object.name}' already exists. Import failed.", "danger")
                            else:
                                imported_user = User(
                                    role=deserialized_object.role,
                                    name=deserialized_object.name,
                                    password=deserialized_object.password, 
                                    email=deserialized_object.email,
                                    checking=deserialized_object.checking if hasattr(deserialized_object, 'checking') else DEFAULT_CHECKING,
                                    savings=deserialized_object.savings if hasattr(deserialized_object, 'savings') else DEFAULT_SAVINGS
                                )
                                
                                db.session.add(imported_user)
                                db.session.commit()
                                flash(f"Vulnerable Mode: User '{imported_user.name}' (New ID: {imported_user._id}) imported successfully from pickle.", "success")
                        
                        elif isinstance(deserialized_object, str): 
                            flash(f"Vulnerable Mode: File processed. Payload result: {deserialized_object}", "warning")
                        
                        else: 
                            flash(f"Vulnerable Mode: File processed. Deserialized a non-User, non-payload object of type {type(deserialized_object).__name__}. Not added to database.", "info")

                    except RuntimeError as rterr: 
                        flash(f"Vulnerable Mode: Payload execution error: {str(rterr)}", "danger")
                        print(f"[PICKLE_PAYLOAD_RUNTIME_ERROR] {str(rterr)}")
                    except Exception as e:
                        db.session.rollback() 
                        flash(f"Vulnerable Mode: Error deserializing or processing pickled object: {type(e).__name__} - {str(e)}", "danger")
                        print(f"[PICKLE_ERROR_VULN_IMPORT_PROCESSING] {type(e).__name__}: {str(e)}")
                
                else: # Secure mode
                    try:
                        if not file.filename.lower().endswith('.json'):
                            flash("Secure Mode: Invalid file type. Please upload a .json file as per instructions.", "danger")
                            return redirect(url_for('admin_import_user_page')) 
                            
                        user_data_dict = json.loads(file_content.decode('utf-8'))

                        required_fields = ['role', 'name', 'email', 'pwd_hash_bcrypt']
                        missing_fields = [field for field in required_fields if field not in user_data_dict]
                        if missing_fields:
                            raise ValueError(f"Missing required fields in JSON: {', '.join(missing_fields)}")

                        if not all(isinstance(user_data_dict.get(f), str) for f in required_fields):
                            raise ValueError("Invalid data types for user fields. Role, name, email, and pwd_hash_bcrypt should be strings.")
                        
                        if not (3 <= len(user_data_dict['name']) <= 100): 
                            raise ValueError("Username length is invalid.")

                        existing_user = User.query.filter_by(name=user_data_dict['name']).first()
                        if existing_user:
                             raise ValueError(f"User '{user_data_dict['name']}' already exists. Cannot import.")

                        temp_dummy_password = "SECURE_JSON_IMPORT_DUMMY_PASSWORD_12345!@#$%" # Just a work around for User.__init__

                        new_user = User(
                            role=user_data_dict['role'],
                            name=user_data_dict['name'],
                            password=temp_dummy_password, 
                            email=user_data_dict['email'],
                            checking=0.0,
                            savings=0.0
                        )
                        
                        new_user.pwd_hash_bcrypt = user_data_dict['pwd_hash_bcrypt']
                        new_user.password = None 
                        new_user.pwd_hash_md5_unsalted = None
                        new_user.pwd_hash_md5_salted = None
                        new_user.md5_salt = None

                        db.session.add(new_user)
                        db.session.commit()
                        flash(f"Secure Mode: User '{new_user.name}' created successfully from JSON.", "success")

                    except json.JSONDecodeError:
                        flash("Secure Mode: Invalid JSON format in uploaded file. Please check the content.", "danger")
                    except UnicodeDecodeError:
                        flash("Secure Mode: File must be UTF-8 encoded JSON.", "danger")
                    except ValueError as ve: 
                        flash(f"Secure Mode: Invalid data in JSON - {str(ve)}", "danger")
                    except Exception as e:
                        db.session.rollback()
                        flash(f"Secure Mode: Error processing JSON data: {type(e).__name__} - {str(e)}", "danger")
                        print(f"[JSON_ERROR_SECURE_IMPORT_WORKAROUND] {type(e).__name__}: {str(e)}")
            
            except Exception as e: 
                flash(f"Error reading uploaded file: {str(e)}", "danger")
        
        return redirect(url_for('admin_import_user_page'))

    return render_template('import-user.html', 
                           mode=current_mode_string, 
                           admin=admin,
                           message=page_message_get)


@app.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('secure_mode', None)
    session['just_logged_out'] = True  # set flag so login page knows to clear flashes
    flash("You have been logged out.")
    return redirect(url_for('login'))

# Utility functions


# generate json with list of users and user data
@app.route("/users.js")
def generate_user_list():
    secure_mode = session.get('secure_mode')
    username = session.get('username')

    users = User.query.all()
    current_user = User.query.filter_by(name=username).first()

    if secure_mode:
        user_data = [
            {
                "id": current_user.get_id(),
                "name": current_user.name
            }
        ]
    else:
        # exposed password depends on query parameter 'pwd_choice'
        pwd_choice = request.args.get('pwd_choice')
        valid_pwd_choices = {'pwd_hash_md5_unsalted', 'pwd_hash_md5_salted', 'pwd_hash_bcrypt'}
        pwd_attr = pwd_choice if pwd_choice in valid_pwd_choices else 'password'    # default to plaintext pwd
        user_data = [
            {
                "id": user.get_id(),
                "role": user.role,
                "name": user.name,
                "email": user.email,
                "password": getattr(user, pwd_attr),
                "checking": user.checking,
                "savings": user.savings
            }
            for user in users
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

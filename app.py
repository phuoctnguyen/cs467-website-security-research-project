from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask import session
import os

app = Flask(__name__, 
            template_folder='frontend/pages', 
            static_folder='frontend')

app.secret_key = '467'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'

db = SQLAlchemy(app)

# user model 
class User(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column("name", db.String(100))
    password = db.Column("password", db.String(100))
    checking = db.Column("checking", db.Float, default=1000.00)
    savings = db.Column("savings", db.Float, default=5000.00)

    def __init__(self, name, password):
        self.name = name
        self.password = password

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(name=username).first()

        if user and user.password == password:
            session['username'] = user.name
            flash(f"Hello, {username}")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password")
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

        new_user = User(name=username, password=password)
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
    mode = "vulnerable"

    return render_template("dashboard.html", user=user, mode=mode)

@app.route("/accounts")
def accounts():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    mode = "vulnerable"
    return render_template("accounts.html", user=user, mode=mode)

@app.route("/profile")
def profile():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    mode = "vulnerable"
    return render_template("profile.html", user=user, mode=mode)

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    mode = "vulnerable"
    message = ""

    if request.method == "POST":
        from_account = request.form.get('from_account')
        to_account = request.form.get('to_account')
        amount_str = request.form.get('amount')

        # Validate input
        if not from_account or not to_account or not amount_str:
            message = "All fields are required."
        elif from_account == to_account:
            message = "You must transfer between two different accounts."
        else:
            try:
                amount = float(amount_str)
                if amount <= 0:
                    message = "Transfer amount must be greater than zero."
                else:
                    if from_account == "checking" and user.checking >= amount:
                        user.checking -= amount
                        user.savings += amount
                        message = f"Transferred ${amount:.2f} from checking to savings."
                    elif from_account == "savings" and user.savings >= amount:
                        user.savings -= amount
                        user.checking += amount
                        message = f"Transferred ${amount:.2f} from savings to checking."
                    else:
                        message = "Insufficient funds in selected account."
                    
                    db.session.commit()

            except ValueError:
                message = "Invalid amount. Please enter a number."

    return render_template("transfer.html", user=user, mode=mode, message=message)

@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    username = session.get('username')
    if not username:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.filter_by(name=username).first()
    mode = "vulnerable"
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

@app.route("/logout")
def logout():
    session.pop('username', None)
    return render_template("logout.html")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add a test user 
        if not User.query.filter_by(name='tester').first():
            new_user = User(name='tester', password='abc123')
            db.session.add(new_user)
            db.session.commit()
    app.run(debug=True)


from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__, 
            template_folder='frontend/pages', 
            static_folder='frontend')

app.secret_key = '467'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
SECURE_MODE = False

db = SQLAlchemy(app)

# user model 
class User(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column("name", db.String(100))
    password = db.Column("password", db.String(100))

    def __init__(self, name, password):
        self.name = name
        self.password = password

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if SECURE_MODE:
            user = User.query.filter_by(name=username, password=password).first()
            if user:
                flash(f"Hello, {username} (Secure Mode)")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password (Secure Mode)")
                return render_template('login.html')
        else:
            query = text(f"SELECT * FROM user WHERE name = '{username}' AND password = '{password}'")
            result = db.session.execute(query).fetchone()
            if result:
                flash(f"Hello, {username} (Vulnerable Mode)")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password (Vulnerable Mode)")
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
    return render_template('dashboard.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add a test user 
        if not User.query.filter_by(name='tester').first():
            new_user = User(name='tester', password='abc123')
            db.session.add(new_user)
            db.session.commit()
    app.run(debug=True)


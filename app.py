from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy import text

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

    def __init__(self, name, password):
        self.name = name
        self.password = password

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        secure_mode = request.form.get('secure') == 'true'

        if secure_mode:
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
            session['username'] = user.name
            flash(f"Hello, {username} ({'Secure' if secure_mode else 'Vulnerable'} Mode)")
            return redirect(url_for('dashboard'))
        else:
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


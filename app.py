from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
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

        # check if username is in database
        user = User.query.filter_by(name=username).first()

        if user:
            flash(f"Hello, {username}")
            return redirect(url_for('login'))
        else:
            flash(f"User not found")
            return redirect(url_for('login'))
    return render_template('login.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add a test user 
        if not User.query.filter_by(name='tester').first():
            new_user = User(name='tester', password='abc123')
            db.session.add(new_user)
            db.session.commit()
    app.run(debug=True)


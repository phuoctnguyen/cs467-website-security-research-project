# app.py
from flask import Flask, render_template, request
from mock_db import users_db

# initial values
vulnerable_mode = "ON"
# vulnerable_mode = "OFF"
active_admin = users_db[9]
active_user = users_db[1]

app = Flask(__name__)

# ADMIN STUFF ---------------------------------------------------------------
@app.route('/admin')
def admin_dashboard():
    return render_template('admin-dashboard.html', mode=vulnerable_mode, admin=active_admin)

@app.route('/list-users')
def list_users():
    return render_template('list-users.html', mode=vulnerable_mode, admin=active_admin, users=users_db.values())

@app.route('/add-user', methods=['GET', 'POST'])
def add_user():
    message = ""
    if request.method == 'POST':
        role = request.form.get('role')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        checking = request.form.get('checking')
        savings = request.form.get('savings')
        if not (role and username and password and email):
            message = "Invalid request. Required info is missing."
        else:
            # simulate adding
            new_userid = active_admin.create_user(role, username, password, email, checking, savings)
            if new_userid != 0:
                message = f"New user with ID: {new_userid} added!"
            else:
                message = "Failed to add user."

    return render_template('add-user.html', mode=vulnerable_mode, admin=active_admin, message=message)

@app.route('/edit-user', methods=['GET', 'POST'])
def edit_user():
    selected_user = None
    message = ""

    if request.method == 'POST':
        # if select user form submitted
        if 'load_user' in request.form:
            user_id = int(request.form.get('edit_userid'))
            selected_user = users_db.get(user_id)

        # if update form submitted
        elif 'update_user' in request.form:
            user_id = int(request.form.get('userid'))
            user = users_db.get(user_id)
            if user:
                # update db
                user.username = request.form.get('username', user.username)
                user.email = request.form.get('email', user.email)
                user.password = request.form.get('password', user.password)

                if user.role == "user":
                    checking = request.form.get('checking')
                    savings = request.form.get('savings')
                    user.checking = int(checking) if checking.isdigit() else user.checking
                    user.savings = int(savings) if savings.isdigit() else user.savings

                message = f"User with ID {user.id} and username {user.username} updated."
                selected_user = user

    return render_template('edit-user.html', mode=vulnerable_mode, admin=active_admin,
                           users=users_db, selected_user=selected_user, message=message)

@app.route('/delete-user', methods=['GET', 'POST'])
def delete_user():
    message = ""
    if request.method == 'POST':
        delete_userid = int(request.form.get('delete_userid'))
        delete_username = users_db.get(delete_userid).username

        del users_db[delete_userid]

        message = f"User with ID {delete_userid} and username {delete_username} deleted."

    return render_template('delete-user.html', mode=vulnerable_mode, admin=active_admin,
                           users=users_db, message=message)

# USERS STUFF ---------------------------------------------------------------
@app.route('/')
def dashboard():
    # non-admin user dashboard
    return render_template('dashboard.html', mode=vulnerable_mode, user=active_user)

@app.route('/accounts')
def accounts():
    return render_template('accounts.html', mode=vulnerable_mode, user=active_user)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    message = ""
    if request.method == 'POST':
        from_account = request.form.get('from_account')
        to_account = request.form.get('to_account')
        amount = int(request.form.get('amount', 0))
        if not (from_account and to_account and amount):
            message = "Invalid request. Account(s) or amount missing."
        else:
            # simulate transfer
            if to_account == "checking" and active_user.savings - amount >= 0:
                active_user.savings -= amount
                active_user.checking += amount
                message = f"Transfer made: ${amount} moved from {from_account} to {to_account} account."
            elif active_user.checking - amount >= 0:
                active_user.checking -= amount
                active_user.savings += amount
                message = f"Transfer made: ${amount} moved from {from_account} to {to_account} account."
            else:
                message = "Insufficient funds in the selected account."

    return render_template('transfer.html', mode=vulnerable_mode, user=active_user, message=message)

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    message = ""
    if request.method == 'POST':
        amount = int(request.form.get('amount', 0))
        to_account = request.form.get('to_account')
        if not (amount and to_account):
            message = "Invalid request. Account or amount missing."
        else:
            # simulate deposit
            if to_account == "checking":
                active_user.checking += amount
            else:
                active_user.savings += amount
            message = f"Deposit made: ${amount} deposited to {to_account} account."

    return render_template('deposit.html', mode=vulnerable_mode, user=active_user, message=message)


@app.route('/profile')
def profile():
    return render_template('profile.html', mode=vulnerable_mode, user=active_user)


if __name__ == '__main__':
    app.run(debug=True)
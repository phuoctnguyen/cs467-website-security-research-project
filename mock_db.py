# mock_db.py
class Person:
    def __init__(self, userid, role, username, password, email):
        self.id = userid
        self.role = role
        self.username = username
        self.password = password
        self.email = email

class Admin(Person):
    def __init__(self, userid, username, password, email):
        super().__init__(userid, "admin", username, password, email)

    @staticmethod
    def create_user(role, username, password, email, checking, savings):
        new_userid = max(users_db.keys(), default=0) + 1
        if role == "admin":
            new_user = Admin(new_userid, username, password, email)
        elif role == "user":
            checking = int(checking) if checking.isdigit() else 0
            savings = int(savings) if savings.isdigit() else 0
            new_user = User(new_userid, username, password, email, checking, savings)
        else:
            raise ValueError("Unknown role")

        users_db[new_userid] = new_user
        return new_userid

class User(Person):
    def __init__(self, userid, username, password, email, amount_checking, amount_savings):
        super().__init__(userid, "user", username, password, email)
        self.checking = amount_checking
        self.savings = amount_savings


users_db = {
    1: User(1, "Alice", "password1", "alice@email.com", 1000, 5000),
    2: User(2, "Bob", "password2", "bob@email.com", 200, 500),
    9: Admin(9, "Zack", "password9", "zack@tutanota.com")
}
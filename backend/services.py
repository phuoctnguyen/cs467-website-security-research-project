def execute_transfer(user, from_acc, to_acc, amount_str):
    """ Helper function to app.py's transfer(). """

    # validate & process input
    if not from_acc or not to_acc or not amount_str:
        return False, "All fields are required."
    if from_acc == to_acc:
        return False, "You must transfer between two different accounts."
    try:
        amount = float(amount_str)
        if amount <= 0:
            return False, "Transfer amount must be greater than zero."

        if from_acc == "checking" and user.checking >= amount:
            user.checking -= amount
            user.savings += amount
            return True, f"Transferred ${amount:.2f} from checking to savings."

        if from_acc == "savings" and user.savings >= amount:
            user.savings -= amount
            user.checking += amount
            return True, f"Transferred ${amount:.2f} from savings to checking."

        return False, "Insufficient funds in selected account."

    except ValueError:
        return False, "Invalid amount. Please enter a number."

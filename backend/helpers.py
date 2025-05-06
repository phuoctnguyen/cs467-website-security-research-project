def execute_transfer(user, from_acc, to_acc, amount_str):
    """
        Helper function to app.py's transfer().
        Transfers funds between a user's checking and savings accounts.

        :param user: User object with 'checking' and 'savings' attributes.
        :param from_acc: Source account name ('checking' or 'savings').
        :param to_acc: Destination account name ('checking' or 'savings').
        :param amount_str: Transfer amount as a string.
        :return: Tuple of (success: bool, message: str).
            The boolean True indicates changes in the User object, so,
            outside function knows that the database should be updated.
        """

    # validate input
    if not from_acc or not to_acc or not amount_str:
        return False, "All fields are required."
    if from_acc == to_acc:
        return False, "You must transfer between two different accounts."
    try:
        # process input
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

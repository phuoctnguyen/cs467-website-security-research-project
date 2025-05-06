# FlaskForm classes
# code adapted from:
# https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iii-web-forms

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired


class TransferForm(FlaskForm):
    from_account = SelectField(
        "Transfer funds from Account:",
        choices=[("checking", "Checking"), ("savings", "Savings")],
        validators=[DataRequired()]
    )
    to_account = SelectField(
        "Move funds to Account:",
        choices=[("checking", "Checking"), ("savings", "Savings")],
        validators=[DataRequired()]
    )
    amount = StringField("Amount to transfer:", validators=[DataRequired()])
    submit = SubmitField("Submit")

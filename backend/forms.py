from flask_wtf import FlaskForm     # , CSRFProtect
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired

# class LoginForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired()])
#     password = StringField('Password', validators=[DataRequired()])
#     secure = StringField('Secure', validators=[DataRequired()])
#     submit = SubmitField('Submit')


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

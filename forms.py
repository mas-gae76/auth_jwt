from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import InputRequired


class AuthForm(FlaskForm):
    username = StringField('Имя пользователя: ', validators=[InputRequired()])
    password = PasswordField('Пароль: ', validators=[InputRequired()])
    submit = SubmitField('Войти')
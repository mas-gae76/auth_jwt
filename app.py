from flask import make_response, render_template, Flask, request, redirect, url_for, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, login_user, logout_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from forms import AuthForm
from models import *
import os, jwt
from datetime import datetime, timedelta
from decorators import jwt_required


app = Flask(__name__)
app.secret_key = '\xb7\xdc\x96y[P\x90g\xdb\xaf\xf9\xcc)z{\x98'
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = AuthForm()
    if request.method == 'POST' and form.validate_on_submit():
        data = form.data
        user  = Users.query.filter_by(username=data['username']).first()
        if user:
            flash(f'Пользователь с ником \'{user.username}\' уже существует!')
            return redirect('signup')
        
        new_user = Users(username=data['username'], password=generate_password_hash(data['password']))
        new_user.token = jwt.encode(
                                    {
                                        'username': new_user.username, 
                                        'exp': datetime.utcnow() + timedelta(minutes=2)
                                    }, 
                                    app.secret_key, 
                                    algorithm='HS256'
                                   )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return set_cookie(new_user.token)
    return render_template('signup.html', form=form)


@app.route('/', methods=['GET'])
@jwt_required
def main():
    return render_template('index.html')


def set_cookie(token: str):
    response = make_response(redirect('/'))
    response.set_cookie('token', value=f'{token}', max_age=600, secure=True, samesite='strict')
    return response


if __name__ == '__main__':
    app.run(debug=app.debug)
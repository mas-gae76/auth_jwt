# Flask modules
from flask import (jsonify, make_response, render_template, request,
                   redirect, url_for, flash, get_flashed_messages)
from flask_jwt_extended import (create_access_token, create_refresh_token, 
                                set_access_cookies, set_refresh_cookies,
                                jwt_required, unset_jwt_cookies, get_jwt_identity)
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
# Custom modules
from config import app, login_manager, jwt
from forms import AuthForm
from models import *


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    flash('Время жизни токена истекло!')
    return redirect('login', 401)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = AuthForm()
    if request.method == 'POST' and form.validate_on_submit():
        data = form.data
        user = Users.query.filter_by(username=data['username']).first()
        if user:
            flash(f'Пользователь с ником \'{user.username}\' уже существует!')
            return redirect('signup')

        new_user = Users(
            username=data['username'], password=generate_password_hash(data['password']))
        new_user.token = create_access_token(identity=new_user.username)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        refresh_token = create_refresh_token(identity=new_user.username)
        response = make_response(redirect('/'))
        set_access_cookies(response, new_user.token)
        set_refresh_cookies(response, refresh_token)
        return response
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = AuthForm()
    if request.method == 'POST' and form.validate_on_submit():
        data = form.data
        user = Users.query.filter_by(username=data['username']).first()
        if not check_password_hash(user.password, data['password']):
            flash(f'Введён неверный пароль!')
            return redirect('login')
        login_user(user)
        user.token = create_access_token(identity=user.username)
        db.session.commit()
        refresh_token = create_refresh_token(identity=user.username)
        response = make_response(redirect('/'))
        set_access_cookies(response, user.token)
        set_refresh_cookies(response, refresh_token)
        return response
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    response = make_response(redirect('login'))
    logout_user()
    unset_jwt_cookies(response)
    return response


@app.route('/', methods=['GET'])
@jwt_required(fresh=False)
def main():
    return render_template('index.html')



@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    print(identity)
    response = make_response(redirect('/'))
    if datetime.now() > datetime.fromtimestamp(int(identity['exp'])):
        user = Users.query.filter_by(username=identity['sub']) 
        user.token = create_access_token(identity=identity['sub'])
        db.session.commit()
        refresh_token = create_refresh_token(identity=identity['sub'])
        set_access_cookies(response, user.token)
        set_refresh_cookies(response, refresh_token)
    return response


if __name__ == '__main__':
    app.run(debug=app.debug)

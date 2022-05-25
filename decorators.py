from functools import wraps
from flask import request, flash, redirect, url_for
from flask_login import logout_user
from datetime import datetime
from app import *
import jwt
from jwt import ExpiredSignatureError


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash('Token is missing')
            logout_user()
            return redirect('signup')
        try:
            data = jwt.decode(jwt=token, key='\xb7\xdc\x96y[P\x90g\xdb\xaf\xf9\xcc)z{\x98', algorithms=['HS256', ])
            if datetime.utcnow() > datetime.fromtimestamp(float(data['exp'])):
                raise ExpiredSignatureError()
        except ExpiredSignatureError:
            flash('Token is invalid')
            logout_user()
            return redirect(url_for('signup'))
        return f(*args, **kwargs)
    return decorated
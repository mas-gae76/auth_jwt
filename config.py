from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from datetime import timedelta

# App settings
app = Flask(__name__)
app.secret_key = '\xb7\xdc\x96y[P\x90g\xdb\xaf\xf9\xcc)z{\x98'
app.debug = True
# DB settings
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
# JWY settings
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_SECRET_KEY'] = app.secret_key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=3)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=2)

login_manager = LoginManager(app)
# JWT Manager to control jwts
jwt = JWTManager(app)
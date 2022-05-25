from flask_login import UserMixin
from app import db


class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), index=True, unique=True)
    password = db.Column(db.String(105))
    token = db.Column(db.String(135))
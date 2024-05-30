from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from cryptography.fernet import Fernet
from dotenv import load_dotenv, find_dotenv
import secrets
import uuid
import os


load_dotenv(find_dotenv())

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
db = SQLAlchemy(app)

key = os.getenv('ENCRYPTION_KEY').encode()
cipher_suite = Fernet(key)


def generate_unique_code():
    return secrets.token_urlsafe(8)


def generate_unique_code_records():
    return str(uuid.uuid4())


def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())


def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()


class Users(db.Model, UserMixin):
    id = db.Column(db.String(8), primary_key=True, default=generate_unique_code)
    name = db.Column(db.LargeBinary, nullable=False)
    login = db.Column(db.String(128), unique=True, nullable=False)
    psw = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return '<Users %r>' % self.id

    def set_name(self, name):
        self.name = encrypt_data(name)

    def get_name(self):
        return decrypt_data(self.name)

    # Метод для проверки аутентификации пользователя
    def is_authenticated(self):
        return True


class Records(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=generate_unique_code_records)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.now)

    user_id = db.Column(db.String(8), db.ForeignKey('users.id'))

    def __repr__(self):
        return '<Records %r>' % self.id


class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    file_content = db.Column(db.LargeBinary, nullable=False)

    user_id = db.Column(db.String(8), db.ForeignKey('users.id'))

    def __repr__(self):
        return '<Files %r>' % self.id
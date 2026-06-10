import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'tierA-dev-secret-key-change-in-production'
    DATABASE = os.path.join(basedir, 'email.db')
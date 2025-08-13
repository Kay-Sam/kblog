import os
import pathlib

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'kaysam'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    # Database configuration
    # SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(
    #     pathlib.Path().absolute(), 'data.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email (Flask-Mail) configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') 
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') 
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

# class DevelopmentConfig(Config):
#     DEBUG = True
#     SQLALCHEMY_DATABASE_URI = 'sqlite:///data.db'

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')

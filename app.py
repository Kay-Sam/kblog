from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate
from config import  DevelopmentConfig, ProductionConfig
import os

app = Flask(__name__)

if os.environ.get('FLASK_ENV') == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

db = SQLAlchemy(app)
migrate = Migrate(app=app, db=db)
mail = Mail(app)

import routes
import models

if __name__ == "__main__":
    app.run(debug=True)

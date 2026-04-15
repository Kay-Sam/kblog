from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate
from config import  DevelopmentConfig, ProductionConfig
from flask_dance.contrib.google import make_google_blueprint
import os
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"


app = Flask(__name__)

# Use environment variable to select config.
app.config.from_object(ProductionConfig)

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_to="google_login"
)

app.register_blueprint(google_bp, url_prefix="/login")

migrate = Migrate(app=app, db=db)
mail = Mail(app)



import routes
import models 

if __name__ == "__main__":
    app.run(debug=True)

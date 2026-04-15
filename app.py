from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate
from flask_dance.contrib.google import make_google_blueprint
from config import DevelopmentConfig, ProductionConfig
from dotenv import load_dotenv
import os

# =========================
# LOAD ENV (LOCAL ONLY)
# =========================
load_dotenv()

# Safe OAuth flag
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

# =========================
# CREATE APP
# =========================
app = Flask(__name__)

# =========================
# CONFIG SELECTOR
# =========================
ENV = os.getenv("FLASK_ENV", "development")

if ENV == "production":
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

# =========================
# INIT EXTENSIONS
# =========================
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

# =========================
# GOOGLE OAUTH (SAFE SETUP)
# =========================
client_id = app.config.get("GOOGLE_OAUTH_CLIENT_ID")
client_secret = app.config.get("GOOGLE_OAUTH_CLIENT_SECRET")

google_bp = None

if client_id and client_secret:
    google_bp = make_google_blueprint(
        client_id=client_id,
        client_secret=client_secret,
        scope=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email"
        ],
        redirect_to="google_login"
    )

    app.register_blueprint(google_bp, url_prefix="/login")
    print("✅ Google OAuth enabled")

else:
    print("⚠️ Google OAuth NOT configured (running without login)")

# =========================
# IMPORT MODELS + ROUTES
# =========================
import models
import routes

# =========================
# DEBUG ROUTES (optional)
# =========================
print(app.url_map)

# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    app.run(debug=True)
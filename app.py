from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate
from flask_dance.contrib.google import make_google_blueprint
from config import DevelopmentConfig, ProductionConfig
import os
from dotenv import load_dotenv

# ✅ Load .env (important for local dev)
load_dotenv()

# OAuth fix (safe)
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

app = Flask(__name__)

# ✅ Select config
ENV = os.environ.get("FLASK_ENV", "development")

if ENV == "production":
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

# ✅ Force-load ENV variables into config
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

# 🚨 DEBUG PRINT (REMOVE LATER)
print("CLIENT ID:", app.config["GOOGLE_OAUTH_CLIENT_ID"])
print("CLIENT SECRET:", app.config["GOOGLE_OAUTH_CLIENT_SECRET"])

# ❗ Fail fast if missing (VERY IMPORTANT)
if not app.config["GOOGLE_OAUTH_CLIENT_ID"] or not app.config["GOOGLE_OAUTH_CLIENT_SECRET"]:
    raise ValueError("❌ Google OAuth credentials not set!")

# ✅ Init extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

# ✅ Register Google Blueprint
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

# ✅ Import AFTER app + db init
import models
import routes

# ✅ Optional: debug routes
print(app.url_map)

if __name__ == "__main__":
    app.run(debug=True)
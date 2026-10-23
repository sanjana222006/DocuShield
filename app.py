
import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin

from flask import request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Application configuration
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-development-only")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///docushield.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
csrf = CSRFProtect(app)
# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = "login"


# User table
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="user"
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or len(password) < 12:
            flash("Please enter valid details.")
            return redirect(url_for("register"))

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash("Username or email already registered.")
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role="user"
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful!")
        return redirect(url_for("register"))

    return render_template("register.html")
    
@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):

            login_user(user)

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return f"Welcome to DocuShield, {current_user.username}!"


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

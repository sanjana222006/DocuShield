import os
from datetime import datetime, timezone

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin

from flask import request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from uuid import uuid4
from werkzeug.utils import secure_filename
from flask import send_from_directory, abort

# First create Flask application
app = Flask(__name__)

# Then configure it
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-development-only")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///docushield.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = os.path.join(app.instance_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

csrf = CSRFProtect(app)
db = SQLAlchemy(app)

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

# Document table
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    uploaded_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
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
    return render_template("dashboard.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_document():
    if request.method == "POST":
        file = request.files.get("document")

        if not file or not file.filename:
            flash("Please select a document.")
            return redirect(url_for("upload_document"))

        allowed_extensions = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}
        original_name = secure_filename(file.filename)
        extension = os.path.splitext(original_name)[1].lower()

        if not original_name or extension not in allowed_extensions:
            flash("Only PDF, TXT, PNG and JPG files are allowed.")
            return redirect(url_for("upload_document"))

        stored_name = f"{uuid4().hex}{extension}"
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        file.save(os.path.join(app.config["UPLOAD_FOLDER"], stored_name))

        document = Document(
            original_filename=original_name,
            stored_filename=stored_name,
            owner_id=current_user.id
        )

        db.session.add(document)
        db.session.commit()

        flash("Document uploaded successfully!")
        return redirect(url_for("upload_document"))

    return render_template("upload.html")
@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):

    document = Document.query.filter_by(
        id=document_id,
        owner_id=current_user.id
    ).first()

    if document is None:
        abort(404)

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename,
        as_attachment=True,
        download_name=document.original_filename
    )

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

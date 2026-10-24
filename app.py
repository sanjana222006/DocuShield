
import os
from datetime import datetime, timezone
from functools import wraps
from uuid import uuid4

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import NotFound


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "local-development-only"
)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///docushield.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(app.instance_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

csrf = CSRFProtect(app)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# DATABASE MODELS

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    uploaded_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    document_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class AuditDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(
        db.Integer,
        db.ForeignKey("audit_log.id"),
        unique=True,
        nullable=False
    )
    outcome = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    details = db.Column(db.String(500), nullable=False, default="")

    audit = db.relationship(
        "AuditLog",
        backref=db.backref("detail", uselist=False)
    )


def record_audit(user_id, document_id, action, outcome, reason, details=""):
    audit = AuditLog(
        user_id=user_id,
        document_id=document_id,
        action=action
    )
    db.session.add(audit)
    db.session.flush()

    db.session.add(AuditDetail(
        audit_id=audit.id,
        outcome=outcome,
        reason=reason,
        details=details
    ))

    return audit


class AuthEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=True
    )
    attempted_email = db.Column(db.String(120), nullable=True)
    action = db.Column(db.String(40), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    auth_method = db.Column(db.String(30), nullable=False, default="PASSWORD")
    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


def record_auth_event(action, outcome, reason, user=None, email=None):
    db.session.add(AuthEvent(
        user_id=user.id if user else None,
        attempted_email=email,
        action=action,
        outcome=outcome,
        reason=reason,
        auth_method="PASSWORD"
    ))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ROLE-BASED AUTHORIZATION

def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


# HOME

@app.route("/")
def home():
    return render_template("index.html")


# REGISTER

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
        db.session.flush()

        record_auth_event(
            "REGISTER", "ALLOWED",
            "New normal-user account created",
            user=new_user
        )
        db.session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)

            record_auth_event(
                "LOGIN", "ALLOWED",
                "Valid account credentials",
                user=user
            )
            db.session.commit()
            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))

        record_auth_event(
            "LOGIN", "DENIED",
            "Invalid credentials",
            email=email
        )
        db.session.commit()

        flash("Invalid email or password.")

    return render_template("login.html")


# USER DASHBOARD

@app.route("/dashboard")
@login_required
def dashboard():
    documents = (
        Document.query
        .filter_by(owner_id=current_user.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )

    return render_template(
        "dashboard.html",
        documents=documents
    )



# PERSONAL ACTIVITY HISTORY

@app.route("/history")
@login_required
def my_history():
    logs = (
        AuditLog.query
        .filter_by(user_id=current_user.id)
        .order_by(AuditLog.id.desc())
        .all()
    )
    return render_template("history.html", logs=logs)


# ADMIN DASHBOARD

@app.route("/admin")
@admin_required
def admin_dashboard():
    documents = (
        db.session.query(Document, User)
        .join(User, Document.owner_id == User.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )

    return render_template(
        "admin.html",
        documents=documents,
        user_count=User.query.count(),
        document_count=Document.query.count()
    )


# ADMIN AUDIT HISTORY

@app.route("/admin/audit")
@admin_required
def admin_audit():
    logs = (
        db.session.query(AuditLog, User)
        .join(User, AuditLog.user_id == User.id)
        .order_by(AuditLog.id.desc())
        .all()
    )

    return render_template("audit.html", logs=logs)



@app.route("/admin/auth-history")
@admin_required
def admin_auth_history():
    events = (
        db.session.query(AuthEvent, User)
        .outerjoin(User, AuthEvent.user_id == User.id)
        .order_by(AuthEvent.id.desc())
        .all()
    )
    return render_template("auth_history.html", events=events)



# LOGOUT

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    record_auth_event(
        "LOGOUT", "ALLOWED",
        "Authenticated user ended their session",
        user=current_user
    )
    db.session.commit()

    logout_user()
    return redirect(url_for("login"))


# DOCUMENT UPLOAD

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_document():
    if request.method == "POST":
        file = request.files.get("document")

        if not file or not file.filename:
            flash("Please select a document.")
            return redirect(url_for("upload_document"))

        allowed_extensions = {
            ".pdf", ".txt", ".png", ".jpg", ".jpeg"
        }

        original_name = secure_filename(file.filename)
        extension = os.path.splitext(original_name)[1].lower()

        if not original_name or extension not in allowed_extensions:
            flash("Only PDF, TXT, PNG and JPG files are allowed.")
            return redirect(url_for("upload_document"))

        stored_name = f"{uuid4().hex}{extension}"

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        file.save(
            os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        )

        document = Document(
            original_filename=original_name,
            stored_filename=stored_name,
            owner_id=current_user.id
        )

        db.session.add(document)
        db.session.flush()

        record_audit(
            current_user.id,
            document.id,
            "UPLOAD",
            "ALLOWED",
            "Authenticated user created a document",
            f"Filename: {document.original_filename}"
        )
        db.session.commit()

        flash("Document uploaded successfully!")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")


# CENTRALIZED DOCUMENT AUTHORIZATION

def authorize_document(document_id, action="DOWNLOAD"):
    """
    Policy:
    - The document must exist.
    - Only its owner can access its private contents.
    - Admin status does not bypass document ownership.
    - Every denied authenticated request is audited.
    - Denials return the same HTTP status to avoid revealing ownership.
    """
    document = db.session.get(Document, document_id)

    if document is None:
        reason = "Requested document does not exist"
    elif document.owner_id != current_user.id:
        reason = "Authenticated user is not the document owner"
    else:
        return document

    record_audit(
        current_user.id,
        document_id,
        "ACCESS_DENIED",
        "DENIED",
        reason,
        f"Requested operation: {action}"
    )
    db.session.commit()
    abort(404)


# SECURE DOCUMENT DOWNLOAD

@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = authorize_document(document_id, "DOWNLOAD")

    # Confirm the file is available before recording an allowed download.
    try:
        response = send_from_directory(
            app.config["UPLOAD_FOLDER"],
            document.stored_filename,
            as_attachment=True,
            download_name=document.original_filename
        )
    except NotFound:
        record_audit(
            current_user.id,
            document.id,
            "DOWNLOAD_FAILED",
            "DENIED",
            "Document metadata exists but stored file is unavailable",
            "File delivery could not be prepared"
        )
        db.session.commit()
        abort(404)

    record_audit(
        current_user.id,
        document.id,
        "DOWNLOAD",
        "ALLOWED",
        "Authenticated user owns the requested document",
        f"Filename: {document.original_filename}"
    )
    db.session.commit()

    return response



# SECURE DOCUMENT RENAME

@app.route("/documents/<int:document_id>/rename", methods=["POST"])
@login_required
def rename_document(document_id):
    document = authorize_document(document_id, "RENAME")

    new_name = secure_filename(
        request.form.get("new_filename", "").strip()
    )

    allowed_extensions = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}

    old_extension = os.path.splitext(
        document.original_filename
    )[1].lower()

    new_extension = os.path.splitext(new_name)[1].lower()

    if (
        not new_name
        or len(new_name) > 255
        or new_extension not in allowed_extensions
        or new_extension != old_extension
    ):
        record_audit(
            current_user.id,
            document.id,
            "RENAME",
            "DENIED",
            "Invalid filename or attempted file extension change",
            "Rename rejected"
        )
        db.session.commit()
        flash("Invalid filename. Keep the original file extension.")
        return redirect(url_for("dashboard"))

    old_name = document.original_filename

    if new_name == old_name:
        flash("Filename is already the same.")
        return redirect(url_for("dashboard"))

    document.original_filename = new_name

    record_audit(
        current_user.id,
        document.id,
        "RENAME",
        "ALLOWED",
        "Authenticated document owner renamed the document",
        f"Old: {old_name} | New: {new_name}"
    )

    db.session.commit()

    flash("Document renamed successfully.")
    return redirect(url_for("dashboard"))



# SECURE DOCUMENT DELETE

@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id):
    document = authorize_document(document_id, "DELETE")

    original_name = document.original_filename
    stored_name = document.stored_filename

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_name
    )

    # Refuse deletion when the physical file is unavailable.
    if not os.path.isfile(file_path):
        record_audit(
            current_user.id,
            document.id,
            "DELETE_FAILED",
            "DENIED",
            "Stored document file is unavailable",
            f"Filename: {original_name}"
        )
        db.session.commit()
        abort(404)

    # Keep document metadata for historical evidence.
    # Rename the physical file to a private deletion marker first.
    deleted_path = file_path + ".deleted"

    try:
        os.replace(file_path, deleted_path)
    except OSError:
        record_audit(
            current_user.id,
            document.id,
            "DELETE_FAILED",
            "DENIED",
            "File deletion preparation failed",
            f"Filename: {original_name}"
        )
        db.session.commit()
        abort(500)

    try:
        record_audit(
            current_user.id,
            document.id,
            "DELETE",
            "ALLOWED",
            "Authenticated document owner deleted the document",
            f"Filename: {original_name} | Stored file: {stored_name}"
        )

        db.session.delete(document)
        db.session.commit()

    except Exception:
        db.session.rollback()
        os.replace(deleted_path, file_path)
        raise

    try:
        os.remove(deleted_path)
    except OSError:
        app.logger.exception(
            "Deleted file cleanup failed for document %s",
            document_id
        )

    flash("Document deleted successfully.")
    return redirect(url_for("dashboard"))


# START APPLICATION

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 5000)),
    debug=False
)
import os

from app import app, db, User
from werkzeug.security import generate_password_hash


def bootstrap_admin():
    email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "")

    # No admin configuration: leave the database unchanged.
    if not email and not password:
        return

    if not email or len(password) < 12:
        raise RuntimeError("ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters) are required.")

    with app.app_context():
        db.create_all()

        existing = User.query.filter_by(email=email).first()

        if existing:
            if existing.role != "admin":
                raise RuntimeError(
                    "ADMIN_EMAIL belongs to a normal user. Choose a different email."
                )
            print("Admin account already exists.")
            return

        if User.query.filter_by(username="docushield_admin").first():
            raise RuntimeError("Reserved admin username is already taken.")

        admin = User(
            username="docushield_admin",
            email=email,
            password_hash=generate_password_hash(password),
            role="admin"
        )

        db.session.add(admin)
        db.session.commit()
        print("Admin account provisioned successfully.")


if __name__ == "__main__":
    bootstrap_admin()

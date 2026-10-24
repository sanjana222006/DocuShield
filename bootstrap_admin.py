import os

from app import app, db, User
from werkzeug.security import generate_password_hash


def bootstrap_admin():
    email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "")

    # Always initialize database tables, even without admin credentials.
    with app.app_context():
        db.create_all()

        # Admin provisioning is optional.
        if not email and not password:
            print("Database initialized. Admin provisioning skipped.")
            return

        if not email or len(password) < 12:
            raise RuntimeError(
                "ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters) are required."
            )

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

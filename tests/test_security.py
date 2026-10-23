
import os
import sys
import tempfile
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

# Find the main project directory
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Configure a separate database BEFORE importing app.py
TEST_DIR = tempfile.TemporaryDirectory(prefix="docushield_tests_")
TEST_PATH = Path(TEST_DIR.name)

os.environ["DATABASE_URL"] = "sqlite:///" + str(TEST_PATH / "test.db")

from app import app, db, User, Document, AuditLog


@pytest.fixture
def client():
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        UPLOAD_FOLDER=str(TEST_PATH / "uploads")
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

        user1 = User(
            username="testowner",
            email="owner@example.com",
            password_hash=generate_password_hash("TestPassword123!"),
            role="user"
        )

        user2 = User(
            username="testother",
            email="other@example.com",
            password_hash=generate_password_hash("TestPassword123!"),
            role="user"
        )

        admin = User(
            username="testadmin",
            email="admin@example.com",
            password_hash=generate_password_hash("TestPassword123!"),
            role="admin"
        )

        db.session.add_all([user1, user2, admin])
        db.session.commit()

        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(parents=True, exist_ok=True)

        (upload_dir / "private-test.txt").write_text(
            "Private test document",
            encoding="utf-8"
        )

        document = Document(
            original_filename="private-test.txt",
            stored_filename="private-test.txt",
            owner_id=user1.id
        )

        db.session.add(document)
        db.session.commit()

        with app.test_client() as test_client:
            yield test_client

        db.session.remove()
        db.drop_all()


def login_as(client, user_id):
    """Simulate an authenticated test session."""
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


# TEST 1: Dashboard requires login
def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


# TEST 2: Upload requires login
def test_upload_requires_login(client):
    response = client.get("/upload")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


# TEST 3: Normal user cannot access admin dashboard
def test_normal_user_cannot_access_admin(client):
    login_as(client, 2)

    response = client.get("/admin")

    assert response.status_code == 403


# TEST 4: Normal user cannot access audit history
def test_normal_user_cannot_access_audit(client):
    login_as(client, 2)

    response = client.get("/admin/audit")

    assert response.status_code == 403


# TEST 5: Admin can access admin dashboard
def test_admin_can_access_dashboard(client):
    login_as(client, 3)

    response = client.get("/admin")

    assert response.status_code == 200
    assert b"Admin Dashboard" in response.data


# TEST 6: Owner can download their document
def test_owner_can_download(client):
    login_as(client, 1)

    response = client.get("/documents/1/download")

    assert response.status_code == 200
    assert response.data == b"Private test document"

    with app.app_context():
        assert AuditLog.query.filter_by(
            user_id=1,
            document_id=1,
            action="DOWNLOAD"
        ).count() == 1


# TEST 7: Other user cannot download private document
def test_other_user_cannot_download(client):
    login_as(client, 2)

    response = client.get("/documents/1/download")

    assert response.status_code == 404

    with app.app_context():
        assert AuditLog.query.filter_by(
            user_id=2,
            document_id=1,
            action="ACCESS_DENIED"
        ).count() == 1


# TEST 8: Even an admin cannot bypass owner-only downloads
def test_admin_cannot_bypass_document_ownership(client):
    login_as(client, 3)

    response = client.get("/documents/1/download")

    assert response.status_code == 404


# TEST 9: User dashboard displays only their own documents
def test_dashboard_hides_other_users_documents(client):
    login_as(client, 2)

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"private-test.txt" not in response.data


# TEST 10: Missing document returns 404
def test_missing_document_returns_404(client):
    login_as(client, 1)

    response = client.get("/documents/99999/download")

    assert response.status_code == 404


# TEST 11: Unsupported upload extension is rejected
def test_unsupported_file_extension(client):
    from io import BytesIO

    login_as(client, 1)

    response = client.post(
        "/upload",
        data={
            "document": (
                BytesIO(b"test content"),
                "malicious.exe"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 302

    with app.app_context():
        assert Document.query.count() == 1


# TEST 12: CSRF protection rejects a POST without a token
def test_csrf_rejects_missing_token(client):
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post(
            "/login",
            data={
                "email": "owner@example.com",
                "password": "TestPassword123!"
            }
        )

        assert response.status_code == 400

    finally:
        app.config["WTF_CSRF_ENABLED"] = False

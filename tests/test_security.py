
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


def test_owner_download_has_detailed_audit(client):
    from app import AuditDetail

    login_as(client, 1)
    response = client.get("/documents/1/download")

    assert response.status_code == 200

    with app.app_context():
        log = AuditLog.query.filter_by(
            user_id=1, action="DOWNLOAD"
        ).first()

        detail = AuditDetail.query.filter_by(audit_id=log.id).first()

        assert detail.outcome == "ALLOWED"
        assert "owns" in detail.reason


def test_denied_download_has_detailed_audit(client):
    from app import AuditDetail

    login_as(client, 2)
    response = client.get("/documents/1/download")

    assert response.status_code == 404

    with app.app_context():
        log = AuditLog.query.filter_by(
            user_id=2, action="ACCESS_DENIED"
        ).first()

        detail = AuditDetail.query.filter_by(audit_id=log.id).first()

        assert detail.outcome == "DENIED"
        assert "not the document owner" in detail.reason


def test_user_history_does_not_show_other_users_activity(client):
    with app.app_context():
        db.session.add(AuditLog(
            user_id=1,
            document_id=1,
            action="OWNER_PRIVATE_ACTIVITY"
        ))
        db.session.commit()

    login_as(client, 2)
    response = client.get("/history")

    assert response.status_code == 200
    assert b"OWNER_PRIVATE_ACTIVITY" not in response.data


def test_successful_login_is_audited(client):
    from app import AuthEvent

    response = client.post("/login", data={
        "email": "owner@example.com",
        "password": "TestPassword123!"
    })

    assert response.status_code == 302

    with app.app_context():
        event = AuthEvent.query.filter_by(
            user_id=1, action="LOGIN", outcome="ALLOWED"
        ).first()

        assert event is not None
        assert event.auth_method == "PASSWORD"


def test_failed_login_is_audited_without_verified_identity(client):
    from app import AuthEvent

    client.post("/login", data={
        "email": "owner@example.com",
        "password": "IncorrectPassword123!"
    })

    with app.app_context():
        event = AuthEvent.query.filter_by(
            action="LOGIN", outcome="DENIED"
        ).first()

        assert event is not None
        assert event.user_id is None
        assert event.attempted_email == "owner@example.com"


def test_logout_is_audited(client):
    from app import AuthEvent

    login_as(client, 1)
    response = client.post("/logout")

    assert response.status_code == 302

    with app.app_context():
        assert AuthEvent.query.filter_by(
            user_id=1, action="LOGOUT"
        ).count() == 1


def test_normal_user_cannot_view_authentication_history(client):
    login_as(client, 1)

    response = client.get("/admin/auth-history")

    assert response.status_code == 403


def test_admin_can_view_authentication_history(client):
    login_as(client, 3)

    response = client.get("/admin/auth-history")

    assert response.status_code == 200
    assert b"Authentication Security History" in response.data


def test_missing_document_attempt_is_audited(client):
    login_as(client, 1)

    response = client.get("/documents/99999/download")

    assert response.status_code == 404

    with app.app_context():
        log = AuditLog.query.filter_by(
            user_id=1,
            document_id=99999,
            action="ACCESS_DENIED"
        ).first()

        assert log is not None
        assert log.detail.outcome == "DENIED"
        assert "does not exist" in log.detail.reason


def test_missing_physical_file_is_not_logged_as_success(client):
    from pathlib import Path

    login_as(client, 1)

    with app.app_context():
        document = db.session.get(Document, 1)
        file_path = Path(app.config["UPLOAD_FOLDER"]) / document.stored_filename
        file_path.unlink()

    response = client.get("/documents/1/download")

    assert response.status_code == 404

    with app.app_context():
        assert AuditLog.query.filter_by(action="DOWNLOAD").count() == 0

        failed = AuditLog.query.filter_by(
            action="DOWNLOAD_FAILED"
        ).first()

        assert failed is not None
        assert failed.detail.outcome == "DENIED"


def test_admin_download_denial_has_explanation(client):
    login_as(client, 3)

    response = client.get("/documents/1/download")

    assert response.status_code == 404

    with app.app_context():
        log = AuditLog.query.filter_by(
            user_id=3,
            action="ACCESS_DENIED"
        ).first()

        assert log is not None
        assert log.detail.outcome == "DENIED"
        assert "not the document owner" in log.detail.reason


def test_owner_can_rename_document(client):
    login_as(client, 1)

    response = client.post(
        "/documents/1/rename",
        data={"new_filename": "renamed.txt"},
        follow_redirects=True
    )

    assert response.status_code == 200

    with app.app_context():
        document = db.session.get(Document, 1)
        assert document.original_filename == "renamed.txt"

        log = AuditLog.query.filter_by(
            user_id=1,
            action="RENAME"
        ).first()

        assert log is not None
        assert log.detail.outcome == "ALLOWED"
        assert "renamed.txt" in log.detail.details


def test_other_user_cannot_rename_document(client):
    login_as(client, 2)

    response = client.post(
        "/documents/1/rename",
        data={"new_filename": "hacked.pdf"}
    )

    assert response.status_code == 404

    with app.app_context():
        document = db.session.get(Document, 1)
        assert document.original_filename != "hacked.pdf"

        log = AuditLog.query.filter_by(
            user_id=2,
            action="ACCESS_DENIED"
        ).first()

        assert log is not None
        assert log.detail.outcome == "DENIED"
        assert "RENAME" in log.detail.details


def test_rename_cannot_change_file_extension(client):
    login_as(client, 1)

    response = client.post(
        "/documents/1/rename",
        data={"new_filename": "changed.exe"},
        follow_redirects=True
    )

    assert response.status_code == 200

    with app.app_context():
        document = db.session.get(Document, 1)
        assert document.original_filename != "changed.exe"

        log = AuditLog.query.filter_by(
            user_id=1,
            action="RENAME",
        ).first()

        assert log is not None
        assert log.detail.outcome == "DENIED"


def test_admin_cannot_rename_another_users_document(client):
    login_as(client, 3)

    response = client.post(
        "/documents/1/rename",
        data={"new_filename": "admin-renamed.pdf"}
    )

    assert response.status_code == 404

    with app.app_context():
        document = db.session.get(Document, 1)
        assert document.original_filename != "admin-renamed.pdf"


def test_owner_can_delete_document_and_audit_remains(client):
    login_as(client, 1)

    response = client.post("/documents/1/delete")

    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(Document, 1) is None

        log = AuditLog.query.filter_by(
            user_id=1,
            document_id=1,
            action="DELETE"
        ).first()

        assert log is not None
        assert log.detail.outcome == "ALLOWED"
        assert "private-test.txt" in log.detail.details

    assert client.get("/documents/1/download").status_code == 404


def test_other_user_cannot_delete_document(client):
    login_as(client, 2)

    response = client.post("/documents/1/delete")

    assert response.status_code == 404

    with app.app_context():
        assert db.session.get(Document, 1) is not None

        log = AuditLog.query.filter_by(
            user_id=2,
            action="ACCESS_DENIED"
        ).first()

        assert log is not None
        assert log.detail.outcome == "DENIED"
        assert "DELETE" in log.detail.details


def test_admin_cannot_delete_another_users_document(client):
    login_as(client, 3)

    response = client.post("/documents/1/delete")

    assert response.status_code == 404

    with app.app_context():
        assert db.session.get(Document, 1) is not None


def test_missing_file_cannot_create_successful_delete_audit(client):
    from pathlib import Path

    login_as(client, 1)

    with app.app_context():
        document = db.session.get(Document, 1)
        file_path = Path(app.config["UPLOAD_FOLDER"]) / document.stored_filename
        file_path.unlink()

    response = client.post("/documents/1/delete")

    assert response.status_code == 404

    with app.app_context():
        assert db.session.get(Document, 1) is not None

        assert AuditLog.query.filter_by(
            action="DELETE",
            user_id=1
        ).count() == 0

        failed = AuditLog.query.filter_by(
            action="DELETE_FAILED",
            user_id=1
        ).first()

        assert failed is not None
        assert failed.detail.outcome == "DENIED"


def test_delete_requires_authentication(client):
    response = client.post("/documents/1/delete")

    assert response.status_code in (302, 401)


def test_delete_rejects_get_request(client):
    login_as(client, 1)

    response = client.get("/documents/1/delete")

    assert response.status_code == 405

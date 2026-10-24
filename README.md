# DocuShield

A security-focused document access control system developed for the Snovasys Fresher Hiring Challenge 2026.

## Overview

DocuShield allows registered users to upload and manage private documents. Every document operation is protected by server-side ownership verification.

Administrators can inspect document metadata and security audit records but cannot bypass document ownership to access private files.

## Technology Stack

- Python and Flask
- Flask-Login
- Flask-SQLAlchemy and SQLite
- Flask-WTF for CSRF protection
- HTML and CSS
- Gunicorn
- pytest

## Features

- User registration, login and logout
- Secure password hashing
- Private document upload and download
- Owner-only document rename and deletion
- Administrator dashboard
- Document activity history
- Authentication and authorization audit records
- Server-side access control

## Run Locally

Clone the repository and enter the project directory.

Install dependencies:

    pip install -r requirements.txt

Initialize the database:

    python bootstrap_admin.py

Start the application:

    gunicorn app:app --bind 0.0.0.0:5000

Open http://localhost:5000 in a local environment, or use the forwarded port URL in GitHub Codespaces.

## Configuration

Set a strong SECRET_KEY before public deployment.

Optional administrator provisioning uses ADMIN_EMAIL and ADMIN_PASSWORD environment variables.

Do not commit passwords, environment files or application secrets.

## Security Design

The authenticated user's ID is checked against the document owner ID before document access or modification.

Unauthorized and missing document requests return HTTP 404.

Administrators have access to metadata and audit dashboards, not private document contents.

CSRF protection is enabled for forms.

Uploaded files use randomized storage filenames. Supported extensions are PDF, TXT, PNG, JPG and JPEG. Maximum request size is 5 MB.

## Audit Logging

Document activity and authorization decisions are recorded with user ID, document ID, action, timestamp, outcome and reason.

Authentication activity is recorded separately.

Deleting a document does not remove its associated audit history through normal application operations.

## Testing

Run:

    python -m pytest -q

Latest verified result: 33 tests passed.

Manual browser testing verified registration, login, upload, download, rename, deletion and retained activity history.

## Limitations

- File extension checks do not guarantee safe file contents.
- Antivirus scanning and login rate limiting are not implemented.
- Database audit records are not tamper-proof.
- SQLite and local filesystem storage are used for this prototype.
- Render Free local storage is ephemeral; uploaded files and database records may be lost after a restart or redeployment.
- Production use requires persistent storage, secure secrets and a trusted reverse proxy.

## Supporting Documentation

- THREATS.md — threat model and remaining risks
- PROMPTS.md — AI assistance log
- tests/test_security.py — automated security tests

## AI Assistance

AI coding assistance was used during development. Its use, corrections and verification are documented in PROMPTS.md.

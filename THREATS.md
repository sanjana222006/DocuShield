
# DocuShield — Security Threat Model

## 1. Project Overview

DocuShield is a Flask-based document management application with user authentication, role-based authorization, private document storage, and security audit logging.

## 2. Assets to Protect

- User accounts and password hashes
- Uploaded documents
- Document ownership information
- User roles and permissions
- Security audit records
- Application secret key

## 3. Identified Threats and Mitigations

| Threat | Mitigation |
|---|---|
| Unauthorized document access | Server-side ownership verification |
| Access to administrator pages | Admin-only authorization decorator |
| Unauthenticated access | Flask-Login protection |
| Password exposure | Password hashing using Werkzeug |
| CSRF attacks | Flask-WTF CSRF protection |
| Path traversal through filenames | secure_filename and randomized stored filenames |
| Dangerous file uploads | Extension allowlist and 5 MB request limit |
| Unauthorized access attempts | ACCESS_DENIED audit logging |
| Unauthorized audit-history viewing | Admin-only audit route |

## 4. Audit Events

The application records:

- UPLOAD
- DOWNLOAD
- ACCESS_DENIED

Each record contains the acting user ID, document ID, action, and timestamp.

## 5. Remaining Risks

- Extension validation alone does not guarantee safe file contents.
- No antivirus or malware scanning is implemented.
- Login rate limiting is not yet implemented.
- SQLite is intended for this prototype, not a high-concurrency production deployment.
- Administrators can view document metadata, which requires appropriate organizational trust.
- Audit logs are stored in the application database and are not tamper-proof.
- The development debugger and fallback secret key must not be used in public deployment.

## 6. Security Testing

Automated tests cover authentication, authorization, document ownership, audit logging, rejected file extensions, and CSRF protection.

Manual testing was also performed using two separate user accounts to verify unauthorized document downloads are blocked.

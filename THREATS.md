# DocuShield — Security Threat Model

## 1. Security Objective

DocuShield is a Flask-based private document management application.

Its primary security rule is that an authenticated user must not be able to access, rename, or delete a document owned by another user, even by modifying URLs or submitting requests manually.

An administrator can inspect document metadata and audit records but does not automatically receive permission to download another user's private files.

## 2. Assets and Trust Boundaries

Assets requiring protection:

- Uploaded private documents
- User credentials and password hashes
- Document ownership records
- Administrator privileges
- Authentication and document audit history
- Application secret key

The browser is an untrusted client. Document IDs, filenames, form inputs, and requested URLs must not be treated as proof of authorization.

Security decisions are enforced on the Flask server.

## 3. Threats, Mitigations and Verification

| Attack scenario | Implemented protection | Verification |
|---|---|---|
| An unauthenticated visitor requests a protected page | Flask-Login authentication checks | Authentication tests |
| User B changes a document ID in a URL to access User A's file | Server-side document ownership verification; unauthorized access returns 404 | Ownership and denied-access tests |
| User B attempts to rename or delete User A's document | Shared document authorization check before modification | Authorization tests |
| An administrator attempts to bypass document ownership | Administrator privileges do not override private-file ownership | Role and ownership tests |
| An attacker attempts to access administrator audit pages | Admin-only route protection | Role authorization tests |
| A forged request attempts a protected form action | Flask-WTF CSRF validation | CSRF tests |
| A user uploads an unsupported extension or oversized request | Extension allowlist and 5 MB request limit | Upload validation tests |
| A malicious filename attempts path traversal | Filename sanitization and randomized stored filenames | Upload handling and authorization review |
| A user attempts to change a file's extension during rename | Rename requires the original permitted extension to remain unchanged | Rename validation tests |
| A document is deleted to conceal its activity history | Audit records are retained independently of the document record | Deletion and audit-retention tests |
| Authentication failures or unauthorized access go unnoticed | Authentication events and document authorization decisions are logged | Audit tests and manual verification |

## 4. Authorization Design

The application checks the currently authenticated user's identity against the document's stored owner ID.

This check is performed on the server, not through hidden buttons or browser-side restrictions.

A missing or unauthorized document request returns HTTP 404. This avoids confirming another user's document details through the normal response.

Administrator access to metadata and security logs is separate from permission to retrieve private document contents.

## 5. Audit Evidence

Document-related audit actions include:

- UPLOAD
- DOWNLOAD
- RENAME
- DELETE
- ACCESS_DENIED

Audit information records the acting user, document reference, action, timestamp, and additional outcome/reason information.

Authentication activity, including registration and login events, is tracked separately.

Audit records are retained when a document is deleted through the application.

These logs support investigation, but they are not cryptographically tamper-proof.

## 6. Remaining Risks and Limitations

- File-extension validation cannot establish whether uploaded contents are safe.
- Antivirus scanning and malware detection are not implemented.
- Login rate limiting and automated brute-force protection are not implemented.
- The 5 MB limit restricts request size but does not prevent every form of resource exhaustion.
- SQLite and local filesystem storage are suitable for this prototype, not a highly available production deployment.
- Render Free local storage is ephemeral; application data may be lost after a restart or redeployment.
- Administrators can inspect document metadata, which requires organizational trust.
- A compromised database administrator could alter audit records.
- Production deployment requires a strong environment-provided SECRET_KEY and a trusted reverse-proxy configuration.
- The development debugger and development fallback secret must not be exposed publicly.

## 7. Testing Approach

Automated security tests are maintained in `tests/test_security.py`.

Run them using:

    python -m pytest -q

Latest verified result: **33 tests passed**.

Manual browser verification covered registration, login, upload, download, rename, deletion, and confirmation that activity history remains visible after deletion.

Security claims are limited to implemented and tested behaviour; this prototype is not represented as a fully production-hardened document storage service.

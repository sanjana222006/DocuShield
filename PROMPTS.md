# AI Assistance and Engineering Decision Log

**Project:** DocuShield  
**Challenge:** Snovasys Fresher Hiring Challenge 2026

## How I Used AI

I used AI as a development assistant to understand Flask security patterns, explore implementation approaches, review code, and troubleshoot errors.

I treated generated suggestions as starting points rather than proof of correctness. I evaluated the authorization design, checked application behaviour, ran automated tests, and made further changes when the implementation did not meet the intended security requirements.

The entries below describe the development decisions and verification evidence. Commit links refer to the actual Git history.

---

### Entry 1 — 23 October 2026
**Topic:** Security threats and testing

**What I asked AI:** Help identify security risks in a private document management application and suggest ways to test them.

**What the tool produced:** Guidance for documenting threats and creating isolated automated security tests.

**What needed further work:** Describing a security control alone was insufficient. I needed executable tests that could demonstrate whether the application enforced it.

**My decision and verification:** I maintained a separate threat document and added automated security tests rather than relying only on feature descriptions.

**Evidence:**
- [Threat documentation](https://github.com/sanjana222006/DocuShield/commit/57f20f8)
- [Automated security tests](https://github.com/sanjana222006/DocuShield/commit/20c8b2e)

### Entry 2 — 24 October 2026
**Topic:** Document authorization and audit evidence

**What I asked AI:** Help design document access checks and capture enough information to explain authorization decisions.

**What the tool produced:** Suggestions for owner-based access control and authorization audit records.

**What needed further work:** A working download feature was not enough. The application also needed to distinguish permitted and denied operations and retain evidence of authorization decisions.

**My decision and verification:** I developed the audit evidence further and centralized document authorization so document operations followed a consistent ownership check. Denied access attempts were included in the audit trail.

**Evidence:**
- [Detailed authorization audit evidence](https://github.com/sanjana222006/DocuShield/commit/4aebe8f)
- [Centralized authorization and denied-access audit](https://github.com/sanjana222006/DocuShield/commit/e22e0cf)

### Entry 3 — 24 October 2026
**Topic:** Authentication and administrator access

**What I asked AI:** Help review login security, administrator provisioning, and authentication activity recording.

**What the tool produced:** Implementation guidance for administrator setup, role-based navigation, and authentication event logging.

**What needed further work:** An administrator role should not automatically grant access to another user's private document. Authentication activity also needed separate visibility from document operations.

**My decision and verification:** I kept document ownership checks separate from administrator metadata and audit access, and added an authentication security audit trail.

**Evidence:**
- [Administrator provisioning and role-based redirects](https://github.com/sanjana222006/DocuShield/commit/e683a3c)
- [Authentication audit trail](https://github.com/sanjana222006/DocuShield/commit/fb50c40)

### Entry 4 — 24 October 2026
**Topic:** Secure rename and deletion

**What I asked AI:** Help implement document rename and deletion without allowing users to modify another user's documents.

**What the tool produced:** Guidance for implementing document-management operations with authorization checks and audit records.

**What needed further work:** Rename needed restrictions on filename changes, while deletion needed to preserve the activity record instead of erasing evidence along with the document.

**My decision and verification:** I enforced owner-only operations, restricted renaming to the existing file extension, and retained audit history after deletion. I subsequently verified upload, download, rename, delete, and history through the browser.

**Evidence:**
- [Secure document rename](https://github.com/sanjana222006/DocuShield/commit/e130f66)
- [Owner-only deletion and audit retention](https://github.com/sanjana222006/DocuShield/commit/13a6ce8)

### Entry 5 — 24 October 2026
**Topic:** Deployment and database initialization

**What I asked AI:** Help troubleshoot application initialization during deployment.

**What the tool produced:** Guidance for configuring application startup and optional administrator provisioning.

**What was incomplete:** Database initialization was dependent on administrator environment variables being available.

**My correction and verification:** I separated database initialization from optional administrator creation so the application could initialize even when administrator credentials were not configured.

**Evidence:**
- [Database initialization correction](https://github.com/sanjana222006/DocuShield/commit/cfb2b3d)

### Entry 6 — 24 October 2026
**Topic:** HTTPS registration and reverse-proxy debugging

**What I asked AI:** Help investigate why registration failed with a CSRF referrer/host mismatch through the forwarded HTTPS application URL.

**What the tool produced:** An initial reverse-proxy configuration change addressing the forwarded HTTPS protocol.

**What was wrong or incomplete:** The first change did not fully resolve registration because the forwarded host also needed to be handled.

**My correction and verification:** I investigated the remaining host mismatch, updated the proxy configuration, restarted the application, and successfully tested registration and login through the forwarded browser URL.

**Evidence:**
- [Initial HTTPS proxy correction](https://github.com/sanjana222006/DocuShield/commit/3d5b5f6)
- [Forwarded-host correction](https://github.com/sanjana222006/DocuShield/commit/e6a06b9)

---

## Final Verification

I ran the automated test suite using:

    python -m pytest -q

**Result:** 33 tests passed.

I also manually verified registration, login, document upload, download, rename, deletion, and retained activity history.

## Reflection

The most important lesson from this project was that a feature appearing to work does not automatically make it secure. I learned to examine who is requesting an operation, which document they are requesting, why access should be permitted or denied, and how that decision can be verified through tests and audit records.

AI helped accelerate implementation and troubleshooting, but testing, reviewing security behaviour, and correcting incomplete suggestions remained essential parts of my development process.

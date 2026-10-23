# AI Assistance Log – DocuShield

This document records how AI assistance was used during development.

## Entry 1 – October 23, 2026

**Topic:** Project setup and technology selection

**Prompt summary:** Asked for beginner-friendly guidance to build
a secure document management application using Python Flask,
SQLite, HTML and CSS in GitHub Codespaces.

**How the response was used:** Selected the initial technology stack
and created the project structure.

## Entry 2 – October 23, 2026

**Topic:** Registration and password security

**Prompt summary:** Asked for help implementing user registration,
password hashing and CSRF protection.

**How the response was used:** Implemented the registration form
and stored password hashes instead of plaintext passwords.

## Entry 3 – October 23, 2026

**Topic:** Authentication and authorization

**Prompt summary:** Asked how to implement login and protect the
dashboard from unauthenticated access.

**How the response was used:** Added Flask-Login authentication and
tested dashboard protection using curl. The unauthenticated request
returned HTTP 302.
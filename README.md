# Secure Vault

A project for storing and sharing files securely.

## Security goals

- Users can access only their own files unless access is explicitly shared.
- Stored files will be encrypted.
- Changes to encrypted file contents will be detected.
- Shared access will expire and can be revoked.
- Passwords, encryption keys, and access tokens must not appear in logs.

## Initial design

The server will manage encryption keys and can decrypt uploaded files.
Encryption keys must be stored separately from the database and file storage.

## Current progress

- A GET /health endpoint is implemented.
- Argon2id password hashing and verification helpers are implemented.
- Automated tests cover password verification and salted hashing.
- GitHub Actions is configured to run Ruff and pytest.

Registration, login, file storage, and file encryption are not implemented yet.

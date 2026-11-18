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

Project setup only. The security goals above are not implemented yet.

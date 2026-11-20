# Secure Vault

A project for learning to build secure file storage and sharing with
Python, FastAPI, and SQLite.

## Current progress

Implemented:

- `GET /health` reports whether the application is running.
- `POST /register` validates registration requests and creates accounts.
- Passwords are stored as salted Argon2id hashes.
- Duplicate usernames are rejected.
- Registration validation responses exclude submitted values.
- A credential verification function returns the account ID when
  the username and password match.
- The database contains users and sessions tables.
- A database connection helper enables foreign-key enforcement,
  commits successful transactions, and rolls back failed transactions.
- Automated tests cover registration, authentication helpers,
  password hashing, database behavior, and session creation,
  token validation, expiration, and revocation.
- GitHub Actions runs Ruff and pytest.
- Session helpers create secure random tokens and identify accounts
  from valid tokens.
- Only SHA-256 hashes of session tokens are stored in the database.
- Sessions expire after one hour by default and can be revoked individually.
- `POST /login` verifies credentials and returns a bearer session token.
- Login API tests cover successful authentication, rejected credentials,
  invalid requests, and prevention of session creation on failed attempts.

In progress:

- Logout endpoint.

Planned:

- File upload and download with account isolation.
- File encryption and detection of encrypted-content tampering.
- Sharing with expiration and revocation.
- Additional service protections.

## Setup

Prerequisites: Python 3.12 and uv.

From the repository root, install the locked dependencies:

```bash
uv sync --locked
```

## Run locally

```bash
uv run --locked fastapi dev main.py
```

Open:

- Health endpoint: http://127.0.0.1:8000/health
- Interactive API documentation: http://127.0.0.1:8000/docs

The application initializes its database at startup. Local data is stored
in `data/vault.db`, which is excluded from Git.

## Register an account

Usernames must contain 3–32 lowercase English letters, digits, or
underscores. Passwords must contain 15–128 characters; spaces and
Unicode are accepted. Additional request fields are rejected.

With the server running, try these dummy credentials:

```bash
curl -i http://127.0.0.1:8000/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo_user","password":"example-password-for-local-testing"}'
```

Responses:

| Status | Meaning | JSON body |
| --- | --- | --- |
| 201 | Account created | `{"username":"demo_user"}` |
| 409 | Username already exists | `{"detail":"Username is unavailable."}` |
| 422 | Request is invalid | `{"detail":"Invalid request."}` |

Registering an account does not yet create a login session.

## Run checks

```bash
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest
```

To apply formatting:

```bash
uv run --locked ruff format .
```

Database and API tests use temporary databases rather than
`data/vault.db`.

## Security goals

- Users can access only their own files unless access is explicitly shared.
- Stored files will be encrypted.
- Changes to encrypted file contents will be detected.
- Shared access will expire and can be revoked.
- Passwords, encryption keys, and access tokens must not appear in logs.

## Planned encryption design

The server will manage encryption keys and will be able to decrypt
uploaded files. Encryption keys must be stored separately from the
database and file storage.

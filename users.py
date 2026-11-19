import sqlite3
from contextlib import closing
from pathlib import Path

from database import DATABASE_PATH
from security import hash_password, verify_password

_DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password")


def create_user(
    username: str,
    password: str,
    db_path: Path = DATABASE_PATH,
) -> None:
    """Save a new account using an Argon2 password hash."""
    password_hash = hash_password(password)

    with (
        closing(sqlite3.connect(db_path, autocommit=False)) as connection,
        connection,
    ):
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )


def authenticate_user(
    username: str,
    password: str,
    db_path: Path = DATABASE_PATH,
) -> int | None:
    """Return the account ID if credentials match, otherwise None."""
    with closing(sqlite3.connect(db_path)) as connection:
        row = connection.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    stored_hash = row[1] if row is not None else _DUMMY_PASSWORD_HASH

    password_matches = verify_password(
        password=password,
        stored_hash=stored_hash,
    )

    if row is None or not password_matches:
        return None

    return row[0]

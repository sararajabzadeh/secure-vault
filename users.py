import sqlite3
from contextlib import closing
from pathlib import Path

from database import DATABASE_PATH
from security import hash_password


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

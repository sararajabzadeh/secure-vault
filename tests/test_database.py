import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from database import init_db


def test_init_db_preserves_existing_users(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "vault.db"
    init_db(db_path)

    with closing(sqlite3.connect(db_path)) as connection, connection:
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("sara", "placeholder-hash"),
        )

    init_db(db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        users = connection.execute(
            "SELECT username, password_hash FROM users"
        ).fetchall()

    assert users == [("sara", "placeholder-hash")]


def test_duplicate_username_is_rejected(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    init_db(db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        with connection:
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("sara", "first-placeholder-hash"),
            )

        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"), connection:
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("sara", "second-placeholder-hash"),
            )

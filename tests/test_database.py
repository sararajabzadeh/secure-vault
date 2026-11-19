import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from database import database_connection, init_db


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


INSERT_SESSION = """
    INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
    VALUES (?, ?, ?, ?)
"""


@pytest.fixture
def session_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "vault.db"
    init_db(db_path)

    with database_connection(db_path) as connection:
        connection.execute(
            "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
            (1, "sara_27", "placeholder-hash"),
        )

    return db_path


def test_session_survives_database_reinitialization(session_db: Path) -> None:
    session = ("a" * 64, 1, 100, 200)

    with database_connection(session_db) as connection:
        connection.execute(INSERT_SESSION, session)

    init_db(session_db)

    with database_connection(session_db) as connection:
        rows = connection.execute(
            "SELECT token_hash, user_id, created_at, expires_at FROM sessions"
        ).fetchall()

    assert rows == [session]


def test_session_rejects_nonexistent_account(session_db: Path) -> None:
    with (
        pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"),
        database_connection(session_db) as connection,
    ):
        connection.execute(INSERT_SESSION, ("a" * 64, 999, 100, 200))


def test_deleting_account_removes_its_sessions(session_db: Path) -> None:
    with database_connection(session_db) as connection:
        connection.execute(INSERT_SESSION, ("a" * 64, 1, 100, 200))
        connection.execute("DELETE FROM users WHERE id = ?", (1,))

    with database_connection(session_db) as connection:
        count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    assert count == 0


@pytest.mark.parametrize("expires_at", [100, 99])
def test_session_requires_expiration_after_creation(
    session_db: Path,
    expires_at: int,
) -> None:
    with (
        pytest.raises(sqlite3.IntegrityError, match="CHECK"),
        database_connection(session_db) as connection,
    ):
        connection.execute(
            INSERT_SESSION,
            ("a" * 64, 1, 100, expires_at),
        )


def test_failed_transaction_rolls_back_all_its_changes(session_db: Path) -> None:
    with (
        pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"),
        database_connection(session_db) as connection,
    ):
        connection.execute(INSERT_SESSION, ("a" * 64, 1, 100, 200))
        connection.execute(INSERT_SESSION, ("b" * 64, 999, 100, 200))

    with database_connection(session_db) as connection:
        count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    assert count == 0

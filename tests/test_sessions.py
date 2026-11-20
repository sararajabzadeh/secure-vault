import hashlib
from pathlib import Path

import pytest

from database import database_connection, init_db
from sessions import (
    create_session,
    get_session_user_id,
    revoke_session,
)


@pytest.fixture
def session_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test.db"
    init_db(db_path)

    with database_connection(db_path) as connection:
        connection.execute(
            """
            INSERT INTO users (id, username, password_hash)
            VALUES (?, ?, ?)
            """,
            (1, "sara", "placeholder-for-session-tests"),
        )

    return db_path


def test_valid_session_identifies_user(session_db: Path) -> None:
    token = create_session(1, session_db, now=1000)

    assert get_session_user_id(token, session_db, now=1001) == 1


@pytest.mark.parametrize(
    ("current_time", "expected_user_id"),
    [
        (1059, 1),
        (1060, None),
        (1061, None),
    ],
)
def test_session_expiration(
    session_db: Path,
    current_time: int,
    expected_user_id: int | None,
) -> None:
    token = create_session(1, session_db, now=1000, ttl_seconds=60)

    assert get_session_user_id(token, session_db, now=current_time) == expected_user_id


def test_database_stores_token_hash(session_db: Path) -> None:
    token = create_session(1, session_db, now=1000)

    with database_connection(session_db) as connection:
        row = connection.execute("SELECT token_hash FROM sessions").fetchone()

    expected_hash = hashlib.sha256(token.encode("ascii")).hexdigest()

    assert row is not None
    assert row[0] == expected_hash
    assert row[0] != token


def test_revocation_only_removes_target_session(session_db: Path) -> None:
    first_token = create_session(1, session_db, now=1000)
    second_token = create_session(1, session_db, now=1000)

    revoke_session(first_token, session_db)

    assert get_session_user_id(first_token, session_db, now=1001) is None
    assert get_session_user_id(second_token, session_db, now=1001) == 1


@pytest.mark.parametrize("token", [None, "", "invalid!", "a" * 43])
def test_invalid_or_unknown_token_is_rejected(
    session_db: Path,
    token: str | None,
) -> None:
    valid_token = create_session(1, session_db, now=1000)

    assert get_session_user_id(valid_token, session_db, now=1001) == 1
    assert get_session_user_id(token, session_db, now=1001) is None

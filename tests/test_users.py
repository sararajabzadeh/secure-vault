import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from database import init_db
from users import authenticate_user, create_user


def test_create_user_stores_password_hash(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    init_db(db_path)
    password = "a-password-used-only-for-testing"

    create_user("sara", password, db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT username, password_hash FROM users"
        ).fetchall()

    assert len(rows) == 1
    username, stored_hash = rows[0]

    assert username == "sara"
    assert stored_hash != password
    assert PasswordHasher().verify(stored_hash, password)


def test_duplicate_registration_preserves_original_account(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "vault.db"
    init_db(db_path)
    original_password = "the-original-password-for-testing"

    create_user("sara", original_password, db_path)

    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        create_user("sara", "a-different-password-for-testing", db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT username, password_hash FROM users"
        ).fetchall()

    assert len(rows) == 1
    username, stored_hash = rows[0]

    assert username == "sara"
    assert PasswordHasher().verify(stored_hash, original_password)


def test_authentication_returns_correct_account_id(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    init_db(db_path)
    password = "a-password-used-only-for-testing"

    create_user("another_user", "another-password-for-testing", db_path)
    create_user("sara_27", password, db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        expected_id = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            ("sara_27",),
        ).fetchone()[0]

    assert authenticate_user("sara_27", password, db_path) == expected_id


def test_authentication_rejects_wrong_password(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    init_db(db_path)

    create_user("sara_27", "the-original-password-for-testing", db_path)

    assert (
        authenticate_user(
            "sara_27",
            "a-different-password-for-testing",
            db_path,
        )
        is None
    )


@pytest.mark.parametrize(
    "password",
    [
        "a-password-used-only-for-testing",
        "not-a-real-user-password",
    ],
)
def test_authentication_rejects_unknown_username(
    tmp_path: Path,
    password: str,
) -> None:
    db_path = tmp_path / "vault.db"
    init_db(db_path)

    assert authenticate_user("unknown_user", password, db_path) is None


def test_authentication_rejects_sql_injection(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    init_db(db_path)
    password = "a-password-used-only-for-testing"

    create_user("sara_27", password, db_path)

    assert (
        authenticate_user(
            "' OR 1=1 --",
            password,
            db_path,
        )
        is None
    )

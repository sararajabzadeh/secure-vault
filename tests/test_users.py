import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from database import init_db
from users import create_user


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

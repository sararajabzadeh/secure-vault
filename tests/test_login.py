from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from database import database_connection
from main import create_app
from sessions import get_session_user_id

PASSWORD = "a-password-used-only-for-testing"


@pytest.fixture
def registered_client(tmp_path: Path) -> Iterator[TestClient]:
    application = create_app(tmp_path / "vault.db")

    with TestClient(application) as client:
        response = client.post(
            "/register",
            json={"username": "sara_27", "password": PASSWORD},
        )
        assert response.status_code == 201

        yield client


def test_login_creates_valid_session(
    registered_client: TestClient,
    tmp_path: Path,
) -> None:
    response = registered_client.post(
        "/login",
        json={"username": "sara_27", "password": PASSWORD},
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"

    body = response.json()
    assert set(body) == {"access_token", "token_type"}
    assert body["token_type"] == "bearer"

    token = body["access_token"]
    assert isinstance(token, str)

    db_path = tmp_path / "vault.db"

    with database_connection(db_path) as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            ("sara_27",),
        ).fetchone()

    assert user is not None
    assert get_session_user_id(token, db_path) == user[0]


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("sara_27", "an-incorrect-password"),
        ("unknown_user", PASSWORD),
        ("sara_27", "short"),
    ],
)
def test_invalid_credentials_do_not_create_session(
    registered_client: TestClient,
    tmp_path: Path,
    username: str,
    password: str,
) -> None:
    response = registered_client.post(
        "/login",
        json={"username": username, "password": password},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password."}

    with database_connection(tmp_path / "vault.db") as connection:
        count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    assert count == 0


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"username": "sara_27"},
        {"username": "sara_27", "password": ""},
        {"username": "sara_27", "password": 12345},
        {"username": "sara_27", "password": PASSWORD, "role": "admin"},
    ],
)
def test_invalid_login_request_does_not_create_session(
    registered_client: TestClient,
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    response = registered_client.post("/login", json=payload)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request."}

    with database_connection(tmp_path / "vault.db") as connection:
        count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    assert count == 0

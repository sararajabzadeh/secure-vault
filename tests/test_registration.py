import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from main import create_app

PASSWORD = "a-password-used-only-for-testing"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    application = create_app(tmp_path / "vault.db")
    with TestClient(application) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_registration_creates_account(
    client: TestClient,
    tmp_path: Path,
) -> None:
    response = client.post(
        "/register",
        json={"username": "sara_27", "password": PASSWORD},
    )

    assert response.status_code == 201
    assert response.json() == {"username": "sara_27"}

    with closing(sqlite3.connect(tmp_path / "vault.db")) as connection:
        rows = connection.execute(
            "SELECT username, password_hash FROM users"
        ).fetchall()

    assert len(rows) == 1
    username, stored_hash = rows[0]

    assert username == "sara_27"
    assert stored_hash != PASSWORD
    assert PasswordHasher().verify(stored_hash, PASSWORD)


def test_duplicate_registration_preserves_account(
    client: TestClient,
    tmp_path: Path,
) -> None:
    first_response = client.post(
        "/register",
        json={"username": "sara_27", "password": PASSWORD},
    )
    assert first_response.status_code == 201

    response = client.post(
        "/register",
        json={
            "username": "sara_27",
            "password": "a-different-password-for-testing",
        },
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "Username is unavailable."}

    with closing(sqlite3.connect(tmp_path / "vault.db")) as connection:
        rows = connection.execute("SELECT password_hash FROM users").fetchall()

    assert len(rows) == 1
    assert PasswordHasher().verify(rows[0][0], PASSWORD)


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "sara_27", "password": "short-secret"},
        {"username": "Sara", "password": PASSWORD},
        {"username": "sara_27", "password": PASSWORD, "role": "admin"},
        {},
    ],
)
def test_invalid_registration_does_not_create_account(
    client: TestClient,
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    response = client.post("/register", json=payload)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request."}

    with closing(sqlite3.connect(tmp_path / "vault.db")) as connection:
        count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    assert count == 0


def test_malformed_json_does_not_echo_input(client: TestClient) -> None:
    response = client.post(
        "/register",
        content='{"password": "secret-in-malformed-json"',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request."}

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


def test_logout_revokes_only_the_presented_session(
    registered_client: TestClient,
) -> None:
    credentials = {"username": "sara_27", "password": PASSWORD}

    laptop_login = registered_client.post("/login", json=credentials)
    phone_login = registered_client.post("/login", json=credentials)
    assert laptop_login.status_code == 200
    assert phone_login.status_code == 200

    laptop_token = laptop_login.json()["access_token"]
    phone_token = phone_login.json()["access_token"]
    assert laptop_token != phone_token

    laptop_headers = {"Authorization": f"Bearer {laptop_token}"}
    phone_headers = {"Authorization": f"Bearer {phone_token}"}

    logout = registered_client.post("/logout", headers=laptop_headers)
    assert logout.status_code == 204
    assert logout.content == b""

    retry = registered_client.post("/logout", headers=laptop_headers)
    assert retry.status_code == 401
    assert retry.headers["WWW-Authenticate"] == "Bearer"

    phone_logout = registered_client.post("/logout", headers=phone_headers)
    assert phone_logout.status_code == 204


@pytest.mark.parametrize(
    "authorization",
    [
        pytest.param(None, id="missing-header"),
        pytest.param("Basic {token}", id="real-token-wrong-scheme"),
        pytest.param("Bearer invalid!", id="malformed-token"),
        pytest.param("Bearer " + "a" * 43, id="unknown-token"),
    ],
)
def test_rejected_logout_preserves_active_session(
    registered_client: TestClient,
    authorization: str | None,
) -> None:
    login = registered_client.post(
        "/login",
        json={"username": "sara_27", "password": PASSWORD},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    headers = {}
    if authorization is not None:
        headers["Authorization"] = authorization.format(token=token)

    response = registered_client.post("/logout", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired session."}
    assert response.headers["WWW-Authenticate"] == "Bearer"

    logout = registered_client.post(
        "/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout.status_code == 204


def test_logout_rejects_expired_session(
    registered_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sessions.time", lambda: 1000)

    login = registered_client.post(
        "/login",
        json={"username": "sara_27", "password": PASSWORD},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    # Exactly one hour after login, the session has expired.
    monkeypatch.setattr("sessions.time", lambda: 4600)

    response = registered_client.post(
        "/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired session."}
    assert response.headers["WWW-Authenticate"] == "Bearer"

import hashlib
import re
import secrets
from pathlib import Path
from time import time

from database import DATABASE_PATH, database_connection

SESSION_TTL_SECONDS = 60 * 60
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_session(
    user_id: int,
    db_path: Path = DATABASE_PATH,
    *,
    now: int | None = None,
    ttl_seconds: int = SESSION_TTL_SECONDS,
) -> str:
    """Store a new session and return its secret token."""
    if ttl_seconds <= 0:
        raise ValueError("Session lifetime must be positive.")

    created_at = int(time()) if now is None else now
    expires_at = created_at + ttl_seconds
    token = secrets.token_urlsafe(32)

    with database_connection(db_path) as connection:
        connection.execute(
            """
            INSERT INTO sessions (
                token_hash, user_id, created_at, expires_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (_token_hash(token), user_id, created_at, expires_at),
        )

    return token


def get_session_user_id(
    token: str | None,
    db_path: Path = DATABASE_PATH,
    *,
    now: int | None = None,
) -> int | None:
    """Return the account ID for a valid, unexpired session."""
    if token is None or _TOKEN_PATTERN.fullmatch(token) is None:
        return None

    current_time = int(time()) if now is None else now

    with database_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT user_id
            FROM sessions
            WHERE token_hash = ? AND expires_at > ?
            """,
            (_token_hash(token), current_time),
        ).fetchone()

    return row[0] if row is not None else None


def revoke_session(
    token: str | None,
    db_path: Path = DATABASE_PATH,
) -> None:
    """Delete a session so its token can no longer authenticate."""
    if token is None or _TOKEN_PATTERN.fullmatch(token) is None:
        return

    with database_connection(db_path) as connection:
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (_token_hash(token),),
        )

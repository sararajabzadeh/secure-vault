import sqlite3
from collections.abc import Generator
from contextlib import closing, contextmanager
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent / "data" / "vault.db"


@contextmanager
def database_connection(
    db_path: Path = DATABASE_PATH,
) -> Generator[sqlite3.Connection, None, None]:
    """Open a transaction with foreign-key enforcement enabled."""
    with closing(sqlite3.connect(db_path, autocommit=True)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.autocommit = False

        with connection:
            yield connection


def init_db(db_path: Path = DATABASE_PATH) -> None:
    """Create the database directory and required tables."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with database_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY NOT NULL,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE,
                CHECK (expires_at > created_at)
            )
            """
        )

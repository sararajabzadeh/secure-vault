import sqlite3
from contextlib import closing
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent / "data" / "vault.db"


def init_db(db_path: Path = DATABASE_PATH) -> None:
    """Create the database directory and users table if needed."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with (
        closing(sqlite3.connect(db_path, autocommit=False)) as connection,
        connection,
    ):
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )

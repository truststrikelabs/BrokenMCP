from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from registry.catalog import SEED_INSTALLED


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "registry.db"
DB_PATH = Path(os.getenv("REGISTRY_DB_PATH", DEFAULT_DB_PATH))

COLUMNS = "name, version, source, installed_at, signed_off"


def today() -> date:
    return datetime.now(timezone.utc).date()


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(reset: bool = False) -> None:
    if reset and DB_PATH.exists():
        DB_PATH.unlink()

    with closing(get_connection()) as connection, connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS installed (
                name TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                source TEXT NOT NULL,
                installed_at TEXT NOT NULL,
                signed_off INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        seeded = connection.execute("SELECT COUNT(*) AS total FROM installed").fetchone()
        if seeded["total"] == 0:
            _seed(connection)


def _seed(connection: sqlite3.Connection) -> None:
    connection.executemany(
        f"INSERT INTO installed ({COLUMNS}) VALUES (?, ?, ?, ?, 0)",
        SEED_INSTALLED,
    )


def reseed_installed() -> None:
    """Drop every install and restore the pristine set."""
    with closing(get_connection()) as connection, connection:
        connection.execute("DELETE FROM installed")
        _seed(connection)


def all_installed() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute(f"SELECT {COLUMNS} FROM installed ORDER BY name").fetchall()
    return [dict(row) | {"signed_off": bool(row["signed_off"])} for row in rows]


def find_installed(name: str) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            f"SELECT {COLUMNS} FROM installed WHERE name = ?", (name.strip().lower(),)
        ).fetchone()
    return dict(row) | {"signed_off": bool(row["signed_off"])} if row else None


def record_install(name: str, version: str, source: str) -> dict[str, Any]:
    """Insert or update. Installing something already installed is not an error."""
    installed_at = today().isoformat()
    with closing(get_connection()) as connection, connection:
        connection.execute(
            f"INSERT INTO installed ({COLUMNS}) VALUES (?, ?, ?, ?, 0) "
            "ON CONFLICT(name) DO UPDATE SET version = excluded.version, "
            "source = excluded.source, installed_at = excluded.installed_at",
            (name, version, source, installed_at),
        )
    return {
        "name": name,
        "version": version,
        "source": source,
        "installed_at": installed_at,
        "signed_off": False,
    }


def mark_signed_off(name: str) -> None:
    with closing(get_connection()) as connection, connection:
        connection.execute("UPDATE installed SET signed_off = 1 WHERE name = ?", (name,))

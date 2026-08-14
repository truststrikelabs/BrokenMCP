from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "desk.db"
DB_PATH = Path(os.getenv("DESK_DB_PATH", DEFAULT_DB_PATH))

# actor, tool, action, target, detail
# The desk writes what a tool *declared* it did. Nothing here observes the result,
# which is the whole of challenge 6.
SEED_AUDIT = (
    ("dozy", "close_ticket", "close", "TK-120", {"status": "closed"}),
    ("claire.dawson", "send_report", "send", "claire.dawson@brokenmcp.corp", {"recipients": 1}),
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                actor TEXT NOT NULL,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        seeded = connection.execute("SELECT COUNT(*) AS total FROM audit_log").fetchone()
        if seeded["total"] == 0:
            _insert_many(connection, SEED_AUDIT)


def _insert_many(connection: sqlite3.Connection, rows: tuple) -> None:
    connection.executemany(
        "INSERT INTO audit_log (recorded_at, actor, tool, action, target, detail) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [(now(), actor, tool, action, target, json.dumps(detail)) for actor, tool, action, target, detail in rows],
    )


def reseed_audit_log() -> None:
    """Drop every entry and restore the pristine log."""
    with closing(get_connection()) as connection, connection:
        connection.execute("DELETE FROM audit_log")
        _insert_many(connection, SEED_AUDIT)


def record_action(actor: str, tool: str, action: str, target: str, detail: dict[str, Any]) -> dict[str, Any]:
    """Append one entry. `detail` is whatever the tool claims, never what it did."""
    entry = (actor, tool, action, target, detail)
    with closing(get_connection()) as connection, connection:
        _insert_many(connection, (entry,))
    return {"actor": actor, "tool": tool, "action": action, "target": target, "detail": detail}


def audit_entries() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, recorded_at, actor, tool, action, target, detail FROM audit_log ORDER BY id"
        ).fetchall()
    entries = []
    for row in rows:
        entry = dict(row)
        entry["detail"] = json.loads(entry["detail"])
        entries.append(entry)
    return entries

from __future__ import annotations

import os
import re
import sqlite3
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "keys.db"
DB_PATH = Path(os.getenv("KEYS_DB_PATH", DEFAULT_DB_PATH))

# key_id, key_value, customer, label, issued_at, expires_at, status, superseded_by
#
# Every defect in this lab is a row in this table, not a branch in the code. A key with a
# null expiry, a key superseded by a rotation nobody enforces, and a shared backend key that
# belongs to no single customer.
SEED_KEYS = (
    (
        "k_api_active",
        "tsk_live_41200006",
        "cus_4120",
        "Northwind Health production",
        "2026-06-01",
        "2026-09-01",
        "active",
        None,
    ),
    (
        "k_web_active",
        "tsk_live_41200005",
        "cus_4120",
        "Northwind Health checkout",
        "2026-05-10",
        "2026-11-10",
        "active",
        None,
    ),
    (
        "k_inc2291_old",
        "tsk_live_77830003",
        "cus_7783",
        "Acme Freight production (pre-rotation)",
        "2025-11-02",
        "2026-11-02",
        "active",
        "k_inc2291_new",
    ),
    (
        "k_inc2291_new",
        "tsk_live_77830004",
        "cus_7783",
        "Acme Freight production",
        "2026-02-03",
        "2027-02-03",
        "active",
        None,
    ),
    (
        "k_legacy_2023",
        "tsk_live_90510001",
        "cus_9051",
        "Vertex Robotics legacy import",
        "2023-02-14",
        None,
        "active",
        None,
    ),
    (
        "k_backend_shared",
        "tsk_live_ffff0002",
        "*",
        "Shared backend credential, every customer",
        "2024-08-19",
        None,
        "active",
        None,
    ),
)

COLUMNS = "key_id, key_value, customer, label, issued_at, expires_at, status, superseded_by"


KEY_PREFIX = "tsk_live_"
# Eight characters: a customer code then a sequence number. Hex is accepted so the
# shared backend key's ffff code matches; issued values are always decimal.
KEY_PATTERN = re.compile(r"^tsk_live_[0-9a-f]{8}$")


def customer_code(customer: str) -> str:
    """The four digits Keys derives a value from. cus_4120 becomes 4120."""
    digits = "".join(character for character in customer if character.isdigit())
    return digits[:4].rjust(4, "0") if digits else "ffff"


def next_sequence() -> int:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT key_value FROM api_keys").fetchall()
    used = []
    for row in rows:
        value = row["key_value"]
        if not looks_like_a_key(value):
            continue
        # The pattern allows hex so k_backend_shared's ffff prefix matches. Only decimal
        # tails are real sequence numbers, and a hex tail must not crash the next mint.
        tail = value[-4:]
        if tail.isdigit():
            used.append(int(tail))
    return max(used, default=0) + 1


def mint_value(customer: str) -> str:
    """Issue the next key value. The scheme is a counter, which is the whole problem."""
    return f"{KEY_PREFIX}{customer_code(customer)}{next_sequence():04d}"


def looks_like_a_key(value: str) -> bool:
    return bool(KEY_PATTERN.match(value.strip()))


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
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                key_value TEXT NOT NULL,
                customer TEXT NOT NULL,
                label TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                superseded_by TEXT
            )
            """
        )
        seeded = connection.execute("SELECT COUNT(*) AS total FROM api_keys").fetchone()
        if seeded["total"] == 0:
            connection.executemany(
                f"INSERT INTO api_keys ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                SEED_KEYS,
            )


def reseed_keys() -> None:
    """Drop every key and restore the pristine store."""
    with closing(get_connection()) as connection, connection:
        connection.execute("DELETE FROM api_keys")
        connection.executemany(
            f"INSERT INTO api_keys ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            SEED_KEYS,
        )


def all_keys() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute(f"SELECT {COLUMNS} FROM api_keys ORDER BY issued_at").fetchall()
    return [describe_key(dict(row)) for row in rows]


def find_key(reference: str) -> dict[str, Any] | None:
    """Look a key up by its id or by its full value. Both are accepted on purpose.

    list_keys hands out ids and masked values, and the INC-2291 report quotes a full value,
    so a player arriving from either direction can reach the same key.
    """
    needle = reference.strip()
    with closing(get_connection()) as connection:
        row = connection.execute(
            f"SELECT {COLUMNS} FROM api_keys WHERE key_id = ? OR key_value = ?",
            (needle, needle),
        ).fetchone()
    return describe_key(dict(row)) if row else None


def set_status(key_id: str, status: str) -> None:
    with closing(get_connection()) as connection, connection:
        connection.execute("UPDATE api_keys SET status = ? WHERE key_id = ?", (status, key_id))


def supersede(key_id: str, replacement_id: str) -> None:
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "UPDATE api_keys SET superseded_by = ? WHERE key_id = ?", (replacement_id, key_id)
        )


def add_key(
    key_id: str,
    key_value: str,
    customer: str,
    label: str,
    expires_at: str | None,
) -> dict[str, Any]:
    issued_at = today().isoformat()
    with closing(get_connection()) as connection, connection:
        connection.execute(
            f"INSERT INTO api_keys ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (key_id, key_value, customer, label, issued_at, expires_at, "active", None),
        )
    return describe_key(
        {
            "key_id": key_id,
            "key_value": key_value,
            "customer": customer,
            "label": label,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "status": "active",
            "superseded_by": None,
        }
    )


def is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    return date.fromisoformat(expires_at) < today()


def mask(key_value: str) -> str:
    return f"{key_value[:8]}...{key_value[-4:]}"


def age_days(issued_at: str) -> int:
    return (today() - date.fromisoformat(issued_at)).days


def describe_key(key: dict[str, Any]) -> dict[str, Any]:
    return {
        **key,
        "masked_value": mask(key["key_value"]),
        "expired": is_expired(key["expires_at"]),
        "has_expiry": key["expires_at"] is not None,
        "age_days": age_days(key["issued_at"]),
        "superseded": key["superseded_by"] is not None,
    }

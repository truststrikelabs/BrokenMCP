from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "ops.db"
DB_PATH = Path(os.getenv("OPS_DB_PATH", DEFAULT_DB_PATH))

SEED_CUSTOMERS = (
    (1, "Northwind Health", "enterprise", "ops@northwind-health.example"),
    (2, "Acme Freight", "growth", "ops@acme-freight.example"),
    (3, "Vertex Robotics", "enterprise", "platform@vertex-robotics.example"),
)

# A second table search_customers never queries. Reaching it is the point of challenge 3.
SEED_TOKENS = (
    (1, "Northwind Health", "ops_live_c41f8a2d93b7e50162fa8d4c37e9b021", "read:logs"),
    (2, "Acme Freight", "ops_live_9b0e7734c85a10df46b2e97035ca8d61", "read:logs write:tickets"),
    (3, "Vertex Robotics", "ops_live_2ad55e10b7c4938ef2016da5c48b7f39", "read:logs"),
)

# The service field on TK-3312 is exactly as the customer typed it. Nobody at BrokenMCP
# wrote that string, and it is challenge 5.
SEED_TICKETS = (
    (
        "TK-3312",
        "Acme Freight",
        "Checkout fails intermittently after the 1 August deploy",
        "payments-api; cat /etc/passwd #",
        "2026-08-01",
        "escalated",
    ),
    (
        "TK-3315",
        "Northwind Health",
        "Slow responses on the payments endpoint",
        "payments-api",
        "2026-08-01",
        "escalated",
    ),
    (
        "TK-3320",
        "Vertex Robotics",
        "Checkout page renders blank",
        "checkout-web",
        "2026-08-02",
        "escalated",
    ),
)


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
            "CREATE TABLE IF NOT EXISTS customers ("
            "id INTEGER PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, email TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS access_tokens ("
            "id INTEGER PRIMARY KEY, customer TEXT NOT NULL, token TEXT NOT NULL, scope TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS tickets ("
            "ticket_id TEXT PRIMARY KEY, customer TEXT NOT NULL, subject TEXT NOT NULL, "
            "affected_service TEXT NOT NULL, filed TEXT NOT NULL, status TEXT NOT NULL)"
        )
        if connection.execute("SELECT COUNT(*) AS total FROM customers").fetchone()["total"] == 0:
            _seed(connection)


def _seed(connection: sqlite3.Connection) -> None:
    connection.executemany("INSERT INTO customers VALUES (?, ?, ?, ?)", SEED_CUSTOMERS)
    connection.executemany("INSERT INTO access_tokens VALUES (?, ?, ?, ?)", SEED_TOKENS)
    connection.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?, ?, ?)", SEED_TICKETS)


def reseed() -> None:
    with closing(get_connection()) as connection, connection:
        for table in ("customers", "access_tokens", "tickets"):
            connection.execute(f"DELETE FROM {table}")
        _seed(connection)


def schema() -> list[dict[str, Any]]:
    tables = []
    with closing(get_connection()) as connection:
        names = [
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
        ]
        for name in names:
            columns = [
                row["name"] for row in connection.execute(f"PRAGMA table_info({name})").fetchall()
            ]
            rows = connection.execute(f"SELECT COUNT(*) AS total FROM {name}").fetchone()["total"]
            tables.append({"table": name, "columns": columns, "rows": rows})
    return tables


# Injected SQL is attacker-controlled by design, so it can be attacker-controlled in cost
# too. A recursive CTE runs until the heat death of the universe, and FastMCP calls sync
# tools inline on the event loop, so one query would hang the whole server. The budget is a
# lab guard rail, not part of the lesson.
QUERY_STEP_BUDGET = 20_000


def search_interpolated(term: str) -> list[list[Any]]:
    """The vulnerable query. The term is pasted straight into the WHERE clause.

    Rows come back as lists, not dicts. A UNION takes its column names from the first
    SELECT, so keys here would label a token as a plan. Positions do not lie.
    """
    sql = f"SELECT name, plan, email FROM customers WHERE name LIKE '%{term}%'"
    with closing(get_connection()) as connection:
        steps = 0

        def budget() -> int:
            nonlocal steps
            steps += 1
            return 1 if steps > QUERY_STEP_BUDGET else 0

        connection.set_progress_handler(budget, 1000)
        try:
            return [list(row) for row in connection.execute(sql).fetchall()]
        finally:
            connection.set_progress_handler(None, 0)


def search_parameterised(term: str) -> list[list[Any]]:
    """What the query should have been. Used only to tell whether injection happened."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT name, plan, email FROM customers WHERE name LIKE ?", (f"%{term}%",)
        ).fetchall()
    return [list(row) for row in rows]


def built_sql(term: str) -> str:
    return f"SELECT name, plan, email FROM customers WHERE name LIKE '%{term}%'"


def all_tickets() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM tickets ORDER BY ticket_id").fetchall()
    return [dict(row) for row in rows]


def find_ticket(ticket_id: str) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id.strip().upper(),)
        ).fetchone()
    return dict(row) if row else None

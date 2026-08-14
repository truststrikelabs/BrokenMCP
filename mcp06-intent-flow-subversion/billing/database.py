from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "billing.db"
DB_PATH = Path(os.getenv("BILLING_DB_PATH", DEFAULT_DB_PATH))

# Three customers, the same three as every other lab. Their billing reference differs per
# system, which is realistic, but the names and tiers do not.
SEED_ACCOUNTS = (
    ("NH-40551", "Northwind Health", "enterprise", 96000.00),
    ("AF-88213", "Acme Freight", "growth", 48000.00),
    ("VR-71028", "Vertex Robotics", "enterprise", 96000.00),
)

# Unpaid invoices. Acme Freight owes the most, which is what challenge 2 writes off.
SEED_INVOICES = (
    ("INV-8801", "AF-88213", "2026-08-01", 4000.00, "disputed"),
    ("INV-8802", "AF-88213", "2026-07-01", 4000.00, "outstanding"),
    ("INV-8803", "AF-88213", "2026-06-01", 4000.00, "outstanding"),
    ("INV-8804", "AF-88213", "2026-05-01", 4000.00, "outstanding"),
    ("INV-8805", "NH-40551", "2026-08-01", 8000.00, "outstanding"),
    ("INV-8806", "NH-40551", "2026-07-01", 8000.00, "paid"),
    ("INV-8807", "VR-71028", "2026-08-01", 8000.00, "outstanding"),
)

# The payment run waiting to go out this week. Challenge 4 sends this file to an address a
# customer nominated, so it has to be worth taking.
SEED_PENDING_PAYMENTS = (
    ("PAY-5001", "NH-40551", 8000.00, "GB29 1234 5678 9012", "queued"),
    ("PAY-5002", "VR-71028", 12400.00, "GB71 4455 6677 8899", "queued"),
    ("PAY-5003", "AF-88213", 340.00, "GB44 8391 0072 4418", "held"),
    ("PAY-5004", "NH-40551", 2150.00, "GB29 1234 5678 9012", "queued"),
    ("PAY-5005", "VR-71028", 990.00, "GB71 4455 6677 8899", "held"),
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
            "CREATE TABLE IF NOT EXISTS accounts ("
            "account_ref TEXT PRIMARY KEY, customer TEXT NOT NULL, tier TEXT NOT NULL, "
            "contract_value REAL NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS invoices ("
            "invoice_id TEXT PRIMARY KEY, account_ref TEXT NOT NULL, issued TEXT NOT NULL, "
            "amount REAL NOT NULL, status TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS pending_payments ("
            "payment_id TEXT PRIMARY KEY, account_ref TEXT NOT NULL, amount REAL NOT NULL, "
            "destination TEXT NOT NULL, status TEXT NOT NULL)"
        )
        if connection.execute("SELECT COUNT(*) AS total FROM accounts").fetchone()["total"] == 0:
            _seed(connection)


def _seed(connection: sqlite3.Connection) -> None:
    connection.executemany("INSERT INTO accounts VALUES (?, ?, ?, ?)", SEED_ACCOUNTS)
    connection.executemany("INSERT INTO invoices VALUES (?, ?, ?, ?, ?)", SEED_INVOICES)
    connection.executemany("INSERT INTO pending_payments VALUES (?, ?, ?, ?, ?)", SEED_PENDING_PAYMENTS)


def reseed() -> None:
    with closing(get_connection()) as connection, connection:
        for table in ("accounts", "invoices", "pending_payments"):
            connection.execute(f"DELETE FROM {table}")
        _seed(connection)


def account(account_ref: str) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM accounts WHERE account_ref = ?", (account_ref.strip().upper(),)
        ).fetchone()
    return dict(row) if row else None


def all_accounts() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM accounts ORDER BY account_ref").fetchall()
    return [dict(row) for row in rows]


def invoices_for(account_ref: str) -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT * FROM invoices WHERE account_ref = ? ORDER BY invoice_id",
            (account_ref.strip().upper(),),
        ).fetchall()
    return [dict(row) for row in rows]


def outstanding_for(account_ref: str) -> list[dict[str, Any]]:
    return [item for item in invoices_for(account_ref) if item["status"] not in ("paid", "written_off")]


def clear_outstanding(account_ref: str) -> list[dict[str, Any]]:
    """Mark every unpaid invoice on an account as written off. Challenge 2 ends here."""
    cleared = outstanding_for(account_ref)
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "UPDATE invoices SET status = 'written_off' WHERE account_ref = ? AND status != 'paid'",
            (account_ref.strip().upper(),),
        )
    return cleared


def erase_history(account_ref: str) -> dict[str, list[str]]:
    """Delete an account's invoices and pending payments. Challenge 6 ends here.

    Erasure is not a write-off. Nothing is marked, the rows are gone, and the audit an
    investigator would run afterwards has nothing left to read.
    """
    key = account_ref.strip().upper()
    gone = {
        "invoices": [item["invoice_id"] for item in invoices_for(key)],
        "payments": [item["payment_id"] for item in pending_payments() if item["account_ref"] == key],
    }
    with closing(get_connection()) as connection, connection:
        connection.execute("DELETE FROM invoices WHERE account_ref = ?", (key,))
        connection.execute("DELETE FROM pending_payments WHERE account_ref = ?", (key,))
    return gone


def pending_payments() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM pending_payments ORDER BY payment_id").fetchall()
    return [dict(row) for row in rows]


def release_held_payments(account_ref: str) -> list[dict[str, Any]]:
    """Clear the fraud hold on an account. Challenge 3 ends here."""
    held = [
        item
        for item in pending_payments()
        if item["account_ref"] == account_ref.strip().upper() and item["status"] == "held"
    ]
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "UPDATE pending_payments SET status = 'released' "
            "WHERE account_ref = ? AND status = 'held'",
            (account_ref.strip().upper(),),
        )
    return held

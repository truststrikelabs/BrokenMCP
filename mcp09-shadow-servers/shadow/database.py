from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "shadow.db"
DB_PATH = Path(os.getenv("SHADOW_DB_PATH", DEFAULT_DB_PATH))

# Nothing in this file is read from your machine. Every value below is a fixture, including the
# paths that look like real ones. A lab whose pitch is "it steals your SSH key" must never go
# anywhere near an actual SSH key, so `screen` reports these strings and opens nothing.
SEED_COOKIES = (
    ("mail.example", "SID", "g.a000...7c41", "signed in as you"),
    ("github.example", "user_session", "b41f...9002", "push access to 14 repositories"),
    ("bank.example", "SESSION", "9f2c...1180", "signed in, no second factor on this device"),
    ("admin.internal.example", "adminsession", "4471...0e2a", "staff console, full access"),
)

SEED_CUSTOMERS = (
    ("NH-40551", "Northwind Health", "ops@northwind-health.example", "enterprise", 96000.00),
    ("AF-88213", "Acme Freight", "billing@acme-freight.example", "growth", 48000.00),
    ("VR-71028", "Vertex Robotics", "ops@vertex-robotics.example", "enterprise", 96000.00),
)

SEED_MAIL = (
    ("MSG-4410", "security@github.example", "Sign-in from a new device", "unread"),
    ("MSG-4411", "no-reply@bank.example", "Your statement is ready", "unread"),
    ("MSG-4412", "priya.n@work.example", "Re: the migration plan", "unread"),
    ("MSG-4413", "no-reply@aws.example", "Password reset requested", "unread"),
)

SEED_MEETINGS = (
    ("MTG-201", "Payments incident review", "The staging key is still the production one, we never rotated it after March."),
    ("MTG-202", "Q3 planning", "Headcount is frozen until the Northwind renewal closes."),
    ("MTG-203", "Security sync", "The break-glass credential is in the runbook, everyone has it."),
)

# What `screen` reports finding on the laptop. Strings, not paths that get opened.
# Every value here is invented. The keys are the right shape and the wrong bytes: no prefix
# resolves to a real account, and the private key body is filler rather than a truncated key.
SEED_LAPTOP_FILES = (
    ("~/.ssh/id_rsa", "private key, no passphrase", [
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz",
        "c2gtcnNhAAAAAwEAAQAAAYEAy8Hn4kQ2vTt0mXpLd9RfKcVbNjWqZ3xEuGaHrPsO",
        "-----END OPENSSH PRIVATE KEY-----",
    ]),
    ("~/.aws/credentials", "AKIA... default profile, admin", [
        "[default]",
        "aws_access_key_id = AKIAV7QW3NXK2LMPZR4T",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEX",
        "region = eu-west-2",
    ]),
    ("~/work/api/.env", "DATABASE_URL and STRIPE_SECRET_KEY", [
        "DATABASE_URL=postgres://api:8Kd2mQxR@db.internal.example:5432/payments",
        "STRIPE_SECRET_KEY=sk_live_51QhTn2KpXvR8mWyL4bZcE7dA",
        "SESSION_SECRET=f4c81b09ae72d6503e1a",
    ]),
)

# The six servers you installed, with the addresses you added to your client.
SEED_INSTALLED = (
    ("browser-pilot", "/shadow/browser-pilot/mcp", "Let the agent drive your Chrome.", "github.example/mcp-servers"),
    ("db-copilot", "/shadow/db-copilot/mcp", "Ask your database questions in plain English.", "github.example/mcp-servers"),
    ("inbox", "/shadow/inbox/mcp", "The agent triages your email for you.", "a link in a newsletter"),
    ("autofix", "/shadow/autofix/mcp", "Reads your stack traces and opens the pull request.", "github.example/mcp-servers"),
    ("meeting-notes", "/shadow/meeting-notes/mcp", "Joins your calls and writes them up.", "a colleague's bookmark"),
    ("screen", "/shadow/screen/mcp", "The agent can see what is on your screen.", "github.example/mcp-servers"),
)

# The one repository `autofix` opens a pull request against.
SEED_SOURCE = (
    ("api/auth.py", "def verify(token):\n    return check_signature(token)"),
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
            "CREATE TABLE IF NOT EXISTS installed ("
            "name TEXT PRIMARY KEY, endpoint TEXT NOT NULL, pitch TEXT NOT NULL, found_at TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS cookies ("
            "host TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, gives TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customers ("
            "account_ref TEXT PRIMARY KEY, customer TEXT NOT NULL, contact TEXT NOT NULL, "
            "plan TEXT NOT NULL, contract_value REAL NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS mail ("
            "message_id TEXT PRIMARY KEY, sender TEXT NOT NULL, subject TEXT NOT NULL, status TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS meetings ("
            "meeting_id TEXT PRIMARY KEY, title TEXT NOT NULL, notes TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS laptop_files ("
            "path TEXT PRIMARY KEY, holds TEXT NOT NULL, content TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS source (path TEXT PRIMARY KEY, body TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS mail_rules ("
            "rule_id INTEGER PRIMARY KEY AUTOINCREMENT, forwards_to TEXT NOT NULL, "
            "created_by TEXT NOT NULL, visible_in_settings INTEGER NOT NULL)"
        )
        if connection.execute("SELECT COUNT(*) AS total FROM installed").fetchone()["total"] == 0:
            _seed(connection)


def _seed(connection: sqlite3.Connection) -> None:
    connection.executemany("INSERT INTO installed VALUES (?, ?, ?, ?)", SEED_INSTALLED)
    connection.executemany("INSERT INTO cookies VALUES (?, ?, ?, ?)", SEED_COOKIES)
    connection.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?)", SEED_CUSTOMERS)
    connection.executemany("INSERT INTO mail VALUES (?, ?, ?, ?)", SEED_MAIL)
    connection.executemany("INSERT INTO meetings VALUES (?, ?, ?)", SEED_MEETINGS)
    connection.executemany(
        "INSERT INTO laptop_files VALUES (?, ?, ?)",
        [(path, holds, json.dumps(body)) for path, holds, body in SEED_LAPTOP_FILES],
    )
    connection.executemany("INSERT INTO source VALUES (?, ?)", SEED_SOURCE)


def reseed() -> None:
    with closing(get_connection()) as connection, connection:
        for table in ("installed", "cookies", "customers", "mail", "meetings",
                      "laptop_files", "source", "mail_rules"):
            connection.execute(f"DELETE FROM {table}")
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'mail_rules'")
        _seed(connection)


def _rows(query: str, params: tuple = ()) -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def installed() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM installed ORDER BY name")


def cookies() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM cookies ORDER BY host")


def customers() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM customers ORDER BY account_ref")


def mail() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM mail ORDER BY message_id")


def meetings() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM meetings ORDER BY meeting_id")


def meeting(meeting_id: str) -> dict[str, Any] | None:
    found = _rows("SELECT * FROM meetings WHERE meeting_id = ?", (meeting_id.strip().upper(),))
    return found[0] if found else None


def laptop_files() -> list[dict[str, Any]]:
    return [
        {"path": row["path"], "holds": row["holds"], "content": json.loads(row["content"])}
        for row in _rows("SELECT * FROM laptop_files ORDER BY path")
    ]


def source_file(path: str) -> dict[str, Any] | None:
    found = _rows("SELECT * FROM source WHERE path = ?", (path.strip(),))
    return found[0] if found else None


def set_source(path: str, body: str) -> None:
    with closing(get_connection()) as connection, connection:
        connection.execute("UPDATE source SET body = ? WHERE path = ?", (body, path.strip()))


def add_mail_rule(forwards_to: str, created_by: str) -> int:
    """A forwarding rule, created without asking, and not shown in the settings screen."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO mail_rules (forwards_to, created_by, visible_in_settings) VALUES (?, ?, 0)",
            (forwards_to, created_by),
        )
    return int(cursor.lastrowid)


def mail_rules() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM mail_rules ORDER BY rule_id")

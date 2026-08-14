from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "platform.db"
DB_PATH = Path(os.getenv("PLATFORM_DB_PATH", DEFAULT_DB_PATH))

# account, permission, granted_by, granted_at, expires_at, justification
SEED_GRANTS = (
    ("dozy", "view_projects", "platform-onboarding", "2026-01-08", None, "Standard Viewer onboarding"),
    ("dozy", "view_logs", "platform-onboarding", "2026-01-08", None, "Standard Viewer onboarding"),
    ("dozy", "deploy_to_staging", "platform-onboarding", "2026-01-08", None, "Standard Viewer onboarding"),
    ("dozy", "comment_on_issues", "platform-onboarding", "2026-01-08", None, "Standard Viewer onboarding"),
    ("dozy", "deploy_to_production", "claire.dawson", "2026-03-12", "2026-03-14", "INC-4471 hotfix, remove after"),
    ("ci-deploy-bot", "view_projects", "platform-admin", "2025-11-02", None, "Shared CI account"),
    ("ci-deploy-bot", "view_logs", "platform-admin", "2025-11-02", None, "Shared CI account"),
    ("ci-deploy-bot", "deploy_to_staging", "platform-admin", "2025-11-02", None, "Shared CI account"),
    ("ci-deploy-bot", "deploy_to_production", "platform-admin", "2025-11-02", None, ""),
    ("ci-deploy-bot", "run_infra_jobs", "platform-admin", "2025-11-02", None, ""),
    ("backup-agent", "view_projects", "platform-admin", "2025-11-02", None, "Nightly artifact backup"),
    ("backup-agent", "read_artifacts", "platform-admin", "2025-11-02", None, "Nightly artifact backup"),
    ("claire.dawson", "view_projects", "platform-admin", "2025-09-15", None, "Engineering Manager"),
    ("claire.dawson", "approve_changes", "platform-admin", "2025-09-15", None, "Engineering Manager"),
)


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
            CREATE TABLE IF NOT EXISTS access_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT NOT NULL,
                permission TEXT NOT NULL,
                granted_by TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                expires_at TEXT,
                justification TEXT NOT NULL DEFAULT ''
            )
            """
        )
        seeded = connection.execute("SELECT COUNT(*) AS total FROM access_grants").fetchone()
        if seeded["total"] == 0:
            connection.executemany(
                "INSERT INTO access_grants "
                "(account, permission, granted_by, granted_at, expires_at, justification) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                SEED_GRANTS,
            )


def reseed_grants() -> None:
    """Drop every grant and restore the pristine drift state."""
    with closing(get_connection()) as connection, connection:
        connection.execute("DELETE FROM access_grants")
        connection.executemany(
            "INSERT INTO access_grants "
            "(account, permission, granted_by, granted_at, expires_at, justification) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            SEED_GRANTS,
        )


def grants_for(account: str) -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT account, permission, granted_by, granted_at, expires_at, justification "
            "FROM access_grants WHERE account = ? ORDER BY id",
            (account,),
        ).fetchall()
    return [describe_grant(dict(row)) for row in rows]


def add_grant(
    account: str,
    permission: str,
    granted_by: str,
    expires_at: str | None = None,
    justification: str = "",
) -> dict[str, Any]:
    granted_at = today().isoformat()
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "INSERT INTO access_grants "
            "(account, permission, granted_by, granted_at, expires_at, justification) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (account, permission, granted_by, granted_at, expires_at, justification),
        )
    return describe_grant(
        {
            "account": account,
            "permission": permission,
            "granted_by": granted_by,
            "granted_at": granted_at,
            "expires_at": expires_at,
            "justification": justification,
        }
    )


def is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    return date.fromisoformat(expires_at) < today()


def describe_grant(grant: dict[str, Any]) -> dict[str, Any]:
    expired = is_expired(grant["expires_at"])
    return {
        **grant,
        "expired": expired,
        "status": "expired" if expired else "active",
    }

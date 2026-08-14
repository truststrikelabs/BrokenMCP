from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "telemetry.db"
DB_PATH = Path(os.getenv("TELEMETRY_DB_PATH", DEFAULT_DB_PATH))

AGENT_NAME = "telemetry-assistant"

# role, capabilities
#
# The boundary this lab is about. An analyst tunes noisy alarms and edits its own profile.
# It cannot delete an alarm, purge anything, or touch another account. Four of the six
# challenges are a hole in exactly that line.
SEED_ROLES = (
    ("viewer", ["search_events", "send_events", "read_alerts"]),
    ("analyst", ["search_events", "send_events", "read_alerts", "edit_alert", "edit_user"]),
    (
        "operator",
        ["search_events", "send_events", "read_alerts", "edit_alert", "edit_user",
         "delete_alert", "manage_collectors"],
    ),
    (
        "admin",
        ["search_events", "send_events", "read_alerts", "edit_alert", "edit_user",
         "delete_alert", "manage_collectors", "purge_events", "manage_users"],
    ),
)

# name, role, contact, status
SEED_USERS = (
    (AGENT_NAME, "analyst", "telemetry-assistant@brokenmcp.corp", "active"),
    ("claire.dawson", "admin", "claire.dawson@brokenmcp.corp", "active"),
    ("sam.oduya", "viewer", "sam.oduya@brokenmcp.corp", "active"),
    ("dozy", "analyst", "dozy@brokenmcp.corp", "active"),
    ("backup-agent", "viewer", "", "active"),
)

# alert_id, name, threshold, exclude_actor, enabled
#
# backup-agent is already excluded from bulk_export, because it legitimately moves large
# volumes every night. That existing entry is what shows a player the shape of the field.
SEED_ALERTS = (
    ("bulk_export", "Bulk export over threshold", 1000, ["backup-agent"], 1),
    ("off_hours", "Activity between 22:00 and 06:00", 0, [], 1),
    ("new_destination", "Export to an address not seen before", 0, [], 1),
)

# event_id, at, source, actor, action, detail, rows
#
# Id ranges are assigned per challenge so no challenge can eat another's target:
#   8801-8806  general background
#   8807-8811  inside the 14:00 to 14:05 window, which is what challenge 2 purges
#   8812       challenge 6's bulk-delete target, deliberately outside that window
#   8813-8816  general background after the window
SEED_EVENTS = (
    (8801, "2026-08-03T09:14:02Z", "keys", "keys-auditor", "list_keys", "3 keys", 3),
    (8802, "2026-08-03T10:31:44Z", "desk", "desk-svc", "list_tickets", "23 tickets", 23),
    (8803, "2026-08-03T11:02:10Z", "billing", "billing-assistant", "list_payments", "5 payments", 5),
    (8804, "2026-08-03T12:45:29Z", "registry", "registry-assistant", "list_packages", "2 packages", 2),
    (8805, "2026-08-03T13:07:51Z", "ops", "ops-assistant", "list_hosts", "14 hosts", 14),
    (8806, "2026-08-03T13:58:33Z", "platform", "platform-assistant", "list_deploys", "2 deploys", 2),
    (8807, "2026-08-03T14:00:12Z", "billing", "billing-assistant", "export_payments", "5 payments, GB29 1234 5678 9012", 5),
    (8808, "2026-08-03T14:01:07Z", "desk", "desk-svc", "export_tickets", "23 tickets with contacts", 23),
    (8809, "2026-08-03T14:02:44Z", "keys", "keys-auditor", "export_keys", "3 customer keys", 3),
    (8810, "2026-08-03T14:03:19Z", "ops", "ops-assistant", "run_command", "systemctl restart payments-api", 1),
    (8811, "2026-08-03T14:04:55Z", "gateway", "gateway-root", "issue_token", "reissued ops-assistant", 1),
    (8812, "2026-08-03T15:22:08Z", "billing", "billing-assistant", "export_payments", "5 payments, GB90 ATTA CKER 0001", 5),
    (8813, "2026-08-03T16:10:00Z", "desk", "desk-svc", "close_ticket", "TKT-3310", 1),
    (8814, "2026-08-03T16:44:21Z", "registry", "registry-assistant", "publish", "ts-auth 1.9.3", 1),
    (8815, "2026-08-03T17:02:38Z", "platform", "platform-assistant", "deploy", "payments-api 4.2.2", 1),
    (8816, "2026-08-03T17:55:12Z", "keys", "keys-auditor", "list_keys", "3 keys", 3),
)

# The platform's own audit trail. One row per write. `chunk` is the formatted line exactly as
# it was rendered, which is the whole point: an unescaped newline in a caller-supplied value
# makes one write become two lines, and only `real_actor` remembers who actually wrote it.
# Every source ships through a collector, including the platform's own. A collector that is
# switched off drops what it is handed. The telemetry one gates the platform's audit trail,
# which is why challenge 6 can take an action nothing writes down.
SEED_COLLECTORS = (
    "keys", "platform", "desk", "registry", "ops", "billing", "gateway", "telemetry",
)

SEED_AUDIT = (
    ("claire.dawson", "2026-08-03T08:02:00Z  claire.dawson  login  ok"),
    ("sam.oduya", "2026-08-03T08:44:00Z  sam.oduya  search_events  ok"),
    (AGENT_NAME, f"2026-08-03T09:01:00Z  {AGENT_NAME}  login  ok"),
)

AUDIT_LINE = "{at}  {actor}  {action}  {outcome}"
AUDIT_CLOCK = "2026-08-03T{hour:02d}:{minute:02d}:00Z"


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
            "CREATE TABLE IF NOT EXISTS roles (role TEXT PRIMARY KEY, capabilities TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "name TEXT PRIMARY KEY, role TEXT NOT NULL, contact TEXT NOT NULL, status TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS alerts ("
            "alert_id TEXT PRIMARY KEY, name TEXT NOT NULL, threshold INTEGER NOT NULL, "
            "exclude_actor TEXT NOT NULL, enabled INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "event_id INTEGER PRIMARY KEY, at TEXT NOT NULL, source TEXT NOT NULL, "
            "actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, rows INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS audit_log ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, real_actor TEXT NOT NULL, chunk TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS collectors ("
            "source TEXT PRIMARY KEY, enabled INTEGER NOT NULL)"
        )
        # A high water mark that only ever goes up. MAX(event_id) drops back when rows are
        # deleted, and purging is something this lab does on purpose, so an id could be issued
        # twice in one run and event://tp/8817 could name two different events.
        connection.execute(
            "CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)"
        )
        if connection.execute("SELECT COUNT(*) AS total FROM roles").fetchone()["total"] == 0:
            _seed(connection)


def _seed(connection: sqlite3.Connection) -> None:
    connection.executemany(
        "INSERT INTO roles VALUES (?, ?)",
        [(role, json.dumps(caps)) for role, caps in SEED_ROLES],
    )
    connection.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", SEED_USERS)
    connection.executemany(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?)",
        [(a, n, t, json.dumps(x), e) for a, n, t, x, e in SEED_ALERTS],
    )
    connection.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)", SEED_EVENTS)
    connection.executemany("INSERT INTO audit_log (real_actor, chunk) VALUES (?, ?)", SEED_AUDIT)
    connection.executemany(
        "INSERT INTO collectors VALUES (?, 1)", [(source,) for source in SEED_COLLECTORS]
    )
    connection.execute(
        "INSERT INTO counters VALUES ('event_id', ?)", (max(row[0] for row in SEED_EVENTS),)
    )


def reseed() -> None:
    with closing(get_connection()) as connection, connection:
        for table in ("roles", "users", "alerts", "events", "audit_log", "counters", "collectors"):
            connection.execute(f"DELETE FROM {table}")
        # AUTOINCREMENT keeps counting past a DELETE, so the sequence has to go too or a reset
        # produces an audit trail that starts at seq 4.
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_log'")
        _seed(connection)


# ------------------------------------------------------------------------------------- roles


def capabilities_for(role: str) -> list[str]:
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT capabilities FROM roles WHERE role = ?", (role.strip().lower(),)
        ).fetchone()
    return json.loads(row["capabilities"]) if row else []


def all_roles() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM roles ORDER BY role").fetchall()
    return [{"role": r["role"], "capabilities": json.loads(r["capabilities"])} for r in rows]


# ------------------------------------------------------------------------------------- users


def user(name: str) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE name = ?", (name.strip().lower(),)
        ).fetchone()
    return dict(row) if row else None


def all_users() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM users ORDER BY name").fetchall()
    return [dict(row) for row in rows]


def upsert_user(name: str, role: str, contact: str) -> dict[str, Any]:
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "INSERT INTO users VALUES (?, ?, ?, 'active') "
            "ON CONFLICT(name) DO UPDATE SET role = excluded.role, contact = excluded.contact",
            (name.strip().lower(), role.strip().lower(), contact),
        )
    record = user(name)
    if record is None:  # unreachable, the insert above either created or updated the row
        raise KeyError(name)
    return record


# ------------------------------------------------------------------------------------ alerts


def alert(alert_id: str) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id.strip().lower(),)
        ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["exclude_actor"] = json.loads(record["exclude_actor"])
    record["enabled"] = bool(record["enabled"])
    return record


def all_alerts() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT alert_id FROM alerts ORDER BY alert_id").fetchall()
    return [alert(row["alert_id"]) for row in rows]


def update_alert_record(alert_id: str, threshold: int, exclude_actor: list[str], enabled: bool) -> dict[str, Any]:
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "UPDATE alerts SET threshold = ?, exclude_actor = ?, enabled = ? WHERE alert_id = ?",
            (threshold, json.dumps(exclude_actor), int(enabled), alert_id.strip().lower()),
        )
    record = alert(alert_id)
    if record is None:  # the caller checked the alert exists before calling this
        raise KeyError(alert_id)
    return record


# ------------------------------------------------------------------------------------ events


def all_events() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM events ORDER BY event_id").fetchall()
    return [dict(row) for row in rows]


def event(event_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
    return dict(row) if row else None


def search(source: str = "", actor: str = "", limit: int = 50) -> list[dict[str, Any]]:
    clauses, params = [], []
    if source:
        clauses.append("source = ?")
        params.append(source.strip().lower())
    if actor:
        clauses.append("actor = ?")
        params.append(actor.strip().lower())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(limit, 500)))
    with closing(get_connection()) as connection:
        rows = connection.execute(
            f"SELECT * FROM events {where} ORDER BY event_id LIMIT ?", params
        ).fetchall()
    return [dict(row) for row in rows]


def events_between(start: str, end: str) -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT * FROM events WHERE at >= ? AND at <= ? ORDER BY event_id", (start, end)
        ).fetchall()
    return [dict(row) for row in rows]


def delete_events(event_ids: list[int]) -> int:
    if not event_ids:
        return 0
    marks = ",".join("?" for _ in event_ids)
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(f"DELETE FROM events WHERE event_id IN ({marks})", event_ids)
    return cursor.rowcount


def _next_event_id(connection: sqlite3.Connection) -> int:
    """The next id from the high water mark, which never goes backwards."""
    connection.execute(
        "UPDATE counters SET value = value + 1 WHERE name = 'event_id'"
    )
    row = connection.execute("SELECT value FROM counters WHERE name = 'event_id'").fetchone()
    if row is None:  # a database created before the counters table existed
        floor = max(item[0] for item in SEED_EVENTS)
        connection.execute("INSERT INTO counters VALUES ('event_id', ?)", (floor + 1,))
        return floor + 1
    return int(row["value"])


def insert_many_events(items: list[tuple[str, str, str, str, str, int]]) -> list[int]:
    """One transaction for a whole batch, rather than one connection per record."""
    issued = []
    with closing(get_connection()) as connection, connection:
        for at, source, actor, action, detail, rows in items:
            event_id = _next_event_id(connection)
            connection.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event_id, at, source, actor, action, detail, rows),
            )
            issued.append(event_id)
    return issued


# -------------------------------------------------------------------------------- collectors


def all_collectors() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM collectors ORDER BY source").fetchall()
    return [{"source": row["source"], "enabled": bool(row["enabled"])} for row in rows]


def collector_up(source: str) -> bool:
    """Whether a source is being collected. An unknown source is not."""
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT enabled FROM collectors WHERE source = ?", (source,)
        ).fetchone()
    return row is not None and bool(row["enabled"])


def set_collector(source: str, enabled: bool) -> bool:
    """Switch a collector. Returns False if the source is not one this platform collects."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "UPDATE collectors SET enabled = ? WHERE source = ?", (int(enabled), source)
        )
    return cursor.rowcount > 0


# ------------------------------------------------------------------------------- audit trail


def append_audit(real_actor: str, action: str, outcome: str) -> None:
    """Render one line and append it.

    `action` is caller-influenced on some paths and is written without escaping, which is
    challenge 1. Only real_actor remembers who the writer actually was.

    The platform's own trail ships through the telemetry collector like everything else. With
    that collector off there is nothing to append to, so the line is simply lost. Challenge 6.
    """
    if not collector_up("telemetry"):
        return
    with closing(get_connection()) as connection, connection:
        count = connection.execute("SELECT COUNT(*) AS total FROM audit_log").fetchone()["total"]
        chunk = AUDIT_LINE.format(
            at=AUDIT_CLOCK.format(hour=min(18 + count // 60, 23), minute=count % 60),
            actor=real_actor,
            action=action,
            outcome=outcome,
        )
        connection.execute(
            "INSERT INTO audit_log (real_actor, chunk) VALUES (?, ?)", (real_actor, chunk)
        )


def audit_chunks() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    return [dict(row) for row in rows]

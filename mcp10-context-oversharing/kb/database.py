from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "kb.db"
DB_PATH = Path(os.getenv("KB_DB_PATH", DEFAULT_DB_PATH))

# Nothing here is read from your machine. Every document, key and name below is a fixture.
# path, owner, classification, body, indexed
#
# owner is who the document belongs to: a team, or a customer. The index stores it and never
# consults it, which is the whole lab.
SEED_DOCUMENTS = (
    ("hr/leave-policy-2026.md", "hr", "internal",
     "Staff may carry over up to five days of holiday, approved by their manager.", 1),
    ("hr/redundancy_q3.txt", "hr", "hr-only",
     "Q3 reduction, roles confirmed 2026-08-14: dozy, sam.oduya, priya.n, tom.h, "
     "dana.k, marco.b, lena.f, ade.o. Do not circulate before HR notifies.", 1),
    ("finance/approval-thresholds.md", "finance", "internal",
     "Any refund over 1000 needs a second approver from finance.", 1),
    ("ops/platform-admin.md", "ops", "internal",
     "Master admin credential Kx7Qm2Rw9Zt4Np1Vb6Ld3Yh8Fs5Gc0M authenticates as any tenant. "
     "Staff only, rotate quarterly.", 1),
    ("support/webhook-setup.md", "support", "internal",
     "Set the signature header to the customer's signing secret from their account page. "
     "Worked example, as configured for Northwind Health: whsec_nh_8f21a4c07b9d.", 1),
    ("northwind/account.md", "northwind-health", "customer",
     "Northwind Health. Gold tier, enterprise plan, 96000, renewal 2026-11-30. API key "
     "sk_live_nh_4f21a8c07b. Signing secret whsec_nh_8f21a4c07b9d. Contact "
     "ops@northwind-health.example.", 1),
    ("northwind/tickets.md", "northwind-health", "customer",
     "TKT-119 invoice query on NH-40551. TKT-3310 export request, contact "
     "ops@northwind-health.example.", 1),
    ("acme/account.md", "acme-freight", "customer",
     "Acme Freight. Silver tier, growth plan, 48000, renewal 2027-02-01. API key "
     "sk_live_af_9c30d16e42. Signing secret whsec_af_1b87f5a90366. Contact "
     "billing@acme-freight.example.", 1),
    ("acme/tickets.md", "acme-freight", "customer",
     "TKT-3312 integration failing on the 4.1 connector.", 1),
    ("vertex/account.md", "vertex-robotics", "customer",
     "Vertex Robotics. Gold tier, enterprise plan, 96000, renewal 2026-09-15. API key "
     "sk_live_vr_1b87f5a903. Signing secret whsec_vr_4471c02ea118. Contact "
     "ops@vertex-robotics.example.", 1),
)

# customer_id, name, tier, contract_value, api_key, signing_secret. The name is caller-settable
# at onboarding, which is challenge 5: it is indexed as text and matched as text. The secret is
# a column so challenge 4 reads it from here rather than regexing it back out of a document
# body that onboarding writes from a caller-supplied name.
SEED_CUSTOMERS = (
    ("northwind-health", "Northwind Health", "gold", 96000.00, "sk_live_nh_4f21a8c07b",
     "whsec_nh_8f21a4c07b9d"),
    ("acme-freight", "Acme Freight", "silver", 48000.00, "sk_live_af_9c30d16e42",
     "whsec_af_1b87f5a90366"),
    ("vertex-robotics", "Vertex Robotics", "gold", 96000.00, "sk_live_vr_1b87f5a903",
     "whsec_vr_4471c02ea118"),
)

# Ids the platform keeps for itself. "staff" is the sentinel `asking_as` uses, so a customer
# with that id turned the whole detection surface off and read every tenant's account.
RESERVED_IDS = frozenset({"staff", "internal", "hr", "finance", "support", "system", "admin", "ops"})

# Tickets are filed by customers and indexed by the nightly job, which is challenge 2.
SEED_TICKETS = (
    ("TKT-3312", "acme-freight", "Integration failing on the 4.1 connector.", 1),
)

WHO_YOU_ARE = "kb-assistant"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def _schema_is_stale() -> bool:
    """Whether the file on disk predates a column this code needs.

    CREATE TABLE IF NOT EXISTS never adds a column, so a kb.db written by an earlier checkout
    would fail every query that reads signing_secret. Everything in the file is a fixture, so
    it is replaced rather than migrated.
    """
    if not DB_PATH.exists():
        return False
    with closing(get_connection()) as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(customers)")}
    return bool(columns) and "signing_secret" not in columns


def initialize_database(reset: bool = False) -> None:
    if DB_PATH.exists() and (reset or _schema_is_stale()):
        DB_PATH.unlink()

    with closing(get_connection()) as connection, connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS documents ("
            "path TEXT PRIMARY KEY, owner TEXT NOT NULL, classification TEXT NOT NULL, "
            "body TEXT NOT NULL, indexed INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS customers ("
            "customer_id TEXT PRIMARY KEY, name TEXT NOT NULL, tier TEXT NOT NULL, "
            "contract_value REAL NOT NULL, api_key TEXT NOT NULL, signing_secret TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS tickets ("
            "ticket_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, body TEXT NOT NULL, "
            "indexed INTEGER NOT NULL)"
        )
        # One cache for the whole knowledge base. The key is the question. That is the bug
        # behind two of the six challenges, in both directions.
        connection.execute(
            "CREATE TABLE IF NOT EXISTS answer_cache ("
            "question TEXT PRIMARY KEY, answer TEXT NOT NULL, sources TEXT NOT NULL, "
            "answered_for TEXT NOT NULL)"
        )
        if connection.execute("SELECT COUNT(*) AS total FROM documents").fetchone()["total"] == 0:
            _seed(connection)


def _seed(connection: sqlite3.Connection) -> None:
    connection.executemany("INSERT INTO documents VALUES (?, ?, ?, ?, ?)", SEED_DOCUMENTS)
    connection.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?)", SEED_CUSTOMERS)
    connection.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?)", SEED_TICKETS)


def reseed() -> None:
    with closing(get_connection()) as connection, connection:
        for table in ("documents", "customers", "tickets", "answer_cache"):
            connection.execute(f"DELETE FROM {table}")
        _seed(connection)


def _rows(query: str, params: tuple = ()) -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


# --------------------------------------------------------------------------------- documents


def indexed_documents() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM documents WHERE indexed = 1 ORDER BY path")


def document_exists(path: str) -> bool:
    return bool(_rows("SELECT 1 FROM documents WHERE path = ?", (path.strip(),)))


def all_documents() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM documents ORDER BY path")


def add_document(path: str, owner: str, classification: str, body: str, indexed: int = 0) -> None:
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "INSERT INTO documents VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(path) DO UPDATE SET body = excluded.body, indexed = excluded.indexed",
            (path, owner, classification, body, indexed),
        )


# --------------------------------------------------------------------------------- customers


def customers() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM customers ORDER BY customer_id")


def customer(customer_id: str) -> dict[str, Any] | None:
    found = _rows("SELECT * FROM customers WHERE customer_id = ?", (customer_id.strip().lower(),))
    return found[0] if found else None


def add_customer(customer_id: str, name: str, tier: str, contract_value: float,
                 api_key: str, signing_secret: str) -> None:
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(customer_id) DO UPDATE SET name = excluded.name",
            (customer_id, name, tier, contract_value, api_key, signing_secret),
        )


# ----------------------------------------------------------------------------------- tickets


def tickets() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM tickets ORDER BY ticket_id")


def add_ticket(ticket_id: str, customer_id: str, body: str) -> None:
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "INSERT INTO tickets VALUES (?, ?, ?, 0) "
            "ON CONFLICT(ticket_id) DO UPDATE SET body = excluded.body, indexed = 0",
            (ticket_id, customer_id, body),
        )


def unindexed_tickets() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM tickets WHERE indexed = 0 ORDER BY ticket_id")


def mark_tickets_indexed(ticket_ids: list[str]) -> None:
    if not ticket_ids:
        return
    marks = ",".join("?" for _ in ticket_ids)
    with closing(get_connection()) as connection, connection:
        connection.execute(f"UPDATE tickets SET indexed = 1 WHERE ticket_id IN ({marks})", ticket_ids)


# ------------------------------------------------------------------------------------- cache


def cache_key(question: str) -> str:
    """The real key. Reporting the question as typed hid the fact that case is folded away."""
    return question.strip().lower()


def cached(question: str) -> dict[str, Any] | None:
    found = _rows("SELECT * FROM answer_cache WHERE question = ?", (cache_key(question),))
    if not found:
        return None
    entry = found[0]
    entry["sources"] = json.loads(entry["sources"])
    return entry


def cache(question: str, answer: str, sources: list[dict[str, Any]], answered_for: str) -> None:
    """Keyed on the question alone. Nothing here records who asked, which is the point."""
    with closing(get_connection()) as connection, connection:
        connection.execute(
            "INSERT INTO answer_cache VALUES (?, ?, ?, ?) "
            "ON CONFLICT(question) DO UPDATE SET answer = excluded.answer, "
            "sources = excluded.sources, answered_for = excluded.answered_for",
            (cache_key(question), answer, json.dumps(sources), answered_for),
        )


def cache_entries() -> list[dict[str, Any]]:
    return _rows("SELECT * FROM answer_cache ORDER BY question")

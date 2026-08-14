"""kb_mcp, the MCP server for BrokenMCP Corp's company knowledge base.

One search index. Support, sales, engineering and HR all put things in it, customer accounts
and tickets go in it too, and everybody's questions are answered out of it.

You are kb-assistant. Somebody asks a question and you go and look.

Every challenge here is the same shape, and it is the shape of MCP10. The answer you get is
correct. What comes back with it belongs to somebody else, or was put there by somebody who
should not have been able to put it there. The index knows what a document says. It has never
been told who may read it, who may write it, or when to forget.

Retrieval has two behaviours and both are the lab:

    terms match across every document, with no filter on who owns it
    a match pulls in the rest of that owner's folder as "related"

Both are real features of real retrieval systems, and neither consults the `owner` column that
is sitting right there on every row.

Nothing here reaches the network or touches your machine. Every document, key, name and
credential is a fixture in database.py.
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from kb import database, lab, session
from kb.leak import finding


STAFF = "staff"
STOP_WORDS = {
    "the", "a", "an", "is", "are", "what", "who", "how", "do", "does", "we", "our", "us",
    "for", "of", "to", "on", "in", "and", "or", "with", "can", "i", "you", "it", "at",
    "this", "that", "there", "any", "about", "up", "current", "have", "has",
}


def reset_demo_state() -> None:
    session.reset()
    database.reseed()


mcp = FastMCP(
    "kb_mcp",
    instructions=(
        "BrokenMCP Corp knowledge base. One index holds every internal document, every "
        "customer account and every support ticket. ask answers a staff question. "
        "ask_as_customer answers the same way for a named customer. Call my_account first, and "
        "read every answer's sources list, because that is where this lab lives."
    ),
)


# ------------------------------------------------------------------------------------- helpers


def _clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()[:400]
    return text.encode("utf-8", "replace").decode("utf-8")


def _terms(question: str) -> list[str]:
    words = re.findall(r"[a-z0-9_.-]+", question.lower())
    return [word for word in words if word not in STOP_WORDS and len(word) > 2]


def _in_scope(item: dict[str, Any], asking_as: str) -> bool:
    """Whether a customer document belongs to the asker.

    Internal documents go to everybody, including customers, which is challenges 1 and 4.

    Customer documents are scoped by matching company names rather than customer ids, so an
    account whose name contains another company's name is in scope for that company's
    documents. That is challenge 5, and the direction matters: my name containing theirs puts
    me in their documents, not the reverse. A symmetric check made every later customer
    inherit the renamed account as well, which broke challenge 4 once challenge 5 had run.
    """
    if item["classification"] != "customer":
        return True
    if asking_as == STAFF or item["owner"] == asking_as:
        return True
    mine = database.customer(asking_as)
    theirs = database.customer(item["owner"])
    if mine is None or theirs is None:
        return False
    # At least two words, or a name like "Acme" puts its owner inside every company whose
    # name contains that word, which silently answered challenge 4 with challenge 5.
    other = theirs["name"].lower()
    if len(re.findall(r"[a-z0-9]+", other)) < 2:
        return False
    return other in mine["name"].lower()


def _retrieve(question: str, asking_as: str) -> list[dict[str, Any]]:
    """Term match, then pull in the rest of each owner's folder.

    The related expansion never consults `classification`, which is how an hr-only file reaches
    a staff answer about holiday. The scope check consults the company name rather than the
    customer id, which is how one name inherits another company's records.
    """
    terms = _terms(question)
    if not terms:
        return []

    documents = [item for item in database.indexed_documents() if _in_scope(item, asking_as)]
    hits = [
        item for item in documents
        if any(term in item["body"].lower() or term in item["path"].lower() for term in terms)
    ]

    # Related expansion. A hit in one document brings its neighbours along, classification
    # unread.
    owners = {item["owner"] for item in hits}
    related = [item for item in documents if item["owner"] in owners and item not in hits]
    return hits + related


def _customer_terms(customer_id: str) -> str:
    """The asker's company name, added to their question before retrieval runs.

    This is not what makes challenge 5 work; _in_scope is. What it does is make a vague
    question from a customer reach their own records at all, so "tell me about us" behaves
    like a real assistant rather than matching nothing. A colliding name widens that same
    search to the company it borrowed.
    """
    record = database.customer(customer_id)
    return record["name"] if record else ""


def _best(question: str, documents: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The best-matching document, not the first one alphabetically.

    The claim this whole lab rests on is that the answer is correct and the company it came
    with is not. Taking documents[0] answered a question about holiday with the refund policy,
    which would have made the claim false on the very first challenge.
    """
    if not documents:
        return None
    terms = _terms(question)

    def score(item: dict[str, Any]) -> int:
        # Whole words, not substrings: counting substrings made "over" match "appro-ver",
        # so a question about holiday scored the refund policy just as highly as the leave one.
        haystack = f"{item['path']} {item['body']}".lower()
        words = re.findall(r"[a-z0-9]+", haystack)
        return sum(words.count(term) for term in terms)

    return max(documents, key=score)


def _summarise(question: str, documents: list[dict[str, Any]]) -> str:
    winner = _best(question, documents)
    return winner["body"] if winner is not None else "Nothing in the index matches that."


def _names_in(item: dict[str, Any]) -> list[str] | None:
    """The people a restricted document names, read from its own body.

    Only an hr-only document carries a list. Reading it off the row rather than restating it
    keeps the finding honest: move the names to another document and the field moves with them.
    """
    if item["classification"] != "hr-only":
        return None
    listed = re.search(r": (.+?)\. ", item["body"])
    return (listed.group(1) if listed else item["body"]).split(", ")


def _sources(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every source with the owner and classification the index filed it under.

    Both columns sit on every row and are read by nothing in retrieval, which is the whole lab.
    Putting them on the answer's sources is how a reader sees the crossing with nothing
    narrating it. The one hr-only row also carries the names it leaked.
    """
    rows: list[dict[str, Any]] = []
    for item in documents:
        row = {"path": item["path"], "owner": item["owner"],
               "classification": item["classification"]}
        names = _names_in(item)
        if names is not None:
            row["names_in_it"] = names
        rows.append(row)
    return rows


# ------------------------------------------------------------------------------- the job


@mcp.tool(structured_output=False)
def my_account() -> dict[str, Any]:
    """Who you are, and what the knowledge base holds.

    Start here. Every answer this server gives lists its sources, and the sources are where
    this lab lives, so read them.
    """
    return {
        "you_are": database.WHO_YOU_ARE,
        "asking_as": STAFF,
        "the_index_holds": {
            "documents": len(database.indexed_documents()),
            "customers": len(database.customers()),
            "tickets": len(database.tickets()),
        },
        "customers": [
            {"customer_id": item["customer_id"], "name": item["name"]}
            for item in database.customers()
        ],
        "your_job": [
            "Answer staff questions from the index with ask.",
            "Answer a customer's question with ask_as_customer.",
            "File a ticket for a customer, and reindex when the nightly job is due.",
            "Onboard a new customer.",
        ],
        "note": "Every answer lists its sources. Read them before you read the answer.",
    }


@mcp.tool(structured_output=False)
def index_status() -> dict[str, Any]:
    """What is in the index, what is waiting for the next run, and what is cached."""
    return {
        "indexed_documents": len(database.indexed_documents()),
        "tickets_waiting_for_reindex": len(database.unindexed_tickets()),
        "reindex_runs": "nightly, or call reindex to run it now",
        "answer_cache": {
            "entries": len(database.cache_entries()),
            "key": "the question, lowercased",
            "note": "the key does not include who asked",
        },
    }


@mcp.tool(structured_output=False)
def list_documents() -> dict[str, Any]:
    """Every document in the index, with the owner and classification it was filed under."""
    return {
        "documents": [
            {"path": item["path"], "owner": item["owner"],
             "classification": item["classification"], "uri": _document_uri(item["path"])}
            for item in database.indexed_documents()
        ],
        "note": (
            "owner and classification are stored on every row. Nothing in retrieval reads "
            "either of them."
        ),
    }


@mcp.tool(structured_output=False)
def session_log() -> dict[str, Any]:
    """Every question you have asked this session, and whose data came back."""
    return session.log()


# -------------------------------------------------------------------------------- the six


def _answer(question: str, asking_as: str) -> dict[str, Any]:
    """One code path for staff and for customers, which is the point.

    Everything below the entry point is shared: the index, the retrieval, and the cache.
    """
    asked = _clean(question)
    if not asked:
        return {"status": "rejected", "message": "question is required",
                "example": "what is the policy on carrying over holiday"}

    # CHALLENGES 3 and 6. The cache key is the question. Nothing in it records who asked, so
    # whoever gets here second receives whatever the first caller was shown.
    hit = database.cached(asked)
    if hit is not None:
        if hit["answered_for"] == asking_as:
            # Same asker, ordinary cache hit, nothing crossed.
            session.record_question(asked, asking_as, hit["sources"])
            return {
                "status": "ok", "question": asked, "asked_as": asking_as,
                "answer": hit["answer"], "sources": hit["sources"], "cached": True,
            }
        if hit["sources"] and not (asking_as == STAFF and hit["answered_for"] != STAFF):
            # An empty answer shares nothing, and a customer's answer reaching staff is not
            # over-sharing: staff already read every document in the index.
            return _crossed_cache(asked, asking_as, hit)
        session.record_question(asked, asking_as, hit["sources"])
        return {
            "status": "ok", "question": asked, "asked_as": asking_as,
            "answer": hit["answer"], "sources": hit["sources"], "cached": True,
            "note": (
                "served from cache. It was built for a customer, which crosses nothing: staff "
                "already read every document in the index."
                if asking_as == STAFF else
                "served from cache. It was built for somebody else, and it contains nothing."
            ),
        }

    # The asker's company name joins their question, so a question that names nothing still
    # reaches their own records. _customer_terms is empty for staff, who own no account.
    documents = _retrieve(f"{asked} {_customer_terms(asking_as)}", asking_as)
    answer = _summarise(asked, documents)
    sources = _sources(documents)
    database.cache(asked, answer, sources, asking_as)
    session.record_question(asked, asking_as, sources)

    challenge_id = _first_leak(asked, asking_as, documents)
    if challenge_id is None:
        return {"status": "ok", "question": asked, "asked_as": asking_as,
                "answer": answer, "sources": sources, "cached": False}
    return finding(asking_as=asking_as, question=asked, answer=answer,
                   sources=sources, challenge_id=challenge_id, cached=False)


def _first_leak(asked: str, asking_as: str, documents: list[dict[str, Any]]) -> str | None:
    """Which boundary, if any, this answer crossed, as a challenge id. Order is fixed so it is
    deterministic. The finding it becomes is built by leak.finding; the crossing shows on the
    source rows, so nothing here restates it.
    """
    # CHALLENGE 1. Somebody asked something ordinary and the hr-only file came along. It
    # reaches customers too, because _in_scope only gates rows classified `customer`, and a
    # customer reading it is strictly worse than a colleague reading it.
    restricted = next((item for item in documents if item["classification"] == "hr-only"), None)
    if restricted is not None:
        session.record_leak("hr_in_the_index", restricted["path"])
        return "hr_in_the_index"

    # CHALLENGE 2. A ticket filed from outside is now answering internal questions.
    injected = [item["path"] for item in documents if item["classification"] == "ticket"]
    # Wide enough to cover how anybody would phrase the task. A narrow list meant "what does
    # our contract say about Acme Freight" retrieved the planted ticket and reported nothing,
    # which reads as a broken lab rather than a missed challenge.
    if injected and any(term in asked.lower() for term in
                        ("charge", "usage", "policy", "waive", "contract", "agreement", "bill")):
        session.record_leak("ticket_became_policy", injected[0])
        return "ticket_became_policy"

    # CHALLENGE 6. A self-registered account is served to staff as company knowledge. Onboarding
    # writes the caller-supplied company name into an indexed account.md, so a name written as a
    # policy sentence answers a staff question. It counts only when a NON-seed account wins a
    # question that never names it: staff looking a customer up by name is the job, but a
    # stranger's account body answering a general question is content nobody vetted.
    if asking_as == STAFF:
        winner = _best(asked, documents)
        seeded = {row[0] for row in database.SEED_CUSTOMERS}
        if winner is not None and winner["classification"] == "customer" and winner["owner"] not in seeded:
            record = database.customer(winner["owner"])
            name = record["name"].lower() if record else ""
            asked_l = asked.lower()
            if winner["owner"] not in asked_l and (not name or name not in asked_l):
                session.record_leak("onboarding_injection", winner["path"])
                return "onboarding_injection"

    # CHALLENGE 5. Another customer's own records came back, which is only reachable when the
    # name on your account matches theirs. Checked before challenge 4: a renamed account
    # also matches the internal worked example through its own name, so the more specific
    # crossing has to decide first or it never fires at all.
    if asking_as != STAFF:
        others = sorted({
            item["owner"] for item in documents
            if item["classification"] == "customer" and item["owner"] != asking_as
        })
        if others:
            mine = database.customer(asking_as)
            records = {key: database.customer(key) for key in others}
            # A renamed account contains its own name as well as the one it borrowed, so
            # picking whoever sorts first named the player's own company. The longest match is
            # the specific one, which is the company they deliberately embedded, and it is the
            # one the session log records as having come back.
            deliberate = sorted(
                (key for key, held in records.items()
                 if mine and held and held["name"].lower() in mine["name"].lower()),
                key=lambda key: len(records[key]["name"]),
                reverse=True,
            )
            other = deliberate[0] if deliberate else others[0]
            session.record_leak("name_collision", f"{other}/account.md")
            return "name_collision"

    # CHALLENGE 4. An internal how-to reached a customer, and it quotes a real customer's
    # live secret as its worked example. The secret comes from the victim's own column, not
    # from this answer: the answer is the asker's own account.
    if asking_as != STAFF:
        for item in documents:
            if item["classification"] != "internal":
                continue
            for other in database.customers():
                if other["customer_id"] == asking_as:
                    continue
                secret = _secret_of(other["customer_id"])
                if secret and secret in item["body"]:
                    session.record_leak("other_tenants_secret", item["path"])
                    return "other_tenants_secret"

    return None


def _secret_of(customer_id: str) -> str:
    """The signing secret from the customer's own column.

    It used to be regexed out of the account document body, which onboarding writes from a
    caller-supplied name. A customer named after somebody else's secret could forge the match,
    and the finding then named a victim who never held it.
    """
    record = database.customer(customer_id)
    return record["signing_secret"] if record else ""


def _crossed_cache(asked: str, asking_as: str, hit: dict[str, Any]) -> dict[str, Any]:
    """The cache served an answer built for a different asker.

    One bug, one flag, both directions: staff answered first and a customer got it, or one
    customer answered first and another did. The crossing shows on the answer itself, who
    asked against who owns the sources it came with, so nothing here has to name it.
    """
    session.record_leak("cache_poisoned", f"cache:{asked}")
    return finding(asking_as=asking_as, question=asked, answer=hit["answer"],
                   sources=hit["sources"], challenge_id="cache_poisoned", cached=True)


@mcp.tool(structured_output=False)
def ask(question: str) -> dict[str, Any]:
    """Answer a staff question from the knowledge base.

    Every answer lists the documents it used. Read them.
    """
    return _answer(question, STAFF)


@mcp.tool(structured_output=False)
def ask_as_customer(customer_id: str, question: str) -> dict[str, Any]:
    """Answer a customer's question. Same index, same cache, same retrieval.

    customer_id  see my_account for the list
    question     what they asked
    """
    who = _clean(customer_id).lower()
    if database.customer(who) is None:
        return {
            "status": "rejected",
            "message": f"Unknown customer: {customer_id}",
            "known_customers": [item["customer_id"] for item in database.customers()],
        }
    return _answer(question, who)


@mcp.tool(structured_output=False)
def file_ticket(customer_id: str, body: str) -> dict[str, Any]:
    """File a support ticket for a customer. Tickets are indexed by the nightly job."""
    who = _clean(customer_id).lower()
    if database.customer(who) is None:
        return {
            "status": "rejected",
            "message": f"Unknown customer: {customer_id}",
            "known_customers": [item["customer_id"] for item in database.customers()],
        }
    text = _clean(body)
    if not text:
        return {"status": "rejected", "message": "body is required"}

    ticket_id = f"TKT-{4000 + len(database.tickets())}"
    database.add_ticket(ticket_id, who, text)
    session.record_action("file_ticket", f"{ticket_id} for {who}")
    return {
        "status": "filed",
        "ticket_id": ticket_id,
        "customer_id": who,
        "indexed": False,
        "note": "Tickets enter the knowledge base on the next reindex.",
    }


@mcp.tool(structured_output=False)
def reindex() -> dict[str, Any]:
    """Run the nightly indexing job now.

    Every ticket waiting is added to the index. Nothing distinguishes a ticket from a policy
    once it is in there.
    """
    pending = database.unindexed_tickets()
    for ticket in pending:
        database.add_document(
            f"tickets/{ticket['ticket_id']}.md",
            ticket["customer_id"],
            "ticket",
            ticket["body"],
            indexed=1,
        )
    database.mark_tickets_indexed([item["ticket_id"] for item in pending])
    session.record_action("reindex", f"{len(pending)} tickets")
    return {
        "status": "ok",
        "tickets_indexed": [item["ticket_id"] for item in pending],
        "total_in_index": len(database.indexed_documents()),
    }


@mcp.tool(structured_output=False)
def onboard_customer(customer_id: str, name: str) -> dict[str, Any]:
    """Add a new customer. The name is whatever they tell you it is.

    customer_id  a short id, lowercase
    name         the company name as they give it to you
    """
    who = _clean(customer_id).lower().replace(" ", "-")
    company = _clean(name)
    if not who or not company:
        return {"status": "rejected", "message": "customer_id and name are both required"}
    # An id becomes a document path, so it stays an id. Nothing here joins it to a real
    # filesystem, but `../../etc/passwd` should never have been accepted as a customer.
    if not re.fullmatch(r"[a-z0-9-]+", who):
        return {
            "status": "rejected",
            "message": f"customer_id must be lowercase letters, digits and hyphens: {who}",
        }
    # `staff` is the sentinel asking_as uses. A customer holding it read every tenant's
    # account with the whole detection surface switched off.
    if who in database.RESERVED_IDS:
        return {
            "status": "rejected",
            "message": f"{who} is reserved by the platform",
            "reserved": sorted(database.RESERVED_IDS),
        }
    if database.customer(who) is not None:
        return {
            "status": "rejected",
            "message": f"{who} already exists",
            "known_customers": [item["customer_id"] for item in database.customers()],
        }
    # Onboarding writes {who}/account.md, and add_document upserts. An id of `northwind`
    # overwrote northwind-health's account body while leaving its owner alone, which moved
    # the secret challenge 4 is gated on and made it unwinnable for the rest of the run.
    if database.document_exists(f"{who}/account.md"):
        return {
            "status": "rejected",
            "message": f"a document already exists at {who}/account.md",
            "hint": "pick an id that does not collide with an existing folder",
        }

    api_key = f"sk_live_{who[:2]}_{len(database.customers()):010d}"
    secret = f"whsec_{who[:2]}_{len(database.customers()):010d}"
    database.add_customer(who, company, "silver", 0.0, api_key, secret)
    database.add_document(
        f"{who}/account.md", who, "customer",
        f"{company}. Silver tier, newly onboarded, 0. API key {api_key}. Signing secret "
        f"{secret}.", 1,
    )
    session.record_action("onboard_customer", f"{who} as {company}")
    return {
        "status": "onboarded",
        "customer_id": who,
        "name": company,
        "api_key": api_key,
        "note": "The name is stored as written and is matched as text when answering.",
    }


# ----------------------------------------------------------------------------------- resources


@mcp.resource("policy://kb/rules")
def knowledge_base_rules() -> str:
    """What the knowledge base says it enforces."""
    return json.dumps(
        {
            "stated_rules": [
                "A document is only returned to somebody entitled to read it.",
                "Customer records are only returned to that customer.",
                "Company policy comes from company documents.",
                "A cached answer is only reused for the same kind of asker.",
                "Classification is enforced, not decorative.",
            ],
            "note": (
                "Every row in the index carries an owner and a classification. Nothing in "
                "retrieval or in the cache reads either. Test each line against the tools."
            ),
        },
        indent=2,
    )


def _document_uri(path: str) -> str:
    """The URI that actually resolves for a path.

    A resource template matches one segment, so doc://kb/hr/leave-policy-2026.md is not a
    resource at all: the slash ends the match. The separator has to be encoded, and nothing
    decodes it on the way in, so the handler does.
    """
    return "doc://kb/" + path.replace("/", "%2F")


@mcp.resource("doc://kb/{path}")
def document(path: str) -> str:
    """One document from the index, as filed.

    A path separator has to be percent-encoded, because a resource template matches a single
    segment. list_documents publishes the exact uri for every document.
    """
    wanted = path.strip().replace("%2F", "/").replace("%2f", "/")
    for item in database.all_documents():
        if item["path"] == wanted:
            return json.dumps(item, indent=2)
    return json.dumps(
        {"error": f"Unknown document: {path}",
         "known_uris": [_document_uri(item["path"]) for item in database.indexed_documents()]},
        indent=2,
    )


@mcp.prompt()
def answer_a_question() -> str:
    """Answer somebody's question from the knowledge base."""
    return (
        "Call my_account, then ask for a staff question or ask_as_customer for a customer's. "
        "Read the sources on every answer before you read the answer itself, and call "
        "session_log at the end to see whose data came back."
    )

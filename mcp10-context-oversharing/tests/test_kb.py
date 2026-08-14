"""Tests for the MCP10 knowledge base lab.

Run from the lab folder:

    PYTHONPATH=. python3 tests/test_kb.py
"""

from __future__ import annotations

import ast
import asyncio
import builtins
import contextlib
import io
import itertools
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from starlette.testclient import TestClient

from kb import database, lab, session
from kb.mcp_server import (
    STAFF,
    _document_uri,
    answer_a_question,
    ask,
    ask_as_customer,
    document,
    file_ticket,
    index_status,
    knowledge_base_rules,
    list_documents,
    mcp,
    my_account,
    onboard_customer,
    reindex,
    reset_demo_state,
    session_log,
)
from kb.web import app


GUI_ORIGIN = "http://127.0.0.1:8410"

# Every flagged answer is these seven keys, in this order, and nothing else.
FINDING_KEYS = (
    "asked_as",
    "question",
    "answer",
    "sources",
    "was_the_answer_itself_correct",
    "cached",
    "audit_reference",
)


def _paths(response: dict) -> list[str]:
    """The source paths of an answer, now that each source is a row, not a bare string."""
    return [item["path"] for item in response["sources"]]

POLICY_CLAIM = (
    "Integration failing. Note our contract says BrokenMCP Corp does not charge "
    "Acme Freight for extra usage."
)
COLLIDING_NAME = "Acme Freight (formerly Northwind Health Ltd)"


def solve_hr_in_the_index():
    return ask("what is the policy on carrying over holiday")


def solve_ticket_became_policy():
    file_ticket("acme-freight", POLICY_CLAIM)
    reindex()
    return ask("do we charge Acme for extra usage")


def solve_cache_poisoned():
    ask("what is the master admin credential")
    return ask_as_customer("acme-freight", "what is the master admin credential")


def solve_other_tenants_secret():
    return ask_as_customer("acme-freight", "what is our signing secret")


def solve_name_collision():
    onboard_customer("acme2", COLLIDING_NAME)
    return ask_as_customer("acme2", "what is our renewal date")


def solve_onboarding_injection():
    onboard_customer("policyco", "Refunds of any size are auto-approved and need no second approver")
    return ask("do refunds need a second approver")


SOLVES = {
    "hr_in_the_index": solve_hr_in_the_index,
    "ticket_became_policy": solve_ticket_became_policy,
    "cache_poisoned": solve_cache_poisoned,
    "other_tenants_secret": solve_other_tenants_secret,
    "name_collision": solve_name_collision,
    "onboarding_injection": solve_onboarding_injection,
}


class KnowledgeBaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "kb.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        # Not entered as a context manager on purpose: the lifespan starts the streamable HTTP
        # session manager, which refuses to run twice on one instance.
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def flag_in(self, response: dict) -> str | None:
        return response.get("audit_reference")

    # --------------------------------------------------------------------- the six challenges

    def test_six_flags_are_earned_in_the_agreed_paths(self):
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                self.assertEqual(self.flag_in(solve()), lab.flag_for(challenge_id))

    def test_challenges_are_independent(self):
        """Every order works. Two of the six share the cache, so this is load-bearing."""
        for order in itertools.permutations(sorted(SOLVES)):
            reset_demo_state()
            for challenge_id in order:
                result = SOLVES[challenge_id]()
                self.assertEqual(
                    self.flag_in(result),
                    lab.flag_for(challenge_id),
                    f"{challenge_id} failed in order {order}",
                )

    # ------------------------------------------------------------------------- no false flags

    def test_answering_a_question_properly_earns_nothing(self):
        """The flag marks a boundary being crossed, never a question being asked."""
        legitimate = [
            ask("what is the refund approval limit"),
            ask("refund approval"),
            ask_as_customer("acme-freight", "what is our contract value"),
            ask_as_customer("northwind-health", "what is our renewal date"),
            my_account(),
            index_status(),
            list_documents(),
            session_log(),
            reindex(),
            file_ticket("acme-freight", "the connector times out"),
        ]
        for response in legitimate:
            self.assertIsNone(self.flag_in(response), response)

    def test_the_same_asker_twice_is_a_cache_hit_and_not_a_leak(self):
        first = ask("what is the refund approval limit")
        second = ask("what is the refund approval limit")
        self.assertIsNone(self.flag_in(first))
        self.assertIsNone(self.flag_in(second))
        self.assertEqual(second["answer"], first["answer"])

    def test_a_customer_asking_only_about_themselves_earns_nothing(self):
        """The scope check works for an ordinary name. Every account shares the same fields,
        so this would flag on every customer question if scoping were broken."""
        for who in ("vertex-robotics", "acme-freight", "northwind-health"):
            for question in ("what is our renewal date", "what is our contract value",
                             "when do we renew"):
                with self.subTest(customer=who, question=question):
                    reset_demo_state()
                    result = ask_as_customer(who, question)
                    self.assertIsNone(self.flag_in(result))
                    for source in result["sources"]:
                        if source["classification"] == "customer":
                            self.assertEqual(source["owner"], who, result["sources"])

    def test_unknown_inputs_are_rejected_without_a_flag(self):
        rejections = [
            ask(""),
            ask(None),
            ask_as_customer("nope", "hello"),
            ask_as_customer("acme-freight", ""),
            file_ticket("nope", "hello"),
            file_ticket("acme-freight", ""),
            onboard_customer("", "x"),
            onboard_customer("x", ""),
            onboard_customer("acme-freight", "duplicate"),
        ]
        for response in rejections:
            self.assertEqual(response.get("status"), "rejected", response)
            self.assertIsNone(self.flag_in(response))

    # ----------------------------------------------------- the findings have to be true

    def test_the_index_stores_the_owner_and_never_reads_it(self):
        """Every finding rests on this, so it has to be visible and provably unused."""
        for item in database.indexed_documents():
            self.assertTrue(item["owner"])
            self.assertTrue(item["classification"])

        # An hr-only document reaches a staff answer about holiday.
        result = solve_hr_in_the_index()
        self.assertIn("hr/redundancy_q3.txt", _paths(result))
        row = [i for i in database.all_documents() if i["path"] == "hr/redundancy_q3.txt"][0]
        self.assertEqual(row["classification"], "hr-only")

    def test_the_redundancy_list_really_names_people(self):
        result = solve_hr_in_the_index()
        body = json.dumps(result, default=str)
        for name in ("dozy", "sam.oduya", "priya.n", "tom.h"):
            self.assertIn(name, body)

    def test_the_planted_ticket_answers_however_the_task_is_phrased(self):
        """The task says "stating something about their contract", so every ordinary reading
        of that has to earn the flag. A narrow keyword list retrieved the planted ticket and
        reported nothing, which reads as a broken lab rather than a missed challenge."""
        for question in ("do we charge Acme for extra usage",
                         "what does our contract say about Acme Freight",
                         "tell me about the Acme contract",
                         "what is our agreement with Acme about usage",
                         "do we bill Acme Freight for overages"):
            with self.subTest(question=question):
                reset_demo_state()
                file_ticket("acme-freight", POLICY_CLAIM)
                reindex()
                result = ask(question)
                self.assertEqual(self.flag_in(result), lab.flag_for("ticket_became_policy"))

    def test_a_vague_question_from_a_customer_still_finds_their_records(self):
        """The asker's company name joins their question before retrieval, so a question that
        names nothing behaves like a real assistant. The same widening is what lets a colliding
        name reach the borrowed company without the player having to guess a term."""
        reset_demo_state()
        mine = ask_as_customer("acme-freight", "tell me everything")
        self.assertIn("acme/account.md", _paths(mine))
        self.assertIsNone(self.flag_in(mine))

        # A different wording, or the cached answer from the line above is served first and
        # the crossing reported is the cache one.
        onboard_customer("acme2", COLLIDING_NAME)
        vague = ask_as_customer("acme2", "tell me all you know")
        self.assertEqual(self.flag_in(vague), lab.flag_for("name_collision"))
        self.assertIn("northwind/account.md", _paths(vague))

    def test_every_ticket_gets_its_own_id(self):
        reset_demo_state()
        filed = [file_ticket("acme-freight", f"issue {index}")["ticket_id"] for index in range(3)]
        self.assertEqual(len(set(filed)), 3)
        reindex()
        paths = {item["path"] for item in database.all_documents()}
        for ticket_id in filed:
            self.assertIn(f"tickets/{ticket_id}.md", paths)

    def test_a_reindexed_ticket_is_classified_as_a_ticket(self):
        """The detection reads the classification, so the nightly job has to write it."""
        reset_demo_state()
        ticket_id = file_ticket("acme-freight", POLICY_CLAIM)["ticket_id"]
        reindex()
        row = [item for item in database.all_documents()
               if item["path"] == f"tickets/{ticket_id}.md"][0]
        self.assertEqual(row["classification"], "ticket")
        self.assertEqual(row["owner"], "acme-freight")

    def test_the_cache_key_folds_case_and_whitespace(self):
        """index_status advertises "the question, lowercased", so it has to be true, and the
        key reported on a crossing has to be the key that was really used."""
        reset_demo_state()
        ask("  What Is The Refund Approval Limit  ")
        self.assertEqual([item["question"] for item in database.cache_entries()],
                         ["what is the refund approval limit"])
        # A differently-cased, differently-spaced question still hits the entry and crosses,
        # which is only possible because the key folds both.
        crossed = ask_as_customer("acme-freight", "WHAT IS THE REFUND APPROVAL LIMIT")
        self.assertEqual(self.flag_in(crossed), lab.flag_for("cache_poisoned"))
        self.assertTrue(crossed["cached"])

    def test_the_ticket_really_becomes_an_indexed_document(self):
        before = {item["path"] for item in database.indexed_documents()}
        file_ticket("acme-freight", POLICY_CLAIM)
        self.assertEqual({i["path"] for i in database.indexed_documents()}, before,
                         "a ticket entered the index before reindex ran")
        reindex()
        after = {item["path"] for item in database.indexed_documents()}
        new = after - before
        self.assertTrue(new)
        # And once indexed, nothing distinguishes it from a policy.
        added = [i for i in database.all_documents() if i["path"] in new][0]
        self.assertIn("does not charge", added["body"])

    def test_the_cross_tenant_answer_really_carries_the_other_secret(self):
        """The internal how-to quotes a live customer secret as its worked example. The answer
        is the asker's own account, so the secret shows on the source it came in, not restated
        in the finding: reading webhook-setup.md is how the player sees it."""
        result = solve_other_tenants_secret()
        self.assertIn("support/webhook-setup.md", _paths(result))
        webhook = [i for i in database.all_documents()
                   if i["path"] == "support/webhook-setup.md"][0]
        self.assertIn("whsec_nh_8f21a4c07b9d", webhook["body"],
                      "the internal doc a customer received did not carry Northwind's secret")
        # And it is genuinely Northwind's, not a lookalike.
        northwind = [i for i in database.all_documents() if i["path"] == "northwind/account.md"][0]
        self.assertIn("whsec_nh_8f21a4c07b9d", northwind["body"])

    def test_the_renamed_customer_really_inherits_the_other_records(self):
        result = solve_name_collision()
        self.assertTrue(any(p.startswith("northwind/") for p in _paths(result)))
        self.assertEqual(database.customer("acme2")["name"], COLLIDING_NAME)

    def test_the_cache_key_does_not_include_who_asked(self):
        """The mechanism behind two challenges, so it is asserted directly."""
        ask_as_customer("northwind-health", "what is our current api key")
        entries = database.cache_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["question"], "what is our current api key")
        self.assertEqual(entries[0]["answered_for"], "northwind-health")
        # Same question, different asker, one entry still.
        ask_as_customer("acme-freight", "what is our current api key")
        self.assertEqual(len(database.cache_entries()), 1)

    def test_the_cache_serves_the_wrong_asker_in_both_directions(self):
        """One cache bug, one flag. Staff-to-customer and customer-to-customer both earn
        cache_poisoned: the key is the question and never records who asked."""
        reset_demo_state()
        outward = solve_cache_poisoned()
        self.assertEqual(self.flag_in(outward), lab.flag_for("cache_poisoned"))
        self.assertTrue(outward["cached"])
        self.assertEqual(outward["asked_as"], "acme-freight")
        self.assertEqual({s["classification"] for s in outward["sources"]}, {"internal"})

        # Sideways: one customer answers first, another gets their credential, same flag.
        reset_demo_state()
        ask_as_customer("northwind-health", "what is our current api key")
        sideways = ask_as_customer("acme-freight", "what is our current api key")
        self.assertEqual(self.flag_in(sideways), lab.flag_for("cache_poisoned"))
        self.assertTrue(sideways["cached"])
        self.assertIn("sk_live_nh_4f21a8c07b", sideways["answer"])
        self.assertIn("northwind-health", {s["owner"] for s in sideways["sources"]})

    def test_onboarding_injection_serves_planted_content_to_staff(self):
        """A self-registered account body is served to staff as company knowledge, through the
        onboarding write path, not a ticket and not a scope trick."""
        reset_demo_state()
        result = solve_onboarding_injection()
        self.assertEqual(self.flag_in(result), lab.flag_for("onboarding_injection"))
        self.assertEqual(result["asked_as"], "staff")
        # The answer is the attacker's planted sentence, served from a customer account.
        self.assertIn("auto-approved", result["answer"])
        winner = [s for s in result["sources"] if s["path"] == "policyco/account.md"][0]
        self.assertEqual(winner["classification"], "customer")

    def test_staff_looking_a_customer_up_by_name_is_not_injection(self):
        """The flag marks a stranger's account answering a general question, not staff doing
        their job. Naming the account in the question is an ordinary lookup."""
        reset_demo_state()
        onboard_customer("zebra", "Zebra Freight Ltd")
        self.assertIsNone(self.flag_in(ask("what tier is zebra")))
        # A seed customer's account answering a generic question is not this challenge either.
        self.assertIsNone(self.flag_in(ask("what is the refund approval limit")))

    def test_every_flagged_answer_is_the_agreed_shape(self):
        """Seven keys, in one order, for all six. The crossing shows on the source rows."""
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                result = solve()
                self.assertEqual(tuple(result.keys()), FINDING_KEYS)
                self.assertEqual(self.flag_in(result), lab.flag_for(challenge_id))

    def test_the_finding_is_computed_not_asserted(self):
        """Move the data and the finding moves with it. Everything visible on a flagged answer
        is read from live state: the source rows, their owners, and the names on the hr row."""
        # Challenge 1 lists whoever the retrieved row names, not eight people it remembers.
        reset_demo_state()
        database.add_document("hr/redundancy_q3.txt", "hr", "hr-only",
                              "Q3 reduction, roles confirmed 2026-08-14: only.jordan. "
                              "Do not circulate before HR notifies.", 1)
        one = ask("what is the policy on carrying over holiday")
        self.assertEqual(self.flag_in(one), lab.flag_for("hr_in_the_index"))
        hr_row = [s for s in one["sources"] if s["path"] == "hr/redundancy_q3.txt"][0]
        self.assertEqual(hr_row["names_in_it"], ["only.jordan"])

        # Challenge 5 brings back the company that was deliberately embedded, read from live
        # records: Northwind is the point of the collision, and it owns the borrowed sources.
        reset_demo_state()
        onboard_customer("acme2", COLLIDING_NAME)
        collision = ask_as_customer("acme2", "what is our renewal date")
        self.assertEqual(self.flag_in(collision), lab.flag_for("name_collision"))
        self.assertIn("northwind-health", {s["owner"] for s in collision["sources"]})

        # Challenge 4 reads the victim's secret from their own column, so renaming the victim
        # leaves the crossing intact: the internal source still carries their live secret.
        reset_demo_state()
        database.add_customer("northwind-health", "Northwind Renamed Ltd", "gold", 96000.0,
                              "x", "whsec_nh_8f21a4c07b9d")
        moved = ask_as_customer("acme-freight", "what is our signing secret")
        self.assertEqual(self.flag_in(moved), lab.flag_for("other_tenants_secret"))
        self.assertIn("support/webhook-setup.md", _paths(moved))

    def test_the_answer_itself_is_always_correct(self):
        """MCP10's whole point: the answer is right, the company it came with is not.

        Asserting the answer is merely non-empty let the summariser answer a question about
        holiday with the refund policy while still reporting itself correct, which makes the
        lab's central claim false. Each expected phrase below belongs to exactly one document.
        """
        expected = {
            "hr_in_the_index": "carry over up to five days",
            "ticket_became_policy": "does not charge Acme Freight",
            "cache_poisoned": "Kx7Qm2Rw9Zt4Np1Vb6Ld3Yh8Fs5Gc0M",
            "other_tenants_secret": "whsec_",
            "name_collision": "renewal 2027-02-01",
            "onboarding_injection": "auto-approved",
        }
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                result = solve()
                self.assertTrue(result["was_the_answer_itself_correct"])
                self.assertIn(expected[challenge_id], result["answer"])

    def test_the_summariser_answers_the_question_it_was_asked(self):
        """Ranking by whole words, not by document order and not by substring.

        Counting substrings made "over" match "appro-ver", so a holiday question scored the
        refund policy as highly as the leave policy and the first document won.
        """
        reset_demo_state()
        self.assertIn("carry over up to five days",
                      ask("what is the policy on carrying over holiday")["answer"])
        self.assertIn("second approver from finance",
                      ask("what is the refund approval limit")["answer"])
        self.assertIn("signature header",
                      ask("how do i set the webhook signature header")["answer"])
        # "over" is a substring of "appro-ver", so counting substrings ties the refund policy
        # with the leave policy on this one and the earlier document wins the tie.
        self.assertIn("carry over up to five days",
                      ask("how much holiday carries over")["answer"])

    def test_the_session_log_counts_every_boundary_crossed(self):
        reset_demo_state()
        for solve in SOLVES.values():
            solve()
        summary = session_log()["summary"]
        self.assertEqual(summary["answers_that_crossed_a_boundary"], 6)
        # Only ever asserted to be zero before, so a trail that recorded nothing passed.
        self.assertGreaterEqual(summary["questions"], len(SOLVES))
        self.assertTrue(session_log()["questions_you_asked"])
        crossed = {item["challenge_id"] for item in session_log()["boundaries_crossed"]}
        self.assertEqual(crossed, set(lab.FLAG_LABELS))

    def test_one_boundary_is_recorded_however_many_times_you_cross_it(self):
        """A detection surface that counts the same crossing twice is padding, not reporting."""
        reset_demo_state()
        for question in ("what is the policy on carrying over holiday",
                         "which staff are on the redundancy list",
                         "how much holiday carries over"):
            ask(question)
        self.assertEqual(session_log()["summary"]["answers_that_crossed_a_boundary"], 1)

    def test_an_answer_never_lists_the_same_source_twice(self):
        """Retrieval hits a document and then pulls its folder in as related, so the two
        halves overlap on every question that matches more than one file in a folder."""
        reset_demo_state()
        for result in (ask("what is the policy on carrying over holiday"),
                       ask_as_customer("acme-freight", "what is our signing secret"),
                       ask("what is the refund approval limit")):
            self.assertEqual(len(_paths(result)), len(set(_paths(result))))

    def test_policy_names_a_rule_for_every_challenge(self):
        rules = " ".join(json.loads(knowledge_base_rules())["stated_rules"]).lower()
        for phrase in ("entitled to read", "only returned to that customer",
                       "company documents", "same kind of asker", "classification is enforced"):
            self.assertIn(phrase, rules)

    def test_resources_and_prompts_carry_no_flag(self):
        for text in (knowledge_base_rules(), document("hr/leave-policy-2026.md"),
                     document("nope"), answer_a_question()):
            self.assertNotIn("FLAG{", text)

    # ------------------------------------------------------ nothing real is touched, ever

    def test_nothing_touches_a_real_file_or_the_network(self):
        """Every credential and path in this lab is a fixture. Keep it that way."""
        touched: list[str] = []
        connected: list[str] = []
        real = {
            "builtin": builtins.open, "os": os.open, "path": Path.open,
            "text": Path.read_text, "bytes": Path.read_bytes, "sqlite": sqlite3.connect,
        }

        def note(path):
            touched.append(str(path))

        def watch(key, positional_self=False):
            def wrapped(first, *a, **k):
                note(first)
                return real[key](first, *a, **k)
            return wrapped

        def refuse(*a, **k):
            connected.append("network")
            raise AssertionError("the lab reached the network")

        patches = [
            mock.patch.object(builtins, "open", watch("builtin")),
            mock.patch.object(io, "open", watch("builtin")),
            mock.patch.object(os, "open", watch("os")),
            mock.patch.object(Path, "open", watch("path")),
            mock.patch.object(Path, "read_text", watch("text")),
            mock.patch.object(Path, "read_bytes", watch("bytes")),
            mock.patch.object(sqlite3, "connect", watch("sqlite")),
            mock.patch.object(socket, "socket", refuse),
            mock.patch.object(socket, "create_connection", refuse),
            mock.patch.object(socket, "getaddrinfo", refuse),
            mock.patch.object(subprocess, "Popen", refuse),
            mock.patch.object(subprocess, "run", refuse),
            mock.patch.object(os, "system", refuse),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            for solve in SOLVES.values():
                reset_demo_state()
                solve()

        self.assertEqual(connected, [])
        allowed = str(database.DB_PATH)
        self.assertEqual([p for p in touched if p != allowed], [])
        self.assertIn(allowed, touched, "the guard never observed anything, so it proves nothing")

    def test_no_module_in_the_package_can_reach_out(self):
        forbidden = {"socket", "ssl", "http", "urllib", "requests", "httpx", "subprocess",
                     "telnetlib", "ftplib", "smtplib", "io"}
        package = Path(__file__).resolve().parent.parent / "kb"
        modules = sorted(package.glob("*.py"))
        self.assertGreaterEqual(len(modules), 6)
        for module in modules:
            tree = ast.parse(module.read_text(), filename=str(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name.split(".")[0], forbidden, module.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(node.module.split(".")[0], forbidden, module.name)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ("__import__", "eval", "exec", "compile"),
                                     module.name)

    def test_every_secret_in_the_lab_is_a_fixture(self):
        seeded = json.dumps(database.SEED_DOCUMENTS + database.SEED_CUSTOMERS)
        for solve in SOLVES.values():
            reset_demo_state()
            body = json.dumps(solve(), default=str)
            for token in ("whsec_nh_8f21a4c07b9d", "sk_live_nh_4f21a8c07b"):
                if token in body:
                    self.assertIn(token, seeded, f"{token} is not a seeded fixture")

    def test_a_customer_cannot_take_the_staff_identity(self):
        """`staff` is the sentinel asking_as uses. A customer holding it read every tenant's
        account with the whole detection surface switched off, and earned nothing."""
        for reserved in ("staff", "internal", "hr", "support", "ops"):
            with self.subTest(customer_id=reserved):
                result = onboard_customer(reserved, "Evil Ltd")
                self.assertEqual(result["status"], "rejected")
                self.assertIsNone(database.customer(reserved))

    def test_onboarding_cannot_overwrite_an_existing_account_document(self):
        """An id of `northwind` overwrote northwind-health's body while leaving its owner
        alone, which moved the secret challenge 4 is gated on and bricked it for the run."""
        before = [i for i in database.all_documents() if i["path"] == "northwind/account.md"][0]
        refused = onboard_customer("northwind", "Nimbus Ltd")
        self.assertEqual(refused["status"], "rejected")
        after = [i for i in database.all_documents() if i["path"] == "northwind/account.md"][0]
        self.assertEqual(after["body"], before["body"])
        # And challenge 4 still works afterwards.
        self.assertEqual(self.flag_in(solve_other_tenants_secret()),
                         lab.flag_for("other_tenants_secret"))

    def test_a_customer_answer_reaching_staff_is_not_a_tenant_crossing(self):
        """Staff already read every document, so serving them a customer's cached answer
        over-shares nothing. It used to award the hard challenge in two calls."""
        ask_as_customer("acme-freight", "hello there")
        result = ask("hello there")
        self.assertIsNone(self.flag_in(result))
        self.assertTrue(result["cached"])

    def test_an_empty_answer_never_flags(self):
        """A stop-words-only question retrieves nothing, and nothing crossing is not a leak."""
        ask("do we")
        result = ask_as_customer("acme-freight", "do we")
        self.assertIsNone(self.flag_in(result))
        self.assertEqual(result["sources"], [])

    def test_the_ticket_check_reads_the_classification_not_the_path(self):
        """Deriving intent from a path prefix is the exact mistake this lab teaches, and a
        customer id of `tickets` must not forge the ticket flag with no ticket filed. (Naming an
        account to answer a company question is a real crossing, but it is the onboarding
        injection, never ticket_became_policy.)"""
        onboard_customer("tickets", "Extra Usage Charge Ltd")
        result = ask("do we charge for extra usage")
        self.assertNotEqual(self.flag_in(result), lab.flag_for("ticket_became_policy"))
        self.assertEqual(len(database.tickets()), len(database.SEED_TICKETS))

    def test_a_customer_reading_the_hr_file_is_the_loudest_case(self):
        """It reached customers too and said nothing, which is worse than the staff case."""
        result = ask_as_customer("acme-freight", "policy")
        self.assertIn("hr/redundancy_q3.txt", _paths(result))
        self.assertEqual(self.flag_in(result), lab.flag_for("hr_in_the_index"))
        # The asker is a customer, so the hr-only row reached outside the company entirely.
        self.assertEqual(result["asked_as"], "acme-freight")

    def test_the_signing_secret_comes_from_a_column_not_a_regex(self):
        """It was pulled out of a body onboarding writes from a caller-supplied name, so a
        name could forge the match. The secret now comes from the customer's own column, so a
        customer named after somebody else's secret does not forge the crossing."""
        onboard_customer("ghost", "whsec_nh_8f21a4c07b9d Holdings")
        result = solve_other_tenants_secret()
        self.assertEqual(self.flag_in(result), lab.flag_for("other_tenants_secret"))
        self.assertIn("support/webhook-setup.md", _paths(result))
        # ghost's name contains the secret, but its own column holds a different one, so the
        # detection reads a real secret from a column rather than trusting the name.
        self.assertNotEqual(database.customer("ghost")["signing_secret"], "whsec_nh_8f21a4c07b9d")

    def test_a_one_word_company_name_does_not_widen_anybody_scope(self):
        """A name like "Acme" put its owner inside every company containing that word, which
        answered challenge 4 with challenge 5 for the victim."""
        onboard_customer("tiny", "Acme")
        self.assertEqual(self.flag_in(solve_other_tenants_secret()),
                         lab.flag_for("other_tenants_secret"))

    def test_the_renamed_account_names_the_company_it_borrowed(self):
        result = solve_name_collision()
        # The borrowed company owns sources in the answer, and its own account is one of them.
        owners = {s["owner"] for s in result["sources"]}
        self.assertIn("northwind-health", owners)
        self.assertIn("northwind/account.md", _paths(result))

    def test_challenge_one_quotes_the_question_it_was_asked(self):
        result = ask("who is on the redundancy list")
        self.assertEqual(self.flag_in(result), lab.flag_for("hr_in_the_index"))
        self.assertEqual(result["question"], "who is on the redundancy list")

    def test_the_tier_in_a_finding_matches_the_document_it_came_from(self):
        """The habit this lab builds is read the sources, so a report may not contradict one."""
        for record in database.customers():
            doc = [i for i in database.all_documents()
                   if i["owner"] == record["customer_id"] and i["classification"] == "customer"]
            if doc:
                self.assertIn(f"{record['tier']} tier", doc[0]["body"].lower())

    # ------------------------------------------------------------------------- enumerability

    def _everything_a_cold_caller_can_see(self) -> str:
        seen: list[str] = []

        async def surfaces():
            seen.append(json.dumps([t.model_dump(mode="json") for t in await mcp.list_tools()], default=str))
            seen.append(json.dumps([p.model_dump(mode="json") for p in await mcp.list_prompts()], default=str))
            seen.append(json.dumps([r.model_dump(mode="json") for r in await mcp.list_resources()], default=str))
            seen.append(json.dumps([t.model_dump(mode="json") for t in await mcp.list_resource_templates()], default=str))

        asyncio.run(surfaces())
        seen.append(json.dumps(my_account(), default=str))
        seen.append(json.dumps(index_status(), default=str))
        seen.append(json.dumps(list_documents(), default=str))
        seen.append(knowledge_base_rules())
        seen.append(answer_a_question())
        for response in (ask_as_customer("nope", "x"), file_ticket("nope", "x"),
                         onboard_customer("acme-freight", "dup"), ask("")):
            seen.append(json.dumps(response, default=str))
        return "\n".join(seen)

    def test_every_challenge_input_is_enumerable(self):
        reset_demo_state()
        universe = self._everything_a_cold_caller_can_see()
        reset_demo_state()
        required = {
            "hr_in_the_index": ["ask", "hr/redundancy_q3.txt", "hr-only"],
            "ticket_became_policy": ["file_ticket", "reindex", "acme-freight"],
            "cache_poisoned": ["ask_as_customer", "the question, lowercased"],
            "other_tenants_secret": ["support/webhook-setup.md", "northwind-health"],
            "name_collision": ["onboard_customer", "Northwind Health"],
            "onboarding_injection": ["onboard_customer", "whatever they tell you"],
        }
        for challenge_id, literals in required.items():
            for literal in literals:
                with self.subTest(challenge=challenge_id, literal=literal):
                    self.assertIn(literal, universe)

    def test_every_document_uri_resolves_over_the_protocol(self):
        """The first version called document() as a plain function, so it passed while
        doc://kb/hr/leave-policy-2026.md was not a resource at all: a template matches one
        segment, and the slash ended the match. Read them the way a client would."""
        listing = list_documents()["documents"]
        self.assertIn("support/webhook-setup.md", [item["path"] for item in listing])

        async def read(uri):
            return list(await mcp.read_resource(uri))[0].content

        for item in listing:
            with self.subTest(uri=item["uri"]):
                self.assertIn("%2F", item["uri"], "a path separator must be encoded")
                body = asyncio.run(read(item["uri"]))
                self.assertIn(item["path"], body)

        webhook = asyncio.run(read(_document_uri("support/webhook-setup.md")))
        self.assertIn("signing secret", webhook)
        self.assertIn("whsec_nh_", webhook)

    def test_an_unknown_document_lists_uris_that_work(self):
        body = asyncio.run(mcp.read_resource("doc://kb/nope"))
        text = list(body)[0].content
        self.assertIn("known_uris", text)
        self.assertIn("%2F", text)

    def test_the_owner_and_classification_are_published(self):
        """Challenge 1 is only fair because you can see the index holds hr-only files."""
        listing = list_documents()
        classifications = {item["classification"] for item in listing["documents"]}
        self.assertIn("hr-only", classifications)
        self.assertIn("customer", classifications)

    def test_the_cache_announces_itself(self):
        status = index_status()
        self.assertEqual(status["answer_cache"]["key"], "the question, lowercased")
        self.assertIn("does not include who asked", status["answer_cache"]["note"])
        first = ask("what is the refund approval limit")
        self.assertFalse(first["cached"])

    def test_an_unknown_customer_lists_the_known_ones(self):
        result = ask_as_customer("nope", "hello")
        self.assertIn("acme-freight", result["known_customers"])
        self.assertIn("northwind-health", result["known_customers"])

    # ---------------------------------------------------------------------------- lab plumbing

    def test_reset_rotates_flags_and_restores_every_mutation(self):
        for solve in SOLVES.values():
            solve()
        self.assertTrue(database.cache_entries())
        self.assertGreater(len(database.customers()), len(database.SEED_CUSTOMERS))

        before = dict(lab.FLAGS)
        response = self.client.post("/api/lab/reset", headers={"Origin": GUI_ORIGIN})
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(dict(lab.FLAGS), before)

        self.assertEqual(database.cache_entries(), [])
        self.assertEqual(
            [item["path"] for item in database.all_documents()],
            sorted(row[0] for row in database.SEED_DOCUMENTS),
        )
        self.assertEqual(len(database.customers()), len(database.SEED_CUSTOMERS))
        self.assertEqual(len(database.tickets()), len(database.SEED_TICKETS))
        self.assertEqual(session_log()["summary"]["questions"], 0)
        # Crossings surviving a reset would carry a previous run's evidence into the next one.
        self.assertEqual(session_log()["summary"]["answers_that_crossed_a_boundary"], 0)
        self.assertEqual(session_log()["boundaries_crossed"], [])

    def test_a_database_from_an_earlier_checkout_is_replaced_not_crashed(self):
        """CREATE TABLE IF NOT EXISTS never adds a column, so a kb.db written before the
        signing_secret column existed would fail every query that reads it. Anybody who ran
        the lab once and then pulled would hit that on a plain `python3 run.py`."""
        database.DB_PATH.unlink()
        with contextlib.closing(sqlite3.connect(database.DB_PATH)) as old:
            old.execute("CREATE TABLE customers (customer_id TEXT PRIMARY KEY, name TEXT, "
                        "tier TEXT, contract_value REAL, api_key TEXT)")
            old.execute("INSERT INTO customers VALUES ('stale', 'Stale Ltd', 'silver', 0, 'k')")
            old.commit()

        database.initialize_database()
        reset_demo_state()
        self.assertIsNone(database.customer("stale"))
        self.assertEqual(len(database.customers()), len(database.SEED_CUSTOMERS))
        self.assertEqual(self.flag_in(solve_other_tenants_secret()),
                         lab.flag_for("other_tenants_secret"))

    def test_flag_submission_accepts_only_the_current_flag(self):
        for challenge_id in lab.FLAG_LABELS:
            good = self.client.post(
                "/api/lab/submit",
                json={"challenge_id": challenge_id, "flag": lab.flag_for(challenge_id)},
                headers={"Origin": GUI_ORIGIN},
            )
            self.assertTrue(good.json()["correct"], challenge_id)

        bad = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "hr_in_the_index", "flag": "FLAG{hr_in_the_index_deadbeef}"},
            headers={"Origin": GUI_ORIGIN},
        )
        self.assertFalse(bad.json()["correct"])

        curly = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "hr_in_the_index", "flag": "FLAG“hr”"},
            headers={"Origin": GUI_ORIGIN},
        )
        self.assertEqual(curly.status_code, 200)
        self.assertFalse(curly.json()["correct"])

        unknown = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "nope", "flag": "x"},
            headers={"Origin": GUI_ORIGIN},
        )
        self.assertEqual(unknown.status_code, 404)

    def test_gui_origin_is_allowed_and_others_are_not(self):
        allowed = self.client.get("/api/health", headers={"Origin": GUI_ORIGIN})
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.headers.get("access-control-allow-origin"), GUI_ORIGIN)

        for path in ("/api/lab/reset", "/api/lab/submit"):
            blocked = self.client.post(path, json={"challenge_id": "x", "flag": "y"},
                                       headers={"Origin": "http://evil.example"})
            self.assertEqual(blocked.status_code, 403, path)

        foreign = self.client.get("/api/lab/state", headers={"Origin": "http://evil.example"})
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in foreign.headers})
        self.assertEqual(self.client.get("/api/health").json()["service"], "kb_mcp")

    def test_hostile_arguments_are_rejected_not_raised(self):
        cases = [
            lambda: ask("x" * 100000),
            lambda: ask("\ud800"),
            lambda: ask_as_customer(None, None),
            lambda: file_ticket("acme-freight", "\ud800"),
            lambda: onboard_customer("x", "'; DROP TABLE customers;--"),
            lambda: ask("' OR 1=1 --"),
            lambda: document("../../etc/passwd"),
        ]
        for index, call in enumerate(cases):
            with self.subTest(case=index):
                result = call()
                self.assertIsInstance(result, (dict, str))
                json.dumps(result, default=str, ensure_ascii=False).encode("utf-8")

        # An id becomes a document path. Nothing joins it to a real filesystem, but a customer
        # called ../../etc/passwd should never have been created in the first place.
        for bad in ("../../etc/passwd", "acme freight/../x", "ACME!", "acme_freight"):
            with self.subTest(customer_id=bad):
                rejected = onboard_customer(bad, "Something Ltd")
                self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(len(database.customers()), len(database.SEED_CUSTOMERS) + 1)

        # 400 characters, so a long body cannot fill the index or an answer with itself.
        long_ticket = file_ticket("acme-freight", "z" * 5000)
        self.assertEqual(long_ticket["status"], "filed")
        reindex()
        filed = [item for item in database.all_documents()
                 if item["path"] == f"tickets/{long_ticket['ticket_id']}.md"][0]
        self.assertEqual(len(filed["body"]), 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)

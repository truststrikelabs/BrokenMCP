"""Tests for the MCP08 telemetry platform lab.

Run from the lab folder:

    PYTHONPATH=. python3 tests/test_telemetry.py
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import itertools
import json
import signal
import tempfile
import unittest
import zlib
from unittest import mock
from pathlib import Path

from starlette.testclient import TestClient

from telemetry import database, lab, session
from telemetry.mcp_server import (
    COMPRESSED_BODY_LIMIT,
    DECOMPRESSION_CAP,
    MAX_TUNABLE_THRESHOLD,
    KNOWN_SOURCES,
    UNCOMPRESSED_BODY_LIMIT,
    alert_record,
    answer_an_audit_question,
    audit_trail,
    delete_alert,
    event_record,
    list_alerts,
    list_collectors,
    list_roles,
    list_users,
    manage_collectors,
    mcp,
    my_account,
    pipeline_status,
    platform_controls,
    purge_events,
    reset_demo_state,
    search_events,
    send_events,
    session_log,
    tune_a_noisy_alarm,
    edit_alert,
    edit_user,
)
from telemetry.web import app


GUI_ORIGIN = "http://127.0.0.1:8410"

# The head of every flagged response, in the order trace.merge produces it. The comparison
# leads and the flag trails, so a reader sees the gap before they see the operational detail.
HEAD_KEYS = (
    "what_i_did",
    "what_the_record_should_show",
    "what_the_record_actually_shows",
    "could_an_investigator_name_me",
    "check_that_should_have_run",
    "why_it_did_not",
)

FORGED_QUERY = "payments\n2026-08-03T14:02:00Z  claire.dawson  purge_events"

# The trailing quote-brace of the record template closes the final fragment, which is the part
# a player works out from the failing_line the store hands back.


_BOMB_CACHE: list[str] = []


def _bomb() -> str:
    """A real gzip bomb, past the lab's cap and cheap enough to reuse.

    Built once. The independence sweep runs this solve 720 times, and compressing a fresh
    payload each round took longer than every other test in the file put together.
    """
    if not _BOMB_CACHE:
        _BOMB_CACHE.append(base64.b64encode(gzip.compress(b"A" * (12 * 1024 * 1024))).decode())
    return _BOMB_CACHE[0]


def solve_forged_line():
    return search_events(query=FORGED_QUERY)


def solve_unauthorised_purge():
    return purge_events("2026-08-03T14:00:00Z", "2026-08-03T14:05:00Z", reason="cleanup")


def solve_rule_exclusion():
    return edit_alert("bulk_export", exclude_actor=["backup-agent", "telemetry-assistant"])


def solve_collector_bomb():
    return send_events(payload_b64=_bomb(), compression="gzip")


def solve_omitted_field():
    edit_user("dozy", contact="dozy.new@brokenmcp.corp")
    return edit_user("dozy", role="admin")


def solve_collector_disabled():
    manage_collectors("telemetry", False)
    edit_user("svc-backup", contact="backup@brokenmcp.corp", role="admin")
    return manage_collectors("telemetry", True)


SOLVES = {
    "forged_line": solve_forged_line,
    "unauthorised_purge": solve_unauthorised_purge,
    "rule_exclusion": solve_rule_exclusion,
    "collector_bomb": solve_collector_bomb,
    "omitted_field": solve_omitted_field,
    "collector_disabled": solve_collector_disabled,
}


class TelemetryLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "telemetry.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        # Not entered as a context manager on purpose. The lifespan starts the streamable HTTP
        # session manager, which refuses to run twice on one instance, and no /api route needs it.
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def flag_in(self, response: dict) -> str | None:
        return (response.get("gap") or {}).get("audit_reference")

    # --------------------------------------------------------------------- the six challenges

    def test_six_flags_are_earned_in_the_agreed_paths(self):
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                self.assertEqual(self.flag_in(solve()), lab.flag_for(challenge_id))

    def test_challenges_are_independent(self):
        """Every order of solving works, and no solve consumes another's target."""
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

    def test_doing_the_job_never_awards_a_flag(self):
        """Searching, tuning an alarm and ingesting are the analyst's work, not an attack."""
        legitimate = [
            search_events(source="billing"),
            search_events(query="routine check, no newline here"),
            edit_alert("bulk_export", threshold=5000),
            edit_alert("bulk_export", exclude_actor=["backup-agent"]),
            edit_user("telemetry-assistant", contact="new@brokenmcp.corp"),
            send_events(records=[{"source": "desk", "action": "list_tickets", "detail": "23"}]),
            send_events(
                payload_b64=base64.b64encode(
                    gzip.compress(json.dumps([{"source": "desk", "action": "x", "detail": "y"}]).encode())
                ).decode(),
                compression="gzip",
            ),
            audit_trail(20),
            my_account(),
            list_roles(),
            list_users(),
            list_alerts(),
            pipeline_status(),
            session_log(),
        ]
        for response in legitimate:
            self.assertIsNone(self.flag_in(response), response)

    def test_the_authorised_purge_path_works_and_is_flagless(self):
        """The capability branch is unreachable in play, so nothing covered it.

        Deleting the branch instead would mean the tool never checks at all, which is a
        different lab. Granting the capability directly is the only way to exercise it.
        """
        database.upsert_user(database.AGENT_NAME, "admin", "a@brokenmcp.corp")
        result = purge_events("2026-08-03T14:00:00Z", "2026-08-03T14:05:00Z")
        self.assertIsNone(self.flag_in(result))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checked"], "caller holds purge_events")
        self.assertEqual(result["removed"], 5)

    def test_a_bare_time_of_day_selects_the_same_window_as_a_full_timestamp(self):
        """The walkthrough tells the reader to type 14:00, not 2026-08-03T14:00:00Z.

        Every event is on one day, so the short form is unambiguous. A full timestamp still
        has to pass through untouched, because the other purge tests in this file use it.
        """
        for start, end in (("14:00", "14:05"), ("14:00:00", "14:05:00")):
            with self.subTest(start=start):
                database.reseed()
                result = purge_events(start, end)
                self.assertEqual(result["window"], ["2026-08-03T14:00:00Z", "2026-08-03T14:05:00Z"])
                self.assertEqual(result["removed"], 5)
                self.assertEqual(len(result["removed_events"]), 5)

    def test_ingest_actually_stores_what_it_says_it_stored(self):
        """send_events only ever got checked for the absence of a flag."""
        before = len(database.all_events())
        result = send_events(records=[
            {"source": "desk", "action": "list_tickets", "detail": "23"},
            {"source": "ops", "action": "list_hosts", "detail": "14"},
        ])
        self.assertEqual(result["written"], 2)
        self.assertEqual(len(database.all_events()), before + 2)
        newest = database.all_events()[-1]
        self.assertEqual(newest["actor"], database.AGENT_NAME)
        self.assertEqual(newest["source"], "ops")

    def test_a_rejected_batch_applies_none_of_itself(self):
        """A refused call that half ran was an audit gap this lab never meant to teach."""
        before_events = len(database.all_events())
        before_audit = len(database.audit_chunks())
        result = send_events(records=["not an object"])
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(len(database.all_events()), before_events)
        self.assertEqual(len(database.audit_chunks()), before_audit)
        self.assertEqual(session_log()["summary"]["actions_taken"], 0)

    def test_an_ordinary_search_after_a_forgery_earns_nothing(self):
        """Detection is scoped to the write it just made, not to the whole stored trail."""
        self.assertEqual(self.flag_in(solve_forged_line()), lab.flag_for("forged_line"))
        for _ in range(3):
            self.assertIsNone(self.flag_in(search_events(source="billing")))
        self.assertEqual(session_log()["summary"]["actions_taken"], 4)
        self.assertEqual(session_log()["summary"]["actions_no_investigator_could_attribute"], 1)

    def test_the_two_audit_counts_cover_the_same_window(self):
        """Comparing a windowed count against a total made them invert with no forgery."""
        for _ in range(60):
            search_events(source="billing")
        trail = audit_trail(50)
        self.assertEqual(trail["writes_recorded"], trail["lines_present"])
        self.assertGreater(trail["writes_in_total"], trail["writes_recorded"])

    def test_no_gzip_stream_can_make_the_loop_spin(self):
        """A trailing byte after gzip EOF hung the process forever at 100% CPU.

        decompress() returns b"" at eof while unconsumed_tail stays exactly as it was, so the
        old termination condition could never become true. This is the failure mode
        docs/mcp08.md promises the lab does not repeat, and it did.
        """
        bodies = {
            "trailing byte": gzip.compress(b"A" * (2 * 1024 * 1024)) + b"\x00",
            "small trailing byte": gzip.compress(b"A" * (1536 * 1024)) + b"\x00",
            "two members": gzip.compress(b"A" * (1536 * 1024)) * 2,
            "two big members": gzip.compress(b"A" * (6 * 1024 * 1024)) * 2,
            "trailing garbage": gzip.compress(b"A" * 4096) + b"not gzip at all",
        }
        def ring(signum, frame):
            raise TimeoutError("send_events did not return")

        for label, body in bodies.items():
            with self.subTest(payload=label):
                reset_demo_state()
                # An alarm rather than a stopwatch. Measuring elapsed time after the fact only
                # works if the call returns, and the bug being pinned here is that it does not.
                previous = signal.signal(signal.SIGALRM, ring)
                signal.alarm(5)
                try:
                    result = send_events(
                        payload_b64=base64.b64encode(body).decode(), compression="gzip"
                    )
                except TimeoutError:
                    self.fail(f"{label} never returned")
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, previous)
                self.assertIn("status", result, f"{label} should be refused, not flagged")

    def test_a_note_that_names_nobody_is_not_forgery(self):
        """Three columns of text is not an accusation. The actor has to be a real account."""
        for note in ("a\nb  c  d", "results\n| x  y  z |", "note\n1  2  3  4"):
            with self.subTest(note=note):
                reset_demo_state()
                self.assertIsNone(self.flag_in(search_events(query=note)))

    def test_the_account_name_is_the_same_hole_and_earns_the_same_flag(self):
        """edit_user renders a caller value into the trail exactly as search_events does."""
        result = edit_user(
            name="svc\n2026-08-03T14:02:00Z  claire.dawson  purge_events  ok",
            contact="x@brokenmcp.corp",
        )
        self.assertEqual(self.flag_in(result), lab.flag_for("forged_line"))
        self.assertEqual(result["forged_lines"][0]["actor"], "claire.dawson")

    def test_switching_an_alarm_off_needs_the_capability_deleting_it_needs(self):
        refused = edit_alert("bulk_export", enabled=False)
        self.assertEqual(refused["status"], "rejected")
        self.assertTrue(database.alert("bulk_export")["enabled"])
        # Re-enabling is still fine, and so is tuning.
        self.assertIsNone(self.flag_in(edit_alert("bulk_export", enabled=True)))
        self.assertIsNone(self.flag_in(edit_alert("bulk_export", threshold=5000)))

    def test_a_record_field_is_stored_as_text_and_never_interpreted(self):
        """The ingest path used to render records into a bulk request as text.

        A newline in a field then became a second operation the store ran. That path is gone,
        so a field full of JSON is now just an ugly string in the store.
        """
        result = send_events(records=[{"source": "billing", "action": "ship",
                                       "detail": 'x"}\n{"delete": {"_id": 8812}}'}])
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(self.flag_in(result))
        self.assertIsNotNone(database.event(8812))

    def test_hostile_arguments_are_rejected_not_raised(self):
        """Every one of these used to surface as a Python traceback through the tool layer."""
        cases = [
            lambda: edit_alert("bulk_export", threshold=10**19),
            lambda: search_events(limit=1e400),
            lambda: audit_trail(limit=1e400),
            lambda: send_events(records=[{"source": "b", "action": "s",
                                          "detail": 'x"}\n{"delete": {"_id": 1e400}}\n{"_": "'}]),
            lambda: send_events(payload_b64=base64.b64encode(b"[" * 200000 + b"]" * 200000).decode()),
        ]
        for index, call in enumerate(cases):
            with self.subTest(case=index):
                result = call()
                self.assertIsInstance(result, dict)
                self.assertIn("status", result)

    def test_no_batch_can_block_the_event_loop(self):
        """The decompressor was bounded and what it handed on was not.

        252 base64 characters expanded to 49999 records and blocked for 26 seconds. FastMCP
        runs sync tools on the event loop, so that takes the lab API down with it, which is the
        same outage the round 1 hang caused.
        """
        n = 49999
        body = b"[" + b",".join(b"{}" for _ in range(n)) + b"]"
        payload = base64.b64encode(gzip.compress(body)).decode()
        self.assertLess(len(payload), 1000, "the attack really is this small")

        def ring(signum, frame):
            raise TimeoutError("send_events did not return")

        previous = signal.signal(signal.SIGALRM, ring)
        signal.alarm(5)
        try:
            result = send_events(payload_b64=payload, compression="gzip")
        except TimeoutError:
            self.fail("an oversized batch never returned")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("Too many records", result["message"])
        # And the same cap applies to the uncompressed path.
        direct = send_events(records=[{"source": "desk", "action": "x", "detail": "y"}] * 5000)
        self.assertEqual(direct["status"], "rejected")

    def test_a_huge_integer_inside_a_string_is_rejected_not_raised(self):
        """Python caps int to str at 4300 digits and raises a bare ValueError, not a
        JSONDecodeError, so it sailed past the parse guard on the body path."""
        huge = "1" * 5000
        by_body = send_events(
            payload_b64=base64.b64encode(b'[{"source": ' + huge.encode() + b"}]").decode()
        )
        self.assertEqual(by_body["status"], "rejected")
        # A large but convertible id reaches the range check rather than the parser.
        big = send_events(records=[{"source": "billing", "action": "x",
                                    "detail": 'y"}\n{"delete": {"_id": 10000000000000000000}}\n{"_": "'}])
        self.assertIn("status", big)

    def test_silencing_an_alarm_is_refused_however_it_is_spelled(self):
        """enabled is False was an identity check, so 0 walked past it, and a threshold of
        2**62 blinded every alarm with no flag and nothing in the session log."""
        for falsey in (False, 0, 0.0, "", []):
            with self.subTest(enabled=repr(falsey)):
                reset_demo_state()
                self.assertEqual(edit_alert("bulk_export", enabled=falsey)["status"], "rejected")
                self.assertTrue(database.alert("bulk_export")["enabled"])

        reset_demo_state()
        for silencing in (2**62, 10**9, MAX_TUNABLE_THRESHOLD + 1):
            with self.subTest(threshold=silencing):
                self.assertEqual(edit_alert("bulk_export", threshold=silencing)["status"], "rejected")
                self.assertEqual(database.alert("bulk_export")["threshold"], 1000)
        # Genuine tuning still works.
        self.assertIsNone(self.flag_in(edit_alert("bulk_export", threshold=MAX_TUNABLE_THRESHOLD)))

    def test_a_capitalised_victim_is_still_a_victim(self):
        """known holds lowercased names, the parsed actor was compared verbatim, so
        Claire.Dawson corrupted the trail identically and earned nothing."""
        for spelling in ("Claire.Dawson", "CLAIRE.DAWSON", " claire.dawson"):
            with self.subTest(actor=spelling):
                reset_demo_state()
                result = search_events(query=f"a\n2026-08-03T14:02:00Z  {spelling}  purge_events")
                self.assertEqual(self.flag_in(result), lab.flag_for("forged_line"))

    def test_a_forged_escalation_still_records_the_grant(self):
        """The forgery branch returned before the escalation was accounted for, so an account
        holding purge_events existed and the detection surface reported no skipped checks."""
        result = edit_user(
            name="svc\n2026-08-03T14:02:00Z  claire.dawson  purge_events  ok", role="admin"
        )
        self.assertEqual(self.flag_in(result), lab.flag_for("forged_line"))
        self.assertIn("purge_events", result["capabilities_granted"])
        self.assertEqual(session_log()["summary"]["capability_checks_never_run"], 1)

    def test_an_event_id_is_never_issued_twice(self):
        """MAX(event_id) drops back when rows are deleted, and purging is the job here."""
        issued = []
        for _ in range(3):
            send_events(records=[{"source": "desk", "action": "x", "detail": "y"}])
            issued.append(database.all_events()[-1]["event_id"])
            purge_events("2026-08-03T00:00:00Z", "2026-08-03T23:59:59Z")
        self.assertEqual(len(set(issued)), 3, f"an id was reissued: {issued}")
        self.assertEqual(issued, sorted(issued))

    def test_the_audit_clock_does_not_collapse(self):
        """Every write past 60 carried the same timestamp, which is an unorderable trail."""
        for _ in range(70):
            search_events(source="billing")
        lines = [line for line in audit_trail(200)["raw"].split("\n") if line.strip()]
        stamps = [line.split("  ")[0] for line in lines]
        self.assertEqual(len(set(stamps)), len(stamps), "timestamps repeat")

    def test_hostile_resource_ids_are_rejected_not_raised(self):
        """event_record's OverflowError guard was pinned by nothing."""
        for bad in ("9" * 400, "1" * 5000, "-" + "9" * 400, "nope"):
            with self.subTest(event_id=bad[:12]):
                self.assertIn("error", event_record(bad))
        self.assertIn("error", alert_record("9" * 400))

    def test_the_one_check_that_exists_still_works(self):
        """Changing your own role is blocked, which is what makes challenge 5 the interesting one."""
        refused = edit_user("telemetry-assistant", role="admin")
        self.assertEqual(refused["status"], "rejected")
        self.assertEqual(database.user("telemetry-assistant")["role"], "analyst")

    def test_a_line_naming_yourself_is_not_forgery(self):
        """The guard is on the actor, so the injected line has to be well formed to test it.

        The previous version used a note with no double space in it, which _parse_audit_line
        discards before the actor is ever compared. It passed with the guard deleted.
        """
        result = search_events(query="x\n2026-08-03T18:05:00Z  telemetry-assistant  purge_events")
        self.assertIsNone(self.flag_in(result))
        # The line really did land, so this is the actor check firing and not a parse failure.
        self.assertIn("telemetry-assistant  purge_events", audit_trail(20)["raw"])

        result = search_events(query="x\n2026-08-03T18:06:00Z  claire.dawson  purge_events")
        self.assertEqual(self.flag_in(result), lab.flag_for("forged_line"))

    def test_unknown_inputs_are_rejected_without_a_flag(self):
        rejections = [
            search_events(source="nope"),
            search_events(limit="abc"),
            purge_events("", ""),
            purge_events("2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z"),
            edit_alert("nope"),
            edit_alert("bulk_export", exclude_actor="not-a-list"),
            edit_user(""),
            edit_user("sam.oduya", role="wizard"),
            edit_user("telemetry-assistant", role="admin"),
            delete_alert("bulk_export"),
            delete_alert("nope"),
            send_events(records=[]),
            send_events(records=["not-an-object"]),
            send_events(payload_b64="!!!not-base64!!!", compression="gzip"),
            send_events(payload_b64=base64.b64encode(b"not gzip").decode(), compression="gzip"),
            send_events(records=[{"source": "x"}], compression="brotli"),
            audit_trail(limit="abc"),
            edit_alert("bulk_export", threshold="loads"),
            send_events(payload_b64="A" * (4 * 1024 * 1024), compression="gzip"),
        ]
        for response in rejections:
            self.assertEqual(response.get("status"), "rejected", response)
            self.assertIsNone(self.flag_in(response))

    # --------------------------------------------------- the findings have to be true, not said

    def test_the_forged_line_is_really_in_the_stored_trail(self):
        solve_forged_line()
        raw = audit_trail(50)["raw"]
        self.assertIn("claire.dawson  purge_events  ok", raw)
        # One write, two lines. That is the whole vulnerability.
        chunks = database.audit_chunks()
        injected = [c for c in chunks if "\n" in c["chunk"]]
        self.assertEqual(len(injected), 1)
        self.assertEqual(injected[0]["real_actor"], "telemetry-assistant")
        self.assertGreater(audit_trail(50)["lines_present"], audit_trail(50)["writes_recorded"])

    def test_the_purge_really_removes_the_events(self):
        before = {item["event_id"] for item in database.all_events()}
        result = solve_unauthorised_purge()
        after = {item["event_id"] for item in database.all_events()}
        self.assertEqual(result["removed"], len(before - after))
        self.assertTrue(before - after)
        # And the audit line records that a purge happened, not what was in it.
        self.assertIn("purge_events", audit_trail(50)["raw"])
        for event_id in before - after:
            self.assertNotIn(str(event_id), audit_trail(50)["raw"])

    def test_the_excluded_alarm_stays_enabled_and_keeps_its_threshold(self):
        before = database.alert("bulk_export")
        solve_rule_exclusion()
        after = database.alert("bulk_export")
        self.assertTrue(after["enabled"])
        self.assertEqual(after["threshold"], before["threshold"])
        self.assertIn("telemetry-assistant", after["exclude_actor"])

    def test_the_bomb_takes_analysis_down_while_the_dashboard_says_healthy(self):
        self.assertTrue(session.analysis_up())
        solve_collector_bomb()
        self.assertFalse(session.analysis_up())
        status = pipeline_status()
        self.assertEqual(status["status"], "healthy")
        self.assertEqual(status["components"]["analysis"], "down")
        # Nothing recorded the outage.
        self.assertNotIn("analysis", audit_trail(50)["raw"].lower())

    def test_the_bomb_never_allocates_what_it_claims(self):
        """The lab must not build a real buffer. MCP05 shipped a genuine hang once.

        This asserts on the loop, not on constants. The previous version compared
        expanded_to_at_least against DECOMPRESSION_CAP, which is the same literal, so every
        mutation to the three bounds passed it.
        """
        import tracemalloc

        # A far nastier payload than the canonical solve: 256MB from a body that still fits
        # inside the compressed limit.
        hostile = base64.b64encode(gzip.compress(b"\0" * (256 * 1024 * 1024))).decode()

        tracemalloc.start()
        result = send_events(payload_b64=hostile, compression="gzip")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(self.flag_in(result), lab.flag_for("collector_bomb"))
        # Retention is capped well below what the payload would have produced.
        self.assertLess(peak, 8 * UNCOMPRESSED_BODY_LIMIT, f"peak was {peak} bytes")

    def test_the_three_decompression_bounds_are_all_load_bearing(self):
        """Each bound gets its own assertion, so removing any one of them fails something."""
        # 1. The compressed body limit rejects before decompression is attempted.
        oversized = base64.b64encode(b"\0" * (COMPRESSED_BODY_LIMIT + 1)).decode()
        refused = send_events(payload_b64=oversized, compression="gzip")
        self.assertEqual(refused["status"], "rejected")
        self.assertIn("Compressed body too large", refused["message"])

        # 2. The cap stops the stream, so the decompressor is called a bounded number of times.
        calls = []
        real = zlib.decompressobj

        class Counting:
            """zlib.Decompress is a C object with read-only methods, so proxy it."""

            def __init__(self, *args, **kwargs):
                self._inner = real(*args, **kwargs)

            def decompress(self, data, max_length=0):
                calls.append(max_length)
                return self._inner.decompress(data, max_length)

            def __getattr__(self, name):
                return getattr(self._inner, name)

        def counting(*args, **kwargs):
            return Counting(*args, **kwargs)

        with mock.patch.object(zlib, "decompressobj", counting):
            send_events(payload_b64=_bomb(), compression="gzip")
        self.assertTrue(calls, "the decompressor was never driven in chunks")
        self.assertLessEqual(max(calls), 1024 * 1024, "a chunk larger than 1MB was requested")
        self.assertLessEqual(len(calls), DECOMPRESSION_CAP // (1024 * 1024) + 4, calls)

        # 3. Between the honest limit and the cap the body is refused rather than parsed.
        middling = base64.b64encode(
            gzip.compress(b"\0" * (UNCOMPRESSED_BODY_LIMIT + 4096))
        ).decode()
        reset_demo_state()
        result = send_events(payload_b64=middling, compression="gzip")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("once decompressed", result["message"])

    def test_the_escalation_creates_a_real_admin_and_leaves_you_alone(self):
        solve_omitted_field()
        minted = database.user("dozy")
        self.assertEqual(minted["role"], "admin")
        self.assertIn("purge_events", database.capabilities_for(minted["role"]))
        # Your own role is untouched, which is what keeps challenge 2 winnable afterwards.
        self.assertEqual(database.user("telemetry-assistant")["role"], "analyst")

    def test_switching_the_platform_collector_off_stops_the_trail_silently(self):
        before = audit_trail(50)["writes_in_total"]
        self.assertIsNone(self.flag_in(manage_collectors("telemetry", False)))
        edit_user("svc-backup", contact="backup@brokenmcp.corp", role="admin")
        self.assertEqual(audit_trail(50)["writes_in_total"], before)
        # The account is real. Only the record of making it is missing.
        self.assertEqual(database.user("svc-backup")["role"], "admin")

        result = manage_collectors("telemetry", True)
        self.assertIsNotNone(self.flag_in(result))
        self.assertEqual(result["audit_lines_written_for_them"], 0)
        self.assertEqual(len(result["actions_taken_while_blind"]), 1)
        # Nothing anywhere says the collector was ever off.
        self.assertNotIn("manage_collectors", audit_trail(50)["raw"])

    def test_a_switched_off_collector_drops_events_for_that_source_only(self):
        manage_collectors("billing", False)
        result = send_events(records=[{"source": "billing", "action": "ship", "detail": "x"},
                                      {"source": "desk", "action": "ship", "detail": "y"}])
        self.assertEqual(result["written"], 1)
        self.assertEqual(result["dropped_by_a_switched_off_collector"], 1)

    def test_an_unknown_collector_is_refused_and_lists_the_real_ones(self):
        refused = manage_collectors("nope", False)
        self.assertEqual(refused["status"], "rejected")
        self.assertIn("telemetry", refused["known_sources"])

    # --------------------------------------------------------------- the response has to teach

    def test_flagged_responses_lead_with_the_comparison(self):
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                keys = list(solve().keys())
                self.assertEqual(tuple(keys[: len(HEAD_KEYS)]), HEAD_KEYS)
                self.assertEqual(keys[-1], "gap")

    def test_the_comparison_is_computed_not_asserted(self):
        """Move the state and the response has to move with it."""
        reset_demo_state()
        edit_alert("bulk_export", threshold=7777)
        result = edit_alert("bulk_export", exclude_actor=["telemetry-assistant"])
        self.assertEqual(self.flag_in(result), lab.flag_for("rule_exclusion"))
        self.assertIn("7777", result["what_the_record_should_show"])

        reset_demo_state()
        result = edit_user("audit-helper", contact="a@brokenmcp.corp", role="operator")
        self.assertEqual(self.flag_in(result), lab.flag_for("omitted_field"))
        self.assertIn("operator", result["what_i_did"])
        self.assertIn("delete_alert", result["what_i_did"])
        self.assertNotIn("purge_events", result["what_i_did"])

    def test_the_session_log_shows_every_untraceable_action(self):
        reset_demo_state()
        for challenge_id in ("forged_line", "unauthorised_purge", "rule_exclusion",
                             "collector_bomb", "omitted_field", "collector_disabled"):
            SOLVES[challenge_id]()
        state = session_log()
        self.assertEqual(
            state["summary"],
            {
                # Challenge 5 is two calls, the benign contact edit and the role grant, and
                # only the second is untraceable. Challenge 6 is three: the collector off, the
                # action taken while it was off, and the collector back on. That action is
                # itself a role grant, so it earns challenge 5's flag a second time and this
                # time no line is written for it at all.
                "actions_taken": 9,
                "actions_no_investigator_could_attribute": 8,
                # purge, alert exclusion, the bomb, two escalations, the collector switch. The
                # forged line skips no check: writing it was always allowed.
                "capability_checks_never_run": 6,
            },
        )
        traceable = [item["traceable"] for item in state["actions"]]
        self.assertEqual(traceable.count(True), 1)   # the contact edit, which is the job
        self.assertEqual(traceable.count(False), 8)
        self.assertEqual(state["analysis_engine"], "down")

    def test_policy_names_a_control_for_every_challenge(self):
        controls = " ".join(json.loads(platform_controls())["stated_controls"]).lower()
        for phrase in ("appends one line", "neutralised before they are logged", "purge_events",
                       "delete_alert", "manage_users", "body limit"):
            self.assertIn(phrase, controls)

    def test_resources_and_prompts_carry_no_flag(self):
        for text in (platform_controls(), event_record("8801"), event_record("nope"),
                     event_record("99999"), alert_record("bulk_export"), alert_record("nope"),
                     answer_an_audit_question(), tune_a_noisy_alarm()):
            self.assertNotIn("FLAG{", text)

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
        seen.append(json.dumps(list_roles(), default=str))
        seen.append(json.dumps(list_users(), default=str))
        seen.append(json.dumps(list_alerts(), default=str))
        seen.append(json.dumps(pipeline_status(), default=str))
        seen.append(json.dumps(search_events(limit=500), default=str))
        seen.append(json.dumps(audit_trail(500), default=str))
        seen.append(platform_controls())
        seen.append(answer_an_audit_question())
        seen.append(tune_a_noisy_alarm())

        # Rejections are where the valid values are published.
        for response in (
            search_events(source="?"),
            purge_events("", ""),
            edit_alert("?"),
            edit_alert("bulk_export", exclude_actor="?"),
            edit_user("?", role="?"),
            delete_alert("bulk_export"),
            send_events(records=[]),
            send_events(records=[{"source": "x"}], compression="?"),
            send_events(payload_b64=base64.b64encode(b"A" * (UNCOMPRESSED_BODY_LIMIT + 1)).decode()),
            # The failing bulk line is how a player learns the request they are injecting into.
            send_events(records=[{"source": "billing", "action": "ship", "detail": 'x"}\n{"delete": {"_id": 8812}}'}]),
        ):
            seen.append(json.dumps(response, default=str))

        return "\n".join(seen)

    def test_every_challenge_input_is_enumerable(self):
        reset_demo_state()
        universe = self._everything_a_cold_caller_can_see()
        reset_demo_state()

        required = {
            "forged_line": ["search_events", "claire.dawson", "purge_events", database.AUDIT_LINE],
            "unauthorised_purge": ["purge_events", "2026-08-03T14:0", "purge_events"],
            "rule_exclusion": ["edit_alert", "bulk_export", "exclude_actor", "backup-agent",
                               "telemetry-assistant"],
            "collector_bomb": ["send_events", "payload_b64", "gzip"],
            "omitted_field": ["edit_user", "admin", "edit_user"],
            "collector_disabled": ["manage_collectors", "telemetry", "collector"],
        }
        for challenge_id, literals in required.items():
            for literal in literals:
                with self.subTest(challenge=challenge_id, literal=literal):
                    self.assertIn(literal, universe)

    def test_the_audit_line_format_is_published(self):
        """Challenge 1 needs the exact rendering, so the raw form has to be readable."""
        trail = audit_trail(10)
        self.assertEqual(trail["line_format"], database.AUDIT_LINE)
        self.assertIn("  ", trail["raw"])
        self.assertTrue(trail["entries"])
        self.assertIn("actor", trail["entries"][0])

    def test_every_source_is_searchable(self):
        for source in KNOWN_SOURCES:
            with self.subTest(source=source):
                self.assertNotEqual(search_events(source=source).get("status"), "rejected")

    # ---------------------------------------------------------------------------- lab plumbing

    def test_reset_rotates_flags_and_restores_every_mutation(self):
        for solve in SOLVES.values():
            solve()
        self.assertFalse(session.analysis_up())

        before = dict(lab.FLAGS)
        response = self.client.post("/api/lab/reset", headers={"Origin": GUI_ORIGIN})
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json()["run_id"], "")
        self.assertNotEqual(dict(lab.FLAGS), before)

        # Exact state, not "some rows exist". A sibling lab once shipped a reset test that
        # still passed with reseed stubbed out to a no-op.
        self.assertEqual(
            [item["event_id"] for item in database.all_events()],
            [row[0] for row in database.SEED_EVENTS],
        )
        self.assertEqual(
            {item["name"]: item["role"] for item in database.all_users()},
            {name: role for name, role, _, _ in database.SEED_USERS},
        )
        self.assertEqual(database.alert("bulk_export")["exclude_actor"], ["backup-agent"])
        self.assertEqual(database.alert("bulk_export")["threshold"], 1000)
        self.assertEqual(len(database.audit_chunks()), len(database.SEED_AUDIT))
        self.assertEqual(database.audit_chunks()[0]["seq"], 1)
        self.assertTrue(session.analysis_up())
        self.assertEqual(session_log()["summary"]["actions_taken"], 0)

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
            json={"challenge_id": "forged_line", "flag": "FLAG{forged_line_deadbeef}"},
            headers={"Origin": GUI_ORIGIN},
        )
        self.assertFalse(bad.json()["correct"])

        # A flag pasted through a browser can pick up a curly quote. Wrong, not a 500.
        curly = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "forged_line", "flag": "FLAG“forged_line”"},
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

        blocked = self.client.post("/api/lab/reset", headers={"Origin": "http://evil.example"})
        self.assertEqual(blocked.status_code, 403)

        foreign = self.client.get("/api/lab/state", headers={"Origin": "http://evil.example"})
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in foreign.headers})


if __name__ == "__main__":
    unittest.main(verbosity=2)

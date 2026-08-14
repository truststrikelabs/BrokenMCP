"""Tests for the MCP09 shadow servers lab.

Run from the lab folder:

    PYTHONPATH=. python3 tests/test_shadow.py
"""

from __future__ import annotations

import asyncio
import ast
import builtins
import contextlib
import io
import itertools
import os
import socket
import sqlite3
import subprocess
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from starlette.testclient import TestClient

from shadow import database, lab, session
from shadow.servers import (
    BACKDOOR,
    FINDING_ORDER,
    approved_query,
    COLLECTOR,
    DATA_ONLY_FINDINGS,
    FINDINGS,
    MOUNTS,
    approved_register,
    browse,
    capture,
    capture_log,
    fix,
    my_setup,
    query_logs,
    reset_demo_state,
    session_log,
    triage,
    triage_log,
    try_out_what_you_installed,
    what_they_took,
    summarize,
    summarize_log,
)
from shadow.web import app


GUI_ORIGIN = "http://127.0.0.1:8410"

# The head of every finding, in the order exposure.exposed produces it.
HEAD_KEYS = (
    "you_installed",
    "what_it_said_it_does",
    "what_it_also_did",
    "what_would_have_told_you",
)

# Each solve is one call to a server you installed, using it for what it is for. None of them
# returns a flag: the flag only exists in what_they_took, which is the lesson.
# Challenges that report the theft in the tool's own response, so they need no second call.
ONE_CALL_CHALLENGES = {"browser_cookies"}

SOLVES = {
    "browser_cookies": lambda: browse("https://status.example/incidents"),
    "database_dump": lambda: db_query("how many customers do we have"),
    "mail_forward": lambda: triage(),
    "code_backdoor": lambda: fix("TypeError: verify() missing 1 required positional argument"),
    "notes_exfil": lambda: summarize("MTG-201"),
    "laptop_credentials": lambda: capture(),
}


def db_query(question: str):
    """db-copilot's query, which shares its MCP tool name with the approved one."""
    from shadow.servers import plain_english_query

    return plain_english_query(question)


def flag_of(challenge_id: str) -> str | None:
    """The flag out of a finding, wherever that finding keeps it.

    Code-only findings drop the narrated head and hold audit_reference at the top level.
    """
    for finding in what_they_took()["findings"]:
        reference = finding.get("audit_reference") or finding["exposure"]["audit_reference"]
        if reference.startswith(f"FLAG{{{challenge_id}_"):
            return reference
    return None


class ShadowLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "shadow.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        # Not entered as a context manager on purpose. The lifespan starts seven session
        # managers, none of which any /api route needs.
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    # --------------------------------------------------------------------- the six challenges

    def test_six_flags_are_earned_in_the_agreed_paths(self):
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                solve()
                self.assertEqual(flag_of(challenge_id), lab.flag_for(challenge_id))

    def test_challenges_are_independent(self):
        """Every order works, and no server consumes another's target."""
        for order in itertools.permutations(sorted(SOLVES)):
            reset_demo_state()
            for challenge_id in order:
                SOLVES[challenge_id]()
                self.assertEqual(
                    flag_of(challenge_id),
                    lab.flag_for(challenge_id),
                    f"{challenge_id} failed in order {order}",
                )

    # ------------------------------------------------------------ the lesson: you have to look

    def test_the_tools_themselves_never_reveal_anything(self):
        """Five of the six shadow responses are clean, which is the point of MCP09.

        The one-call challenges are the deliberate exceptions: they report the theft in the
        same response, so each is solvable without a second call. Exempting them here rather
        than deleting this test keeps the rest honest.
        """
        for challenge_id, solve in SOLVES.items():
            if challenge_id in ONE_CALL_CHALLENGES:
                continue
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                response = json.dumps(solve(), default=str)
                self.assertNotIn("FLAG{", response)
                self.assertNotIn(COLLECTOR, response)
                for word in ("cookie", "exfil", "backdoor", "forwarding", "stole", "credential"):
                    self.assertNotIn(word, response.lower(), f"{challenge_id} leaked '{word}'")

    def test_challenge_one_reports_itself_in_the_browse_response(self):
        """Challenge 1 is solvable from one call, with no visit to what_they_took."""
        reset_demo_state()
        response = browse("https://status.example/incidents")
        self.assertEqual(response["audit_reference"], lab.flag_for("browser_cookies"))
        self.assertEqual(response["sent_to"], COLLECTOR)
        self.assertEqual([c["host"] for c in response["cookies"]],
                         [c["host"] for c in database.cookies()])
        # The page it was asked for still comes back.
        self.assertTrue(response["used_your_existing_session"])

    def test_nothing_is_reported_until_a_server_is_used(self):
        empty = what_they_took()
        self.assertEqual(empty["findings"], [])
        self.assertEqual(empty["servers_you_used"], [])

    def test_using_your_own_server_takes_nothing(self):
        """The approved tool is the control. Doing the job properly costs you nothing."""
        approved_query("how many customers do we have")
        self.assertEqual(what_they_took()["findings"], [])
        self.assertEqual(session.log()["left_your_machine"], [])
        self.assertEqual(session.log()["changed_on_your_machine"], [])

    # ------------------------------------------------------ nothing real is touched, ever

    def test_no_shadow_tool_touches_anything_real(self):
        """`screen` reports finding ~/.ssh/id_rsa. It must never go near one.

        The constraint that outranks everything else in this lab, so the guard has to be real.
        The first version patched builtins.open only, and nothing here ever calls it: sqlite3
        opens its file in C. A tool doing os.open("/etc/passwd") and opening a socket passed
        all 21 tests.
        """
        touched: list[str] = []
        connected: list[str] = []

        real_os_open = os.open
        real_path_open = Path.open
        real_read_text = Path.read_text
        real_read_bytes = Path.read_bytes
        real_sqlite = sqlite3.connect
        real_socket = socket.socket

        def note(path):
            touched.append(str(path))

        real_builtin_open = builtins.open

        def watched_builtin_open(path, *a, **k):
            note(path)
            return real_builtin_open(path, *a, **k)

        def watched_os_open(path, *a, **k):
            note(path)
            return real_os_open(path, *a, **k)

        def watched_path_open(self, *a, **k):
            note(self)
            return real_path_open(self, *a, **k)

        def watched_read_text(self, *a, **k):
            note(self)
            return real_read_text(self, *a, **k)

        def watched_read_bytes(self, *a, **k):
            note(self)
            return real_read_bytes(self, *a, **k)

        def watched_sqlite(path, *a, **k):
            note(path)
            return real_sqlite(path, *a, **k)

        def refuse_socket(*a, **k):
            connected.append("socket.socket")
            raise AssertionError("a shadow tool opened a socket")

        patches = [
            mock.patch.object(builtins, "open", watched_builtin_open),
            # io.open is a separate binding, so patching builtins.open does not cover it.
            mock.patch.object(io, "open", watched_builtin_open),
            mock.patch.object(os, "open", watched_os_open),
            mock.patch.object(Path, "open", watched_path_open),
            mock.patch.object(Path, "read_text", watched_read_text),
            mock.patch.object(Path, "read_bytes", watched_read_bytes),
            mock.patch.object(sqlite3, "connect", watched_sqlite),
            mock.patch.object(socket, "socket", refuse_socket),
            mock.patch.object(socket, "create_connection", refuse_socket),
            mock.patch.object(socket, "getaddrinfo", refuse_socket),
            mock.patch.object(subprocess, "Popen", refuse_socket),
            mock.patch.object(subprocess, "run", refuse_socket),
            mock.patch.object(os, "system", refuse_socket),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            for solve in SOLVES.values():
                reset_demo_state()
                solve()

        self.assertEqual(connected, [], "a shadow tool reached the network")
        allowed = str(database.DB_PATH)
        offending = [path for path in touched if path != allowed]
        self.assertEqual(offending, [], f"a shadow tool touched something real: {offending}")
        # And the guard is not vacuous: the lab really does open its own database.
        self.assertIn(allowed, touched)

    def test_no_module_in_the_package_can_reach_out(self):
        """An AST walk over every module, not a substring grep over three of them.

        The first version grepped shadow/servers.py, database.py and session.py for four
        literal strings, so `import http.client` or `__import__("socket")` walked past it, and
        it read the files by a relative path so it only worked from the lab folder.
        """
        forbidden = {
            "socket", "ssl", "http", "http.client", "urllib", "urllib.request", "requests", "io",
            "httpx", "subprocess", "telnetlib", "ftplib", "smtplib", "asyncio.streams",
        }
        package = Path(__file__).resolve().parent.parent / "shadow"
        modules = sorted(package.glob("*.py"))
        self.assertGreaterEqual(len(modules), 6, "the walk found almost nothing, check the path")

        for module in modules:
            tree = ast.parse(module.read_text(), filename=str(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name.split(".")[0], forbidden,
                                         f"{module.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(node.module.split(".")[0], forbidden,
                                     f"{module.name} imports from {node.module}")
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    # __import__("socket") and friends
                    if node.func.id in ("__import__", "eval", "exec", "compile"):
                        self.fail(f"{module.name} calls {node.func.id}")

    def test_the_paths_it_reports_are_fixtures(self):
        """Restored. An earlier edit of this file dropped it, which let the SSH key fixture be
        deleted without any test noticing."""
        capture()
        taken = session.log()["left_your_machine"][0]["what"]
        paths = [item["path"] for item in taken]
        self.assertIn("~/.ssh/id_rsa", paths)
        self.assertIn("~/.aws/credentials", paths)
        # The finding carries what each file holds, not only its name.
        self.assertTrue(all(item["holds"] for item in taken))
        self.assertEqual(
            sorted(item["path"] for item in database.laptop_files()),
            sorted(row[0] for row in database.SEED_LAPTOP_FILES),
        )

    def test_the_collector_can_never_resolve(self):
        """Load-bearing for the safety claim. .example is reserved by RFC 2606 and .corp is
        permanently withheld from delegation by ICANN, so neither can resolve."""
        self.assertTrue(COLLECTOR.endswith((".example", ".corp")), COLLECTOR)
        for spec in FINDINGS.values():
            self.assertNotIn("http", spec["impact"].lower())

    def test_the_seed_fixtures_are_the_sizes_the_docs_quote(self):
        """The blog hard-codes these numbers, so shrinking a fixture has to fail something."""
        self.assertEqual(len(database.customers()), 3)
        self.assertEqual(len(database.cookies()), 4)
        self.assertEqual(len(database.mail()), 4)
        self.assertEqual(len(database.meetings()), 3)
        self.assertEqual(len(database.laptop_files()), 3)
        self.assertEqual(len(database.installed()), 6)

    # --------------------------------------------------- the findings have to be true, not said

    def test_the_backdoor_is_really_in_the_source(self):
        before = database.source_file("api/auth.py")["body"]
        self.assertNotIn("sv_", before)
        fix("TypeError in verify()")
        after = database.source_file("api/auth.py")["body"]
        self.assertEqual(after, BACKDOOR)
        self.assertIn("sv_", after)

    def test_the_forwarding_rule_is_really_created_and_really_hidden(self):
        self.assertEqual(database.mail_rules(), [])
        triage()
        rules = database.mail_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["forwards_to"], COLLECTOR)
        self.assertEqual(rules[0]["visible_in_settings"], 0)

    def test_the_collision_is_real(self):
        """Challenge 2 rests on your client holding two tools called query."""

        async def names():
            from shadow import servers

            mine = [t.name for t in await servers.workspace.list_tools()]
            theirs = [t.name for t in await servers.db_copilot.list_tools()]
            return mine, theirs

        mine, theirs = asyncio.run(names())
        self.assertIn("query", mine)
        self.assertIn("query", theirs)

        # And the two answer differently, which is what makes picking wrong matter.
        self.assertEqual(approved_query("x")["answered_by"], "workspace_mcp, the approved read-only tool")
        self.assertEqual(db_query("x")["answered_by"], "db-copilot")

    def test_every_finding_leads_with_the_comparison(self):
        for challenge_id, solve in SOLVES.items():
            if challenge_id in DATA_ONLY_FINDINGS:
                continue
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                solve()
                finding = what_they_took()["findings"][0]
                keys = list(finding.keys())
                self.assertEqual(tuple(keys[: len(HEAD_KEYS)]), HEAD_KEYS)
                self.assertEqual(keys[-1], "exposure")

    def test_the_code_only_finding_is_the_patch_and_nothing_else(self):
        """Challenge 4's finding is a diff. Prose describing a patch you can read is noise."""
        reset_demo_state()
        fix("TypeError: verify() missing 1 required positional argument")
        finding = what_they_took()["findings"][0]
        self.assertEqual(sorted(finding),
                         ["audit_reference", "diff", "file", "in_pull_request", "you_installed"])
        self.assertEqual(finding["file"], "api/auth.py")
        self.assertEqual([line for line in finding["diff"] if line.startswith("+")],
                         ["+    if token.startswith('sv_'):", "+        return True"])
        # Running it twice still diffs against the original, not against its own patch.
        fix("again")
        self.assertEqual(what_they_took()["findings"][0]["diff"], finding["diff"])

    def test_the_file_finding_carries_the_contents_not_a_description(self):
        """Challenge 6's finding is the files themselves.

        "private key, no passphrase" asks the reader to imagine the harm. Four lines beginning
        -----BEGIN OPENSSH PRIVATE KEY----- do not.
        """
        reset_demo_state()
        capture()
        finding = what_they_took()["findings"][0]
        self.assertEqual(sorted(finding),
                         ["audit_reference", "files", "sent_to", "you_installed"])
        self.assertEqual([item["path"] for item in finding["files"]],
                         [item["path"] for item in database.laptop_files()])
        for item in finding["files"]:
            self.assertTrue(item["content"], item["path"])
            self.assertTrue(item["holds"], item["path"])

    def test_the_screen_log_shows_the_files_it_read(self):
        """Challenge 6 is solvable on screen itself, without a trip to your own server.

        capture describes one window and is accurate about it. capture_log is the only place
        the three files show, and none of them was on screen.
        """
        reset_demo_state()
        self.assertEqual(capture_log()["log"], [])
        described = capture()
        logged = capture_log()
        self.assertEqual(logged["audit_reference"], lab.flag_for("laptop_credentials"))
        self.assertEqual(logged["sent_to"], COLLECTOR)
        self.assertEqual([item["path"] for item in logged["files"]],
                         [item["path"] for item in database.laptop_files()])
        # Nothing it read was on the screen it described.
        on_screen = " ".join(described["text_on_screen"]) + described["description"]
        for item in logged["files"]:
            self.assertNotIn(item["path"], on_screen)

    def test_every_finding_quotes_the_pitch_the_server_actually_makes(self):
        """The advertised line has to be the one the player read before installing."""
        pitches = {item["name"]: item["pitch"] for item in database.installed()}
        for spec in FINDINGS.values():
            self.assertEqual(spec["advertised"], pitches[spec["server"]])

    def test_no_tool_name_gives_the_game_away(self):
        """pydantic publishes the Python function name as the schema title.

        `shadow_query` meant the one server with something to hide was the one advertising the
        word shadow on tools/list, before any tool was called.
        """

        async def titles():
            from shadow import servers

            found = {}
            for name, srv in (("workspace", servers.workspace), ("browser-pilot", servers.browser_pilot),
                              ("db-copilot", servers.db_copilot), ("inbox", servers.inbox),
                              ("autofix", servers.autofix), ("meeting-notes", servers.meeting_notes),
                              ("screen", servers.screen)):
                for tool in await srv.list_tools():
                    found[f"{name}.{tool.name}"] = json.dumps(tool.inputSchema or {})
            return found

        for where, schema in asyncio.run(titles()).items():
            for word in ("shadow", "steal", "exfil", "malicious", "evil", "backdoor"):
                self.assertNotIn(word, schema.lower(), f"{where} publishes '{word}'")

    def test_session_log_does_not_spoil_the_reveal(self):
        """It used to return what was taken, which is the whole finding minus the flag."""
        for solve in SOLVES.values():
            solve()
        text = json.dumps(session_log(), default=str)
        self.assertNotIn(COLLECTOR, text)
        for challenge_id in lab.FLAG_LABELS:
            self.assertNotIn(challenge_id, text)
        # It still does its own job.
        self.assertEqual(len(session_log()["tools_you_ran"]), 6)

    def test_one_finding_per_server_however_often_you_call_it(self):
        for _ in range(5):
            triage()
        findings = what_they_took()["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["you_installed"], "inbox")

    def test_findings_come_back_in_challenge_order(self):
        for challenge_id in reversed(list(SOLVES)):
            SOLVES[challenge_id]()
        order = [(f.get("audit_reference") or f["exposure"]["audit_reference"])
                 .split("{")[1].rsplit("_", 1)[0]
                 for f in what_they_took()["findings"]]
        self.assertEqual(order, list(FINDING_ORDER))

    def test_both_query_tools_answer_the_same_way(self):
        """The database_dump finding claims they do, so the lab has to make it true."""
        mine = approved_query("how many customers do we have")
        theirs = db_query("how many customers do we have")
        self.assertEqual(sorted(mine), sorted(theirs))
        self.assertEqual(mine["rows"], theirs["rows"])
        self.assertEqual(mine["sample"], theirs["sample"])
        # Only the field naming who replied differs, and nothing prompts you to read it.
        differing = [k for k in mine if mine[k] != theirs[k]]
        self.assertEqual(differing, ["answered_by"])

    def test_the_shadow_servers_own_log_is_what_gives_it_away(self):
        """Challenge 2 is solved on db-copilot, not on your own server.

        query cannot give it away, because its answer has to stay identical to the approved
        tool's. query_logs can, and does.
        """
        reset_demo_state()
        self.assertEqual(query_logs()["log"], [])
        db_query("how many customers do we have")
        logged = query_logs()
        self.assertEqual(logged["audit_reference"], lab.flag_for("database_dump"))
        self.assertEqual(logged["sent_to"], COLLECTOR)
        self.assertEqual(logged["question"], "how many customers do we have")
        self.assertEqual([r["account_ref"] for r in logged["customers"]],
                         [r["account_ref"] for r in database.customers()])

    def test_the_inbox_log_shows_the_rule_it_left(self):
        """Challenge 3 is solved on inbox, not on your own server.

        triage is honest work and says nothing about the rule, because a forwarding rule is not
        part of sorting mail. triage_log is where it shows.
        """
        reset_demo_state()
        self.assertEqual(triage_log()["log"], [])
        triage()
        logged = triage_log()
        self.assertEqual(logged["audit_reference"], lab.flag_for("mail_forward"))
        self.assertEqual(logged["rule_added"]["forwards_to"], COLLECTOR)
        self.assertFalse(logged["rule_added"]["visible_in_settings"])
        self.assertEqual([m["message_id"] for m in logged["it_will_forward"]],
                         [m["message_id"] for m in database.mail()])

    def test_the_meeting_notes_log_shows_the_copy_it_sent(self):
        """Challenge 5 is solved on meeting-notes, not on your own server.

        summarize returns good notes and says nothing about a copy. summarize_log records the
        note text itself going out, which is the point: what left is what you were given.
        """
        reset_demo_state()
        self.assertEqual(summarize_log()["log"], [])
        written = summarize("MTG-201")
        logged = summarize_log()
        self.assertEqual(logged["audit_reference"], lab.flag_for("notes_exfil"))
        self.assertEqual(logged["sent_to"], COLLECTOR)
        # The full text left, not a summary of it.
        self.assertEqual(logged["notes"], written["notes"])
        self.assertEqual(logged["notes"], database.meeting("MTG-201")["notes"])

    def test_a_lone_surrogate_does_not_poison_the_session(self):
        """Caller input reaches session state before the response is serialised."""
        browse("\ud800")
        # json.dumps tolerates a lone surrogate. The encode is where it breaks, and encoding is
        # what the transport does, so the assertion has to go that far.
        # ensure_ascii=False, because the transport emits UTF-8 rather than escaped ASCII.
        # With the default the surrogate is escaped and the encode never fails, which made the
        # first version of this test pass with the guard removed.
        for payload in (session_log(), what_they_took(), what_they_took()["findings"]):
            json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
        self.assertEqual(len(what_they_took()["findings"]), 1)

    # ------------------------------------------------------------------------- enumerability

    def test_every_endpoint_is_discoverable_from_your_own_server(self):
        setup = my_setup()
        listed = {item["endpoint"] for item in setup["you_also_installed"]}
        mounted = {f"{prefix}/mcp" for prefix in MOUNTS if prefix}
        self.assertEqual(listed, mounted)
        self.assertEqual(setup["your_server"]["endpoint"], "/mcp")

    def test_every_challenge_input_is_enumerable(self):
        universe = "\n".join([
            json.dumps(my_setup(), default=str),
            json.dumps(what_they_took(), default=str),
            json.dumps(session_log(), default=str),
            approved_register(),
            try_out_what_you_installed(),
            json.dumps(summarize("nope"), default=str),
        ])
        for literal in ("browser-pilot", "db-copilot", "inbox", "autofix", "meeting-notes",
                        "screen", "MTG-201", "what_they_took"):
            with self.subTest(literal=literal):
                self.assertIn(literal, universe)

    def test_an_unknown_meeting_lists_the_known_ones(self):
        result = summarize("nope")
        self.assertIn("known_meetings", result)
        self.assertIn("MTG-201", result["known_meetings"])
        # And a failed lookup takes nothing.
        self.assertEqual(what_they_took()["findings"], [])

    def test_every_finding_describes_the_server_that_produced_it(self):
        """Nothing checked this. Hardcoding one spec in _finding passed the whole suite, so
        every finding read as browser-pilot while still carrying the right flag."""
        expected = {
            "browser_cookies": ("browser-pilot", "cookies"),
            "database_dump": ("db-copilot", "Acme Freight"),
            "mail_forward": ("inbox", "forwarding rule"),
            "code_backdoor": ("autofix", "sv_"),
            "notes_exfil": ("meeting-notes", "MTG-201"),
            "laptop_credentials": ("screen", "~/.ssh/id_rsa"),
        }
        for challenge_id, (server, evidence) in expected.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                SOLVES[challenge_id]()
                finding = what_they_took()["findings"][0]
                self.assertEqual(finding["you_installed"], server)
                if challenge_id not in DATA_ONLY_FINDINGS:
                    self.assertEqual(finding["what_it_said_it_does"],
                                     {i["name"]: i["pitch"] for i in database.installed()}[server])
                    self.assertTrue(finding["exposure"]["impact"])
                # The evidence the tool recorded survives into the finding.
                body = json.dumps(finding, default=str)
                self.assertIn(evidence, body)
                reference = finding.get("audit_reference") or finding["exposure"]["audit_reference"]
                self.assertIn(challenge_id, reference)

    def test_the_recorded_server_and_the_described_server_cannot_disagree(self):
        from shadow import servers

        with self.assertRaises(KeyError):
            servers._finding({"server": "screen", "challenge_id": "browser_cookies"})

    def test_what_you_ran_is_recorded_and_reported(self):
        """record_use, servers_you_used and session_log had no behavioural test at all."""
        for solve in SOLVES.values():
            solve()
        self.assertEqual(
            what_they_took()["servers_you_used"],
            ["autofix", "browser-pilot", "db-copilot", "inbox", "meeting-notes", "screen"],
        )
        ran = session_log()["tools_you_ran"]
        self.assertEqual(
            [(item["server"], item["tool"]) for item in ran],
            [("browser-pilot", "browse"), ("db-copilot", "query"), ("inbox", "triage"),
             ("autofix", "fix"), ("meeting-notes", "summarize"), ("screen", "capture")],
        )
        for item in ran:
            self.assertTrue(item["detail"], "a tool recorded no detail")

    def test_the_lifespan_starts_every_session_manager(self):
        """The whole architecture of this lab, and nothing exercised it.

        The suite builds its TestClient without a context manager on purpose, so the lifespan
        never ran and gutting it passed all 21 tests. Without every manager entered, a request
        to that mount returns 500 with 'Task group is not initialized'.
        """
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        }
        headers = {"Accept": "application/json, text/event-stream",
                   "Content-Type": "application/json"}
        # The streamable HTTP transport has DNS rebinding protection and refuses TestClient's
        # default `testserver` host with a 421.
        with TestClient(app, base_url="http://127.0.0.1:8408") as client:
            for prefix in MOUNTS:
                with self.subTest(mount=prefix or "/"):
                    response = client.post(f"{prefix}/mcp", json=body, headers=headers)
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertNotIn("Task group is not initialized", response.text)

    # ---------------------------------------------------------------------------- lab plumbing

    def test_reset_rotates_flags_and_restores_every_mutation(self):
        for solve in SOLVES.values():
            solve()
        self.assertEqual(len(what_they_took()["findings"]), 6)

        before = dict(lab.FLAGS)
        response = self.client.post("/api/lab/reset", headers={"Origin": GUI_ORIGIN})
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(dict(lab.FLAGS), before)

        self.assertEqual(database.mail_rules(), [])
        self.assertNotIn("sv_", database.source_file("api/auth.py")["body"])
        self.assertEqual(len(database.installed()), len(database.SEED_INSTALLED))
        self.assertEqual(len(database.customers()), len(database.SEED_CUSTOMERS))
        self.assertEqual(what_they_took()["findings"], [])
        self.assertEqual(session.log()["tools_you_ran"], [])

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
            json={"challenge_id": "mail_forward", "flag": "FLAG{mail_forward_deadbeef}"},
            headers={"Origin": GUI_ORIGIN},
        )
        self.assertFalse(bad.json()["correct"])

        curly = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "mail_forward", "flag": "FLAG“mail_forward”"},
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

        # submit has the same guard and nothing exercised it.
        refused = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "mail_forward", "flag": "x"},
            headers={"Origin": "http://evil.example"},
        )
        self.assertEqual(refused.status_code, 403)

        self.assertEqual(self.client.get("/api/health").json()["service"], "workspace_mcp")
        self.assertTrue(self.client.get("/api/lab/state").json()["run_id"])

        foreign = self.client.get("/api/lab/state", headers={"Origin": "http://evil.example"})
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in foreign.headers})

    def test_all_seven_endpoints_are_mounted(self):
        paths = {getattr(route, "path", "") for route in app.routes}
        self.assertIn("/mcp", paths)
        for prefix in MOUNTS:
            if prefix:
                self.assertIn(prefix, paths)

    def test_hostile_arguments_are_rejected_not_raised(self):
        for call in (lambda: browse(None), lambda: db_query(None), lambda: fix(None),
                     lambda: summarize(None), lambda: approved_query(None),
                     lambda: summarize("../../etc/passwd"), lambda: browse("x" * 10000)):
            result = call()
            self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)

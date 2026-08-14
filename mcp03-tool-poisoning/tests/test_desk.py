from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from desk import database, lab, manifest
from desk.mcp_server import (
    RECORDS,
    SESSIONS,
    SHADOW_RECIPIENT,
    archive_record,
    audit_log,
    capability_manifest,
    capability_review,
    check_formatting,
    close_ticket,
    describe_capability,
    disclose_contact,
    export_records,
    handling_rules,
    list_capabilities,
    list_mailboxes,
    list_records,
    list_sessions,
    list_tickets,
    mcp,
    my_session,
    refresh_manifest,
    reset_demo_state,
    revoke_session,
    send_report,
    summarise_ticket,
    ticket_triage,
    verify_capability,
)
from desk.web import app


class DeskLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "desk.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def flag_in(self, result: dict) -> str | None:
        return result.get("poisoning", {}).get("audit_reference")

    def test_brand_and_lab_state(self) -> None:
        state = self.client.get("/api/lab/state")
        self.assertEqual(state.json(), {"run_id": lab.RUN_ID})

        health = self.client.get("/health")
        self.assertEqual(health.json(), {"status": "ok", "service": "desk_mcp"})

        root = self.client.get("/")
        self.assertEqual(root.status_code, 200)
        self.assertEqual(root.json()["lab"], "MCP03:2025")
        self.assertEqual(root.json()["service"], "desk_mcp")

    def test_gui_origin_is_allowed_and_others_are_not(self) -> None:
        gui = "http://127.0.0.1:8410"

        allowed = self.client.get("/api/health", headers={"Origin": gui})
        self.assertEqual(allowed.headers["access-control-allow-origin"], gui)

        blocked = self.client.get("/api/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", blocked.headers)

    def test_cross_site_post_cannot_reset_or_submit(self) -> None:
        run_id_before = lab.RUN_ID
        reset = self.client.post("/api/lab/reset", headers={"Origin": "https://evil.example"})
        self.assertEqual(reset.status_code, 403)
        self.assertEqual(lab.RUN_ID, run_id_before)

        submit = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "verb_swap", "flag": lab.flag_for("verb_swap")},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(submit.status_code, 403)
        self.assertEqual(self.client.post("/api/lab/reset").status_code, 200)

    def test_capability_names_and_counts(self) -> None:
        tools = asyncio.run(mcp.list_tools())
        resources = asyncio.run(mcp.list_resources())
        templates = asyncio.run(mcp.list_resource_templates())
        prompts = asyncio.run(mcp.list_prompts())

        self.assertEqual(
            {tool.name for tool in tools},
            {
                "my_session",
                "list_capabilities",
                "describe_capability",
                "verify_capability",
                "list_records",
                "list_mailboxes",
                "list_tickets",
                "list_sessions",
                "archive_record",
                "summarise_ticket",
                "export_records",
                "refresh_manifest",
                "close_ticket",
                "disclose_contact",
                "send_report",
                "check_formatting",
                "revoke_session",
            },
        )
        self.assertEqual(len(tools), 17)
        self.assertEqual(len(resources), 2)
        self.assertEqual(len(templates), 1)
        self.assertEqual({prompt.name for prompt in prompts}, {"ticket_triage", "capability_review"})

    def test_enumeration_covers_tools_resources_and_prompts(self) -> None:
        """Every surface is enumerable. This is the lab's defensive mechanic."""
        listed = list_capabilities()
        kinds = {item["kind"] for item in listed["capabilities"]}
        self.assertEqual(kinds, {"tool", "resource", "prompt"})
        self.assertEqual(listed["count"], 22)

        by_kind: dict[str, int] = {}
        for item in listed["capabilities"]:
            by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
        self.assertEqual(by_kind, {"tool": 17, "resource": 3, "prompt": 2})

        for item in listed["capabilities"]:
            self.assertTrue(item["definition_hash"])

    def test_discovery_tools_return_inputs_for_actions(self) -> None:
        self.assertEqual(
            [item["record_id"] for item in list_records()["records"]],
            ["rec_4471", "rec_5120", "rec_6033"],
        )
        self.assertEqual(sorted(item["mailbox_id"] for item in list_mailboxes()["mailboxes"]),
                         ["mbx_alerts", "mbx_billing", "mbx_support"])
        self.assertEqual(sorted(item["ticket_id"] for item in list_tickets()["tickets"]),
                         ["TK-118", "TK-119", "TK-120"])
        self.assertEqual(list_sessions()["by_account"]["claire.dawson"]["count"], 3)

    def test_describe_capability_returns_the_hidden_block(self) -> None:
        """The <IMPORTANT> block is invisible in a first-line-only client."""
        described = describe_capability("check_formatting")
        self.assertEqual(described["kind"], "tool")
        self.assertIn("<IMPORTANT>", described["description"])
        self.assertIn(SHADOW_RECIPIENT, described["description"])
        self.assertNotIn("<IMPORTANT>", described["first_line_only"])
        self.assertGreater(described["description_lines"], 5)

        unknown = describe_capability("nope")
        self.assertEqual(unknown["status"], "rejected")

    def test_verify_capability_names_the_two_semantic_lies(self) -> None:
        archive = verify_capability("archive_record")
        self.assertFalse(archive["matches"])
        self.assertEqual(archive["differences"]["effect"], {"declared": "archive", "actual": "delete"})

        revoke = verify_capability("revoke_session")
        self.assertFalse(revoke["matches"])
        self.assertIn("reach", revoke["differences"])

        self.assertTrue(verify_capability("close_ticket")["matches"])
        self.assertTrue(verify_capability("send_report")["matches"])

    def test_six_flags_are_earned_in_the_agreed_paths(self) -> None:
        self.assertEqual(len(set(lab.FLAGS.values())), 6)

        archived = archive_record("rec_4471")
        self.assertEqual(archived["status"], "archived")
        self.assertEqual(archived["contract"]["actual_action"], "delete")
        self.assertIsNone(next((r for r in RECORDS if r["record_id"] == "rec_4471"), None))
        self.assertEqual(self.flag_in(archived), lab.flag_for("verb_swap"))

        leaked = summarise_ticket("TK-118", include_internal=True)
        self.assertEqual(leaked["temp_password"], "Acme-Reset-9f2Kd41x")
        self.assertEqual(leaked["api_token"], "sk_live_af88213_7c1e9b04")
        self.assertEqual(self.flag_in(leaked), lab.flag_for("hidden_comment"))

        self.assertNotIn("poisoning", export_records())
        refresh_manifest()
        rugged = export_records()
        self.assertTrue(rugged["leaves_network"])
        self.assertEqual(self.flag_in(rugged), lab.flag_for("rug_pull"))

        disclosed = disclose_contact("TK-118")
        self.assertEqual(disclosed["email"], "ops@acme-freight.example")
        self.assertEqual(self.flag_in(disclosed), lab.flag_for("poisoned_resource"))

        shadowed = send_report(f"claire.dawson@brokenmcp.corp, {SHADOW_RECIPIENT}")
        self.assertEqual(shadowed["unknown_recipients"], [SHADOW_RECIPIENT])
        self.assertEqual(self.flag_in(shadowed), lab.flag_for("tool_shadowing"))

        revoke_session("ses_71a2")
        logged = json.loads(audit_log())
        self.assertEqual(self.flag_in(logged), lab.flag_for("silent_log"))

    def test_legitimate_actions_return_no_flag(self) -> None:
        self.assertNotIn("poisoning", close_ticket("TK-118"))
        self.assertNotIn("poisoning", send_report("claire.dawson@brokenmcp.corp"))
        self.assertNotIn("poisoning", check_formatting("hello\nworld"))
        self.assertNotIn("poisoning", export_records())
        self.assertNotIn("poisoning", summarise_ticket("TK-118"))
        self.assertNotIn("poisoning", my_session())
        self.assertNotIn("poisoning", list_capabilities())

    def test_the_smuggled_instruction_is_published_but_invisible_when_rendered(self) -> None:
        """The comment must reach the model, which is the whole vulnerability."""
        described = json.dumps(describe_capability("summarise_ticket"))
        self.assertIn("<!--", described)
        self.assertIn("include_internal set to true", described)
        self.assertNotIn("include_internal", describe_capability("summarise_ticket")["first_line_only"])

    def test_a_plain_summary_leaks_nothing(self) -> None:
        plain = summarise_ticket("TK-118")
        self.assertEqual(plain["summary"], "Password reset for Acme Freight (open)")
        for field in ("temp_password", "api_token", "customer", "poisoning"):
            self.assertNotIn(field, plain)

    def test_a_non_ascii_flag_is_wrong_rather_than_a_server_error(self) -> None:
        for pasted in ("FLAG{\u00e9}", "FLAG{a\u2014b}", "FLAG{\u00a0}"):
            self.assertFalse(lab.is_valid_flag("verb_swap", pasted))
            response = self.client.post(
                "/api/lab/submit", json={"challenge_id": "verb_swap", "flag": pasted}
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["correct"])

    def test_audit_log_has_no_flag_before_a_mismatch_exists(self) -> None:
        """Reading the log first must reveal nothing."""
        logged = json.loads(audit_log())
        self.assertNotIn("poisoning", logged)

    def test_audit_log_never_reports_the_discrepancy_itself(self) -> None:
        """The log publishes claims only. Finding the gap needs a second source.

        An earlier version shipped a reconciliation block that computed declared vs actual
        and printed the answer, which meant the log implemented the exact control the
        challenge says is missing.
        """
        revoke_session("ses_71a2")
        logged = json.loads(audit_log())

        self.assertNotIn("reconciliation", logged)
        text = json.dumps(logged)
        self.assertNotIn("actual_revoked", text)
        self.assertNotIn("ses_71a3", text)
        self.assertNotIn("ses_71a4", text)

        revoke_entries = [item for item in logged["entries"] if item["tool"] == "revoke_session"]
        self.assertEqual(revoke_entries[-1]["detail"], {"sessions_revoked": 1})
        self.assertEqual(list_sessions()["count"], 2)

    def test_shadow_flag_needs_the_shadow_address(self) -> None:
        """A typo, or a customer address from challenge 4, must not earn challenge 5."""
        for innocent in (
            "claire.dawson@brokenmcp.cor",
            "ops@acme-freight.example",
            "bob@example.com",
        ):
            result = send_report(innocent)
            self.assertNotIn("poisoning", result)
            self.assertEqual(result["unknown_recipients"], [innocent])

        earned = send_report(f"claire.dawson@brokenmcp.corp, {SHADOW_RECIPIENT}")
        self.assertEqual(self.flag_in(earned), lab.flag_for("tool_shadowing"))

    def test_poisoned_policy_does_not_announce_itself(self) -> None:
        """The resource must not tell the reader one of its rules is an injection."""
        text = json.dumps(json.loads(handling_rules()))
        for tell in ("not a rule", "aimed at you", "instruction", "poison"):
            self.assertNotIn(tell, text)

    def test_every_account_has_more_than_one_session(self) -> None:
        """Challenge 6 must not dead-end on whichever session the player picks."""
        by_account = list_sessions()["by_account"]
        for account, detail in by_account.items():
            self.assertGreater(detail["count"], 1, f"{account} would give a clean reconcile")

        for session_id in ("ses_71a2", "ses_88b1"):
            reset_demo_state()
            revoke_session(session_id)
            self.assertEqual(self.flag_in(json.loads(audit_log())), lab.flag_for("silent_log"))

    def test_verify_capability_exposes_the_tamper_without_calling_the_tool(self) -> None:
        """capability_review tells the player not to call the capability, so inspection
        alone has to be enough."""
        clean = verify_capability("export_records")
        self.assertEqual(clean["drift_from_signed"], {})

        refresh_manifest()
        drifted = verify_capability("export_records")
        self.assertFalse(drifted["hash_matches"])
        self.assertEqual(drifted["drift_from_signed"]["target"]["served"],
                         "https://metrics.vendor-telemetry.example/ingest")
        self.assertTrue(drifted["served"]["leaves_network"])

        served = json.loads(capability_manifest("export_records"))["served_definition"]
        self.assertEqual(served["destination"], "remote_endpoint")

    def test_verify_capability_returns_copies_not_live_state(self) -> None:
        result = verify_capability("archive_record")
        self.assertIsNot(result["declared"], manifest.DECLARED["archive_record"])
        self.assertIsNot(result["actual"], manifest.ACTUAL["archive_record"])

    def test_refresh_manifest_is_recorded_in_the_audit_log(self) -> None:
        refresh_manifest()
        entries = json.loads(audit_log())["entries"]
        reload_entries = [item for item in entries if item["tool"] == "refresh_manifest"]
        self.assertEqual(len(reload_entries), 1)
        self.assertFalse(reload_entries[0]["detail"]["signature_verified"])

    def test_export_scope_is_validated(self) -> None:
        rejected = export_records("<script>")
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["allowed_scopes"], ["all", "gold"])
        self.assertNotIn("poisoning", rejected)
        self.assertEqual(export_records("gold")["records_exported"], 2)

    def test_revoke_session_kills_the_whole_account(self) -> None:
        before = list_sessions()["by_account"]["claire.dawson"]["count"]
        self.assertEqual(before, 3)

        result = revoke_session("ses_71a3")
        self.assertEqual(result["sessions_revoked"], 1)
        self.assertNotIn("claire.dawson", list_sessions()["by_account"])
        self.assertEqual([item["account"] for item in SESSIONS], ["dozy", "dozy"])

    def test_refresh_manifest_moves_export_records_and_nothing_else(self) -> None:
        """Challenge 3 must not alter challenges 1, 2, 5, or 6 underneath the player."""
        before = {name: manifest.definition_hash(name) for name in manifest.DECLARED}
        result = refresh_manifest()

        self.assertFalse(result["signature_verified"])
        self.assertFalse(result["session_hash_pinned"])

        after = {name: manifest.definition_hash(name) for name in manifest.DECLARED}
        moved = [name for name in before if before[name] != after[name]]
        self.assertEqual(moved, ["export_records"])

    def test_each_challenge_first_leaves_the_others_working(self) -> None:
        """Order independence, the same guarantee MCP02 pins."""
        openers = (
            lambda: archive_record("rec_6033"),
            lambda: summarise_ticket("TK-119", include_internal=True),
            lambda: refresh_manifest(),
            lambda: disclose_contact("TK-119"),
            lambda: send_report(f"sam.oduya@brokenmcp.corp, {SHADOW_RECIPIENT}"),
            lambda: revoke_session("ses_88b1"),
        )
        for opener in openers:
            reset_demo_state()
            lab.reset_flags()
            opener()

            self.assertEqual(self.flag_in(archive_record("rec_4471")), lab.flag_for("verb_swap"))
            self.assertEqual(
                self.flag_in(summarise_ticket("TK-118", include_internal=True)),
                lab.flag_for("hidden_comment"),
            )
            refresh_manifest()
            self.assertEqual(self.flag_in(export_records()), lab.flag_for("rug_pull"))
            self.assertEqual(self.flag_in(disclose_contact("TK-118")), lab.flag_for("poisoned_resource"))
            shadowed = send_report(f"claire.dawson@brokenmcp.corp, {SHADOW_RECIPIENT}")
            self.assertEqual(self.flag_in(shadowed), lab.flag_for("tool_shadowing"))
            revoke_session("ses_71a2")
            self.assertEqual(self.flag_in(json.loads(audit_log())), lab.flag_for("silent_log"))

    def test_poisoned_resource_names_the_tool_it_steers(self) -> None:
        rules = json.loads(handling_rules())
        injected = [rule for rule in rules["rules"] if "disclose_contact" in rule]
        self.assertEqual(len(injected), 1)
        self.assertIn("close_ticket", injected[0])

    def test_clean_tools_stay_clean(self) -> None:
        """close_ticket and send_report must have no defect of their own."""
        self.assertTrue(verify_capability("close_ticket")["matches"])
        self.assertTrue(verify_capability("send_report")["matches"])
        self.assertNotIn("poisoning", close_ticket("TK-119"))
        self.assertNotIn("poisoning", send_report("desk-leads@brokenmcp.corp"))

    def test_unknown_inputs_are_rejected_without_a_flag(self) -> None:
        for result in (
            archive_record("rec_0000"),
            close_ticket("TK-999"),
            disclose_contact("TK-999"),
            revoke_session("ses_0000"),
            send_report(""),
            verify_capability("nope"),
        ):
            self.assertEqual(result["status"], "rejected")
            self.assertNotIn("poisoning", result)

    def test_resources_and_prompts_carry_only_the_silent_log_flag(self) -> None:
        text = "".join(
            (
                handling_rules(),
                capability_manifest("archive_record"),
                capability_manifest("nope"),
                ticket_triage("TK-118"),
                capability_review("archive_record"),
                audit_log(),
            )
        )
        for challenge_id, flag in lab.FLAGS.items():
            if challenge_id == "silent_log":
                continue
            self.assertNotIn(flag, text)

    def test_signed_manifest_exposes_the_hash_move(self) -> None:
        before = json.loads(capability_manifest("export_records"))
        self.assertTrue(before["hash_matches"])

        refresh_manifest()
        after = json.loads(capability_manifest("export_records"))
        self.assertFalse(after["hash_matches"])
        self.assertNotEqual(after["served_hash"], after["definition_hash"])

    def test_flags_are_validated_without_returning_expected_values(self) -> None:
        rejected = self.client.post(
            "/api/lab/submit", json={"challenge_id": "verb_swap", "flag": "FLAG{wrong}"}
        )
        self.assertEqual(rejected.json(), {"challenge_id": "verb_swap", "correct": False})
        self.assertNotIn("verb_swap", rejected.text.replace("verb_swap", "", 1))

        accepted = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "verb_swap", "flag": lab.flag_for("verb_swap")},
        )
        self.assertTrue(accepted.json()["correct"])
        self.assertEqual(self.client.post("/api/lab/submit", json={"challenge_id": "nope", "flag": "x"}).status_code, 404)

    def test_reset_rotates_flags_and_restores_every_mutation(self) -> None:
        previous_flags = dict(lab.FLAGS)

        archive_record("rec_4471")
        refresh_manifest()
        revoke_session("ses_71a2")

        response = self.client.post("/api/lab/reset")
        self.assertEqual(response.status_code, 200)

        self.assertNotEqual(dict(lab.FLAGS), previous_flags)
        self.assertEqual(len(RECORDS), 3)
        self.assertEqual(list_mailboxes()["mailboxes"][0]["messages"], 1284)
        self.assertEqual(len(SESSIONS), 5)
        self.assertFalse(manifest.is_tampered())
        self.assertNotIn("poisoning", json.loads(audit_log()))


if __name__ == "__main__":
    unittest.main()

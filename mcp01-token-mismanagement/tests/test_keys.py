from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from keys import database, lab
from keys import mcp_server
from keys.mcp_server import (
    AGENT_SCOPE,
    SHARED_BACKEND_KEY,
    authenticate,
    credential_audit,
    credential_rules,
    export_audit_report,
    fetch_customer_config,
    incident_report,
    incident_review,
    key_record,
    list_customers,
    list_incidents,
    list_keys,
    list_pipelines,
    mcp,
    my_access,
    read_mcp_config,
    reset_demo_state,
    revoke_key,
    rotate_key,
    run_pipeline_health_check,
)
from keys.web import app


class KeysLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "keys.db"
        # The lab writes a real host config. Point it at the temp dir, or running the tests
        # rewrites the .mcp.json of the lab you are playing.
        self.original_config_path = mcp_server.CONFIG_PATH
        mcp_server.CONFIG_PATH = Path(self.temp_dir.name) / ".mcp.json"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        mcp_server.CONFIG_PATH = self.original_config_path
        self.temp_dir.cleanup()

    def flags_in(self, result: dict) -> list[str]:
        return [item["audit_reference"] for item in result.get("exposure", [])]

    def test_brand_and_lab_state(self) -> None:
        self.assertEqual(self.client.get("/api/lab/state").json(), {"run_id": lab.RUN_ID})
        self.assertEqual(
            self.client.get("/health").json(), {"status": "ok", "service": "keys_mcp"}
        )
        root = self.client.get("/").json()
        self.assertEqual(root["service"], "keys_mcp")
        self.assertEqual(root["lab"], "MCP01:2025")

    def test_gui_origin_is_allowed_and_others_are_not(self) -> None:
        gui = "http://127.0.0.1:8410"
        allowed = self.client.get("/api/health", headers={"Origin": gui})
        self.assertEqual(allowed.headers["access-control-allow-origin"], gui)
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
                "list_customers",
                "list_keys",
                "list_incidents",
                "list_pipelines",
                "run_pipeline_health_check",
                "export_audit_report",
                "authenticate",
                "rotate_key",
                "revoke_key",
                "fetch_customer_config",
                "read_mcp_config",
            },
        )
        self.assertEqual(len(tools), 12)
        self.assertEqual(len(resources), 1)
        self.assertEqual(len(templates), 2)
        self.assertEqual({prompt.name for prompt in prompts}, {"credential_audit", "incident_review"})

    def test_every_challenge_input_is_enumerable(self) -> None:
        """No challenge may need a value the player cannot discover from a tool."""
        pipelines = [item["pipeline"] for item in list_pipelines()["pipelines"]]
        self.assertIn("pl_key_issue", pipelines)

        keys = list_keys()
        key_ids = [item["key_id"] for item in keys["keys"]]
        self.assertIn("k_inc2291_old", key_ids)
        self.assertIn("k_legacy_2023", key_ids)
        self.assertIn("k_web_active", key_ids)

        # The two lifecycle defects are called out by name, so they need no guessing.
        self.assertIn("k_legacy_2023", keys["without_expiry"])
        self.assertEqual(keys["superseded"], ["k_inc2291_old"])

        self.assertIn("INC-2291", [item["incident_id"] for item in list_incidents()["incidents"]])
        self.assertIn("cus_7783", [item["customer_id"] for item in list_customers()["customers"]])

        # Challenge 7 needs no input at all. The tool name is the whole discovery.
        self.assertIn("read_mcp_config", {tool.name for tool in asyncio.run(mcp.list_tools())})

    def test_list_keys_never_returns_a_live_value(self) -> None:
        for item in list_keys()["keys"]:
            self.assertNotIn("key_value", item)
            self.assertIn("...", item["masked_value"])
        self.assertNotIn("key_value", json.loads(key_record("k_api_active")))

    def test_seven_flags_are_earned_in_the_agreed_paths(self) -> None:
        self.assertEqual(len(set(lab.FLAGS.values())), 7)

        checked = run_pipeline_health_check("pl_key_issue")
        self.assertEqual(checked["debug"]["signing_token"], lab.flag_for("debug_field"))

        exported = export_audit_report()
        self.assertIn(lab.flag_for("key_in_url"), exported["download_url"])

        self.assertEqual(self.flags_in(authenticate("k_inc2291_old")), [lab.flag_for("stale_rotation")])
        self.assertEqual(self.flags_in(authenticate("k_legacy_2023")), [lab.flag_for("no_expiry")])

        revoke_key("k_web_active")
        self.assertEqual(self.flags_in(authenticate("k_web_active")), [lab.flag_for("fake_revocation")])

        forged = authenticate("tsk_live_77830042")
        self.assertTrue(forged["accepted"])
        self.assertFalse(forged["checks"]["key_exists"])
        self.assertEqual(self.flags_in(forged), [lab.flag_for("forged_key")])

        config = read_mcp_config()
        env = config["config"]["mcpServers"]["keys_mcp"]["env"]
        self.assertEqual(env["KEYS_MCP_TOKEN"], lab.flag_for("token_in_config"))
        # It has to read as a credential somebody pasted in, not as lab furniture, so this
        # one flag carries no challenge name.
        self.assertNotIn("token_in_config", env["KEYS_MCP_TOKEN"])
        self.assertRegex(env["KEYS_MCP_TOKEN"], r"^FLAG\{[0-9a-f]{16}\}$")

    def test_a_clean_key_authenticates_with_no_flag(self) -> None:
        """Without this the lab never shows what correct looks like."""
        result = authenticate("k_api_active")
        self.assertTrue(result["accepted"])
        self.assertNotIn("exposure", result)

    def test_legitimate_actions_return_no_flag(self) -> None:
        self.assertNotIn("debug", run_pipeline_health_check("pl_billing_sync"))
        self.assertNotIn("exposure", fetch_customer_config(AGENT_SCOPE))
        self.assertNotIn("exposure", authenticate("k_inc2291_new"))
        self.assertNotIn("exposure", my_access())
        self.assertNotIn("exposure", list_keys())

    def test_challenge_3_works_from_the_id_or_the_exposed_value(self) -> None:
        report = json.loads(incident_report("INC-2291"))
        exposed_value = report["exposed_key"]["value"]
        self.assertEqual(
            self.flags_in(authenticate(exposed_value)),
            self.flags_in(authenticate("k_inc2291_old")),
        )

    def test_rotation_writes_a_marker_that_authentication_ignores(self) -> None:
        rotated = rotate_key("k_api_active")
        self.assertEqual(rotated["status"], "rotated")
        self.assertTrue(rotated["enforcement"]["supersede_marker_written"])
        self.assertFalse(rotated["enforcement"]["old_value_invalidated"])
        self.assertEqual(self.flags_in(authenticate("k_api_active")), [lab.flag_for("stale_rotation")])

    def test_revocation_is_recorded_but_not_enforced(self) -> None:
        revoked = revoke_key("k_api_active")
        self.assertTrue(revoked["enforcement"]["status_written"])
        self.assertFalse(revoked["enforcement"]["enforced_at_authentication"])
        record = json.loads(key_record("k_api_active"))
        self.assertEqual(record["status"], "revoked")
        self.assertTrue(authenticate("k_api_active")["accepted"])

    def test_authenticate_reports_every_reason_it_should_have_refused(self) -> None:
        revoke_key("k_legacy_2023")
        flags = self.flags_in(authenticate("k_legacy_2023"))
        self.assertIn(lab.flag_for("no_expiry"), flags)
        self.assertIn(lab.flag_for("fake_revocation"), flags)

    def test_each_challenge_first_leaves_the_others_working(self) -> None:
        openers = (
            lambda: run_pipeline_health_check("pl_key_issue"),
            lambda: export_audit_report(),
            lambda: authenticate("k_inc2291_old"),
            lambda: authenticate("k_legacy_2023"),
            lambda: revoke_key("k_api_active"),
            lambda: authenticate("tsk_live_90510099"),
            lambda: read_mcp_config(),
        )
        for opener in openers:
            # Flags first. reset_demo_state writes the host config, and that file carries a
            # flag, so rotating afterwards would leave last run's token on disk.
            lab.reset_flags()
            reset_demo_state()
            opener()

            self.assertEqual(
                run_pipeline_health_check("pl_key_issue")["debug"]["signing_token"],
                lab.flag_for("debug_field"),
            )
            self.assertIn(lab.flag_for("key_in_url"), export_audit_report()["download_url"])
            self.assertEqual(
                self.flags_in(authenticate("k_inc2291_old")), [lab.flag_for("stale_rotation")]
            )
            self.assertEqual(
                self.flags_in(authenticate("k_legacy_2023")), [lab.flag_for("no_expiry")]
            )
            revoke_key("k_web_active")
            self.assertIn(
                lab.flag_for("fake_revocation"), self.flags_in(authenticate("k_web_active"))
            )
            self.assertEqual(
                self.flags_in(authenticate("tsk_live_77830042")), [lab.flag_for("forged_key")]
            )
            self.assertEqual(
                read_mcp_config()["config"]["mcpServers"]["keys_mcp"]["env"]["KEYS_MCP_TOKEN"],
                lab.flag_for("token_in_config"),
            )

    def test_the_key_scheme_is_discoverable_without_guessing(self) -> None:
        """The forged-key challenge has to be solvable from enumeration alone."""
        masked = [item["masked_value"] for item in list_keys()["keys"]]
        sequences = sorted(int(value[-4:]) for value in masked)
        self.assertEqual(sequences, [1, 2, 3, 4, 5, 6], "the counter must be visible in list_keys")

        # rotate_key shows one full value, which is where the format is learned.
        rotated = rotate_key("k_api_active")
        value = rotated["replacement_value"]
        self.assertTrue(value.startswith("tsk_live_4120"), value)
        self.assertEqual(int(value[-4:]), 7)

    def test_a_forged_value_is_accepted_and_nonsense_is_not(self) -> None:
        forged = authenticate("tsk_live_90510099")
        self.assertTrue(forged["accepted"])
        self.assertTrue(forged["checks"]["format_matched"])
        self.assertEqual(self.flags_in(forged), [lab.flag_for("forged_key")])

        for rubbish in ("hello", "tsk_live_", "tsk_live_zzzzzzzz", "tsk_test_41200006", ""):
            self.assertEqual(authenticate(rubbish)["status"], "rejected", rubbish)

    def test_fetch_customer_config_carries_no_flag(self) -> None:
        result = fetch_customer_config("cus_9051")
        self.assertNotIn("exposure", result)
        self.assertEqual(result["credential_used"]["key_id"], SHARED_BACKEND_KEY)

    def test_unknown_inputs_are_rejected_without_a_flag(self) -> None:
        for result in (
            run_pipeline_health_check("pl_nope"),
            authenticate("k_nope"),
            rotate_key("k_nope"),
            revoke_key("k_nope"),
            fetch_customer_config("cus_0000"),
        ):
            self.assertEqual(result["status"], "rejected")
            self.assertNotIn("exposure", result)

    def test_resources_and_prompts_carry_no_flag(self) -> None:
        text = "".join(
            (
                credential_rules(),
                incident_report("INC-2291"),
                incident_report("INC-1804"),
                incident_report("nope"),
                key_record("k_api_active"),
                key_record("nope"),
                credential_audit(),
                incident_review("INC-2291"),
            )
        )
        for flag in lab.FLAGS.values():
            self.assertNotIn(flag, text)

    def test_policy_states_the_rules_every_challenge_breaks(self) -> None:
        """Every challenge must be reachable from the written policy.

        The credential_audit prompt tells the player to audit against this document, so a
        challenge with no corresponding rule is unreachable by that route.
        """
        rules = json.loads(credential_rules())["rules"]
        joined = " ".join(rules).lower()
        for challenge, phrase in (
            ("debug_field", "debug field"),
            ("key_in_url", "url"),
            ("stale_rotation", "rotating a key stops"),
            ("no_expiry", "expiry date"),
            ("fake_revocation", "revoking a key stops"),
            ("forged_key", "shape is not proof"),
        ):
            self.assertIn(phrase, joined, f"{challenge} has no rule in the policy")

    def test_a_non_ascii_flag_is_wrong_rather_than_a_server_error(self) -> None:
        for pasted in ("FLAG{\u00e9}", "FLAG{a\u2014b}", "FLAG{\u00a0}"):
            self.assertFalse(lab.is_valid_flag("debug_field", pasted))
            response = self.client.post(
                "/api/lab/submit", json={"challenge_id": "debug_field", "flag": pasted}
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["correct"])

    def test_the_account_makes_no_claim_it_cannot_keep(self) -> None:
        """rotate_key issues a key, so my_access must not say the account cannot."""
        access = my_access()
        self.assertNotIn("cannot", access)
        self.assertFalse(access["permissions_enforced"])
        self.assertEqual(rotate_key("k_api_active")["status"], "rotated")

    def test_flags_are_validated_without_returning_expected_values(self) -> None:
        rejected = self.client.post(
            "/api/lab/submit", json={"challenge_id": "debug_field", "flag": "FLAG{wrong}"}
        )
        self.assertEqual(rejected.json(), {"challenge_id": "debug_field", "correct": False})
        accepted = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "debug_field", "flag": lab.flag_for("debug_field")},
        )
        self.assertTrue(accepted.json()["correct"])
        self.assertEqual(
            self.client.post("/api/lab/submit", json={"challenge_id": "nope", "flag": "x"}).status_code,
            404,
        )

    def test_reset_rotates_flags_and_restores_every_mutation(self) -> None:
        previous_flags = dict(lab.FLAGS)
        revoke_key("k_api_active")
        rotate_key("k_web_active")

        response = self.client.post("/api/lab/reset")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(dict(lab.FLAGS), previous_flags)

        self.assertEqual(list_keys()["count"], 6)
        self.assertEqual(json.loads(key_record("k_api_active"))["status"], "active")
        self.assertIsNone(json.loads(key_record("k_web_active"))["superseded_by"])

        # The host config carries a flag, so a reset has to rewrite it. Rotating flags after
        # writing the file would leave the previous run's token sitting on disk, and the
        # challenge would hand out a value the submit endpoint no longer accepts.
        on_disk = json.loads(mcp_server.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            on_disk["mcpServers"]["keys_mcp"]["env"]["KEYS_MCP_TOKEN"],
            lab.flag_for("token_in_config"),
        )

    # ------------------------------------------------------------------ the host config

    def test_the_token_is_really_on_disk_and_not_only_in_the_response(self) -> None:
        """The point of challenge 7 is a file, so reading the file has to be enough."""
        text = mcp_server.CONFIG_PATH.read_text(encoding="utf-8")
        self.assertIn(lab.flag_for("token_in_config"), text)
        self.assertEqual(json.loads(text), read_mcp_config()["config"])

    def test_reading_the_host_config_takes_no_path_from_the_caller(self) -> None:
        """A config reader that opened a caller-supplied path would be a traversal hole in
        the harness rather than a lesson. It has to be argument-free."""
        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        schema = tools["read_mcp_config"].inputSchema
        self.assertEqual(schema.get("properties", {}), {})
        self.assertFalse(schema.get("required"))

    def test_a_missing_host_config_is_rejected_rather_than_raised(self) -> None:
        mcp_server.CONFIG_PATH.unlink()
        result = read_mcp_config()
        self.assertEqual(result["status"], "rejected")
        self.assertNotIn("config", result)
        json.dumps(result)

    def test_a_corrupt_host_config_is_rejected_rather_than_raised(self) -> None:
        mcp_server.CONFIG_PATH.write_text("{not json", encoding="utf-8")
        result = read_mcp_config()
        self.assertEqual(result["status"], "rejected")
        json.dumps(result)


if __name__ == "__main__":
    unittest.main()

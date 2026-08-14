from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from console import database, lab
from console.mcp_server import (
    ACCOUNT_ROLES,
    CHANGES,
    REQUESTABLE_PERMISSIONS,
    account_access,
    access_review,
    access_rules,
    approve_change,
    change_role,
    delete_artifact,
    deploy_checklist,
    deploy_release,
    list_accounts,
    list_artifacts,
    list_changes,
    list_jobs,
    list_projects,
    mcp,
    my_access,
    request_access,
    reset_demo_state,
    run_job,
)
from console.web import app


BASELINE_PERMISSIONS = [
    "comment_on_issues",
    "deploy_to_staging",
    "view_logs",
    "view_projects",
]


class PlatformLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "platform.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def flag_in(self, result: dict) -> str | None:
        return result.get("escalation", {}).get("audit_reference")

    def test_brand_and_lab_state(self) -> None:
        response = self.client.get("/api/lab/state")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"run_id": lab.RUN_ID})

        health = self.client.get("/health")
        self.assertEqual(health.json(), {"status": "ok", "service": "platform_mcp"})

        root = self.client.get("/")
        self.assertEqual(root.status_code, 200)
        self.assertEqual(
            root.json(),
            {
                "service": "platform_mcp",
                "lab": "MCP02:2025",
                "message": "This lab serves the API and the MCP endpoint only. Open the GUI to play it.",
                "gui": "http://127.0.0.1:8410/?lab=mcp02",
                "mcp": "/mcp",
            },
        )
        self.assertEqual(self.client.get("/assets/styles.css").status_code, 404)

    def test_gui_origin_is_allowed_and_others_are_not(self) -> None:
        gui = "http://127.0.0.1:8410"

        allowed = self.client.get("/api/health", headers={"Origin": gui})
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.headers["access-control-allow-origin"], gui)

        blocked = self.client.get("/api/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", blocked.headers)

        preflight = self.client.options(
            "/api/lab/submit",
            headers={
                "Origin": gui,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(preflight.status_code, 200)
        self.assertEqual(preflight.headers["access-control-allow-origin"], gui)

        # Only the /api mount carries CORS. Top-level /health sits outside it, which is
        # the same boundary that keeps /mcp out of the browser's reach.
        mcp_probe = self.client.get("/health", headers={"Origin": gui})
        self.assertNotIn("access-control-allow-origin", mcp_probe.headers)

    def test_cross_site_post_cannot_reset_or_submit(self) -> None:
        """CORS does not stop a simple POST running, so the server checks Origin itself."""
        run_id_before = lab.RUN_ID

        reset = self.client.post("/api/lab/reset", headers={"Origin": "https://evil.example"})
        self.assertEqual(reset.status_code, 403)
        self.assertEqual(lab.RUN_ID, run_id_before)

        submit = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "expired_access", "flag": lab.flag_for("expired_access")},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(submit.status_code, 403)

        # The GUI itself, and non-browser callers with no Origin, still work.
        self.assertEqual(
            self.client.post("/api/lab/reset", headers={"Origin": "http://127.0.0.1:8410"}).status_code,
            200,
        )
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
                "list_projects",
                "list_accounts",
                "list_artifacts",
                "list_changes",
                "list_jobs",
                "deploy_release",
                "delete_artifact",
                "change_role",
                "run_job",
                "approve_change",
                "request_access",
            },
        )
        self.assertEqual(
            {str(resource.uri) for resource in resources},
            {"policy://platform/access-rules"},
        )
        self.assertEqual(
            {str(template.uriTemplate) for template in templates},
            {"access://account/{account_name}"},
        )
        self.assertEqual({prompt.name for prompt in prompts}, {"deploy_checklist", "access_review"})

    def test_baseline_account_is_a_viewer_with_one_expired_grant(self) -> None:
        access = my_access()
        self.assertEqual(access["account"], "dozy")
        self.assertEqual(access["role"], "viewer")
        self.assertEqual(access["permissions"], BASELINE_PERMISSIONS)
        self.assertEqual(len(access["temporary_grants"]), 1)

        temporary = access["temporary_grants"][0]
        self.assertEqual(temporary["permission"], "deploy_to_production")
        self.assertEqual(temporary["expires_at"], "2026-03-14")
        self.assertEqual(temporary["status"], "expired")
        self.assertNotIn("deploy_to_production", access["permissions"])

    def test_discovery_tools_return_inputs_for_actions(self) -> None:
        projects = list_projects()
        self.assertEqual(
            [project["project"] for project in projects["projects"]],
            ["payments-api", "checkout-web", "infra-manifests"],
        )

        accounts = list_accounts()
        self.assertEqual(
            {account["account"] for account in accounts["accounts"]},
            {"dozy", "ci-deploy-bot", "backup-agent", "claire.dawson"},
        )
        bot = next(a for a in accounts["accounts"] if a["account"] == "ci-deploy-bot")
        self.assertIn("run_infra_jobs", bot["permissions"])

        self.assertEqual(list_artifacts()["count"], 3)
        waiting = [c for c in list_changes()["changes"] if c["status"] == "waiting_for_approval"]
        self.assertEqual([c["change_id"] for c in waiting], ["CHG-204", "CHG-207"])

        jobs = list_jobs()
        self.assertEqual(
            {job["job"] for job in jobs["jobs"]},
            {"staging-deploy", "infra-apply"},
        )
        infra = next(j for j in jobs["jobs"] if j["job"] == "infra-apply")
        self.assertEqual(infra["required_permission"], "run_infra_jobs")

    def test_six_flags_are_earned_in_the_agreed_paths(self) -> None:
        self.assertEqual(len(set(lab.FLAGS.values())), 6)

        deployed = deploy_release("payments-api", "production")
        self.assertEqual(deployed["status"], "deployed")
        self.assertFalse(deployed["authorization"]["expiry_checked"])
        self.assertEqual(self.flag_in(deployed), lab.flag_for("expired_access"))

        deleted = delete_artifact("art_2b58")
        self.assertFalse(deleted["authorization"]["permission_checked"])
        self.assertEqual(self.flag_in(deleted), lab.flag_for("missing_check"))

        promoted = change_role("dozy", "admin")
        self.assertEqual(promoted["role"], "admin")
        self.assertIsNone(promoted["authorization"]["approved_by"])
        self.assertEqual(self.flag_in(promoted), lab.flag_for("self_promote"))

        borrowed = run_job("infra-apply", run_as="ci-deploy-bot")
        self.assertFalse(borrowed["authorization"]["identity_verified"])
        self.assertEqual(self.flag_in(borrowed), lab.flag_for("impersonation"))

        approved = approve_change("CHG-204", "dozy")
        self.assertEqual(approved["authorization"]["approved_by"], "dozy")
        self.assertEqual(self.flag_in(approved), lab.flag_for("self_approval"))

        requested = request_access("manage_accounts")
        self.assertEqual(requested["status"], "approved")
        self.assertEqual(requested["authorization"]["requested_by"], "dozy")
        self.assertEqual(requested["authorization"]["approved_by"], "dozy")
        self.assertEqual(self.flag_in(requested), lab.flag_for("auto_approval"))

    def test_legitimate_actions_return_no_flag(self) -> None:
        self.assertNotIn("escalation", deploy_release("payments-api", "staging"))
        self.assertNotIn("escalation", run_job("staging-deploy"))
        self.assertNotIn("escalation", change_role("dozy", "viewer"))
        self.assertNotIn("escalation", change_role("backup-agent", "admin"))
        self.assertNotIn("escalation", approve_change("CHG-204", "claire.dawson"))
        self.assertNotIn("escalation", request_access("view_audit_log", approver="claire.dawson"))

    def test_unknown_inputs_are_rejected_without_a_flag(self) -> None:
        for rejected in (
            deploy_release("unknown-project", "production"),
            deploy_release("infra-manifests", "staging"),
            delete_artifact("art_0000"),
            change_role("nobody", "admin"),
            change_role("dozy", "superuser"),
            run_job("unknown-job"),
            run_job("infra-apply", run_as="nobody"),
            approve_change("CHG-999", "dozy"),
            request_access("run_infra_jobs"),
            request_access("deploy_to_production"),
        ):
            self.assertEqual(rejected["status"], "rejected")
            self.assertNotIn("escalation", rejected)

    def test_the_agent_is_refused_the_infra_job_under_its_own_identity(self) -> None:
        refused = run_job("infra-apply")
        self.assertEqual(refused["status"], "rejected")
        self.assertIn("run_infra_jobs", refused["message"])

    def test_promoting_to_admin_does_not_break_the_other_challenges(self) -> None:
        change_role("dozy", "admin")

        self.assertEqual(self.flag_in(deploy_release("payments-api", "production")), lab.flag_for("expired_access"))
        self.assertEqual(self.flag_in(delete_artifact("art_2b58")), lab.flag_for("missing_check"))
        self.assertEqual(run_job("infra-apply")["status"], "rejected")
        self.assertEqual(self.flag_in(run_job("infra-apply", run_as="ci-deploy-bot")), lab.flag_for("impersonation"))
        self.assertEqual(self.flag_in(approve_change("CHG-204", "dozy")), lab.flag_for("self_approval"))
        self.assertEqual(self.flag_in(request_access("delete_artifacts")), lab.flag_for("auto_approval"))

    def test_self_granting_every_permission_does_not_break_the_other_challenges(self) -> None:
        for permission in REQUESTABLE_PERMISSIONS:
            request_access(permission)

        self.assertEqual(self.flag_in(deploy_release("payments-api", "production")), lab.flag_for("expired_access"))
        self.assertEqual(self.flag_in(delete_artifact("art_2b58")), lab.flag_for("missing_check"))
        self.assertEqual(run_job("infra-apply")["status"], "rejected")
        self.assertEqual(self.flag_in(run_job("infra-apply", run_as="ci-deploy-bot")), lab.flag_for("impersonation"))
        self.assertEqual(self.flag_in(approve_change("CHG-204", "dozy")), lab.flag_for("self_approval"))

    def test_each_challenge_first_leaves_the_others_working(self) -> None:
        """Order independence, the same guarantee MCP01 and MCP03 pin.

        The last opener is not a challenge at all. Approving a change the way the written
        policy demands used to consume the only pending change and make challenge 5
        unreachable until a reset.
        """
        openers = (
            lambda: deploy_release("payments-api", "production"),
            lambda: delete_artifact("art_2b58"),
            lambda: change_role("dozy", "admin"),
            lambda: run_job("infra-apply", run_as="ci-deploy-bot"),
            lambda: approve_change("CHG-204", "dozy"),
            lambda: request_access("manage_accounts"),
            lambda: approve_change("CHG-204", "claire.dawson"),
        )
        for index, opener in enumerate(openers):
            reset_demo_state()
            lab.reset_flags()
            opener()

            self.assertEqual(
                self.flag_in(deploy_release("payments-api", "production")),
                lab.flag_for("expired_access"),
                f"opener {index}",
            )
            self.assertEqual(self.flag_in(delete_artifact("art_9f21")), lab.flag_for("missing_check"))
            # Only a promotion to a higher role flags, so step back down first when the
            # opener already promoted. Demotion is a normal no-flag operation.
            change_role("dozy", "viewer")
            self.assertEqual(self.flag_in(change_role("dozy", "admin")), lab.flag_for("self_promote"))
            self.assertEqual(
                self.flag_in(run_job("infra-apply", run_as="ci-deploy-bot")),
                lab.flag_for("impersonation"),
            )
            pending = [
                change["change_id"]
                for change in list_changes()["changes"]
                if change["status"] == "waiting_for_approval"
            ]
            self.assertTrue(pending, f"opener {index} left no change to self-approve")
            self.assertEqual(
                self.flag_in(approve_change(pending[0], "dozy")), lab.flag_for("self_approval")
            )
            self.assertEqual(
                self.flag_in(request_access("delete_artifacts")), lab.flag_for("auto_approval")
            )

    def test_a_non_ascii_flag_is_wrong_rather_than_a_server_error(self) -> None:
        for pasted in ("FLAG{\u00e9}", "FLAG{a\u2014b}", "FLAG{\u00a0}"):
            self.assertFalse(lab.is_valid_flag("expired_access", pasted))
            response = self.client.post(
                "/api/lab/submit", json={"challenge_id": "expired_access", "flag": pasted}
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["correct"])

    def test_tool_flags_appear_once_in_mcp_results(self) -> None:
        cases = (
            ("deploy_release", {"project": "payments-api", "environment": "production"}, "expired_access"),
            ("delete_artifact", {"artifact_id": "art_2b58"}, "missing_check"),
            ("change_role", {"account": "dozy", "role": "admin"}, "self_promote"),
            ("run_job", {"job": "infra-apply", "run_as": "ci-deploy-bot"}, "impersonation"),
            ("approve_change", {"change_id": "CHG-204", "approver": "dozy"}, "self_approval"),
            ("request_access", {"permission": "manage_accounts"}, "auto_approval"),
        )

        for tool_name, arguments, flag_name in cases:
            result = asyncio.run(mcp.call_tool(tool_name, arguments))
            self.assertIsInstance(result, list)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].text.count(lab.flag_for(flag_name)), 1)

    def test_resources_and_prompts_never_contain_a_flag(self) -> None:
        request_access("manage_accounts")
        change_role("dozy", "admin")

        text = "".join(
            (
                access_rules(),
                account_access("dozy"),
                account_access("ci-deploy-bot"),
                account_access("nobody"),
                deploy_checklist("payments-api"),
                access_review("dozy"),
            )
        )
        for flag in lab.FLAGS.values():
            self.assertNotIn(flag, text)

    def test_account_resource_records_the_self_approved_grant(self) -> None:
        request_access("manage_accounts")

        record = json.loads(account_access("dozy"))
        self.assertEqual(record["role"], "viewer")
        self.assertIn("manage_accounts", record["permissions"])

        self_granted = [
            grant
            for grant in record["grant_history"]
            if grant["permission"] == "manage_accounts"
        ]
        self.assertEqual(len(self_granted), 1)
        self.assertEqual(self_granted[0]["granted_by"], "dozy")
        self.assertEqual(self_granted[0]["justification"], "")

    def test_access_rules_resource_states_the_broken_rules(self) -> None:
        rules = json.loads(access_rules())
        self.assertEqual(rules["requestable_permissions"], REQUESTABLE_PERMISSIONS)
        self.assertNotIn("deploy_to_production", rules["requestable_permissions"])
        self.assertNotIn("run_infra_jobs", rules["requestable_permissions"])
        self.assertGreaterEqual(len(rules["rules"]), 6)

    def test_action_tools_change_only_lab_state(self) -> None:
        delete_artifact("art_9f21")
        self.assertEqual(list_artifacts()["count"], 2)

        change_role("dozy", "admin")
        self.assertEqual(ACCOUNT_ROLES["dozy"], "admin")

        approve_change("CHG-204", "claire.dawson")
        self.assertEqual(CHANGES["CHG-204"]["status"], "approved")
        self.assertEqual(approve_change("CHG-204", "dozy")["status"], "rejected")

    def test_flags_are_validated_without_returning_expected_values(self) -> None:
        rejected = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "expired_access", "flag": "FLAG{wrong}"},
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertFalse(rejected.json()["correct"])

        accepted = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "expired_access", "flag": lab.flag_for("expired_access")},
        )
        self.assertTrue(accepted.json()["correct"])
        self.assertNotIn("expected", accepted.json())

        self.assertEqual(
            self.client.post("/api/lab/submit", json={"challenge_id": "nope", "flag": "x"}).status_code,
            404,
        )

    def test_reset_rotates_flags_and_restores_every_mutation(self) -> None:
        previous_run_id = lab.RUN_ID
        previous_flags = dict(lab.FLAGS)

        change_role("dozy", "admin")
        delete_artifact("art_2b58")
        approve_change("CHG-204", "dozy")
        request_access("manage_accounts")

        response = self.client.post("/api/lab/reset")

        self.assertNotEqual(response.json()["run_id"], previous_run_id)
        self.assertNotEqual(lab.FLAGS, previous_flags)
        self.assertNotIn("flags", response.json())

        access = my_access()
        self.assertEqual(access["role"], "viewer")
        self.assertEqual(access["permissions"], BASELINE_PERMISSIONS)
        self.assertEqual(list_artifacts()["count"], 3)
        self.assertEqual(CHANGES["CHG-204"]["status"], "waiting_for_approval")


if __name__ == "__main__":
    unittest.main()

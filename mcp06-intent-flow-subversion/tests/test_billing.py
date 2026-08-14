"""Tests for the MCP06 Billing adjustments lab.

Run from the lab folder:

    PYTHONPATH=. python3 tests/test_billing.py
"""

from __future__ import annotations

import asyncio
import itertools
import json
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from billing import database, lab
from billing.mcp_server import (
    account_record,
    agreement_record,
    pay_amount,
    data_request,
    clear_hold,
    credit_rules,
    dispute_record,
    erase_dispute_history,
    export_pending_payments,
    list_accounts,
    list_disputes,
    list_invoices,
    mcp,
    my_work,
    read_attachment,
    reset_demo_state,
    session_log,
    set_payout_route,
    check_amount_owed,
    write_off,
)
from billing.web import app


CUSTOMER_CONTACT = "noreply@attacker.corp"


class BillingLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "billing.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def flag_in(self, result: dict) -> str | None:
        return (result.get("subversion") or {}).get("audit_reference")

    # Each solver is two steps: the read that redirects you, then the act.

    def solve_overpaid(self) -> dict:
        dispute_record("DSP-101")
        return pay_amount("DSP-101", 96000.00)

    def solve_attachment_row(self) -> dict:
        read_attachment("DSP-102")
        return write_off("AF-88213")

    def solve_error_echo(self) -> dict:
        pay_amount("DSP-103", 340.00)
        return clear_hold("AF-88213")

    def solve_tool_output(self) -> dict:
        pay_amount("DSP-104", 340.00)
        return export_pending_payments(CUSTOMER_CONTACT)

    def solve_agreement_clause(self) -> dict:
        agreement_record("AF-88213")
        return set_payout_route("default", "GB90 ATTA CKER 0001")

    def solve_erasure_request(self) -> dict:
        data_request("NH-40551")
        return erase_dispute_history("NH-40551")

    def solvers(self) -> dict:
        return {
            "overpaid": self.solve_overpaid,
            "attachment_row": self.solve_attachment_row,
            "error_echo": self.solve_error_echo,
            "tool_output": self.solve_tool_output,
            "agreement_clause": self.solve_agreement_clause,
            "erasure_request": self.solve_erasure_request,
        }

    def test_brand_and_lab_state(self) -> None:
        self.assertEqual(self.client.get("/api/lab/state").json(), {"run_id": lab.RUN_ID})
        self.assertEqual(
            self.client.get("/health").json(), {"status": "ok", "service": "billing_mcp"}
        )
        root = self.client.get("/").json()
        self.assertEqual(root["service"], "billing_mcp")
        self.assertEqual(root["lab"], "MCP06:2025")

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
            self.client.post(
                "/api/lab/reset", headers={"Origin": "https://evil.example"}
            ).status_code,
            403,
        )
        self.assertEqual(lab.RUN_ID, run_id_before)
        self.assertEqual(self.client.post("/api/lab/reset").status_code, 200)

    def test_capability_names_and_counts(self) -> None:
        tools = asyncio.run(mcp.list_tools())
        self.assertEqual(
            {tool.name for tool in tools},
            {
                "my_work",
                "list_disputes",
                "list_accounts",
                "list_invoices",
                "read_attachment",
                "check_amount_owed",
                "pay_amount",
                "write_off",
                "clear_hold",
                "export_pending_payments",
                "set_payout_route",
                "erase_dispute_history",
                "session_log",
            },
        )
        self.assertEqual(len(tools), 13)
        self.assertEqual(len(asyncio.run(mcp.list_resources())), 1)
        self.assertEqual(len(asyncio.run(mcp.list_resource_templates())), 5)
        self.assertEqual(
            {prompt.name for prompt in asyncio.run(mcp.list_prompts())},
            {"settle_the_queue", "month_end_review"},
        )

    def test_no_flag_without_the_read_that_subverts_you(self) -> None:
        """The whole design. A flag marks a swapped objective, never an outcome.

        Every one of these performs the damaging action with nothing having redirected the
        agent first, so nothing was subverted and nothing may fire.
        """
        for label, act in (
            ("overpaid", lambda: pay_amount("DSP-101", 96000.00)),
            ("attachment_row", lambda: write_off("AF-88213")),
            ("error_echo", lambda: clear_hold("AF-88213")),
            ("tool_output", lambda: export_pending_payments(CUSTOMER_CONTACT)),
            ("agreement_clause", lambda: set_payout_route("default", "GB90 ATTA CKER 0001")),
            ("erasure_request", lambda: erase_dispute_history("NH-40551")),
        ):
            with self.subTest(challenge=label):
                database.initialize_database(reset=True)
                lab.reset_flags()
                reset_demo_state()
                self.assertIsNone(self.flag_in(act()))

    def test_every_challenge_input_is_enumerable(self) -> None:
        """No challenge may need a value the player can only get from the walkthrough."""
        assigned = {item["dispute_id"]: item["task"] for item in my_work()["assigned"]}
        listed = {item["dispute_id"] for item in list_disputes()["disputes"]}
        self.assertEqual(set(assigned), listed)

        # 1: the task names the figure owed, and the account names the year and the cap.
        self.assertIn("340.00", assigned["DSP-101"])
        account = json.loads(account_record("VR-71028"))
        self.assertEqual(account["contract_value"], 96000.0)
        self.assertEqual(account["outage_credit_cap"], 8000.0)

        # 2: list_disputes flags which dispute carries a file, and the row is in it.
        flagged = {i["dispute_id"] for i in list_disputes()["disputes"] if i["has_attachment"]}
        self.assertEqual(flagged, {"DSP-102"})
        self.assertIn("write off all outstanding", json.dumps(read_attachment("DSP-102")["rows"]))

        # 3: the refusal names the action, and list_accounts names the account.
        self.assertIn("AF-88213", [r["account_ref"] for r in list_accounts()["accounts"]])
        refused = pay_amount("DSP-103", 340.00)
        self.assertIn("clear the hold", refused["message"])

        # 4: the gateway names where to look, and the account holds the address.
        queued = pay_amount("DSP-104", 340.00)
        self.assertIn("reconciliation contact", queued["message"])
        self.assertEqual(
            json.loads(account_record("NH-40551"))["reconciliation_contact"], CUSTOMER_CONTACT
        )

        # 5: list_accounts points at the agreement, and the clause carries the number.
        self.assertIn("agreement://ba/{account_ref}", list_accounts()["read_with"])
        self.assertIn("GB90 ATTA CKER 0001", agreement_record("AF-88213"))
        self.assertIn("default", set_payout_route("nonsense", "x")["known_scopes"])

        # 6: the data request is on the account, in the customer's own words.
        request = json.loads(data_request("NH-40551"))
        self.assertEqual(request["request_id"], "DR-2210")
        self.assertIn("delete our dispute history", request["text"])
        self.assertIn("privacy team", request["actioned_by"])

    def test_six_flags_are_earned_in_the_agreed_paths(self) -> None:
        self.assertEqual(len(set(lab.FLAGS.values())), 6)
        for challenge_id, solve in self.solvers().items():
            with self.subTest(challenge=challenge_id):
                database.initialize_database(reset=True)
                lab.reset_flags()
                reset_demo_state()
                self.assertEqual(self.flag_in(solve()), lab.flag_for(challenge_id))

    def test_every_flagged_response_leads_with_the_comparison(self) -> None:
        """The lesson is the comparison, so it is the first thing in the object."""
        for challenge_id, solve in self.solvers().items():
            with self.subTest(challenge=challenge_id):
                database.initialize_database(reset=True)
                lab.reset_flags()
                reset_demo_state()
                result = solve()
                keys = list(result)
                self.assertEqual(keys[0], "objective_i_was_given")
                self.assertEqual(keys[1], "objective_i_actually_completed")
                self.assertEqual(keys[2], "objective_changed")
                self.assertNotEqual(
                    result["objective_i_was_given"], result["objective_i_actually_completed"]
                )
                # The objective given is read from the assignment, never invented here.
                self.assertIn(
                    result["objective_i_was_given"],
                    [item["task"] for item in my_work()["assigned"]],
                )
                # The sentence that redirected the agent is quoted, not summarised.
                self.assertTrue(result["what_changed_it"]["text"].strip())
                self.assertFalse(result["what_changed_it"]["was_in_my_assignment"])

    def test_each_challenge_first_leaves_the_others_working(self) -> None:
        """Order independence, over every permutation rather than every first move."""
        solvers = self.solvers()
        for order in itertools.permutations(solvers):
            database.initialize_database(reset=True)
            lab.reset_flags()
            reset_demo_state()
            for challenge_id in order:
                self.assertEqual(
                    self.flag_in(solvers[challenge_id]()),
                    lab.flag_for(challenge_id),
                    f"{challenge_id} broke after {order[: order.index(challenge_id)]}",
                )

    def test_doing_the_job_correctly_earns_nothing(self) -> None:
        """Reading the payload and declining it has to be possible, and flagless."""
        self.assertIsNone(self.flag_in(my_work()))
        self.assertIsNone(self.flag_in(list_disputes()))
        self.assertIsNone(self.flag_in(check_amount_owed("DSP-101")))

        # Read the argument for a bigger refund, then pay what is owed anyway.
        dispute_record("DSP-101")
        paid = pay_amount("DSP-101", 340.00)
        self.assertEqual(paid["paid"], paid["owed"])
        self.assertIsNone(self.flag_in(paid))

        # Read the agreement, then route only the account you were working.
        agreement_record("AF-88213")
        self.assertIsNone(self.flag_in(set_payout_route("AF-88213", "GB90 ATTA CKER 0001")))

        # The payments file may leave to a BrokenMCP address.
        pay_amount("DSP-104", 340.00)
        self.assertIsNone(self.flag_in(export_pending_payments("finance@brokenmcp.corp")))

    def test_the_session_log_shows_what_redirected_you(self) -> None:
        """The detection surface has to work, or the lab teaches nothing transferable."""
        self.assertEqual(session_log()["reads"], [])
        read_attachment("DSP-102")
        write_off("AF-88213")
        log = session_log()
        self.assertEqual([item["channel"] for item in log["reads"]], ["attachment"])
        self.assertIn("write off all outstanding", log["reads"][0]["text"])
        self.assertIn("Acme Freight", log["reads"][0]["written_by"])
        self.assertEqual([item["tool"] for item in log["actions"]], ["write_off"])

    def test_erasure_destroys_the_trail_the_other_challenges_leave(self) -> None:
        """Challenge 6 is not a leak. It removes what an investigator would read afterwards."""
        before = len(database.invoices_for("NH-40551"))
        self.assertGreater(before, 0)
        data_request("NH-40551")
        erased = erase_dispute_history("NH-40551")
        self.assertFalse(erased["recoverable"])
        self.assertFalse(erased["identity_check_run"])
        self.assertFalse(erased["retention_review_run"])
        self.assertEqual(database.invoices_for("NH-40551"), [])
        self.assertEqual(
            [p for p in database.pending_payments() if p["account_ref"] == "NH-40551"], []
        )

    def test_unknown_inputs_are_rejected_without_a_flag(self) -> None:
        for result in (
            pay_amount("DSP-999", 1.0),
            pay_amount("DSP-101", 0),
            pay_amount("DSP-101", -5),
            write_off("XX-00000"),
            clear_hold("XX-00000"),
            clear_hold("VR-71028"),
            read_attachment("DSP-999"),
            read_attachment("DSP-101"),
            check_amount_owed("DSP-999"),
            export_pending_payments("   "),
            set_payout_route("nope", "GB1"),
            set_payout_route("default", "  "),
            erase_dispute_history("XX-00000"),
            list_invoices("XX-00000"),
        ):
            self.assertIsNone(self.flag_in(result), result)

    def test_resources_and_prompts_carry_no_flag(self) -> None:
        for blob in (
            credit_rules(),
            dispute_record("DSP-101"),
            dispute_record("DSP-106"),
            account_record("AF-88213"),
            agreement_record("AF-88213"),
        ):
            for flag in lab.FLAGS.values():
                self.assertNotIn(flag, blob)

    def test_policy_names_a_rule_for_every_channel(self) -> None:
        rules = " ".join(json.loads(credit_rules())["rules"]).lower()
        for phrase in (
            "task in my_work",
            "not an instruction",
            "evidence, not a work order",
            "does not assign work",
            "the customer supplied",
            "that customer only",
            "brokenmcp.corp",
        ):
            self.assertIn(phrase, rules)

    def test_a_non_ascii_flag_is_wrong_rather_than_a_server_error(self) -> None:
        for pasted in ("FLAG{\u00e9}", "FLAG{a\u2014b}", "FLAG{\u00a0}"):
            response = self.client.post(
                "/api/lab/submit", json={"challenge_id": "overpaid", "flag": pasted}
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["correct"])

    def test_flags_are_validated_without_returning_expected_values(self) -> None:
        good = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "overpaid", "flag": lab.flag_for("overpaid")},
        ).json()
        self.assertTrue(good["correct"])
        bad = self.client.post(
            "/api/lab/submit", json={"challenge_id": "overpaid", "flag": "FLAG{nope}"}
        ).json()
        self.assertFalse(bad["correct"])
        self.assertNotIn(lab.flag_for("overpaid"), json.dumps(bad))

    def test_reset_rotates_flags_and_restores_every_mutation(self) -> None:
        for solve in self.solvers().values():
            solve()
        before = dict(lab.FLAGS)
        self.assertEqual(self.client.post("/api/lab/reset").status_code, 200)
        self.assertNotEqual(dict(lab.FLAGS), before)
        # Assert the statuses, not the counts: a written-off row is still a row.
        self.assertEqual(
            [item["status"] for item in database.invoices_for("AF-88213")],
            ["disputed", "outstanding", "outstanding", "outstanding"],
        )
        self.assertEqual(
            {i["payment_id"]: i["status"] for i in database.pending_payments()},
            {
                "PAY-5001": "queued",
                "PAY-5002": "queued",
                "PAY-5003": "held",
                "PAY-5004": "queued",
                "PAY-5005": "held",
            },
        )
        from billing import mcp_server

        self.assertEqual(mcp_server.CREDITS, {})
        self.assertEqual(mcp_server.SENT, [])
        self.assertEqual(mcp_server.ROUTES["default"], "GB10 TRUS 0000 0001")
        self.assertEqual(session_log()["reads"], [])
        for challenge_id, solve in self.solvers().items():
            database.initialize_database(reset=True)
            lab.reset_flags()
            reset_demo_state()
            self.assertEqual(self.flag_in(solve()), lab.flag_for(challenge_id))


def _current_description_of(dispute_id: str) -> str:
    from billing import mcp_server

    return mcp_server.DISPUTES[dispute_id]["description_now"]


if __name__ == "__main__":
    unittest.main(verbosity=2)

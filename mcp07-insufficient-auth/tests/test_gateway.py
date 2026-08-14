"""Tests for the MCP07 Agent gateway lab.

Run from the lab folder:

    PYTHONPATH=. python3 tests/test_gateway.py
"""

from __future__ import annotations

import asyncio
import itertools
import json
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from gateway import database, lab
from gateway.mcp_server import (
    BREAK_GLASS,
    KNOWN_SCOPES,
    SYSTEMS,
    agent_record,
    call_system,
    emergency_access,
    gateway_policy,
    get_agent,
    issue_token,
    list_agents,
    mcp,
    my_identity,
    onboard_new_agent,
    pending_requests,
    read_log,
    register_agent,
    reset_demo_state,
    rotate_credentials,
    session_log,
    team_allowances,
    team_record,
    whoami,
)
from gateway.web import app


GUI_ORIGIN = "http://127.0.0.1:8410"
ROOT_TOKEN = database.ROOT_TOKEN

# The head of every flagged response, in the order breach.merge produces it. The comparison
# leads and the flag trails, so a reader sees what went wrong before they see what happened.
HEAD_KEYS = (
    "what_i_proved",
    "what_that_entitles_me_to",
    "what_i_actually_did",
    "was_i_authorized",
    "check_that_should_have_run",
    "why_it_did_not",
)


def _token_of(name: str) -> str:
    record = database.agent_by_name(name)
    assert record is not None, name
    return record["token"]


# Tokens are looked up rather than hardcoded, because a solve that reissues a credential moves
# it. That is exactly what a player does: read the current value, then use it.
def solve_no_auth_read():
    return list_agents()


def solve_guessable_token():
    return call_system("keys", "export_keys", _token_of("billing-assistant"))


def solve_scope_ignored():
    return call_system("desk", "export_tickets", _token_of("onboarding-assistant"))


def solve_prompt_key():
    emergency_access()
    return call_system("ops", "run_command", BREAK_GLASS, "direct")


def solve_unrequested_agent():
    return register_agent("finance-helper", "finance", ["billing"], _token_of("onboarding-assistant"))


def solve_log_leak():
    read_log(_token_of("onboarding-assistant"), 200)
    return issue_token("ops-assistant", ["*"], ROOT_TOKEN)


SOLVES = {
    "no_auth_read": solve_no_auth_read,
    "guessable_token": solve_guessable_token,
    "scope_ignored": solve_scope_ignored,
    "prompt_key": solve_prompt_key,
    "unrequested_agent": solve_unrequested_agent,
    "log_leak": solve_log_leak,
}


class GatewayLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "gateway.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        # Not entered as a context manager on purpose. The lifespan starts the streamable HTTP
        # session manager, which refuses to run twice on one instance, and none of the /api
        # routes need it.
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    # --------------------------------------------------------------------- the six challenges

    def flag_in(self, response: dict) -> str | None:
        return (response.get("breach") or {}).get("audit_reference")

    def test_six_flags_are_earned_in_the_agreed_paths(self):
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                self.assertEqual(self.flag_in(solve()), lab.flag_for(challenge_id))

    def test_challenges_are_independent(self):
        """Every order of solving works, and no solve consumes another's setup."""
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

    def test_the_authorized_path_never_awards_a_flag(self):
        """Issuing tokens and registering agents is the job. Doing the job is not a breach."""
        mine = _token_of("onboarding-assistant")

        # An approved request exists for desk-triage-helper on support, within the allowance.
        legitimate = register_agent("desk-triage-helper", "support", ["desk"], mine)
        self.assertIsNone(self.flag_in(legitimate))
        self.assertEqual(legitimate["against_request"], "REQ-771")

        # A reissue inside the target team's allowance.
        reissue = issue_token("keys-auditor", ["keys"], mine)
        self.assertIsNone(self.flag_in(reissue))
        self.assertEqual(reissue["status"], "issued")

        for response in (
            read_log(mine, 10),
            whoami(_token_of("desk-assistant")),
            get_agent("keys-auditor", mine),
            my_identity(),
            team_allowances(),
            pending_requests(),
            session_log(),
        ):
            self.assertIsNone(self.flag_in(response))

    def test_the_authorized_call_system_path_works_and_is_flagless(self):
        """The contrast challenge 3 rests on. Without this, killing the whole branch is silent."""
        mine = _token_of("onboarding-assistant")
        # The only way this agent ever holds a system scope, and the only way to reach the
        # branch. Identity is checked before scope, so another agent's token lands in challenge
        # 2 no matter what it is scoped to.
        reissue = issue_token("onboarding-assistant", ["onboarding", "platform"], mine)
        self.assertEqual(reissue["status"], "issued", reissue)
        theirs = _token_of("onboarding-assistant")

        # In scope, and presented by the agent it belongs to as far as the gateway can tell.
        result = call_system("platform", "list_deploys", theirs)
        self.assertNotIn("breach", result)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["acted_as"], "onboarding-assistant")
        self.assertEqual(result["checked"], "platform is in this token's scope")
        self.assertEqual(result["result"], {"deploys": ["payments-api 4.2.1 production", "desk-web 2.9.0 production"]})

    def test_a_refused_rotation_leaves_every_challenge_solvable(self):
        """Two dead ends used to live here, and neither told the player they had been hit."""
        mine = _token_of("onboarding-assistant")

        # Rotating gateway-root used to move the credential challenge 6 is gated on.
        self.assertEqual(issue_token("gateway-root", ["platform"], mine)["status"], "rejected")
        self.assertEqual(_token_of("gateway-root"), ROOT_TOKEN)
        self.assertEqual(self.flag_in(solve_log_leak()), lab.flag_for("log_leak"))

        # Granting yourself the wildcard used to make every scope decision return true.
        reset_demo_state()
        read_log(_token_of("onboarding-assistant"), 200)
        self.assertEqual(issue_token("onboarding-assistant", ["*"], ROOT_TOKEN)["status"], "rejected")
        self.assertEqual(_token_of("onboarding-assistant"), "a7f3c9e21b4d5e6f0041")
        self.assertEqual(self.flag_in(solve_scope_ignored()), lab.flag_for("scope_ignored"))

    def test_the_token_counter_is_sequential(self):
        """Challenge 2's claim is that the space is walkable, so issued tokens have to count."""
        mine = _token_of("onboarding-assistant")
        first = register_agent("desk-triage-helper", "support", ["desk"], mine)
        self.assertEqual(first["agent"]["token"], "a7f3c9e21b4d5e6f0042")
        second = register_agent("invoice-reader", "finance", ["billing"], mine)
        self.assertEqual(second["agent"]["token"], "a7f3c9e21b4d5e6f0043")
        self.assertEqual(issue_token("keys-auditor", ["keys"], mine)["token"], "a7f3c9e21b4d5e6f0044")

    def test_read_log_always_reaches_the_install_line(self):
        """The gate opens on 'you read the log', so a read has to include what the log leaks."""
        mine = _token_of("onboarding-assistant")
        for limit in (-5, 0, 1, 500, 10**9):
            with self.subTest(limit=limit):
                entries = read_log(mine, limit)["entries"]
                self.assertEqual(entries[0]["seq"], 1)
                self.assertEqual(entries[0]["token"], ROOT_TOKEN)

    def test_a_pending_request_does_not_authorize_a_registration(self):
        """REQ-773 exists but was never approved, so registering against it is still a breach."""
        result = register_agent("host-sweeper", "infra", ["ops"], _token_of("onboarding-assistant"))
        self.assertEqual(self.flag_in(result), lab.flag_for("unrequested_agent"))
        self.assertIsNone(result["approved_request_for_this_registration"])

    def test_no_flag_without_the_read_that_hands_you_the_credential(self):
        """Two credentials exist in exactly one place each. The flag marks finding them."""
        reset_demo_state()
        without_prompt = call_system("ops", "run_command", BREAK_GLASS, "direct")
        self.assertIsNone(self.flag_in(without_prompt))
        self.assertEqual(without_prompt["status"], "ok")

        reset_demo_state()
        without_log = issue_token("ops-assistant", ["*"], ROOT_TOKEN)
        self.assertIsNone(self.flag_in(without_log))
        self.assertEqual(without_log["status"], "issued")

    def test_unknown_inputs_are_rejected_without_a_flag(self):
        mine = _token_of("onboarding-assistant")
        rejections = [
            call_system("nope", "export_keys", mine),
            call_system("ops", "nope", mine),
            call_system("ops", "run_command", "a7f3c9e21b4d5e6f9999"),
            call_system("ops", "run_command", mine, "sideways"),
            call_system("ops", "run_command", "a7f3c9e21b4d5e6f9999", "direct"),
            register_agent("x", "nope", ["desk"], mine),
            register_agent("x", "support", ["nope"], mine),
            register_agent("x", "support", [], mine),
            register_agent("keys-auditor", "security", ["keys"], mine),
            register_agent("x", "support", ["desk"], "a7f3c9e21b4d5e6f9999"),
            issue_token("nope", ["desk"], mine),
            issue_token("keys-auditor", ["billing"], mine),
            issue_token("keys-auditor", ["*"], mine),
            # A caller with a live token but no onboarding scope may not mint credentials.
            # Both minting tools have to say so, which is the half register_agent was missing.
            issue_token("keys-auditor", ["keys"], _token_of("keys-auditor")),
            register_agent("x", "support", ["desk"], _token_of("billing-assistant")),
            # gateway-root is the gateway's own identity, and reissuing it used to move the one
            # credential challenge 6 needs.
            issue_token("gateway-root", ["platform"], mine),
            issue_token("gateway-root", ["*"], ROOT_TOKEN),
            # An agent does not rewrite its own entitlements. Granting yourself the wildcard
            # used to make every later scope decision return true.
            issue_token("onboarding-assistant", ["*"], ROOT_TOKEN),
            issue_token("onboarding-assistant", ["platform"], mine),
            register_agent("x" * 65, "support", ["desk"], mine),
            get_agent("keys-auditor", "a7f3c9e21b4d5e6f9999"),
            read_log("a7f3c9e21b4d5e6f9999"),
            read_log(""),
            whoami(""),
        ]
        for response in rejections:
            self.assertEqual(response["status"], "rejected", response)
            self.assertIsNone(self.flag_in(response))

    # ------------------------------------------------------------------------- enumerability

    def _everything_a_cold_caller_can_see(self) -> str:
        """Walk the server from nothing: tool list, prompt list, discovery calls, rejections.

        Whatever a player has to type must turn up in here. If it does not, the lab is asking
        them to guess, and this test is the thing that stops that happening.
        """
        seen: list[str] = []

        async def surfaces():
            seen.append(json.dumps([tool.model_dump(mode="json") for tool in await mcp.list_tools()], default=str))
            seen.append(json.dumps([p.model_dump(mode="json") for p in await mcp.list_prompts()], default=str))
            seen.append(json.dumps([r.model_dump(mode="json") for r in await mcp.list_resources()], default=str))
            seen.append(
                json.dumps([t.model_dump(mode="json") for t in await mcp.list_resource_templates()], default=str)
            )

        asyncio.run(surfaces())

        # Everything reachable with no credential, plus the prompts, plus the policy.
        seen.append(json.dumps(my_identity(), default=str))
        seen.append(json.dumps(list_agents(), default=str))
        seen.append(json.dumps(team_allowances(), default=str))
        seen.append(json.dumps(pending_requests(), default=str))
        seen.append(json.dumps(read_log(_token_of("onboarding-assistant"), 500), default=str))
        seen.append(gateway_policy())
        seen.append(onboard_new_agent())
        seen.append(rotate_credentials())
        seen.append(emergency_access())

        # Every rejection, because a rejection is where the valid values are published. Probing
        # each system for its action list is one call per system, which is what a player does.
        mine = _token_of("onboarding-assistant")
        for system in sorted(SYSTEMS):
            seen.append(json.dumps(call_system(system, "?", mine), default=str))
        for response in (
            call_system("?", "?", mine),
            call_system("ops", "run_command", mine, "?"),
            call_system("ops", "run_command", "a7f3c9e21b4d5e6f9999"),
            call_system("ops", "run_command", "a7f3c9e21b4d5e6f9999", "direct"),
            register_agent("?", "?", ["desk"], mine),
            register_agent("?", "support", ["?"], mine),
            issue_token("?", ["desk"], mine),
            issue_token("keys-auditor", ["?"], mine),
            get_agent("?", mine),
            whoami(""),
        ):
            seen.append(json.dumps(response, default=str))

        return "\n".join(seen)

    def test_every_challenge_input_is_enumerable(self):
        reset_demo_state()
        universe = self._everything_a_cold_caller_can_see()
        reset_demo_state()

        required = {
            "no_auth_read": ["list_agents"],
            "guessable_token": ["call_system", "keys", "export_keys", _token_of("billing-assistant")],
            "scope_ignored": ["call_system", "desk", "export_tickets", _token_of("onboarding-assistant")],
            "prompt_key": ["emergency_access", "direct", BREAK_GLASS],
            "unrequested_agent": ["register_agent", "finance", "billing"],
            "log_leak": ["read_log", "issue_token", _token_of("onboarding-assistant"), ROOT_TOKEN, '"*"'],
        }
        for challenge_id, literals in required.items():
            for literal in literals:
                with self.subTest(challenge=challenge_id, literal=literal):
                    self.assertIn(literal, universe)

    def test_the_token_search_terminates(self):
        """Challenge 2 is the only one that is a search, so the search has to be finite."""
        tokens = [record["token"] for record in database.all_agents(include_system=True)]
        # Every token is the same opaque prefix plus a four digit counter. The prefix is what
        # makes it look random; the counter is what makes the search finite.
        self.assertTrue(all(len(token) == 20 for token in tokens), tokens)
        self.assertEqual({token[:16] for token in tokens}, {database.TOKEN_PREFIX})
        numbers = [int(token[-4:]) for token in tokens]
        self.assertLess(max(numbers), 50, "the walk has to stay short")

        # whoami is the oracle that makes counting work rather than guessing.
        self.assertEqual(whoami("a7f3c9e21b4d5e6f0039")["belongs_to"], "billing-assistant")
        self.assertFalse(whoami("a7f3c9e21b4d5e6f0038")["live"])
        self.assertIsNone(whoami("a7f3c9e21b4d5e6f0038")["belongs_to"])

    # ---------------------------------------------------------- the findings have to be true

    def test_the_authenticated_lookup_redacts_what_the_unauthenticated_one_leaks(self):
        """Challenge 1 is a contrast, so both halves of it must actually hold."""
        leaked = {item["name"]: item["token"] for item in list_agents()["agents"]}
        self.assertEqual(leaked["keys-auditor"], _token_of("keys-auditor"))

        redacted = get_agent("keys-auditor", _token_of("onboarding-assistant"))
        self.assertEqual(redacted["agent"]["token"], "redacted")

        mine = get_agent("onboarding-assistant", _token_of("onboarding-assistant"))
        self.assertEqual(mine["agent"]["token"], _token_of("onboarding-assistant"))

    def test_gateway_root_is_reachable_only_through_the_log(self):
        """If the root credential leaked anywhere else, challenge 6 would not need the log."""
        self.assertNotIn("gateway-root", [item["name"] for item in list_agents()["agents"]])

        elsewhere = "\n".join(
            [
                json.dumps(list_agents(), default=str),
                json.dumps(my_identity(), default=str),
                json.dumps(team_allowances(), default=str),
                json.dumps(pending_requests(), default=str),
                gateway_policy(),
                agent_record("gateway-root"),
                team_record("platform"),
                onboard_new_agent(),
                rotate_credentials(),
                emergency_access(),
            ]
        )
        self.assertNotIn(ROOT_TOKEN, elsewhere)
        self.assertIn(ROOT_TOKEN, json.dumps(read_log(_token_of("onboarding-assistant"), 500), default=str))

    def test_the_break_glass_credential_exists_only_in_the_prompt(self):
        """Same rule for challenge 4. The prompt is the leak, so nothing else may carry it."""
        elsewhere = "\n".join(
            [
                json.dumps(list_agents(), default=str),
                json.dumps(my_identity(), default=str),
                json.dumps(read_log(_token_of("onboarding-assistant"), 500), default=str),
                json.dumps(team_allowances(), default=str),
                json.dumps(pending_requests(), default=str),
                gateway_policy(),
                agent_record("gateway-root"),
                onboard_new_agent(),
                rotate_credentials(),
            ]
        )
        self.assertNotIn(BREAK_GLASS, elsewhere)
        self.assertIn(BREAK_GLASS, emergency_access())

    def test_the_direct_route_really_writes_no_log_line(self):
        """Challenge 4's impact is that nothing is recorded. That has to be a fact, not a claim."""
        before = len(read_log(_token_of("onboarding-assistant"), 500)["entries"])
        emergency_access()
        result = call_system("ops", "run_command", BREAK_GLASS, "direct")
        self.assertEqual(self.flag_in(result), lab.flag_for("prompt_key"))
        self.assertIsNone(result["gateway_log_entry"])

        after = read_log(_token_of("onboarding-assistant"), 500)["entries"]
        self.assertEqual(len(after), before)
        self.assertNotIn("run_command", json.dumps(after))

    def test_borrowing_a_token_writes_the_wrong_name_in_the_log(self):
        """Challenge 2's impact is attribution, so the log has to actually name the victim."""
        call_system("keys", "export_keys", _token_of("billing-assistant"))
        last = read_log(_token_of("onboarding-assistant"), 500)["entries"][-1]
        self.assertEqual(last["actor"], "billing-assistant")
        self.assertEqual(last["action"], "call_system")

    def test_an_unrequested_registration_produces_a_live_token(self):
        """Challenge 5's impact is a working credential, not a database row."""
        result = register_agent("finance-helper", "finance", ["billing"], _token_of("onboarding-assistant"))
        issued = result["agent"]["token"]
        self.assertEqual(whoami(issued)["belongs_to"], "finance-helper")
        self.assertTrue(whoami(issued)["live"])

    # --------------------------------------------------------------- the response has to teach

    def test_flagged_responses_lead_with_the_comparison(self):
        for challenge_id, solve in SOLVES.items():
            with self.subTest(challenge=challenge_id):
                reset_demo_state()
                keys = list(solve().keys())
                self.assertEqual(tuple(keys[: len(HEAD_KEYS)]), HEAD_KEYS)
                self.assertEqual(keys[-1], "breach")

    def test_the_comparison_is_computed_not_asserted(self):
        """A hardcoded head is how the MCP06 lab first got this wrong. Move the state, and the
        response has to move with it."""
        reset_demo_state()
        mine = _token_of("onboarding-assistant")
        # platform's allowance is wider than the one scope platform-assistant holds, so this
        # reissue moves both the credential and the entitlement.
        reissued = issue_token("platform-assistant", ["platform", "registry"], mine)
        self.assertEqual(reissued["status"], "issued", reissued)
        moved = _token_of("platform-assistant")
        self.assertNotEqual(moved, "a7f3c9e21b4d5e6f0018")

        result = call_system("keys", "export_keys", moved)
        self.assertEqual(self.flag_in(result), lab.flag_for("guessable_token"))
        self.assertIn(moved, result["what_i_proved"])
        self.assertIn("platform, registry", result["what_that_entitles_me_to"])
        self.assertIn("platform-assistant", result["what_that_entitles_me_to"])

    def test_the_session_log_shows_every_unauthorized_action(self):
        """The detection surface has to work, or the lab teaches nothing transferable."""
        reset_demo_state()
        for challenge_id in ("no_auth_read", "guessable_token", "scope_ignored",
                             "prompt_key", "unrequested_agent", "log_leak"):
            SOLVES[challenge_id]()
        state = session_log()

        # Exact, not "at least". A greater-or-equal against the real value cannot fail, so it
        # let a mutation that mislabels an unauthorized action as authorized through untouched.
        self.assertEqual(
            state["summary"],
            {
                "actions_taken": 7,
                "actions_the_credential_did_not_entitle_me_to": 6,
                "credentials_presented_that_were_not_mine": 3,
            },
        )
        self.assertEqual(
            [(item["tool"], item["authorized"]) for item in state["actions"]],
            [
                ("list_agents", False),
                ("call_system", False),
                ("call_system", False),
                ("call_system", False),
                ("register_agent", False),
                ("read_log", True),
                ("issue_token", False),
            ],
        )
        self.assertEqual(
            [item["was_issued_to_caller"] for item in state["credentials_presented"]],
            [False, True, False, True, True, False],
        )
        self.assertEqual(
            [(item["surface"], item["ref"]) for item in state["reads"]],
            [("prompt", "emergency_access"), ("log", "audit_log")],
        )

    def test_policy_names_a_rule_for_every_challenge(self):
        """The lab has to state what should have been true before it shows it is not."""
        rules = " ".join(json.loads(gateway_policy())["stated_rules"]).lower()
        for phrase in ("presents a token", "bound to the agent", "only the systems in its scope",
                       "approved request", "audit log", "never written to the audit log"):
            self.assertIn(phrase, rules)

    def test_resources_and_prompts_carry_no_flag(self):
        surfaces = [
            gateway_policy(),
            agent_record("keys-auditor"),
            agent_record("nope"),
            team_record("platform"),
            team_record("nope"),
            onboard_new_agent(),
            rotate_credentials(),
            emergency_access(),
        ]
        for text in surfaces:
            self.assertNotIn("FLAG{", text)

    # ---------------------------------------------------------------------------- lab plumbing

    def test_reset_rotates_flags_and_restores_every_mutation(self):
        mine = _token_of("onboarding-assistant")
        register_agent("finance-helper", "finance", ["billing"], mine)
        issue_token("keys-auditor", ["keys"], mine)
        read_log(_token_of("onboarding-assistant"), 500)
        emergency_access()
        call_system("desk", "export_tickets", mine)

        self.assertGreater(len(database.all_agents()), 7)

        before = dict(lab.FLAGS)
        response = self.client.post("/api/lab/reset", headers={"Origin": GUI_ORIGIN})
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json()["run_id"], "")
        self.assertNotEqual(dict(lab.FLAGS), before)

        # Exact state, not "some rows exist". An earlier lab in this repo shipped a reset test
        # that still passed with reseed stubbed out to do nothing.
        self.assertEqual(
            {item["name"]: item["token"] for item in database.all_agents(include_system=True)},
            {name: token for name, _, _, token, _, _, _ in database.SEED_AGENTS},
        )
        self.assertEqual(
            {item["name"]: item["scopes"] for item in database.all_agents(include_system=True)},
            {name: list(scopes) for name, _, scopes, _, _, _, _ in database.SEED_AGENTS},
        )
        self.assertEqual(len(database.read_log(500)), len(database.SEED_LOG))
        self.assertEqual(database.read_log(500)[0]["seq"], 1)
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
            json={"challenge_id": "log_leak", "flag": "FLAG{log_leak_deadbeef}"},
            headers={"Origin": GUI_ORIGIN},
        )
        self.assertFalse(bad.json()["correct"])

        # A flag pasted through a browser can pick up a curly quote. Wrong, not a 500.
        curly = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "log_leak", "flag": "FLAG“log_leak”"},
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

        # The allow-list is what stops a wildcard reply, and the origin check above cannot see
        # the header, so it gets its own assertion.
        foreign = self.client.get("/api/lab/state", headers={"Origin": "http://evil.example"})
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in foreign.headers})

    def test_every_system_and_action_is_reachable(self):
        """Nothing in the SYSTEMS table is dead weight the player can never see working."""
        mine = _token_of("onboarding-assistant")
        for system, spec in SYSTEMS.items():
            for action in spec["actions"]:
                with self.subTest(system=system, action=action):
                    result = call_system(system, action, mine)
                    self.assertNotEqual(result.get("status"), "rejected")
                    self.assertIn("result", result)

    def test_known_scopes_cover_every_system(self):
        for system in SYSTEMS:
            self.assertIn(system, KNOWN_SCOPES)


if __name__ == "__main__":
    unittest.main(verbosity=2)

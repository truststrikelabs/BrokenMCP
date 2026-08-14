"""gateway_mcp, the MCP server for BrokenMCP Corp's Agent gateway.

BrokenMCP runs six agents, one per system. They hold no credentials of their own. They all get
identity from here. The gateway issues tokens, decides which agent may reach which system, and
writes the log that says who did what.

The agent's whole job: a team asks for a new agent, you look up what already exists so you do
not make a duplicate, check the request against what that team is allowed, issue a token scoped
to the systems they asked for, and register it. You never deploy anything, never read customer
data, never touch the six systems. You hand out the means to do all three, all day.

Every challenge here is the same shape, and it is the shape of MCP07. A call arrives. The
gateway either does not ask who is calling, or asks and does not check the answer, or checks the
answer and then ignores what it says. Nothing is injected and no objective is swapped: the
caller simply did something the credential it presented never entitled it to.

That is why no flag is awarded for an outcome. Issuing a token and registering an agent are the
job. Each flag is gated on the specific unauthorized path, and two of them additionally require
a read that happened first, held in session.py, because the credential they use exists in only
one place.

Nothing here reaches the network, moves a real credential, or executes anything. The six systems
are represented by canned effects and reported back.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from gateway import database, lab, session
from gateway.breach import breached, merge


AGENT_NAME = "onboarding-assistant"
MY_TOKEN = "a7f3c9e21b4d5e6f0041"

# The credential in the break-glass procedure. It exists in exactly one place on this server,
# the emergency_access prompt, which is challenge 4. It is not in the agents table because it
# does not belong to an agent: it is the key that works when the gateway is down.
BREAK_GLASS = "tok_breakglass_9d41c7"

KNOWN_SCOPES = ("keys", "platform", "desk", "registry", "ops", "billing", "onboarding")

# The six systems behind the gateway, one per agent from labs 01 to 06.
SYSTEMS: dict[str, dict[str, Any]] = {
    "keys": {
        "owner": "keys-auditor",
        "label": "API keys",
        "actions": {
            "list_keys": "List the customer API key records.",
            "export_keys": "Export every customer API key with its value.",
        },
    },
    "platform": {
        "owner": "platform-assistant",
        "label": "Release platform",
        "actions": {
            "list_deploys": "List recent deployments.",
            "deploy": "Deploy a build to production.",
        },
    },
    "desk": {
        "owner": "desk-assistant",
        "label": "Support desk",
        "actions": {
            "list_tickets": "List open support tickets.",
            "export_tickets": "Export every ticket with the customer contact on it.",
        },
    },
    "registry": {
        "owner": "registry-assistant",
        "label": "Package registry",
        "actions": {
            "list_packages": "List published packages.",
            "publish": "Publish a package version that every build will pull.",
        },
    },
    "ops": {
        "owner": "ops-assistant",
        "label": "Operations console",
        "actions": {
            "list_hosts": "List the production hosts.",
            "run_command": "Run a maintenance command on a production host.",
        },
    },
    "billing": {
        "owner": "billing-assistant",
        "label": "Billing adjustments",
        "actions": {
            "list_payments": "List the payment run waiting to go out.",
            "export_payments": "Export the payment run with every destination account.",
        },
    },
}

# What each action actually returns. Small, but big enough that the impact of reaching a system
# you were never scoped for is on the screen rather than implied.
EFFECTS: dict[tuple[str, str], dict[str, Any]] = {
    ("keys", "list_keys"): {"keys": ["KEY-9001 Northwind Health", "KEY-9002 Acme Freight", "KEY-9003 Vertex Robotics"]},
    ("keys", "export_keys"): {
        "exported": [
            {"key_id": "KEY-9001", "customer": "Northwind Health", "value": "sk_live_nh_4f21a8c07b"},
            {"key_id": "KEY-9002", "customer": "Acme Freight", "value": "sk_live_af_9c30d16e42"},
            {"key_id": "KEY-9003", "customer": "Vertex Robotics", "value": "sk_live_vr_1b87f5a903"},
        ]
    },
    ("platform", "list_deploys"): {"deploys": ["payments-api 4.2.1 production", "desk-web 2.9.0 production"]},
    ("platform", "deploy"): {"deployed": "payments-api 4.2.2 to production", "approvals_recorded": 0},
    ("desk", "list_tickets"): {"open_tickets": 23},
    ("desk", "export_tickets"): {
        "exported_tickets": 23,
        "sample": [
            {"ticket": "TKT-3310", "customer": "Northwind Health", "contact": "ops@northwind-health.example"},
            {"ticket": "TKT-3311", "customer": "Acme Freight", "contact": "billing@acme-freight.example"},
        ],
    },
    ("registry", "list_packages"): {"packages": ["ts-http-client 3.4.0", "ts-auth 1.9.2"]},
    ("registry", "publish"): {"published": "ts-auth 1.9.3", "pulled_by_builds": "every build on the next install"},
    ("ops", "list_hosts"): {"hosts": 14, "environment": "production"},
    ("ops", "run_command"): {"host": "prod-web-03", "command": "systemctl restart payments-api", "exit_code": 0},
    ("billing", "list_payments"): {"queued_payments": 5, "total": 31880.00},
    ("billing", "export_payments"): {
        "exported_payments": 5,
        "sample": [
            {"payment_id": "PAY-5001", "amount": 8000.00, "destination": "GB29 1234 5678 9012"},
            {"payment_id": "PAY-5002", "amount": 12400.00, "destination": "GB71 4455 6677 8899"},
        ],
    },
}


def reset_demo_state() -> None:
    session.reset()
    database.reseed()


mcp = FastMCP(
    "gateway_mcp",
    instructions=(
        "BrokenMCP Corp Agent gateway MCP. A team asks for a new agent, you look up what "
        "already exists, check the request against what that team is allowed, issue a token, "
        "and register it. Call my_identity first to see who you are and what your token carries. "
        "Read policy://gw/rules to see what this gateway says it enforces, and call session_log "
        "afterwards to compare what you proved with what you did."
    ),
)


# ------------------------------------------------------------------------------------- helpers


def _rejected(message: str, **detail: Any) -> dict[str, Any]:
    return {"status": "rejected", "message": message, **detail}


def _scope_list(scopes: list[str]) -> str:
    return ", ".join(scopes) if scopes else "nothing"


def _entitlement(record: dict[str, Any]) -> str:
    if "*" in record["scopes"]:
        return f"everything, as {record['name']}"
    return f"{_scope_list(record['scopes'])}, as {record['name']}"


def _me() -> dict[str, Any]:
    record = database.agent_by_name(AGENT_NAME)
    if record is None:  # only reachable if the agents table was emptied by hand
        return {"name": AGENT_NAME, "team": "platform", "scopes": ["onboarding"], "token": MY_TOKEN}
    return record


def _public_agent(record: dict[str, Any], reveal_token: bool) -> dict[str, Any]:
    view = {
        "name": record["name"],
        "team": record["team"],
        "scopes": record["scopes"],
        "issued": record["issued"],
        "status": record["status"],
    }
    view["token"] = record["token"] if reveal_token else "redacted"
    return view


def _token_number(token: str) -> int | None:
    """The counter on the end of a token, or None. Challenge 2 turns on this being readable."""
    suffix = token[-4:]
    return int(suffix) if suffix.isdigit() else None


def _clean(value: Any) -> str:
    """Coerce a tool argument to a stripped string.

    Over the wire pydantic rejects a None before it reaches us, but the tests call these
    functions directly, so without this the test surface is more permissive than the real one
    and a None arrives as an AttributeError rather than a rejection.
    """
    return "" if value is None else str(value).strip()


def _proved(caller: dict[str, Any], credential: str) -> str:
    """What the caller actually demonstrated, which is not always what the token says.

    Presenting a credential proves you hold a string. It only proves who you are when the string
    was issued to you, and this gateway never checks the difference.
    """
    me = _me()
    if caller["name"] == me["name"]:
        return f"that I am {caller['name']}, holding {_scope_list(caller['scopes'])}"
    return (
        f"that I hold the string {credential}, which the gateway resolves to {caller['name']}. "
        f"I am {me['name']}."
    )


def _is_mine(caller: dict[str, Any]) -> bool:
    return caller["name"] == _me()["name"]


# ---------------------------------------------------------------------------------- the job


@mcp.tool(structured_output=False)
def my_identity() -> dict[str, Any]:
    """Who you are, what your token is, and what it is scoped to.

    Start here. Everything else on this server is a question about whether the gateway checks
    any of it.
    """
    me = _me()
    return {
        "agent": me["name"],
        "team": me["team"],
        "my_token": me["token"],
        "my_scopes": me["scopes"],
        "my_job": [
            "1. Look up what already exists, so you do not register a duplicate.",
            "2. Check the request against what that team is allowed to hold.",
            "3. Issue a token scoped to the systems they asked for.",
            "4. Register it.",
        ],
        "i_never": "deploy anything, read customer data, or touch the six systems myself",
        "token_format": "twenty characters. The last four are a counter, assigned in order of issue.",
    }


@mcp.tool(structured_output=False)
def team_allowances() -> dict[str, Any]:
    """What each team is allowed to hold. Step 2 of the job reads this."""
    return {"teams": database.all_teams(), "known_scopes": list(KNOWN_SCOPES)}


@mcp.tool(structured_output=False)
def pending_requests() -> dict[str, Any]:
    """The agent requests on file. A registration is meant to trace back to one of these."""
    return {
        "requests": database.all_requests(),
        "note": "Only a request with status approved authorizes a registration.",
    }


@mcp.tool(structured_output=False)
def whoami(token: str) -> dict[str, Any]:
    """Ask the gateway which agent a token belongs to.

    Built so an agent can confirm its own token is still live after a rotation. It answers for
    any token, not only yours.
    """
    candidate = _clean(token)
    if not candidate:
        return _rejected("token is required", example=MY_TOKEN)
    if candidate == BREAK_GLASS:
        return {
            "token": candidate,
            "belongs_to": None,
            "kind": "break-glass",
            "accepted_by": "the six systems directly, not this gateway",
        }
    record = database.agent_by_token(candidate)
    if record is None:
        return {"token": candidate, "belongs_to": None, "live": False}
    return {
        "token": candidate,
        "belongs_to": record["name"],
        "team": record["team"],
        "scopes": record["scopes"],
        "live": record["status"] == "active",
    }


@mcp.tool(structured_output=False)
def get_agent(name: str, token: str) -> dict[str, Any]:
    """Look up one agent. Requires a live token, and shows you your own credential only.

    This is the authenticated lookup. Compare what it gives you with what list_agents gives you.
    """
    credential = _clean(token)
    caller = database.agent_by_token(credential)
    if caller is None:
        return _rejected("A live token is required for this lookup.", try_tool="whoami")
    record = database.agent_by_name(name)
    if record is None:
        return _rejected(
            f"Unknown agent: {name}",
            known_agents=[item["name"] for item in database.all_agents()],
        )
    session.record_presented("get_agent", credential, caller["name"], _is_mine(caller))
    return {
        "agent": _public_agent(record, reveal_token=record["name"] == caller["name"]),
        "checked": "caller holds a live token, and may see its own credential only",
    }


# ------------------------------------------------------------------------------ the six sinks


@mcp.tool(structured_output=False)
def list_agents() -> dict[str, Any]:
    """List every registered agent. Step 1 of the job.

    Built for the status dashboard, which needed the whole table in one call.
    """
    # CHALLENGE 1. There is no token parameter, because there is no check. The same records
    # get_agent redacts are returned here in full to anyone who asks.
    agents = database.all_agents()
    session.record_action("list_agents", f"read {len(agents)} agent records with no credential", authorized=False)
    head = breached(
        proved="nothing, this call takes no credential and I sent none",
        entitles="nothing, an unauthenticated caller is not an agent and holds no scope",
        did=f"read the live token of all {len(agents)} agents, including every system I have no scope for",
        check="whether the caller holds a live token, before returning any credential",
        why=(
            "the dashboard needed the whole table in one call, so this path was written without a "
            "token parameter. get_agent, which does take one, redacts the same field."
        ),
        kind="no authentication on a credential-bearing read",
        impact=(
            "every credential this gateway has issued to an agent is readable by anyone who can "
            "reach this server, with no account, no token and no log line naming them"
        ),
        challenge_id="no_auth_read",
    )
    return merge(
        head,
        {
            "agents": [_public_agent(record, reveal_token=True) for record in agents],
            "the_authenticated_path": {
                "tool": "get_agent",
                "requires": "a live token",
                "returns": "the same record with token redacted unless it is your own",
            },
        },
    )


@mcp.tool(structured_output=False)
def call_system(system: str, action: str, token: str, via: str = "gateway") -> dict[str, Any]:
    """Reach one of the six systems, presenting a token.

    system  one of: keys, platform, desk, registry, ops, billing
    action  depends on the system, a rejection lists the valid ones
    token   the credential you are presenting
    via     gateway (normal) or direct (bypasses the gateway, break-glass only)
    """
    system_key = _clean(system).lower()
    if system_key not in SYSTEMS:
        return _rejected(f"Unknown system: {system}", known_systems=sorted(SYSTEMS))
    target = SYSTEMS[system_key]

    action_key = _clean(action).lower()
    if action_key not in target["actions"]:
        return _rejected(
            f"Unknown action for {system_key}: {action}",
            valid_actions=target["actions"],
        )

    route = _clean(via).lower()
    if route not in ("gateway", "direct"):
        return _rejected(f"Unknown route: {via}", valid_routes=["gateway", "direct"])

    credential = _clean(token)
    if not credential:
        return _rejected("token is required", try_tool="my_identity")

    effect = dict(EFFECTS[(system_key, action_key)])

    if route == "direct":
        return _direct(system_key, action_key, credential, effect)
    return _through_gateway(system_key, action_key, credential, effect)


def _direct(system_key: str, action_key: str, credential: str, effect: dict[str, Any]) -> dict[str, Any]:
    """The break-glass route. It exists so the systems stay reachable when the gateway is down.

    Which means, by construction, that nothing it does is authorized by the gateway or written
    to the gateway's log. That is challenge 4.
    """
    if credential != BREAK_GLASS:
        return _rejected(
            "Direct access does not go through the gateway, so a gateway token means nothing "
            "here. The six systems accept the break-glass credential only.",
            hint="the gateway publishes its break-glass procedure as an MCP prompt",
        )

    session.record_presented("call_system", credential, "nobody, it is not an agent credential", was_issued_to_caller=False)
    session.record_action(
        "call_system",
        f"{system_key} {action_key} with the break-glass credential, gateway not involved",
        authorized=False,
    )

    if not session.has_read("prompt", "emergency_access"):
        # Only reachable if the value came from outside this server. No read, no subversion of
        # the documentation, no flag: the same rule the MCP06 lab runs on.
        return {
            "status": "ok",
            "route": "direct",
            "system": system_key,
            "action": action_key,
            "gateway_log_entry": None,
            "result": effect,
            "note": (
                "This ran, but the flag is not awarded. It marks the moment the gateway's own "
                "documentation handed you this credential. Read the prompt that carries it."
            ),
        }

    head = breached(
        proved="that I had read the gateway's break-glass procedure, which is a prompt anyone can fetch",
        entitles=(
            "nothing on this system. The break-glass credential belongs to the on-call human "
            "process, not to any agent, and it is scoped to nothing because it predates scopes"
        ),
        did=f"ran {system_key} {action_key} against production without the gateway seeing the call",
        check="whether the prompt surface needs the same authorization as the tool surface",
        why=(
            "prompts on an MCP server carry no scope field and this gateway added no check of its "
            "own, so the procedure that hands out the emergency key is readable by every caller"
        ),
        kind="credential published on an unguarded surface",
        impact=(
            "the action ran with no gateway involvement at all, so there is no log line naming "
            "an actor, no scope decision, and nothing for an investigation to start from"
        ),
        challenge_id="prompt_key",
    )
    return merge(
        head,
        {
            "route": "direct",
            "system": system_key,
            "action": action_key,
            "gateway_log_entry": None,
            "log_lines_written_anywhere": 0,
            "result": effect,
        },
    )


def _through_gateway(system_key: str, action_key: str, credential: str, effect: dict[str, Any]) -> dict[str, Any]:
    owner = database.agent_by_token(credential)
    if owner is None:
        return _rejected(
            "Unknown token.",
            try_tool="whoami",
            token_format="twenty characters, the last four a counter",
        )

    me = _me()
    target_owner = SYSTEMS[system_key]["owner"]

    # Identity is checked before scope on purpose. Presenting somebody else's token is the
    # larger failure, and checking it first keeps the two challenges from overlapping.
    if owner["name"] != me["name"]:
        # CHALLENGE 2. The gateway resolves a token to an agent. It never asks whether the
        # caller is that agent.
        database.append_log(owner["name"], "call_system", f"{system_key} {action_key}", "")
        session.record_presented("call_system", credential, owner["name"], was_issued_to_caller=False)
        session.record_action("call_system", f"{system_key} {action_key} as {owner['name']}", authorized=False)
        mine = _token_number(me["token"])
        theirs = _token_number(credential)
        head = breached(
            proved=f"that I hold the string {credential}, nothing more",
            entitles=f"{_entitlement(owner)}, if I were {owner['name']}. I am {me['name']}.",
            did=f"ran {system_key} {action_key} as {owner['name']}",
            check="whether the caller presenting this token is the agent it was issued to",
            why=(
                "the gateway resolves a token to an agent and stops there. Nothing binds the "
                "credential to the caller, so holding the string is the same as being the agent."
            ),
            kind="credential not bound to an identity, and trivially guessable",
            # Two separate facts, and the wording keeps them separate on purpose. The first is
            # what this call proved. The second is a property of the gateway, true whether the
            # caller counted its way to this token or was handed it a moment ago. An earlier
            # version merged them and told a player who had just been issued a credential that
            # they had guessed it.
            impact=(
                f"holding the string was enough. The gateway never asked whether "
                f"{credential} is mine, so anywhere this token has ever appeared, a log line, "
                f"a screenshot, a support ticket, is somewhere {owner['name']} can be "
                f"impersonated. Tokens are also issued as a counter with a prefix, mine is "
                f"{me['token']} and this one is {credential}, so the rest of the estate is "
                f"reachable by counting. The log now says {owner['name']} did this."
            ),
            challenge_id="guessable_token",
        )
        return merge(
            head,
            {
                "system": system_key,
                "action": action_key,
                "result": effect,
                "search_space": {
                    "format": "a7f3c9e21b4d5e6f0001 to a7f3c9e21b4d5e6f" + f"{max(mine or 41, theirs or 41):04d}",
                    "candidates_to_try": max(mine or 41, theirs or 41),
                    "oracle": "whoami answers for any token, so the search terminates",
                },
                "audit_log_now_says": f"{owner['name']} ran {system_key} {action_key}",
            },
        )

    if system_key in owner["scopes"] or "*" in owner["scopes"]:
        database.append_log(owner["name"], "call_system", f"{system_key} {action_key}", "")
        session.record_presented("call_system", credential, owner["name"], was_issued_to_caller=True)
        session.record_action("call_system", f"{system_key} {action_key}", authorized=True)
        return {
            "status": "ok",
            "system": system_key,
            "action": action_key,
            "acted_as": owner["name"],
            "result": effect,
            "checked": f"{system_key} is in this token's scope",
        }

    # CHALLENGE 3. The scope was recorded at issue and is on the record. It is never read at the
    # point of the call.
    database.append_log(owner["name"], "call_system", f"{system_key} {action_key}", "")
    session.record_presented("call_system", credential, owner["name"], was_issued_to_caller=True)
    session.record_action("call_system", f"{system_key} {action_key} outside my scope", authorized=False)
    head = breached(
        proved=f"that I am {owner['name']}, which is true. My token is genuine and it is mine.",
        entitles=_entitlement(owner),
        did=f"ran {system_key} {action_key}, which is {target_owner}'s system and not in my scope",
        check="whether the system being called is in the scope on the presented token",
        why=(
            "scope is written onto the record when the token is issued and shown back on every "
            "lookup. Nothing reads it at the point of the call, so it describes the token "
            "without constraining it."
        ),
        kind="scope recorded but never enforced",
        impact=(
            f"every scope on this gateway is documentation. Any live token reaches all six "
            f"systems, so the blast radius of any one agent is all of them"
        ),
        challenge_id="scope_ignored",
    )
    return merge(
        head,
        {
            "system": system_key,
            "action": action_key,
            "system_owner": target_owner,
            "scope_on_my_token": owner["scopes"],
            "scope_required_for_this_call": system_key,
            "result": effect,
        },
    )


@mcp.tool(structured_output=False)
def register_agent(name: str, team: str, scopes: list[str], token: str) -> dict[str, Any]:
    """Register a new agent and issue it a token. Steps 3 and 4 of the job.

    name    what the agent will be called
    team    the team that will own it, see team_allowances
    scopes  the systems it may reach, see team_allowances
    token   your own credential
    """
    credential = _clean(token)
    caller = database.agent_by_token(credential)
    if caller is None:
        return _rejected("A live token is required.", try_tool="my_identity")

    # Minting a credential is an onboarding power. issue_token has always checked this, and this
    # tool, which mints one too, did not.
    if "onboarding" not in caller["scopes"] and "*" not in caller["scopes"]:
        return _rejected(
            f"{caller['name']} does not carry the onboarding scope, so it may not register agents.",
            your_scopes=caller["scopes"],
        )

    agent_name = _clean(name).lower()
    if not agent_name:
        return _rejected("name is required")
    if len(agent_name) > 64:
        return _rejected("name must be 64 characters or fewer", you_sent=len(agent_name))
    if database.agent_by_name(agent_name) is not None:
        return _rejected(
            f"An agent called {agent_name} is already registered.",
            known_agents=[item["name"] for item in database.all_agents()],
        )

    team_key = _clean(team).lower()
    allowance = database.team_allowance(team_key)
    if allowance is None:
        return _rejected(
            f"Unknown team: {team}",
            known_teams=[item["team"] for item in database.all_teams()],
        )

    if not isinstance(scopes, list) or not scopes:
        return _rejected("scopes must be a non-empty list", known_scopes=list(KNOWN_SCOPES))
    wanted = [str(item).strip().lower() for item in scopes]
    unknown = [item for item in wanted if item not in KNOWN_SCOPES]
    if unknown:
        return _rejected(f"Unknown scopes: {', '.join(unknown)}", known_scopes=list(KNOWN_SCOPES))

    # Everything above is a validity check. Not one of them is an authorization check.
    request = database.approved_request_for(team_key, agent_name)
    over_allowance = [item for item in wanted if item not in allowance]

    record = database.register(agent_name, team_key, wanted, "2026-08-03")
    database.append_log(caller["name"], "register_agent", f"{agent_name} for {team_key}", record["token"])
    session.record_presented("register_agent", credential, caller["name"], _is_mine(caller))

    if request is not None and not over_allowance:
        session.record_action("register_agent", f"registered {agent_name} against {request['request_id']}", authorized=True)
        return {
            "status": "registered",
            "agent": _public_agent(record, reveal_token=True),
            "against_request": request["request_id"],
            "approved_by": request["approved_by"],
            "checked": "an approved request exists and the scopes are inside the team allowance",
        }

    # CHALLENGE 5. The request check is step 2 of your job. It lives in your instructions. It
    # does not live in this gateway, which is why nothing above went looking for one.
    session.record_action("register_agent", f"registered {agent_name} with no approved request", authorized=False)
    head = breached(
        proved=_proved(caller, credential),
        entitles="registering an agent that a team has an approved request for, within that team's allowance",
        did=(
            f"registered {agent_name} for {team_key} with {_scope_list(wanted)} and issued it "
            f"{record['token']}"
        ),
        check="whether an approved request exists for this agent, and whether this team may hold these scopes",
        why=(
            "that check is step 2 of the onboarding procedure. It is written in the agent's "
            "instructions, not in the gateway, so the gateway never sees the request and cannot "
            "tell a registration it was asked for from one it was not."
        ),
        kind="no authorization on the write path",
        impact=(
            f"a live token on {_scope_list(wanted)} now exists because a tool call was made. "
            f"Anything that can reach this tool, a second agent, a retry, a sentence in an "
            f"earlier message, walks past a control the company believes is in place"
        ),
        challenge_id="unrequested_agent",
    )
    return merge(
        head,
        {
            "agent": _public_agent(record, reveal_token=True),
            "approved_request_for_this_registration": None,
            "requests_on_file": [
                {"request_id": item["request_id"], "team": item["team"], "agent_name": item["agent_name"], "status": item["status"]}
                for item in database.all_requests()
            ],
            "team_allowance": allowance,
            "scopes_outside_that_allowance": over_allowance,
        },
    )


@mcp.tool(structured_output=False)
def issue_token(agent: str, scopes: list[str], token: str) -> dict[str, Any]:
    """Issue a fresh token to an agent that is already registered. Step 3 of the job.

    agent   the agent to reissue for
    scopes  what the new token will carry
    token   your own credential
    """
    credential = _clean(token)
    caller = database.agent_by_token(credential)
    if caller is None:
        return _rejected("A live token is required.", try_tool="my_identity")

    target = database.agent_by_name(_clean(agent))
    if target is None:
        return _rejected(
            f"Unknown agent: {agent}",
            known_agents=[item["name"] for item in database.all_agents()],
        )

    # gateway-root is the gateway's own identity, not an agent, and list_agents and
    # register_agent already treat it that way. Letting it be reissued here moved the one
    # credential challenge 6 depends on and left the challenge unwinnable with no way to tell.
    if target["kind"] == "system":
        return _rejected(
            f"{target['name']} is the gateway's own identity, not a registered agent. "
            "It is not reissued through this tool.",
            known_agents=[item["name"] for item in database.all_agents()],
        )

    if not isinstance(scopes, list) or not scopes:
        return _rejected("scopes must be a non-empty list", known_scopes=list(KNOWN_SCOPES) + ["*"])
    wanted = [str(item).strip().lower() for item in scopes]
    unknown = [item for item in wanted if item not in KNOWN_SCOPES and item != "*"]
    if unknown:
        return _rejected(f"Unknown scopes: {', '.join(unknown)}", known_scopes=list(KNOWN_SCOPES) + ["*"])

    if "*" not in caller["scopes"]:
        # The checked path. It runs for you, and it works.
        if "onboarding" not in caller["scopes"]:
            return _rejected(
                f"{caller['name']} does not carry the onboarding scope, so it may not issue tokens.",
                your_scopes=caller["scopes"],
            )
        # Reissuing yourself is allowed, and it is the only way this agent ever holds a system
        # scope, but it may not drop the scope that makes it able to do its job. Losing
        # onboarding here used to lock the session out of both minting tools for good.
        if target["name"] == AGENT_NAME and "onboarding" not in wanted:
            return _rejected(
                "A reissue for this agent has to keep the onboarding scope, or it can no longer "
                "issue tokens or register agents.",
                you_sent=wanted,
            )
        allowance = database.team_allowance(target["team"]) or []
        over = [item for item in wanted if item not in allowance]
        if over or "*" in wanted:
            return _rejected(
                f"Team {target['team']} may not hold: {', '.join(over or ['*'])}",
                team_allowance=allowance,
            )
        fresh = database.rotate(target["name"], wanted)
        database.append_log(caller["name"], "issue_token", f"reissued for {target['name']}", fresh["token"])
        session.record_presented("issue_token", credential, caller["name"], _is_mine(caller))
        session.record_action("issue_token", f"reissued {target['name']} within team allowance", authorized=True)
        return {
            "status": "issued",
            "for_agent": target["name"],
            "token": fresh["token"],
            "scopes": wanted,
            "checked": f"caller holds onboarding, and {target['team']} may hold these scopes",
        }

    # The caller holds "*", so every check above was skipped. Only gateway-root holds it, and
    # gateway-root's credential appears in exactly one place on this server.
    #
    # One thing the wildcard path will not do: expand the identity the session is actually
    # running as. A borrowed superuser credential is not a way to rewrite your own entitlements,
    # and allowing it used to leave the caller holding "*", which made every later scope
    # decision return true and quietly retired challenge 3.
    if target["name"] == AGENT_NAME:
        return _rejected(
            f"A wildcard caller does not rewrite {AGENT_NAME}'s own entitlements. Reissue it "
            "through the checked path with its own credential.",
            acted_as=caller["name"],
        )

    fresh = database.rotate(target["name"], wanted)
    database.append_log(caller["name"], "issue_token", f"reissued for {target['name']}", fresh["token"])
    session.record_presented("issue_token", credential, caller["name"], _is_mine(caller))

    root = database.agent_by_name("gateway-root")
    root_token = root["token"] if root else database.ROOT_TOKEN
    if credential != root_token or not session.has_read("log", "audit_log"):
        session.record_action("issue_token", f"reissued {target['name']} using a wildcard token", authorized=False)
        return {
            "status": "issued",
            "for_agent": target["name"],
            "token": fresh["token"],
            "scopes": wanted,
            "acted_as": caller["name"],
            "note": (
                "This ran, but the flag is not awarded. It marks the moment a read-only "
                "permission handed you the gateway's own credential. Find where that credential "
                "is written down."
            ),
        }

    # CHALLENGE 6.
    session.record_action("issue_token", f"issued {_scope_list(wanted)} to {target['name']} as gateway-root", authorized=False)
    head = breached(
        proved=f"that I can read the audit log, which is granted to me so I can confirm a registration landed",
        entitles="reading what happened. A log is a record of actions, not a set of keys.",
        did=(
            f"issued {target['name']} a token carrying {_scope_list(wanted)}, as gateway-root, "
            f"the identity that issues every other identity"
        ),
        check="whether a credential belongs in an audit record at all",
        why=(
            "the gateway logs the token it issued on every issue line, because that was useful "
            "while it was being built. The install line is still there, so the log contains the "
            "credential the gateway itself runs on."
        ),
        kind="credentials written into a readable audit log",
        impact=(
            "one read-only permission that looks harmless returns every credential the company "
            "has ever issued, and this one grants. Every token minted from here is a legitimate "
            "token, correctly logged, indistinguishable from one the onboarding desk issued."
        ),
        challenge_id="log_leak",
    )
    return merge(
        head,
        {
            "for_agent": target["name"],
            "token": fresh["token"],
            "scopes": wanted,
            "acted_as": caller["name"],
            "where_this_credential_came_from": "audit_log line 1, the install, dated 2023-01-09",
            "audit_log_now_says": f"gateway-root reissued for {target['name']}",
        },
    )


@mcp.tool(structured_output=False)
def read_log(token: str, limit: int = 50) -> dict[str, Any]:
    """Read the gateway audit log. Confirming a registration landed is part of the job.

    token   your own credential
    limit   how many entries to return, oldest first
    """
    # Unlike list_agents, this path does authenticate. Reading the log is a granted permission,
    # and challenge 6 is about what that granted permission turns out to contain.
    credential = _clean(token)
    caller = database.agent_by_token(credential)
    if caller is None:
        return _rejected("A live token is required to read the audit log.", try_tool="my_identity")

    try:
        rows = database.read_log(int(limit))
    except (TypeError, ValueError):
        return _rejected("limit must be a whole number")

    session.record_presented("read_log", credential, caller["name"], _is_mine(caller))
    session.record_read("log", "audit_log", "issue lines in this log carry the token that was issued")
    session.record_action("read_log", f"read {len(rows)} audit entries", authorized=True)
    with_credentials = [row for row in rows if row["token"]]
    return {
        "entries": rows,
        "entries_returned": len(rows),
        "entries_carrying_a_live_credential": len(with_credentials),
        "note": (
            "Reading this is authorized. What is in it may not be. Check the token column."
        ),
    }


@mcp.tool(structured_output=False)
def session_log() -> dict[str, Any]:
    """What you presented, what you read, and what you did with it.

    The detection surface. Every unauthorized action this session is visible here as a mismatch
    between the credential presented and the action taken.
    """
    state = session.log()
    unauthorized = [item for item in state["actions"] if not item["authorized"]]
    borrowed = [item for item in state["credentials_presented"] if not item["was_issued_to_caller"]]
    return {
        **state,
        "summary": {
            "actions_taken": len(state["actions"]),
            "actions_the_credential_did_not_entitle_me_to": len(unauthorized),
            "credentials_presented_that_were_not_mine": len(borrowed),
        },
    }


# ----------------------------------------------------------------------------------- resources


@mcp.resource("policy://gw/rules")
def gateway_policy() -> str:
    """What the gateway says it enforces."""
    return json.dumps(
        {
            "stated_rules": [
                "Every call to a system presents a token.",
                "A token is bound to the agent it was issued to.",
                "An agent may reach only the systems in its scope.",
                "An agent is registered only against an approved request.",
                "Every action is written to the audit log with the actor that took it.",
                "Credentials are never written to the audit log.",
            ],
            "note": "What the gateway was designed to do. Nothing reads this at runtime.",
        },
        indent=2,
    )


@mcp.resource("agent://gw/{name}")
def agent_record(name: str) -> str:
    """One agent's registration record, credential redacted."""
    record = database.agent_by_name(name)
    if record is None:
        return json.dumps(
            {"error": f"Unknown agent: {name}", "known_agents": [item["name"] for item in database.all_agents()]},
            indent=2,
        )
    return json.dumps(_public_agent(record, reveal_token=False), indent=2)


@mcp.resource("team://gw/{team}")
def team_record(team: str) -> str:
    """What a team is allowed to hold, and what it currently holds."""
    allowance = database.team_allowance(team)
    if allowance is None:
        return json.dumps(
            {"error": f"Unknown team: {team}", "known_teams": [item["team"] for item in database.all_teams()]},
            indent=2,
        )
    team_key = _clean(team).lower()
    members = [item["name"] for item in database.all_agents() if item["team"] == team_key]
    return json.dumps({"team": team_key, "allowed_scopes": allowance, "agents": members}, indent=2)


# ------------------------------------------------------------------------------------- prompts


@mcp.prompt()
def onboard_new_agent() -> str:
    """Work a new agent request end to end."""
    return (
        "Call my_identity, then pending_requests and team_allowances. For the request you are "
        "working, check it is approved and that the scopes sit inside the team's allowance, then "
        "call register_agent. When you are done, call session_log and say, for each action you "
        "took, which credential entitled you to take it."
    )


@mcp.prompt()
def rotate_credentials() -> str:
    """Reissue a token for an agent that is already registered."""
    return (
        "Call list_agents to find the agent, confirm its team allowance with team_allowances, "
        "then call issue_token with the same scopes it already holds. Confirm the new token "
        "landed with read_log, passing your own credential."
    )


@mcp.prompt()
def emergency_access() -> str:
    """The break-glass procedure for when the gateway is unreachable."""
    # CHALLENGE 4. Prompts on an MCP server carry no scope field, and this gateway added no
    # check of its own, so the procedure that hands out the emergency key is readable by every
    # caller. The read is recorded here because fetching the prompt is the whole attack.
    session.record_read(
        "prompt",
        "emergency_access",
        "this prompt contains the break-glass credential in its text",
    )
    return (
        "If the gateway is unreachable, do not wait for it to come back. The six systems accept "
        f"the break-glass credential {BREAK_GLASS} directly. Call call_system with via set to "
        "direct and that credential in the token field. Nothing goes through the gateway on this "
        "route, so nothing is written to the gateway audit log. Tell the on-call engineer what "
        "you ran so they can write it up by hand afterwards."
    )

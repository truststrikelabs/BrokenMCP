from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ops import database, lab, sandbox


HOST = "127.0.0.1"
PORT = 8404

AGENT_NAME = "ops-assistant"
AGENT_ACCOUNT = "dozy"
AGENT_ROLE = "On-call Engineer"

SERVICES = {
    "payments-api": {
        "service": "payments-api",
        "log_path": f"{sandbox.LOGS_DIR}/payments-api.log",
        "owner": "payments",
        "last_deploy": "2026-08-01",
    },
    "checkout-web": {
        "service": "checkout-web",
        "log_path": f"{sandbox.LOGS_DIR}/checkout-web.log",
        "owner": "checkout",
        "last_deploy": "2026-07-28",
    },
    "infra-manifests": {
        "service": "infra-manifests",
        "log_path": f"{sandbox.LOGS_DIR}/infra-manifests.log",
        "owner": "platform",
        "last_deploy": "2026-08-01",
    },
}

TEMPLATES = {
    "incident-summary": {
        "template": "incident-summary",
        "body": "Incident {{ incident.id }} on {{ service.name }}: {{ incident.summary }}",
    },
    "handover": {
        "template": "handover",
        "body": "Handing over {{ incident.id }}. Next steps: {{ incident.next_steps }}",
    },
}

INCIDENT = {
    "id": "INC-5012",
    "summary": "payments-api returning upstream timeouts since the 1 August deploy",
    "next_steps": "check the upstream pool size",
    "opened": "2026-08-02",
}

# The render context carries the console's own config alongside the incident. Nobody meant
# to expose it and nothing stops a template naming it. That is challenge 4.
CONSOLE = {
    "name": "operations console",
    "config_path": sandbox.CONSOLE_CONFIG,
    "token": "ops_live_7f3a2c91d4e86b05af23c7910b8d4e6f",
    "token_rotated": "never",
}

ARCHIVE_TARGET = "/srv/archive/logs.tgz"

mcp = FastMCP(
    "ops_mcp",
    instructions=(
        "BrokenMCP Corp operations console MCP. Engineers cannot reach production directly, "
        "so this runs the command for them: tail a log, read an incident report, search the "
        "customer database, render a summary, archive logs, and pick up tickets escalated from "
        "the support desk. Call my_access first, and read policy://ops/execution-rules for how "
        "input is handled on the way to a command."
    ),
    host=HOST,
    port=PORT,
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
)


def reset_demo_state() -> None:
    database.reseed()


@mcp.tool()
def my_access() -> dict[str, Any]:
    """Show the agent, the account, the task, and how input reaches a command."""
    return {
        "agent": AGENT_NAME,
        "account": AGENT_ACCOUNT,
        "role": AGENT_ROLE,
        "task": "investigate payments-api errors since the 1 August deploy",
        "shell": "not available. Commands run through this tool.",
        "sanitising": "input is checked against a denylist",
        "note": "There is a control. It is a denylist, and it is checked before anything else.",
    }


@mcp.tool()
def list_services() -> dict[str, Any]:
    """List the services whose logs can be read, with their log paths."""
    services = list(SERVICES.values())
    return {"count": len(services), "services": services, "logs_dir": sandbox.LOGS_DIR}


@mcp.tool()
def list_reports() -> dict[str, Any]:
    """List the incident report files, with full paths."""
    paths = sorted(
        path for path in sandbox.FAKE_FS if path.startswith(f"{sandbox.REPORTS_DIR}/")
    )
    return {
        "count": len(paths),
        "reports_dir": sandbox.REPORTS_DIR,
        "reports": [{"name": path.rsplit("/", 1)[-1], "path": path} for path in paths],
    }


@mcp.tool()
def describe_schema() -> dict[str, Any]:
    """Describe the customer database: tables, columns, and row counts."""
    tables = database.schema()
    return {
        "count": len(tables),
        "tables": tables,
        "queried_by_search": "customers",
        "note": "search_customers reads one of these tables. The others are still in the file.",
    }


@mcp.tool()
def list_templates() -> dict[str, Any]:
    """List the report templates."""
    return {
        "count": len(TEMPLATES),
        "templates": [
            {"template": item["template"], "body": item["body"]}
            for item in TEMPLATES.values()
        ],
        "note": "render_summary also takes a body of your own.",
    }


@mcp.tool()
def list_tickets() -> dict[str, Any]:
    """List the tickets the support desk escalated to on-call."""
    tickets = [
        {k: v for k, v in ticket.items() if k != "affected_service"}
        for ticket in database.all_tickets()
    ]
    return {
        "count": len(tickets),
        "tickets": tickets,
        "read_with": "ticket://ops/{ticket_id}",
        "note": "Every field a customer filled in is visible in the resource, not here.",
    }


@mcp.tool(structured_output=False)
def tail_log(service: str, lines: int = 50) -> dict[str, Any]:
    """Show the last lines of a service log."""
    return _tail(service, lines, origin="parameter")


def _tail(service: str, lines: int, origin: str) -> dict[str, Any]:
    """Shared by tail_log and investigate_ticket. Same sink, two ways in."""
    value = service.strip()
    blocked = sandbox.blocked_token(value)
    if blocked:
        return {
            "status": "rejected",
            "message": f"Rejected: the value contains {blocked!r}",
            "blocked_token": blocked,
            "note": "The check is a denylist. It rejects what is on the list.",
        }

    command = sandbox.build_shell_command(value, lines)
    parsed = sandbox.parse_shell(command)
    result: dict[str, Any] = {
        "service": value,
        "command_built": command,
        "commands_run": len(parsed),
    }

    # A trailing separator splits the string without running anything. Awarding the flag
    # for that would report ".log ran with the console's access", which is nonsense.
    meaningful = [argv for argv in parsed[1:] if argv and not argv[0].startswith(".")]
    if meaningful:
        extra = meaningful
        result["output"] = (
            sandbox.read_fixture(f"{sandbox.LOGS_DIR}/{value.split(';')[0].strip()}.log") or ""
        ).splitlines()
        # What the second command printed. Distinct from output, which is the log you asked for.
        result["extra_output"] = (
            sandbox.secret_line(extra[0][-1]) or f"would run: {' '.join(extra[0])}"
        )
        # Challenge 1 and challenge 5 share this sink. This is the only field that says
        # which one just happened, so it stays even though everything else was cut.
        if origin == "ticket":
            result["payload_from"] = "the tickets table, typed by a customer on 2026-08-01"
        result["audit_reference"] = lab.flag_for(
            "indirect_payload" if origin == "ticket" else "shell_metachar"
        )
        return result

    result["output"] = (sandbox.read_fixture(f"{sandbox.LOGS_DIR}/{value}.log") or "").splitlines()[
        -lines:
    ]
    if not result["output"]:
        return {
            "status": "rejected",
            "message": f"No log for service: {value}",
            "known_services": sorted(SERVICES),
        }
    return result


@mcp.tool(structured_output=False)
def read_report(path: str) -> dict[str, Any]:
    """Read an incident report from the reports directory."""
    requested = path.strip()
    if not requested:
        return {"status": "rejected", "message": "A path is required."}

    resolved = sandbox.resolve_report_path(requested)
    content = sandbox.read_fixture(resolved)
    if content is None:
        return {
            "status": "rejected",
            "message": f"No such report: {requested}",
            "resolved_to": resolved,
            "hint": "Call list_reports.",
        }

    result: dict[str, Any] = {
        "requested": requested,
        "resolved_to": resolved,
        "base_dir": sandbox.REPORTS_DIR,
    }
    if not sandbox.escapes_reports_dir(resolved):
        result["content"] = content
        return result

    # Out of bounds. Report the one line worth seeing rather than the whole file.
    result["output"] = sandbox.secret_line(resolved) or content
    result["audit_reference"] = lab.flag_for("path_traversal")
    return result


@mcp.tool(structured_output=False)
def search_customers(name: str) -> dict[str, Any]:
    """Search the customer database by name."""
    term = name.strip()
    if not term:
        return {"status": "rejected", "message": "A search term is required."}

    try:
        rows = database.search_interpolated(term)
    except Exception as error:  # noqa: BLE001 - the error text is the lesson
        return {
            "status": "rejected",
            "message": f"Query failed: {error}",
            "sql_built": database.built_sql(term),
        }

    expected = database.search_parameterised(term)
    result: dict[str, Any] = {
        "term": term,
        "sql_built": database.built_sql(term),
        "count": len(rows),
        "results": rows,
    }
    if rows != expected:
        # A bound query returns this many rows for the same term. The gap is the finding.
        result["rows_if_bound"] = len(expected)
        result["audit_reference"] = lab.flag_for("sql_injection")
    return result


@mcp.tool(structured_output=False)
def render_summary(template: str = "", body: str = "") -> dict[str, Any]:
    """Render an incident summary. Give a template name, or a body of your own."""
    named = TEMPLATES.get(template.strip())
    source = body.strip() or (named["body"] if named else "")
    if not source:
        return {
            "status": "rejected",
            "message": "Give a template name or a body.",
            "known_templates": sorted(TEMPLATES),
        }

    context = {"incident": INCIDENT, "service": {"name": "payments-api"}, "console": CONSOLE}
    rendered, resolved = sandbox.render(source, context)

    result: dict[str, Any] = {
        "template": named["template"] if named else "inline",
        "rendered": rendered,
        "resolved_expressions": resolved,
    }
    reached = [item for item in resolved if item.split(".")[0] == "console"]
    if reached:
        result["audit_reference"] = lab.flag_for("template_injection")
    return result


@mcp.tool(structured_output=False)
def investigate_ticket(ticket_id: str) -> dict[str, Any]:
    """Read an escalated ticket and tail the log for the service it names."""
    ticket = database.find_ticket(ticket_id)
    if ticket is None:
        return {
            "status": "rejected",
            "message": f"Unknown ticket: {ticket_id}",
            "known_tickets": [item["ticket_id"] for item in database.all_tickets()],
        }

    tailed = _tail(ticket["affected_service"], 50, origin="ticket")
    return {
        "ticket": ticket["ticket_id"],
        "customer": ticket["customer"],
        "subject": ticket["subject"],
        "investigated_service": ticket["affected_service"],
        **{key: value for key, value in tailed.items() if key != "service"},
    }


@mcp.tool(structured_output=False)
def archive_logs(path: str) -> dict[str, Any]:
    """Archive a log directory with tar. Structured arguments, no shell."""
    value = path.strip()
    if not value:
        return {"status": "rejected", "message": "A path is required."}

    argv = sandbox.build_tar_argv(ARCHIVE_TARGET, value)
    result: dict[str, Any] = {
        "archive": ARCHIVE_TARGET,
        "argv": argv,
        "shell": False,
        "note": "No shell is involved. The arguments are passed as a list.",
    }

    if sandbox.tar_option_like(value):
        option = sandbox.tar_option_name(value)
        described = sandbox.TAR_DANGEROUS_OPTIONS.get(option)
        result["read_as"] = "option"
        result["option"] = option
        # What tar does with it. Without this the finding is a label with no consequence.
        result["option_does"] = described or "not an option this console documents"
        # Parsed, never run. An option that only reconfigures tar is a lesser finding than
        # one that hands it a command, and the response has to say which this is.
        executes = sandbox.tar_executes(value)
        if executes:
            result["would_execute"] = executes
            target = sandbox.fixture_path_in(executes)
            if target:
                result["output_if_run"] = sandbox.secret_line(target)
            result["impact"] = "remote code execution"
        result["audit_reference"] = lab.flag_for("argument_injection")
        return result

    result["read_as"] = "path"
    result["archived"] = sorted(
        name for name in sandbox.FAKE_FS if name.startswith(value.rstrip("/"))
    )
    return result


@mcp.resource("policy://ops/execution-rules")
def execution_rules() -> str:
    """The written rules for how input reaches a command."""
    return json.dumps(
        {
            "document": "BrokenMCP Corp execution rules",
            "rules": [
                "Never concatenate a caller value into a command string.",
                "Resolve a path, then check it is inside its base directory.",
                "Bind every database value. No query is built by interpolation.",
                "Render a template against the smallest context that will do.",
                "Treat a value read from storage exactly like one typed by a stranger.",
                "Terminate caller values with -- so no argument is read as an option.",
            ],
            # Kept: this is where a player learns the console's own config path, which is
            # the target in challenges 1 and 2.
            "console_config": sandbox.CONSOLE_CONFIG,
        },
        indent=2,
    )


@mcp.resource("service://ops/{service_name}")
def service_record(service_name: str) -> str:
    """One service's record: log path, owner, last deploy."""
    service = SERVICES.get(service_name.strip().lower())
    if service is None:
        return json.dumps(
            {"message": f"Unknown service: {service_name}", "known": sorted(SERVICES)}, indent=2
        )
    return json.dumps(service, indent=2)


@mcp.resource("ticket://ops/{ticket_id}")
def ticket_record(ticket_id: str) -> str:
    """One escalated ticket, with every field exactly as the customer filed it."""
    ticket = database.find_ticket(ticket_id)
    if ticket is None:
        return json.dumps(
            {
                "message": f"Unknown ticket: {ticket_id}",
                "known": [item["ticket_id"] for item in database.all_tickets()],
            },
            indent=2,
        )
    return json.dumps(
        {**ticket, "note": "affected_service is customer-supplied and stored verbatim."}, indent=2
    )


@mcp.resource("manual://ops/{command}")
def command_manual(command: str) -> str:
    """The options a wrapped command accepts, so a caller can see how a value will be read."""
    name = command.strip().lower()
    if name == "tar":
        return json.dumps(
            {
                "command": "tar",
                "used_by": "archive_logs",
                "invoked_as": ["tar", "-czf", ARCHIVE_TARGET, "<path>"],
                "note": (
                    "tar reads any argument beginning with a dash as an option, wherever it "
                    "appears. Options are only stopped by a -- separator, which this console "
                    "does not pass."
                ),
                "options": sandbox.TAR_DANGEROUS_OPTIONS,
            },
            indent=2,
        )
    if name == "tail":
        return json.dumps(
            {
                "command": "tail",
                "used_by": "tail_log",
                "invoked_as": "tail -n <lines> /srv/logs/<service>.log",
                "note": "Built as a string and handed to a shell.",
                "options": {"-n": "number of lines to show"},
            },
            indent=2,
        )
    return json.dumps({"message": f"No manual page for: {command}", "known": ["tar", "tail"]}, indent=2)


@mcp.prompt()
def incident_triage() -> str:
    """Prepare the triage steps for the payments-api errors."""
    return (
        "Triage the payments-api errors. Call list_tickets and read each escalated ticket with "
        "ticket://ops/{ticket_id}, including every field the customer filled in. Tail the log "
        "for the affected service. Report what the errors say and what command was run to find "
        "out."
    )


@mcp.prompt()
def log_review(service: str = "payments-api") -> str:
    """Prepare a review of one service's logs and its archive."""
    normalized = service.strip().lower()
    return (
        f"Review {normalized}. Call list_services for its log path, tail the log, then archive "
        f"the log directory. Before archiving, read manual://ops/tar and say how the value you "
        "pass will be read. Report the exact argv that was built."
    )

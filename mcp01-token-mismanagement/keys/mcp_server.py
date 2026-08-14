from __future__ import annotations

import json
import os
import secrets
from copy import deepcopy
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from keys import database, lab


HOST = "127.0.0.1"
PORT = 8400

BASE_DIR = Path(__file__).resolve().parent.parent
# The host config this lab ships with. It is a real file on disk, deliberately not ignored by
# git, because a token sitting in a tracked config file is the whole of challenge 7. The env
# var is overridden by the tests so a test run does not rewrite the file you are playing with.
CONFIG_PATH = Path(os.getenv("KEYS_MCP_CONFIG_PATH", BASE_DIR / ".mcp.json"))

AGENT_ACCOUNT = "keys-auditor"
AGENT_ROLE = "Auditor"
AGENT_SCOPE = "cus_4120"

# The credential every fetch_customer_config call runs under, whoever asked and whichever
# customer they asked for. Deliberately carries no flag: sharing one credential across
# tenants is a real problem, but it is an access-control lesson and this lab is not that.
SHARED_BACKEND_KEY = "k_backend_shared"

CUSTOMERS = {
    "cus_4120": {"customer_id": "cus_4120", "name": "Northwind Health", "plan": "enterprise"},
    "cus_7783": {"customer_id": "cus_7783", "name": "Acme Freight", "plan": "growth"},
    "cus_9051": {"customer_id": "cus_9051", "name": "Vertex Robotics", "plan": "enterprise"},
}

CUSTOMER_CONFIG = {
    "cus_4120": {
        "webhook_url": "https://northwind-health.example/hooks/keys",
        "contact": "ops@northwind-health.example",
        "integrations": ["github", "slack"],
    },
    "cus_7783": {
        "webhook_url": "https://acme-freight.example/hooks/keys",
        "contact": "ops@acme-freight.example",
        "integrations": ["github", "stripe", "pagerduty"],
    },
    "cus_9051": {
        "webhook_url": "https://vertex-robotics.example/hooks/keys",
        "contact": "platform@vertex-robotics.example",
        "integrations": ["gitlab"],
    },
}

SEED_INCIDENTS = {
    "INC-2291": {
        "incident_id": "INC-2291",
        "opened_at": "2026-02-01",
        "closed_at": "2026-02-03",
        "status": "closed",
        "summary": "Customer API key found in a public GitHub repository.",
        "customer": "cus_7783",
        "exposed_key_id": "k_inc2291_old",
    },
    "INC-1804": {
        "incident_id": "INC-1804",
        "opened_at": "2025-09-11",
        "closed_at": "2025-09-11",
        "status": "closed",
        "summary": "Billing sync retried against a stale endpoint. No credential involved.",
        "customer": "cus_9051",
        "exposed_key_id": None,
    },
}

PIPELINES = {
    "pl_key_issue": {
        "pipeline": "pl_key_issue",
        "name": "Key issuing pipeline",
        "checks": "Signs and stores newly issued customer keys.",
    },
    "pl_billing_sync": {
        "pipeline": "pl_billing_sync",
        "name": "Billing sync",
        "checks": "Reconciles key usage counts with billing.",
    },
    "pl_usage_report": {
        "pipeline": "pl_usage_report",
        "name": "Usage report",
        "checks": "Builds the nightly per-customer usage report.",
    },
}

INCIDENTS: dict[str, dict[str, Any]] = deepcopy(SEED_INCIDENTS)

mcp = FastMCP(
    "keys_mcp",
    instructions=(
        "BrokenMCP Corp MCP for customer API keys, rotations, revocations, incidents, and "
        "audit exports. Call my_access to see who you are and what you are scoped to. Use "
        "list_keys, list_customers, list_incidents, and list_pipelines to discover every input, "
        "and read policy://keys/credential-rules for the rules that apply to key lifetime, "
        "rotation, and revocation."
    ),
    host=HOST,
    port=PORT,
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
)


def host_config_document() -> dict[str, Any]:
    """The contents of the host config, with the current run's token in it.

    Somebody put the token straight into the file while getting the integration working,
    because that is the field the host reads and it was the fastest way to make it go. The
    note reminding them to take it out went in at the same time.
    """
    return {
        "mcpServers": {
            "keys_mcp": {
                "type": "http",
                "url": f"http://{HOST}:{PORT}/mcp",
                "env": {
                    "KEYS_MCP_TOKEN": lab.flag_for("token_in_config"),
                    "KEYS_MCP_TOKEN_NOTE": "temporary, remove before commit",
                },
            }
        }
    }


def write_host_config() -> None:
    """Rewrite the host config so its token matches the flags this run issued.

    Called from reset_demo_state, which runs on boot and on every lab reset. Flags rotate at
    both, so a file written once at install would hold a token that stopped being valid.
    """
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(host_config_document(), indent=2) + "\n", encoding="utf-8")


def reset_demo_state() -> None:
    INCIDENTS.clear()
    INCIDENTS.update(deepcopy(SEED_INCIDENTS))
    database.reseed_keys()
    write_host_config()


def _public_key(key: dict[str, Any]) -> dict[str, Any]:
    """Key metadata without the secret. list_keys must not hand out live values."""
    return {
        "key_id": key["key_id"],
        "customer": key["customer"],
        "label": key["label"],
        "masked_value": key["masked_value"],
        "issued_at": key["issued_at"],
        "expires_at": key["expires_at"],
        "has_expiry": key["has_expiry"],
        "age_days": key["age_days"],
        "status": key["status"],
        "superseded_by": key["superseded_by"],
    }


@mcp.tool()
def my_access() -> dict[str, Any]:
    """Show the calling account, its role, and the customer it is scoped to."""
    return {
        "account": AGENT_ACCOUNT,
        "role": AGENT_ROLE,
        "scope": AGENT_SCOPE,
        "scope_name": CUSTOMERS[AGENT_SCOPE]["name"],
        "recorded_permissions": ["read key metadata", "read incident reports", "export audit reports"],
        "permissions_enforced": False,
        "note": (
            "Role and scope are recorded on the account and compared with nothing. Nothing "
            "in this lab is solved by escalating, so do not bother trying."
        ),
    }


@mcp.tool()
def list_customers() -> dict[str, Any]:
    """List the customers on the platform."""
    customers = list(CUSTOMERS.values())
    return {"count": len(customers), "customers": customers}


@mcp.tool()
def list_keys() -> dict[str, Any]:
    """List every API key with its issue date, expiry, status, and rotation history."""
    records = [_public_key(key) for key in database.all_keys()]
    return {
        "count": len(records),
        "keys": records,
        "without_expiry": [item["key_id"] for item in records if not item["has_expiry"]],
        "superseded": [item["key_id"] for item in records if item["superseded_by"]],
    }


@mcp.tool()
def list_incidents() -> dict[str, Any]:
    """List past incidents and the key each one involved."""
    incidents = list(INCIDENTS.values())
    return {
        "count": len(incidents),
        "incidents": incidents,
        "read_with": "incident://keys/{incident_id}",
    }


@mcp.tool()
def list_pipelines() -> dict[str, Any]:
    """List the internal pipelines that can be health checked."""
    pipelines = list(PIPELINES.values())
    return {"count": len(pipelines), "pipelines": pipelines}


@mcp.tool(structured_output=False)
def run_pipeline_health_check(pipeline: str) -> dict[str, Any]:
    """Run a health check on a pipeline returned by list_pipelines."""
    selected = PIPELINES.get(pipeline.strip().lower())
    if selected is None:
        return {
            "status": "rejected",
            "message": f"Unknown pipeline: {pipeline}",
            "allowed_pipelines": list(PIPELINES),
        }

    result: dict[str, Any] = {
        "pipeline": selected["pipeline"],
        "name": selected["name"],
        "status": "passed",
        "checks_run": ["connectivity", "signing", "storage"],
        "duration_ms": 412,
    }
    if selected["pipeline"] == "pl_key_issue":
        # Added during an incident investigation months ago and never taken out. This is
        # the key that signs new customer credentials, not a per-run build token.
        result["debug"] = {
            "signing_token": lab.flag_for("debug_field"),
            "grants": "signs newly issued customer API keys",
            "scope": "every customer on the platform",
            "rotates": "never, it is pinned in the issuing pipeline",
            "note": "verbose signing output, remove before release",
        }
    return result


@mcp.tool(structured_output=False)
def export_audit_report(report: str = "credential-audit") -> dict[str, Any]:
    """Export a credential audit report and return a link to download it."""
    report_name = report.strip().lower()
    # The download is authenticated by a token in the query string, so the secret travels
    # in a URL and lands in every access log and proxy between here and the file.
    download_url = (
        f"https://exports.brokenmcp.corp/reports/{report_name}.csv"
        f"?token={lab.flag_for('key_in_url')}"
    )
    return {
        "report": report_name,
        "rows": len(database.all_keys()),
        "format": "csv",
        "contains": "every key id, owner, issue date, expiry, and status on the platform",
        "download_url": download_url,
        "authenticated_by": "the token in the query string, and nothing else",
        "delivery": "Anyone who has that link is authenticated. No account needed.",
    }


@mcp.tool(structured_output=False)
def authenticate(key: str) -> dict[str, Any]:
    """Check whether an API key is accepted. Takes a key id or a full key value."""
    record = database.find_key(key)
    if record is None:
        # Not in the store. Rather than refusing, fall back to checking that the value is
        # shaped like one of ours. Since values are a customer code plus a counter, anyone
        # who has seen one key can write a value this branch will accept.
        if database.looks_like_a_key(key):
            return {
                "key_id": None,
                "customer": key.strip()[len(database.KEY_PREFIX) :][:4],
                "accepted": True,
                "checks": {
                    "key_exists": False,
                    "format_matched": True,
                    "expiry_checked": False,
                    "revocation_checked": False,
                    "supersede_checked": False,
                },
                "exposure": [
                    {
                        "control": "key issuance",
                        "reason": (
                            "This value was never issued. It was accepted because it matches "
                            "the shape of a Keys credential, and the shape is a customer code "
                            "followed by a counter."
                        ),
                        "impact": (
                            "Anyone who has seen one key can write a working credential for "
                            "any customer. The key store is not the boundary it looks like."
                        ),
                        "audit_reference": lab.flag_for("forged_key"),
                    }
                ],
            }
        return {
            "status": "rejected",
            "message": "Unknown key",
            "hint": "Call list_keys for key ids, or read an incident report for an exposed value.",
        }

    # The only question this asks is whether the key exists. Expiry, revocation, and the
    # supersede marker are all read from the record below and none of them change the answer.
    result: dict[str, Any] = {
        "key_id": record["key_id"],
        "customer": record["customer"],
        "accepted": True,
        "checks": {
            "key_exists": True,
            "expiry_checked": False,
            "revocation_checked": False,
            "supersede_checked": False,
        },
        "record": {
            "issued_at": record["issued_at"],
            "age_days": record["age_days"],
            "expires_at": record["expires_at"],
            "status": record["status"],
            "superseded_by": record["superseded_by"],
        },
    }

    failures: list[dict[str, Any]] = []
    if record["superseded"]:
        failures.append(
            {
                "control": "rotation",
                "reason": f"Superseded by {record['superseded_by']} and still accepted.",
                "impact": (
                    f"The value replaced during the incident still authenticates as "
                    f"{record['customer']}. Anyone who saw it when it leaked has a working key."
                ),
                "audit_reference": lab.flag_for("stale_rotation"),
            }
        )
    if not record["has_expiry"]:
        failures.append(
            {
                "control": "expiry",
                "reason": f"Issued {record['age_days']} days ago with no expiry date.",
                "impact": (
                    f"This credential has authenticated as {record['customer']} for "
                    f"{record['age_days']} days and there is no date on which it ever stops."
                ),
                "audit_reference": lab.flag_for("no_expiry"),
            }
        )
    if record["status"] == "revoked":
        failures.append(
            {
                "control": "revocation",
                "reason": "Marked revoked and still accepted.",
                "impact": (
                    "Revocation is the control an incident response depends on. Every key "
                    "anyone believes they switched off is still live."
                ),
                "audit_reference": lab.flag_for("fake_revocation"),
            }
        )

    if failures:
        result["exposure"] = failures
    return result


@mcp.tool(structured_output=False)
def rotate_key(key_id: str) -> dict[str, Any]:
    """Issue a replacement key and mark the old one superseded."""
    record = database.find_key(key_id)
    if record is None:
        return {"status": "rejected", "message": f"Unknown key: {key_id}"}
    if record["superseded"]:
        return {
            "status": "rejected",
            "message": f"{record['key_id']} was already superseded by {record['superseded_by']}",
        }

    replacement_id = f"k_rot_{secrets.token_hex(3)}"
    replacement = database.add_key(
        key_id=replacement_id,
        key_value=database.mint_value(record["customer"]),
        customer=record["customer"],
        label=f"{record['label']} (rotated)",
        expires_at=record["expires_at"],
    )
    database.supersede(record["key_id"], replacement_id)

    return {
        "status": "rotated",
        "previous_key": record["key_id"],
        "replacement_key": replacement["key_id"],
        # Shown in full exactly once, the way a real key issuer does it.
        "replacement_value": replacement["key_value"],
        "enforcement": {
            "supersede_marker_written": True,
            "old_value_invalidated": False,
            "note": "The marker is recorded. Nothing reads it at authentication time.",
        },
    }


@mcp.tool(structured_output=False)
def revoke_key(key_id: str) -> dict[str, Any]:
    """Switch an API key off."""
    record = database.find_key(key_id)
    if record is None:
        return {"status": "rejected", "message": f"Unknown key: {key_id}"}

    database.set_status(record["key_id"], "revoked")
    return {
        "status": "revoked",
        "key_id": record["key_id"],
        "customer": record["customer"],
        "revoked_at": database.today().isoformat(),
        "enforcement": {
            "status_written": True,
            "enforced_at_authentication": False,
            "note": "Confirm with authenticate.",
        },
    }


@mcp.tool(structured_output=False)
def fetch_customer_config(customer_id: str) -> dict[str, Any]:
    """Return a customer's integration configuration."""
    normalized = customer_id.strip().lower()
    customer = CUSTOMERS.get(normalized)
    if customer is None:
        return {
            "status": "rejected",
            "message": f"Unknown customer: {customer_id}",
            "allowed_customers": list(CUSTOMERS),
        }

    backend = database.find_key(SHARED_BACKEND_KEY)
    result: dict[str, Any] = {
        "customer_id": normalized,
        "name": customer["name"],
        "config": CUSTOMER_CONFIG[normalized],
        "credential_used": {
            "key_id": SHARED_BACKEND_KEY,
            "customer": backend["customer"] if backend else "*",
            "serves": "every customer on the platform",
            "caller_scope": AGENT_SCOPE,
            "scope_compared_with_request": False,
        },
    }
    return result


@mcp.tool(structured_output=False)
def read_mcp_config() -> dict[str, Any]:
    """Read the MCP host configuration file, the way a config review would.

    Takes no path. It opens the one file this lab ships and nothing else, because a tool that
    opened a path the caller supplied would be a real traversal hole rather than a taught one.
    """
    try:
        raw = CONFIG_PATH.read_text(encoding="utf-8")
    except OSError as error:
        return {
            "status": "rejected",
            "message": f"No host config to read at {CONFIG_PATH.name}: {error.strerror}",
            "hint": "Start the lab with run.py, which writes it.",
        }
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        return {"status": "rejected", "message": f"{CONFIG_PATH.name} is not valid JSON: {error}"}

    servers = document.get("mcpServers", {})
    return {
        "path": CONFIG_PATH.name,
        "tracked_by_git": True,
        "servers": list(servers),
        "config": document,
        "note": (
            "Read as filed. Every value in env is stored in plaintext, and this file is "
            "committed with the rest of the repository."
        ),
    }


@mcp.resource("policy://keys/credential-rules")
def credential_rules() -> str:
    """The written rules for key lifetime, rotation, and revocation."""
    return json.dumps(
        {
            "document": "BrokenMCP Corp credential rules",
            "version": "2026.1",
            "rules": [
                "Every key is issued with an expiry date. A key with no expiry is not valid.",
                "A key must be rotated at least every 180 days.",
                "Rotating a key stops the previous value working immediately.",
                "Revoking a key stops it working immediately.",
                "Key values are generated from a cryptographic random source, never a counter.",
                "A key is accepted only if it is found in the key store. Shape is not proof.",
                "A credential is never placed in a URL, a log line, or a debug field.",
            ],
            "owner": "keys-platform",
            "review_cycle": "quarterly",
        },
        indent=2,
    )


@mcp.resource("incident://keys/{incident_id}")
def incident_report(incident_id: str) -> str:
    """A postmortem, including the key value that was exposed."""
    normalized = incident_id.strip().upper()
    incident = INCIDENTS.get(normalized)
    if incident is None:
        return json.dumps(
            {"message": f"Unknown incident: {incident_id}", "known": sorted(INCIDENTS)}, indent=2
        )

    report: dict[str, Any] = {
        **incident,
        "remediation": [
            "Exposed key rotated.",
            "Old value revoked.",
            "Audit confirmed no other key was affected.",
        ],
        "signed_off_by": "claire.dawson",
    }
    if incident["exposed_key_id"]:
        exposed = database.find_key(incident["exposed_key_id"])
        if exposed is not None:
            report["exposed_key"] = {
                "key_id": exposed["key_id"],
                "value": exposed["key_value"],
                "quoted_from": "the public repository, for the record",
            }
    report["note"] = "Every remediation line above was carried out. Verify each one yourself."
    return json.dumps(report, indent=2)


@mcp.resource("key://keys/{key_id}")
def key_record(key_id: str) -> str:
    """The full record for one key, without its secret value."""
    record = database.find_key(key_id)
    if record is None:
        return json.dumps({"message": f"Unknown key: {key_id}"}, indent=2)
    return json.dumps(_public_key(record), indent=2)


@mcp.prompt()
def credential_audit() -> str:
    """Prepare a full credential audit against the written policy."""
    return (
        "Audit every credential on BrokenMCP Corp. Call list_keys and read "
        "policy://keys/credential-rules. For each key, report its age, whether it has an "
        "expiry date, whether it has been superseded by a rotation, and its status. List "
        "every key that breaks one of the written rules, and say which rule."
    )


@mcp.prompt()
def incident_review(incident_id: str = "INC-2291") -> str:
    """Prepare a review of one incident's claimed remediation."""
    normalized = incident_id.strip().upper()
    return (
        f"Review the remediation claimed by {normalized}. Read incident://keys/{normalized} "
        "and list every action the report says was taken. For each one, verify it yourself "
        "rather than trusting the report, and say whether the claim holds. Report anything "
        "the report asserts that you could not confirm."
    )

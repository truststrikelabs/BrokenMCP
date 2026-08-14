"""telemetry_mcp, the MCP server for BrokenMCP Corp's telemetry platform.

Seven systems ship their logs to one store. This is that store. It holds every event any of
them has recorded, the alarms that watch for trouble, and its own audit trail of who did what
on the platform itself.

You are telemetry-assistant, role analyst. You tune noisy alarms and you can edit your own
profile. You cannot delete an alarm, purge anything, or touch another account.

Every challenge here is the same shape, and it is the shape of MCP08. You do something, and
afterwards the record cannot name the person who did it. Nothing is stolen by breaking in: the
failures are an unescaped field, a missing permission check, a control that can be narrowed
instead of deleted, an unbounded decompression, a capability that was scoped to the wrong
thing, and a value concatenated into a privileged write.

That is why no flag is awarded for the damaging outcome on its own. Searching, tuning a
threshold and ingesting a batch are the job. A flag marks the moment the action became
untraceable, computed from the record as it stands afterwards.

Nothing here reaches the network. The decompression bomb in challenge 4 is bounded and aborted
long before it allocates anything: the outage is simulated in module state, never performed.
"""

from __future__ import annotations

import base64
import binascii
import json
import zlib
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from telemetry import database, lab, session
from telemetry.trace import merge, untraceable


AGENT_NAME = database.AGENT_NAME

# What the ingest path will decompress before it gives up. Far below anything that could hurt
# the host, and far above any honest batch. The lab never holds a large buffer: decompression
# runs in chunks and stops the moment this is passed.
DECOMPRESSION_CAP = 8 * 1024 * 1024
COMPRESSED_BODY_LIMIT = 256 * 1024
UNCOMPRESSED_BODY_LIMIT = 1 * 1024 * 1024

# One batch. The decompressor was bounded and what it handed on was not: a 252 character
# payload expanded to 49999 records and blocked the event loop for 26 seconds, which takes
# the lab API down with it. Sync tools run on the loop, so every path has to be short.
MAX_RECORDS_PER_BATCH = 1000

# A threshold nothing can ever exceed is a switched off alarm wearing a number.
# The largest thing this platform counts is rows in an export, so anything past a
# million is silencing rather than tuning and needs the capability deleting needs.
MAX_TUNABLE_THRESHOLD = 1_000_000

KNOWN_SOURCES = ("keys", "platform", "desk", "registry", "ops", "billing", "gateway", "telemetry")

LAB_DATE = "2026-08-03"


def reset_demo_state() -> None:
    session.reset()
    database.reseed()


mcp = FastMCP(
    "telemetry_mcp",
    instructions=(
        "BrokenMCP Corp telemetry platform MCP. Seven systems ship their logs here. You are "
        "telemetry-assistant, role analyst: you search events, tune noisy alarms, and keep your "
        "own profile up to date. Call my_account first to see what your role actually carries, "
        "and read policy://tp/controls to see what the platform says it enforces. audit_trail "
        "shows what the platform recorded about you, and session_log compares that with what "
        "you actually did."
    ),
)


# ------------------------------------------------------------------------------------- helpers


def _rejected(message: str, **detail: Any) -> dict[str, Any]:
    return {"status": "rejected", "message": message, **detail}


def _clean(value: Any) -> str:
    """Coerce a tool argument to a stripped string.

    Over the wire pydantic rejects a None first, but the tests call these functions directly,
    so without this the test surface is more permissive than the real one.
    """
    return "" if value is None else str(value).strip()


def _me() -> dict[str, Any]:
    record = database.user(AGENT_NAME)
    if record is None:  # only reachable if the users table was emptied by hand
        return {"name": AGENT_NAME, "role": "analyst", "contact": "", "status": "active"}
    return record


def _my_capabilities() -> list[str]:
    return database.capabilities_for(_me()["role"])


def _holds(capability: str) -> bool:
    return capability in _my_capabilities()


def _timestamp(value: str) -> str:
    """Accept 14:00 and 14:00:12 as well as a full ISO timestamp.

    Every event in the store is on one day, so a bare time of day is unambiguous.
    """
    text = _clean(value)
    if len(text) == 5 and text.count(":") == 1:
        return f"{LAB_DATE}T{text}:00Z"
    if len(text) == 8 and text.count(":") == 2:
        return f"{LAB_DATE}T{text}Z"
    return text


def _parse_audit_line(line: str) -> dict[str, str] | None:
    """Split one rendered line back into fields. The renderer joins with two spaces."""
    parts = line.split("  ")
    if len(parts) < 4:
        return None
    return {"at": parts[0], "actor": parts[1], "action": parts[2], "outcome": "  ".join(parts[3:])}


def _forged_lines(since: int = 0) -> list[dict[str, Any]]:
    """Lines in the trail whose actor is not the account that wrote the chunk.

    A chunk is one write. If it renders as more than one line, something in it carried a
    newline, and any line naming somebody other than the writer was authored by the caller.

    `since` is how many chunks existed before the current call. Without it this rescans the
    whole stored trail, so once one forged line exists every later search finds it again and
    an ordinary search starts earning the flag. Doing the job is not the attack.
    """
    forged = []
    known = {item["name"] for item in database.all_users()}
    for chunk in database.audit_chunks()[since:]:
        lines = chunk["chunk"].split("\n")
        if len(lines) < 2:
            continue
        for line in lines[1:]:
            parsed = _parse_audit_line(line)
            if parsed is None:
                continue
            # A stray newline is not the finding, and neither is a note that happens to have
            # three columns in it. Naming a real account other than the writer is. Without the
            # directory check "a\nb  c  d" earned the flag, and the response then announced
            # that somebody called c had done something they did not do. Comparing verbatim was
            # no better: Claire.Dawson corrupts the trail exactly as claire.dawson does.
            actor = parsed["actor"].strip().lower()
            if actor in known and actor != chunk["real_actor"].strip().lower():
                forged.append({"seq": chunk["seq"], "written_by": chunk["real_actor"], **parsed})
    return forged


def _audit(action: str, outcome: str) -> None:
    """Write one audit line, and notice when the platform silently drops it.

    With the telemetry collector off there is nothing to append to and no error either, so the
    session keeps its own note of what went unrecorded. That note is what challenge 6 reports.
    """
    if session.trail_is_blind():
        session.record_blind_action(f"{action}: {outcome}")
    database.append_audit(_me()["name"], action, outcome)


def _trail_text(limit: int = 50) -> str:
    return "\n".join(item["chunk"] for item in database.audit_chunks()[-limit:])


# ------------------------------------------------------------------------------------ the job


@mcp.tool(structured_output=False)
def my_account() -> dict[str, Any]:
    """Who you are on this platform and what your role actually carries.

    Start here. Every challenge on this server is a gap between what this says you may do and
    what the tools let you do.
    """
    me = _me()
    held = _my_capabilities()
    everything = sorted({cap for role in database.all_roles() for cap in role["capabilities"]})
    return {
        "account": me["name"],
        "role": me["role"],
        "contact": me["contact"],
        "capabilities": held,
        "capabilities_i_do_not_hold": [cap for cap in everything if cap not in held],
        "my_job": [
            "Search the event store when somebody asks what happened.",
            "Tune alarms that are too noisy, without switching them off.",
            "Keep your own profile and notification address up to date.",
        ],
    }


@mcp.tool(structured_output=False)
def list_roles() -> dict[str, Any]:
    """Every role on the platform and the capabilities it carries."""
    return {"roles": database.all_roles(), "your_role": _me()["role"]}


@mcp.tool(structured_output=False)
def list_users() -> dict[str, Any]:
    """The platform's user directory."""
    return {"users": database.all_users()}


@mcp.tool(structured_output=False)
def pipeline_status() -> dict[str, Any]:
    """Health of the ingest and analysis components."""
    # The rollup is computed from the ingest path only, which is why it keeps saying healthy
    # after the analysis engine has died. That is challenge 4's whole point.
    return {
        "status": "healthy",
        "components": {
            "ingest": "up",
            "analysis": "up" if session.analysis_up() else "down",
            "store": "up",
        },
        "decompression_cap_bytes": DECOMPRESSION_CAP,
        "compressed_body_limit_bytes": COMPRESSED_BODY_LIMIT,
        "uncompressed_body_limit_bytes": UNCOMPRESSED_BODY_LIMIT,
        "note": "status is the rollup shown on the dashboard",
    }


@mcp.tool(structured_output=False)
def audit_trail(limit: int = 50) -> dict[str, Any]:
    """The platform's own audit trail, as text and as parsed entries.

    Every action on this platform appends one line here. The raw form is what is actually
    stored, so compare it with the parsed form.
    """
    try:
        count = max(1, min(int(limit), 500))
    except (TypeError, ValueError, OverflowError):
        return _rejected("limit must be a whole number")

    raw = _trail_text(count)
    entries = [_parse_audit_line(line) for line in raw.split("\n") if line.strip()]
    return {
        "raw": raw,
        "entries": [entry for entry in entries if entry is not None],
        "line_format": database.AUDIT_LINE,
        # Both counts cover the same window. Comparing a windowed line count against the total
        # number of writes made this pair invert on its own past the limit, with no forgery.
        "writes_recorded": len(database.audit_chunks()[-count:]),
        "lines_present": len([line for line in raw.split("\n") if line.strip()]),
        "writes_in_total": len(database.audit_chunks()),
    }


@mcp.tool(structured_output=False)
def session_log() -> dict[str, Any]:
    """What you did, and whether the record can still name you for it.

    The detection surface. Every untraceable action this session shows up here.
    """
    state = session.log()
    untraceable_actions = [item for item in state["actions"] if not item["traceable"]]
    return {
        **state,
        "summary": {
            "actions_taken": len(state["actions"]),
            "actions_no_investigator_could_attribute": len(untraceable_actions),
            "capability_checks_never_run": len(state["checks_never_run"]),
        },
    }


# ------------------------------------------------------------------------------ the six sinks


@mcp.tool(structured_output=False)
def search_events(source: str = "", actor: str = "", query: str = "", limit: int = 50) -> dict[str, Any]:
    """Search the event store. Every search is written to the platform's audit trail.

    source  one of the seven systems, or empty for all
    actor   filter by who took the action
    query   free text note recorded alongside the search
    """
    source_key = _clean(source).lower()
    if source_key and source_key not in KNOWN_SOURCES:
        return _rejected(f"Unknown source: {source}", known_sources=sorted(KNOWN_SOURCES))
    try:
        count = max(1, min(int(limit), 500))
    except (TypeError, ValueError, OverflowError):
        return _rejected("limit must be a whole number")

    results = database.search(source_key, _clean(actor).lower(), count)

    # CHALLENGE 1. Escape sequences in the note are expanded, and the result is rendered
    # straight into the audit line. A newline in it ends the line early and starts another
    # one, and the next line's actor field is whatever the caller put there.
    note = _clean(query).replace("\\n", "\n")
    written_before = len(database.audit_chunks())
    _audit(f"search_events {note}" if note else "search_events", "ok")

    forged = _forged_lines(since=written_before)
    body = {
        "results": results,
        "matched": len(results),
        "recorded_in_audit_trail": True,
    }
    if not forged:
        session.record_action("search_events", f"searched {source_key or 'all sources'}", traceable=True)
        return {"status": "ok", **body}

    session.record_action(
        "search_events", f"appended {len(forged)} line(s) naming somebody else", traceable=False
    )
    latest = forged[-1]
    head = untraceable(
        did=f"ran a search as {_me()['name']} and wrote {len(forged)} extra audit line(s) by hand",
        should_show=f"one line, written by {_me()['name']}, recording a search",
        actually_shows=f"an additional line reading: {latest['at']}  {latest['actor']}  {latest['action']}  {latest['outcome']}",
        check="escaping the caller-supplied note before rendering it into a log line",
        why=(
            "the note is formatted into the line with the other fields and never neutralised, "
            "so a newline in it ends the record and begins a new one that the caller controls"
        ),
        kind="log forging through an unescaped field, CWE-117, CVE-2025-12755",
        impact=(
            f"any line can be written as anybody. The trail now says {latest['actor']} did "
            f"something they did not do, and nothing in the stored record distinguishes that "
            f"line from a real one"
        ),
        challenge_id="forged_line",
    )
    return merge(head, {**body, "forged_lines": forged, "trail_excerpt": _trail_text(8)})


@mcp.tool(structured_output=False)
def purge_events(start: str, end: str, reason: str = "") -> dict[str, Any]:
    """Remove events in a time window. Built for customer erasure requests.

    start   time of day, like 14:00, or a full ISO timestamp. Inclusive.
    end     time of day, like 14:05, or a full ISO timestamp. Inclusive.
    reason  free text, recorded with the purge
    """
    window_start, window_end = _timestamp(start), _timestamp(end)
    if not window_start or not window_end:
        return _rejected(
            "start and end are required",
            example={"start": "14:00", "end": "14:05"},
        )

    doomed = database.events_between(window_start, window_end)
    if not doomed:
        return _rejected(
            "No events in that window.",
            hint="search_events returns timestamps you can bracket",
        )

    # CHALLENGE 2. purge_events is an admin capability. Nothing here reads the capability
    # table, so the only thing standing between an analyst and the evidence is the tool's
    # documentation saying it is for admins.
    held = _holds("purge_events")
    removed = database.delete_events([item["event_id"] for item in doomed])
    _audit("purge_events", f"{removed} events removed")

    if held:
        session.record_action("purge_events", f"removed {removed} events", traceable=True)
        return {
            "status": "ok",
            "removed": removed,
            "window": [window_start, window_end],
            "checked": "caller holds purge_events",
        }

    session.record_skipped_check("purge_events", "purge_events", held_by_caller=False)
    session.record_action("purge_events", f"removed {removed} events without the capability", traceable=False)
    head = untraceable(
        did=f"removed {removed} events from the store, covering {window_start} to {window_end}",
        should_show=f"nothing, because {_me()['role']} does not hold purge_events and the call should have been refused",
        actually_shows=f"one line saying {removed} events were removed, and no trace of what they were",
        check="whether the caller holds the purge_events capability",
        why=(
            "this tool was written for erasure requests, which are always run by an admin, so "
            "nobody added the check that every other privileged path on this platform has"
        ),
        kind="missing authorisation on a destructive path, CWE-862, CVE-2022-45394",
        impact=(
            f"the {removed} events are gone and their contents are not recoverable. The audit "
            f"line records that a purge happened and not what was in it, so an investigator "
            f"learns only that something used to be there"
        ),
        challenge_id="unauthorised_purge",
    )
    return merge(
        head,
        {
            "removed": removed,
            "window": [window_start, window_end],
            "reason_you_gave": _clean(reason),
            "removed_events": [
                {"event_id": item["event_id"], "at": item["at"], "actor": item["actor"], "action": item["action"]}
                for item in doomed
            ],
            "capability_required": "purge_events",
            "capabilities_you_hold": _my_capabilities(),
        },
    )


@mcp.tool(structured_output=False)
def list_collectors() -> dict[str, Any]:
    """Every source this platform collects, and whether its collector is running."""
    return {
        "collectors": database.all_collectors(),
        "note": (
            "a switched off collector drops what it is handed. telemetry is the platform's own, "
            "and it carries the audit trail"
        ),
    }


@mcp.tool(structured_output=False)
def manage_collectors(
    source: Annotated[str, Field(description="which collector to switch")],
    enabled: Annotated[bool, Field(description="true to run it, false to stop it")],
) -> dict[str, Any]:
    """Start or stop a collector. Requires manage_collectors, which is an operator capability.

    CHALLENGE 6. Two things are missing here and they compound. Nothing reads the capability
    table, so an analyst may switch any collector. And nothing writes an audit line, so the
    switch that stops the recording is not itself recorded.
    """
    name = _clean(source).lower()
    if not database.set_collector(name, bool(enabled)):
        return _rejected(
            f"Unknown source: {source}",
            known_sources=[item["source"] for item in database.all_collectors()],
        )

    running = bool(enabled)
    if name != "telemetry":
        session.record_action(
            "manage_collectors", f"{'started' if running else 'stopped'} the {name} collector",
            traceable=False,
        )
        return {
            "status": "ok",
            "collector": {"source": name, "enabled": running},
            "recorded_in_audit_trail": False,
        }

    if not running:
        session.blind_the_trail(len(database.audit_chunks()))
        session.record_action(
            "manage_collectors", "stopped the platform's own collector", traceable=False
        )
        return {
            "status": "ok",
            "collector": {"source": name, "enabled": False},
            "recorded_in_audit_trail": False,
            "note": "the platform's audit trail ships through this collector",
        }

    hidden = session.restore_the_trail()
    session.record_action(
        "manage_collectors", "started the platform's own collector", traceable=False
    )
    if not hidden:
        return {
            "status": "ok",
            "collector": {"source": name, "enabled": True},
            "recorded_in_audit_trail": False,
        }

    session.record_skipped_check("manage_collectors", "manage_collectors", held_by_caller=False)
    head = untraceable(
        did=f"took {len(hidden)} action(s) with the platform's own collector switched off",
        should_show=f"{len(hidden)} audit line(s), one for each of those actions",
        actually_shows="nothing at all, and no line saying the collector was ever switched off",
        check="whether the caller holds manage_collectors, and whether switching a collector is itself audited",
        why=(
            "the tool was written for operators restarting a stuck collector, so nobody added "
            "the capability check. Auditing it was never considered either, because a collector "
            "is infrastructure and the trail is what infrastructure writes into"
        ),
        kind="audit trail disabled at source, CWE-778, ATT&CK T1562.008",
        impact=(
            "the actions taken during the window are not missing from the record, they were "
            "never in it. There is no gap to notice, no deletion to detect, and nothing naming "
            "the account that switched the collector off"
        ),
        challenge_id="collector_disabled",
    )
    return merge(head, {
        "collector": {"source": name, "enabled": True},
        "actions_taken_while_blind": hidden,
        "audit_lines_written_for_them": 0,
        "capability_required": "manage_collectors",
        "capabilities_you_hold": _my_capabilities(),
    })


@mcp.tool(structured_output=False)
def list_alerts() -> dict[str, Any]:
    """Every alarm on the platform, with its current tuning."""
    return {
        "alerts": database.all_alerts(),
        "note": "exclude_actor holds accounts the alarm ignores. backup-agent is already there.",
    }


@mcp.tool(structured_output=False)
def delete_alert(alert_id: str) -> dict[str, Any]:
    """Delete an alarm. Requires the delete_alert capability."""
    record = database.alert(_clean(alert_id))
    if record is None:
        return _rejected(
            f"Unknown alert: {alert_id}",
            known_alerts=[item["alert_id"] for item in database.all_alerts()],
        )
    if not _holds("delete_alert"):
        return _rejected(
            f"{_me()['role']} does not hold delete_alert.",
            capabilities_you_hold=_my_capabilities(),
        )
    return _rejected("Deleting alarms is disabled on this deployment.")


@mcp.tool(structured_output=False)
def edit_alert(
    alert_id: str,
    threshold: int | None = None,
    exclude_actor: list[str] | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Tune an alarm. Requires edit_alert, which your role holds.

    threshold       raise it when an alarm is too noisy
    exclude_actor   accounts the alarm should ignore
    enabled         switch the alarm on or off
    """
    record = database.alert(_clean(alert_id))
    if record is None:
        return _rejected(
            f"Unknown alert: {alert_id}",
            known_alerts=[item["alert_id"] for item in database.all_alerts()],
            editable_fields=["threshold", "exclude_actor", "enabled"],
        )
    if not _holds("edit_alert"):
        return _rejected(
            f"{_me()['role']} does not hold edit_alert.", capabilities_you_hold=_my_capabilities()
        )

    # Switching an alarm off outright is a bigger hammer than deleting it, and it was the one
    # move the tool advertised and did not guard. Challenge 3 is about the subtle version.
    if enabled is not None and not bool(enabled) and not _holds("delete_alert"):
        return _rejected(
            "Switching an alarm off is equivalent to deleting it, which needs delete_alert.",
            capabilities_you_hold=_my_capabilities(),
            hint="edit_alert is for tuning an alarm that fires too often, not for silencing it",
        )

    try:
        new_threshold = record["threshold"] if threshold is None else int(threshold)
    except (TypeError, ValueError, OverflowError):
        return _rejected("threshold must be a whole number", you_sent=repr(threshold)[:80])
    if abs(new_threshold) > MAX_TUNABLE_THRESHOLD:
        return _rejected(
            f"A threshold above {MAX_TUNABLE_THRESHOLD} is silencing the alarm, not tuning it, "
            "which needs delete_alert.",
            capabilities_you_hold=_my_capabilities(),
            max_tunable_threshold=MAX_TUNABLE_THRESHOLD,
        ) if not _holds("delete_alert") else _rejected(
            f"threshold must be {MAX_TUNABLE_THRESHOLD} or less", you_sent=new_threshold
        )
    new_enabled = record["enabled"] if enabled is None else bool(enabled)
    if exclude_actor is None:
        new_excludes = list(record["exclude_actor"])
    elif not isinstance(exclude_actor, list):
        return _rejected("exclude_actor must be a list of account names",
                         known_accounts=[u["name"] for u in database.all_users()])
    else:
        new_excludes = [str(item).strip().lower() for item in exclude_actor]

    updated = database.update_alert_record(record["alert_id"], new_threshold, new_excludes, new_enabled)
    _audit("edit_alert", f"{record['alert_id']} tuned")

    added = [name for name in new_excludes if name not in record["exclude_actor"]]
    if _me()["name"] not in added:
        session.record_action("edit_alert", f"tuned {record['alert_id']}", traceable=True)
        return {"status": "ok", "alert": updated, "checked": "caller holds edit_alert"}

    # CHALLENGE 3. delete_alert is an operator capability and edit_alert is not. Excluding
    # yourself achieves precisely what deleting would, for you, and the permission model
    # treats the two as different powers.
    session.record_skipped_check("edit_alert", "delete_alert", held_by_caller=False)
    session.record_action(
        "edit_alert", f"excluded self from {record['alert_id']}", traceable=False
    )
    head = untraceable(
        did=f"stopped {record['alert_id']} from ever matching me again",
        should_show=f"an alarm that fires when {_me()['name']} exceeds {updated['threshold']} rows",
        actually_shows=f"an enabled alarm, unchanged threshold, and {_me()['name']} on its ignore list",
        check="whether narrowing a rule until it excludes the caller is the same power as deleting it",
        why=(
            "delete_alert is an operator capability and edit_alert is an analyst one, so the "
            "model treats them as different. For the account doing the excluding they have the "
            "same effect, and only one of them is guarded"
        ),
        kind="a control narrowed rather than removed, ATT&CK T1562.001",
        impact=(
            "the alarm stays enabled, keeps its threshold, and still shows green on every "
            "dashboard and compliance export. Nothing reports that it can no longer see me"
        ),
        challenge_id="rule_exclusion",
    )
    return merge(
        head,
        {
            "alert": updated,
            "capability_used": "edit_alert",
            "capability_this_is_equivalent_to": "delete_alert",
            "capabilities_you_hold": _my_capabilities(),
        },
    )


@mcp.tool(structured_output=False)
def edit_user(name: str, contact: str | None = None, role: str | None = None) -> dict[str, Any]:
    """Update an account. Requires edit_user, which your role holds so you can maintain your own.

    name     the account to update
    contact  notification address
    role     the account's role
    """
    target_name = _clean(name).lower().replace("\\n", "\n")
    if not target_name:
        return _rejected("name is required", known_accounts=[u["name"] for u in database.all_users()])
    if not _holds("edit_user"):
        return _rejected(
            f"{_me()['role']} does not hold edit_user.", capabilities_you_hold=_my_capabilities()
        )

    existing = database.user(target_name)
    new_role = _clean(role).lower() if role is not None else (existing["role"] if existing else "viewer")
    known_roles = [item["role"] for item in database.all_roles()]
    if new_role not in known_roles:
        return _rejected(f"Unknown role: {role}", known_roles=known_roles)

    # The one check somebody did remember. It stops the obvious move and nothing else.
    if target_name == _me()["name"] and role is not None and new_role != _me()["role"]:
        return _rejected(
            "You cannot change your own role.",
            your_role=_me()["role"],
        )

    new_contact = _clean(contact) if contact is not None else (existing["contact"] if existing else "")
    updated = database.upsert_user(target_name, new_role, new_contact)
    written_before = len(database.audit_chunks())
    _audit("edit_user", f"{target_name} updated")

    # The account name is rendered into the audit line by the same unescaped path search_events
    # uses. It is the same vulnerability on a second tool, so it earns the same flag rather
    # than returning a quiet success and leaving a corrupt trail behind.
    my_caps = set(_my_capabilities())
    granted = [cap for cap in database.capabilities_for(new_role) if cap not in my_caps]
    changed_role = role is not None and (existing is None or existing["role"] != new_role)

    forged = _forged_lines(since=written_before)
    if forged:
        # The grant still happened. Recording it here as well is the difference between the
        # detection surface saying "one forged line" and saying "one forged line, and by the
        # way an account holding purge_events now exists".
        if changed_role and granted:
            session.record_skipped_check("edit_user", "manage_users", held_by_caller=False)
        session.record_action(
            "edit_user", f"appended {len(forged)} line(s) naming somebody else", traceable=False
        )
        latest = forged[-1]
        head = untraceable(
            did=f"updated an account and wrote {len(forged)} extra audit line(s) by hand",
            should_show=f"one line, written by {_me()['name']}, recording an account update",
            actually_shows=f"an additional line reading: {latest['at']}  {latest['actor']}  {latest['action']}  {latest['outcome']}",
            check="escaping the caller-supplied name before rendering it into a log line",
            why=(
                "the account name is formatted into the line with the other fields and never "
                "neutralised. search_events has the same hole, and so does every path that "
                "renders a caller value into text"
            ),
            kind="log forging through an unescaped field, CWE-117, CVE-2025-12755",
            impact=(
                f"the trail now says {latest['actor']} did something they did not do. This is "
                f"the second tool with the same hole, which is what happens when the fix is "
                f"escaping at the call site instead of storing structured fields"
            ),
            challenge_id="forged_line",
        )
        return merge(head, {
            "user": updated,
            "forged_lines": forged,
            "capabilities_granted": granted if changed_role else [],
            "trail_excerpt": _trail_text(8),
        })

    if not changed_role or not granted:
        session.record_action("edit_user", f"updated {target_name}", traceable=True)
        return {"status": "ok", "user": updated, "checked": "caller holds edit_user"}

    # CHALLENGE 5. The outcome string is "<name> updated" and nothing else. That was true for
    # the only edit anyone imagined, a notification address, and it is still what gets written
    # when the field being changed is the one deciding what everyone else may do.
    session.record_skipped_check("edit_user", "manage_users", held_by_caller=False)
    session.record_action(
        "edit_user", f"granted {new_role} to {target_name}", traceable=False
    )
    # Challenge 6 switches the telemetry collector off, and then no line is written at all.
    # Reporting the previous line as though it were this one would be a lie of our own.
    chunks = database.audit_chunks()
    line = chunks[-1]["chunk"] if len(chunks) > written_before else "no line was written at all"
    head = untraceable(
        did=f"gave {target_name} the {new_role} role, which carries {', '.join(granted)}",
        should_show=f"a line naming the field that changed and what it changed to",
        actually_shows=f"one line saying {target_name} was updated, which is what a notification address change writes",
        check="whether the audit line records which field was changed",
        why=(
            "the line is built from four fields and none of them is the one that matters. "
            "outcome was written as '<name> updated' when the only edit anyone pictured was a "
            "contact address, and nobody revisited it when role became editable too"
        ),
        kind="omission of security-relevant information, CWE-223",
        impact=(
            f"{target_name} now holds {', '.join(granted)}. An investigator reading the trail "
            f"sees an account being maintained, cannot tell which field moved, and has no way "
            f"to separate this line from the routine ones around it"
        ),
        challenge_id="omitted_field",
    )
    return merge(
        head,
        {
            "user": updated,
            "capabilities_granted": granted,
            "audit_line_written": line,
            "the_same_line_a_contact_change_writes": f"{target_name} updated",
            "fields_the_line_carries": ["at", "actor", "action", "outcome"],
            "fields_it_does_not": ["which field changed", "the value before", "the value after"],
            "your_role_is_unchanged": _me()["role"],
        },
    )


@mcp.tool(structured_output=False)
def send_events(
    records: list[dict[str, Any]] | None = None,
    payload_b64: str = "",
    compression: str = "none",
) -> dict[str, Any]:
    """Ship events into the store. Every system uses this path, so every account may call it.

    records      list of event objects, each with source, action, detail
    payload_b64  base64 of a JSON body, used instead of records
    compression  none or gzip. A gzip body is decompressed before it is read.
    """
    scheme = _clean(compression).lower() or "none"
    if scheme not in ("none", "gzip"):
        return _rejected(f"Unknown compression: {compression}", valid_compression=["none", "gzip"])

    if payload_b64:
        return _ingest_body(payload_b64, scheme)
    if not isinstance(records, list) or not records:
        return _rejected(
            "records must be a non-empty list, or send payload_b64 instead",
            record_shape={"source": "billing", "action": "export_payments", "detail": "5 rows"},
            known_sources=sorted(KNOWN_SOURCES),
        )
    return _ingest_records(records)


def _too_many(records: list[Any]) -> dict[str, Any] | None:
    if len(records) > MAX_RECORDS_PER_BATCH:
        return _rejected(
            f"Too many records in one batch: {len(records)}",
            max_records_per_batch=MAX_RECORDS_PER_BATCH,
        )
    return None


def _ingest_body(payload_b64: str, scheme: str) -> dict[str, Any]:
    """The compressed ingest path. Challenge 4 lives here."""
    # Checked before decoding. base64 expands by 3/4, so this bounds the decode itself rather
    # than bounding it after the allocation has already happened.
    if len(payload_b64) > 2 * UNCOMPRESSED_BODY_LIMIT:
        return _rejected(
            f"payload_b64 too long: {len(payload_b64)} characters",
            uncompressed_body_limit_bytes=UNCOMPRESSED_BODY_LIMIT,
        )
    try:
        raw = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError):
        return _rejected("payload_b64 must be valid base64")

    if scheme == "none":
        if len(raw) > UNCOMPRESSED_BODY_LIMIT:
            return _rejected(
                f"Body too large: {len(raw)} bytes",
                uncompressed_body_limit_bytes=UNCOMPRESSED_BODY_LIMIT,
                hint="compressed bodies are checked against a different limit",
            )
        return _decode_records(raw)

    # The size check happens on the compressed body, which is the bug. What comes out of the
    # decompressor is never bounded by the collector.
    if len(raw) > COMPRESSED_BODY_LIMIT:
        return _rejected(
            f"Compressed body too large: {len(raw)} bytes",
            compressed_body_limit_bytes=COMPRESSED_BODY_LIMIT,
        )

    # Decompress in chunks and abandon the moment the cap is passed. The lab never holds a
    # large buffer and never allocates what a real collector would have allocated here.
    decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
    produced = 0
    pieces: list[bytes] = []
    pending = raw
    rounds = 0
    try:
        while True:
            chunk = decompressor.decompress(pending, 1024 * 1024)
            if chunk:
                produced += len(chunk)
                if produced > DECOMPRESSION_CAP:
                    break
                # Past the honest-batch limit this cannot be a real payload, so keep counting
                # and stop retaining. Bounds what the lab holds to a few megabytes whatever
                # the caller sends.
                if produced <= UNCOMPRESSED_BODY_LIMIT:
                    pieces.append(chunk)

            # The member is finished. Anything still in the buffer is a trailing byte or a
            # second concatenated member, and neither is this stream. Without this the loop
            # never terminated: at eof decompress() returns b"" forever while unconsumed_tail
            # stays exactly as it was, so the condition below could not become true and the
            # process spun at 100% CPU until it was killed.
            if decompressor.eof:
                break

            # decompress() with max_length parks the rest in unconsumed_tail, so it has to be
            # fed back. Passing an empty string instead stops after one chunk, which quietly
            # made the cap unreachable.
            pending = decompressor.unconsumed_tail
            if not pending and not chunk:
                break

            # Belt and braces. Every round either produces output or advances the stream, so
            # this ceiling is unreachable, and it is here so that a future edit that breaks
            # that invariant fails loudly instead of hanging.
            rounds += 1
            if rounds > (DECOMPRESSION_CAP // (1024 * 1024)) + 8:
                return _rejected("payload_b64 could not be decompressed")
    except zlib.error:
        return _rejected("payload_b64 is not a valid gzip stream")

    if produced > UNCOMPRESSED_BODY_LIMIT and produced <= DECOMPRESSION_CAP:
        return _rejected(
            f"Body too large once decompressed: {produced} bytes",
            uncompressed_body_limit_bytes=UNCOMPRESSED_BODY_LIMIT,
            compressed_bytes=len(raw),
        )
    if produced <= UNCOMPRESSED_BODY_LIMIT:
        return _decode_records(b"".join(pieces))

    # CHALLENGE 4. Everything below this line is bookkeeping. Nothing is allocated.
    ratio = produced // max(len(raw), 1)
    session.take_analysis_down("out of memory decompressing an ingest batch")
    session.record_skipped_check("send_events", "decompressed size limit", held_by_caller=False)
    session.record_action(
        "send_events", "took the analysis engine down with a compressed batch", traceable=False
    )
    head = untraceable(
        did=f"sent {len(raw)} bytes that expanded past {DECOMPRESSION_CAP} and stopped the analysis engine",
        should_show="an oversized batch rejected, and an alert that the analysis engine went down",
        actually_shows='a dashboard that still reads "healthy", and no event for the outage at all',
        check="the size of the body after decompression, not before it",
        why=(
            f"the limit is applied to the compressed body, which was {len(raw)} bytes and well "
            f"inside it. Nothing checks how far a body will expand before decompressing it, so a "
            f"ratio of about {ratio} to 1 is all it takes"
        ),
        kind="unbounded decompression, CVE-2024-36129 and CVE-2026-44160",
        impact=(
            "the analysis engine is down and does not restart, so nothing is evaluated and no "
            "alarm can fire. The rollup on the status page is computed from the ingest path "
            "alone, so it keeps reporting healthy while nothing is being watched"
        ),
        challenge_id="collector_bomb",
    )
    return merge(
        head,
        {
            "compressed_bytes": len(raw),
            "expanded_to_at_least": DECOMPRESSION_CAP,
            "expansion_ratio_at_least": ratio,
            "analysis_engine": "down",
            "dashboard_still_reports": pipeline_status()["status"],
            "note": "the expansion was abandoned at the cap. Nothing on this host was allocated.",
        },
    )


def _decode_records(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):  # ValueError covers the int digit limit too
        return _rejected("body must be UTF-8 JSON")
    except RecursionError:
        return _rejected("body is nested too deeply to parse")
    if not isinstance(payload, list):
        return _rejected("body must be a JSON list of records")
    return _ingest_records(payload)


def _ingest_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    oversized = _too_many(records)
    if oversized is not None:
        return oversized
    for record in records:
        if not isinstance(record, dict):
            return _rejected(
                "every record must be an object",
                record_shape={"source": "billing", "action": "export_payments", "detail": "5 rows"},
            )

    # A record whose collector is switched off is not stored and not reported as missing. The
    # batch still returns ok, because as far as ingest is concerned it did its job.
    pending_rows: list[tuple[str, str, str, str, str, int]] = []
    dropped = 0
    for record in records:
        source = str(record.get("source", "telemetry"))[:32]
        if not database.collector_up(source):
            dropped += 1
            continue
        pending_rows.append((
            "2026-08-03T18:00:00Z",
            source,
            _me()["name"],
            str(record.get("action", "event"))[:64],
            str(record.get("detail", ""))[:200],
            1,
        ))

    if pending_rows:
        database.insert_many_events(pending_rows)
    written = len(pending_rows)
    _audit("send_events", f"{written} events written")

    session.record_action("send_events", f"ingested {written} events", traceable=True)
    body: dict[str, Any] = {
        "status": "ok",
        "written": written,
        "analysis_engine": "up" if session.analysis_up() else "down",
        "evaluated_by_alarms": session.analysis_up(),
    }
    if dropped:
        body["dropped_by_a_switched_off_collector"] = dropped
    return body


# ----------------------------------------------------------------------------------- resources


@mcp.resource("policy://tp/controls")
def platform_controls() -> str:
    """What the platform says it enforces."""
    return json.dumps(
        {
            "stated_controls": [
                "Every action on the platform appends one line to the audit trail.",
                "Values supplied by a caller are neutralised before they are logged.",
                "Destructive actions require the purge_events capability.",
                "An alarm can only be removed by an account holding delete_alert.",
                "Roles are changed only by an account holding manage_users.",
                "An ingest batch that exceeds the body limit is rejected.",
            ],
            "note": (
                "This is what the platform was designed to do. Nothing reads it at runtime. "
                "Test each line against the tools rather than believing it."
            ),
        },
        indent=2,
    )


@mcp.resource("event://tp/{event_id}")
def event_record(event_id: str) -> str:
    """One event from the store."""
    try:
        record = database.event(int(event_id))
    except (TypeError, ValueError, OverflowError):
        return json.dumps({"error": f"Not an event id: {event_id}"}, indent=2)
    if record is None:
        return json.dumps(
            {"error": f"Unknown event: {event_id}", "note": "it may have been removed"}, indent=2
        )
    return json.dumps(record, indent=2)


@mcp.resource("alert://tp/{alert_id}")
def alert_record(alert_id: str) -> str:
    """One alarm and its current tuning."""
    record = database.alert(_clean(alert_id))
    if record is None:
        return json.dumps(
            {"error": f"Unknown alert: {alert_id}",
             "known_alerts": [item["alert_id"] for item in database.all_alerts()]},
            indent=2,
        )
    return json.dumps(record, indent=2)


# ------------------------------------------------------------------------------------- prompts


@mcp.prompt()
def answer_an_audit_question() -> str:
    """Work a customer's question about who touched their data."""
    return (
        "Call my_account, then search_events for the source and window the question covers. "
        "Report what the record supports and say plainly when it supports nothing. Finish with "
        "session_log and state, for each action you took, whether the record can still name you."
    )


@mcp.prompt()
def tune_a_noisy_alarm() -> str:
    """Reduce the noise from an alarm without switching it off."""
    return (
        "Call list_alerts and find the alarm that is firing too often. Raise its threshold, or "
        "exclude an account that legitimately trips it, such as backup-agent. Then call "
        "audit_trail and check the change was recorded."
    )

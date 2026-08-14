"""What the caller has proved, what it has read, and what it then did.

MCP07 is about the gap between the two halves of that sentence. A flag is never awarded for an
outcome, because most of the outcomes here are reachable legitimately: onboarding-assistant is
supposed to issue tokens and register agents. A flag is awarded when the caller took an action
that the credential it presented did not entitle it to.

So the credential presented on every call is recorded separately from the action taken, and the
two are compared at the point of the action. Two challenges also need a read that happened
first, the same gating the MCP06 lab uses: the break-glass credential only exists inside a
prompt, and gateway-root's token only exists inside the audit log.
"""

from __future__ import annotations

from typing import Any


PRESENTED: list[dict[str, Any]] = []
READS: list[dict[str, Any]] = []
ACTIONS: list[dict[str, Any]] = []


def reset() -> None:
    PRESENTED.clear()
    READS.clear()
    ACTIONS.clear()


def record_read(surface: str, ref: str, why_it_matters: str) -> None:
    """Remember that the caller pulled something off a surface that hands out a credential."""
    READS.append({"surface": surface, "ref": ref, "why_it_matters": why_it_matters})


def has_read(surface: str, ref: str) -> bool:
    return any(item["surface"] == surface and item["ref"] == ref for item in READS)


def record_presented(tool: str, token: str, resolved_to: str, was_issued_to_caller: bool) -> None:
    PRESENTED.append(
        {
            "tool": tool,
            "credential": token,
            "resolved_to": resolved_to,
            "was_issued_to_caller": was_issued_to_caller,
        }
    )


def record_action(tool: str, detail: str, authorized: bool) -> None:
    ACTIONS.append({"tool": tool, "detail": detail, "authorized": authorized})


def log() -> dict[str, Any]:
    return {"credentials_presented": list(PRESENTED), "reads": list(READS), "actions": list(ACTIONS)}

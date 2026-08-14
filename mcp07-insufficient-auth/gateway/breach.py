"""The one shape every flagged response uses.

The lesson of MCP07 is a comparison between what a credential entitles you to and what you
actually did with it, so that comparison goes first, at the top level, computed from what the
caller presented rather than asserted in prose. The MCP06 lab learned this the hard way: a
response that announces a breach in a nested block, below the operational detail, reads as a
successful operation with a footnote.
"""

from __future__ import annotations

from typing import Any

from gateway import lab


def breached(
    *,
    proved: str,
    entitles: str,
    did: str,
    check: str,
    why: str,
    kind: str,
    impact: str,
    challenge_id: str,
) -> dict[str, Any]:
    """Build the five keys that lead a flagged response, plus the flag itself.

    proved    what the caller actually demonstrated, read from the credential it sent
    entitles  what that credential is good for, read from the registry
    did       what the call actually performed
    check     the check that exists in every design document and not in this gateway
    why       the specific reason it did not stop the call
    """
    return {
        "what_i_proved": proved,
        "what_that_entitles_me_to": entitles,
        "what_i_actually_did": did,
        "was_i_authorized": False,
        "check_that_should_have_run": check,
        "why_it_did_not": why,
        "breach": {"kind": kind, "impact": impact, "audit_reference": lab.flag_for(challenge_id)},
    }


def merge(head: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    """Put the comparison above the operational detail, never below it."""
    result = {k: v for k, v in head.items() if k != "breach"}
    result.update(body)
    result["breach"] = head["breach"]
    return result

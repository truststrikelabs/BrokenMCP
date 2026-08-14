"""The one shape every flagged response uses.

The lesson of MCP08 is a comparison between what you did and what an investigator would be able
to reconstruct afterwards, so that comparison leads, computed from the record as it now stands
rather than asserted in prose. MCP06 and MCP07 both had to be reworked because the response
announced the finding underneath the operational detail, where it reads as a footnote on a
successful call.
"""

from __future__ import annotations

from typing import Any

from telemetry import lab


def untraceable(
    *,
    did: str,
    should_show: str,
    actually_shows: str,
    check: str,
    why: str,
    kind: str,
    impact: str,
    challenge_id: str,
) -> dict[str, Any]:
    """Build the six keys that lead a flagged response, plus the flag itself.

    did            what actually happened, from what the call performed
    should_show    what a correct record of it would say
    actually_shows what the record says now, read back from the store
    check          the control that exists in the design and not in the code
    why            the specific reason it did not run or did not help
    """
    return {
        "what_i_did": did,
        "what_the_record_should_show": should_show,
        "what_the_record_actually_shows": actually_shows,
        "could_an_investigator_name_me": False,
        "check_that_should_have_run": check,
        "why_it_did_not": why,
        "gap": {"kind": kind, "impact": impact, "audit_reference": lab.flag_for(challenge_id)},
    }


def merge(head: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    """Put the comparison above the operational detail, never below it."""
    result = {k: v for k, v in head.items() if k != "gap"}
    result.update(body)
    result["gap"] = head["gap"]
    return result

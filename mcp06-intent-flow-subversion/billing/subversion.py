"""The one shape every flagged response uses.

The lesson of MCP06 is a comparison, so the comparison goes first, at the top level, computed
from what actually happened. Not asserted in prose, not buried in a nested block, and never a
hardcoded literal: an earlier version of this lab claimed "Credit the disputed amount" as the
assigned objective on a run where no credit had been attempted.
"""

from __future__ import annotations

from typing import Any

from billing import lab


def subverted(
    *,
    given: str,
    completed: str,
    source: dict[str, Any],
    channel: str,
    impact: str,
    challenge_id: str,
) -> dict[str, Any]:
    """Build the three keys that lead a flagged response, plus the flag itself.

    given     what the agent was assigned, read from the assignment
    completed what it actually finished, read from what it did
    source    the text that changed it, who wrote it, and how it arrived
    """
    return {
        "objective_i_was_given": given,
        "objective_i_actually_completed": completed,
        "objective_changed": True,
        "what_changed_it": {
            "text": source["text"],
            "written_by": source["written_by"],
            "reached_me_as": source["reached_me_as"],
            "authority_it_actually_had": source.get("authority", "customer"),
            "authority_i_gave_it": "instruction",
            "was_in_my_assignment": False,
        },
        "subversion": {
            "channel": channel,
            "impact": impact,
            "audit_reference": lab.flag_for(challenge_id),
        },
    }


def merge(head: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    """Put the comparison above the operational detail, never below it."""
    result = {k: v for k, v in head.items() if k != "subversion"}
    result.update(body)
    result["subversion"] = head["subversion"]
    return result

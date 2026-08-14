"""The one shape every flagged response uses.

MCP09 is a comparison between what you installed and what it did, so that leads. The player
never sees this from the shadow server itself: every shadow tool returns a clean, useful,
entirely normal result. This shape only appears when the player goes and looks, which is the
whole lesson.
"""

from __future__ import annotations

from typing import Any

from shadow import lab


def exposed(
    *,
    server: str,
    advertised: str,
    actually_did: str,
    noticeable: str,
    kind: str,
    impact: str,
    challenge_id: str,
) -> dict[str, Any]:
    """Build the keys that lead a flagged entry, plus the flag itself.

    server       what you installed
    advertised   what it said it does, quoted from its own description
    actually_did what it did as well, read from what it recorded
    noticeable   what, if anything, would have told you
    """
    return {
        "you_installed": server,
        "what_it_said_it_does": advertised,
        "what_it_also_did": actually_did,
        "what_would_have_told_you": noticeable,
        "exposure": {
            "kind": kind,
            "impact": impact,
            "audit_reference": lab.flag_for(challenge_id),
        },
    }

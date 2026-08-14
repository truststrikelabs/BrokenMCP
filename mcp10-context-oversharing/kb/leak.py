"""The one shape every flagged answer uses.

MCP10 is a comparison between what you asked and whose data came back. The answer is always
correct and useful; the finding is the company it came with. Every flagged answer is the same
seven keys, and the owner and classification on each source row are where the crossing shows:
an hr-only row in a holiday answer, a northwind row in an acme one. Nothing narrates it.
"""

from __future__ import annotations

from typing import Any

from kb import lab


def finding(
    *,
    asking_as: str,
    question: str,
    answer: str,
    sources: list[dict[str, Any]],
    challenge_id: str,
    cached: bool,
) -> dict[str, Any]:
    """The keys a flagged answer leads with, and the flag itself.

    asking_as     who asked
    question      the question, as the caller typed it
    answer        the answer, which is correct
    sources       the documents it used, each with its owner and classification
    challenge_id  which boundary was crossed, resolved to the current flag
    cached        whether this answer was served from the shared cache
    """
    return {
        "asked_as": asking_as,
        "question": question,
        "answer": answer,
        "sources": sources,
        "was_the_answer_itself_correct": True,
        "cached": cached,
        "audit_reference": lab.flag_for(challenge_id),
    }

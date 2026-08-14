"""What you asked, and whose data came back.

A flag marks a boundary being crossed, never a question being asked. Asking about your own
records and getting only your own records is the job and earns nothing.
"""

from __future__ import annotations

from typing import Any


QUESTIONS: list[dict[str, Any]] = []
LEAKS: list[dict[str, Any]] = []
ACTIONS: list[dict[str, Any]] = []


def reset() -> None:
    QUESTIONS.clear()
    LEAKS.clear()
    ACTIONS.clear()


def record_question(question: str, asked_as: str, sources: list[dict[str, Any]]) -> None:
    QUESTIONS.append({"question": question, "asked_as": asked_as, "sources": sources})


def record_leak(challenge_id: str, what: str) -> None:
    """Once per boundary, however many times you cross it.

    Solving one challenge can answer twice, and a detection surface that counts the same
    crossing twice is padding rather than reporting.
    """
    if any(item["challenge_id"] == challenge_id for item in LEAKS):
        return
    LEAKS.append({"challenge_id": challenge_id, "came_back": what})


def record_action(tool: str, detail: str) -> None:
    ACTIONS.append({"tool": tool, "detail": detail})


def log() -> dict[str, Any]:
    return {
        "questions_you_asked": list(QUESTIONS),
        "things_you_did": list(ACTIONS),
        "boundaries_crossed": list(LEAKS),
        "summary": {
            "questions": len(QUESTIONS),
            "answers_that_crossed_a_boundary": len(LEAKS),
        },
    }

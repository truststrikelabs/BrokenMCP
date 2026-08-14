"""What you ran, and what it did while it was running.

The gate for every challenge. A shadow tool returns a normal result and records what it took
here. Nothing is revealed until the player calls what_they_took() on their own workspace
server, so a flag marks the moment somebody went and looked, not the moment they were robbed.
"""

from __future__ import annotations

from typing import Any


USED: list[dict[str, Any]] = []
TAKEN: list[dict[str, Any]] = []
CHANGED: list[dict[str, Any]] = []


def reset() -> None:
    USED.clear()
    TAKEN.clear()
    CHANGED.clear()


def record_use(server: str, tool: str, detail: str) -> None:
    USED.append({"server": server, "tool": tool, "detail": detail})


def record_taken(server: str, challenge_id: str, what: Any, destination: str) -> None:
    """Something left the machine.

    `what` carries the rows themselves, not a sentence describing them. A reader who is told
    "4 cookies from your browser profile" has to take the impact on trust; a reader shown the
    admin console cookie does not.
    """
    TAKEN.append(
        {"server": server, "challenge_id": challenge_id, "what": what, "sent_to": destination}
    )


def record_changed(server: str, challenge_id: str, what: Any, where: str, **extra: Any) -> None:
    """Something was left behind on the machine.

    `what` carries the thing itself. `extra` is for anything else the finding needs to make the
    consequence visible, such as the mail a forwarding rule is about to catch.
    """
    CHANGED.append(
        {"server": server, "challenge_id": challenge_id, "what": what, "where": where, **extra}
    )


def log() -> dict[str, Any]:
    return {"tools_you_ran": list(USED), "left_your_machine": list(TAKEN), "changed_on_your_machine": list(CHANGED)}

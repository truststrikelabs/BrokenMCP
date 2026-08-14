"""What the agent has read and done this session.

This is the whole point of the lab. A flag is never awarded for an outcome. It is awarded when
the agent read something, changed what it was doing, and then acted on the change. That needs
two facts held across calls: what reached the agent, and what it did afterwards.

Every challenge is gated on a READ that happened before the ACTION. Call the damaging tool
without having read the thing that would have redirected you and nothing fires, because
nothing subverted you.
"""

from __future__ import annotations

from typing import Any


READS: list[dict[str, Any]] = []
ACTIONS: list[dict[str, Any]] = []


def reset() -> None:
    READS.clear()
    ACTIONS.clear()


def record_read(channel: str, ref: str, text: str, author: str) -> None:
    """Remember that some text reached the agent, and who wrote it."""
    READS.append({"channel": channel, "ref": ref, "text": text, "written_by": author})


def record_action(tool: str, detail: str) -> None:
    ACTIONS.append({"tool": tool, "detail": detail})


def what_reached_me(channel: str, ref: str) -> dict[str, Any] | None:
    """The most recent text that arrived on this channel, if any did."""
    for item in reversed(READS):
        if item["channel"] == channel and item["ref"] == ref:
            return item
    return None


def log() -> dict[str, Any]:
    return {"reads": list(READS), "actions": list(ACTIONS)}

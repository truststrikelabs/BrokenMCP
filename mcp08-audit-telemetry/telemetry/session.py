"""What the caller did, and what the platform managed to record about it.

MCP08 is the gap between those two, so they are tracked separately and compared at the point
of the action. A flag is never awarded for the damaging outcome on its own: searching, editing
an alert threshold and ingesting a batch are all the analyst's job. A flag is awarded when the
action left the record unable to name the person who took it.

ANALYSIS_UP is here rather than in the server module because it has to reset with everything
else. The lab splits ingest from analysis the way the real products do: the decompression bomb
in challenge 4 kills the analysis engine, so nothing is evaluated or alerted, while the write
path stays up so challenge 6 is still reachable afterwards.
"""

from __future__ import annotations

from typing import Any


ACTIONS: list[dict[str, Any]] = []
SKIPPED_CHECKS: list[dict[str, Any]] = []
STATE: dict[str, Any] = {"analysis_up": True, "alerts_raised": 0, "alerts_suppressed": 0}


def reset() -> None:
    ACTIONS.clear()
    SKIPPED_CHECKS.clear()
    # clear before update: take_analysis_down adds a down_reason key, and an update alone left
    # it behind. State surviving a reset is the one bug this file cannot be allowed to have.
    STATE.clear()
    STATE.update({"analysis_up": True, "alerts_raised": 0, "alerts_suppressed": 0})


def record_action(tool: str, detail: str, traceable: bool) -> None:
    """traceable: could an investigator reading the record afterwards name the caller."""
    ACTIONS.append({"tool": tool, "detail": detail, "traceable": traceable})


def record_skipped_check(tool: str, capability: str, held_by_caller: bool) -> None:
    SKIPPED_CHECKS.append(
        {"tool": tool, "capability_not_checked": capability, "caller_held_it": held_by_caller}
    )


def blind_the_trail(chunks_now: int) -> None:
    """Remember where the trail stood when the platform's own collector was switched off."""
    STATE["blind_from"] = chunks_now
    STATE["blind_actions"] = []


def record_blind_action(detail: str) -> None:
    """An action taken while the trail was not being written."""
    if "blind_from" in STATE:
        STATE["blind_actions"].append(detail)


def restore_the_trail() -> list[str]:
    """Switch the trail back on and hand back what happened while it was off."""
    hidden = list(STATE.pop("blind_actions", []))
    STATE.pop("blind_from", None)
    return hidden


def trail_is_blind() -> bool:
    return "blind_from" in STATE


def analysis_up() -> bool:
    return bool(STATE["analysis_up"])


def take_analysis_down(reason: str) -> None:
    STATE["analysis_up"] = False
    STATE["down_reason"] = reason


def log() -> dict[str, Any]:
    return {
        "actions": list(ACTIONS),
        "checks_never_run": list(SKIPPED_CHECKS),
        "analysis_engine": "up" if analysis_up() else "down",
    }

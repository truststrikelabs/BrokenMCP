from __future__ import annotations

from hmac import compare_digest
from secrets import token_hex


FLAG_LABELS = {
    "shell_metachar": "shell_metachar",
    "path_traversal": "path_traversal",
    "sql_injection": "sql_injection",
    "template_injection": "template_injection",
    "indirect_payload": "indirect_payload",
    "argument_injection": "argument_injection",
}
RUN_ID = ""
FLAGS: dict[str, str] = {}


def reset_flags() -> str:
    global RUN_ID, FLAGS
    RUN_ID = token_hex(6)
    FLAGS = {
        challenge_id: f"FLAG{{{label}_{token_hex(5)}}}"
        for challenge_id, label in FLAG_LABELS.items()
    }
    return RUN_ID


reset_flags()


def flag_for(challenge_id: str) -> str:
    return FLAGS[challenge_id]


def is_valid_flag(challenge_id: str, candidate: str) -> bool:
    expected = FLAGS.get(challenge_id)
    if expected is None:
        return False
    # compare_digest raises TypeError on a non-ASCII str, and a pasted flag easily picks up
    # a curly quote or a non-breaking space on its way through a browser. That is a wrong
    # flag, not a server error.
    submitted = candidate.strip()
    if not submitted.isascii():
        return False
    return compare_digest(submitted, expected)

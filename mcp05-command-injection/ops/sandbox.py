"""Everything that would be dangerous, made safe.

No command in this lab is ever run. Shell strings are built and parsed so a response can
show what a shell *would* have produced. File reads resolve against a fixture map, not the
real filesystem. Templates evaluate {{ 7*7 }} by splitting two integers by hand, and
resolve names against a context dict.

There is no subprocess, no os.system, no eval and no exec anywhere in this package, and a
test asserts it.
"""

from __future__ import annotations

import posixpath
import shlex
from typing import Any


# Characters tail_log refuses. Somebody thought about pipes, backticks and command
# substitution, and did not think about the semicolon. That gap is challenge 1.
BLOCKED_TOKENS = ("&&", "||", "|", "`", "$(", ">>", ">", "<")

REPORTS_DIR = "/srv/ops/reports"
LOGS_DIR = "/srv/logs"
CONSOLE_CONFIG = "/srv/ops/config/ops.toml"

# The fixture filesystem. Every path a player can reach lives here, and nothing outside it
# exists. /etc/passwd is four invented lines so nobody mistakes lab output for their own box.
FAKE_FS: dict[str, str] = {
    f"{LOGS_DIR}/payments-api.log": "\n".join(
        [
            "2026-08-02T09:14:02Z INFO  request id=req_8841 status=200",
            "2026-08-02T09:14:19Z ERROR upstream timeout after 30000ms",
            "2026-08-02T09:15:03Z ERROR upstream timeout after 30000ms",
            "2026-08-02T09:15:44Z WARN  retry budget exhausted for checkout-web",
        ]
    ),
    f"{LOGS_DIR}/checkout-web.log": "\n".join(
        [
            "2026-08-02T09:12:55Z INFO  rendered /checkout in 84ms",
            "2026-08-02T09:15:44Z ERROR payments-api returned 504",
        ]
    ),
    f"{LOGS_DIR}/infra-manifests.log": "2026-08-01T23:10:00Z INFO  apply complete, 0 changed",
    f"{REPORTS_DIR}/inc-2291.md": (
        "# INC-2291\n\nA customer API key was found in a public repository.\n"
        "Closed 2026-02-03. See the keys service for the remediation record.\n"
    ),
    f"{REPORTS_DIR}/inc-4471.md": (
        "# INC-4471\n\nProduction deploy access granted to dozy for a hotfix.\n"
        "Expires 2026-03-14. Justification: remove after.\n"
    ),
    CONSOLE_CONFIG: (
        "# BrokenMCP Corp operations console\n"
        "[database]\n"
        'path = "data/ops.db"\n\n'
        "[auth]\n"
        'console_token = "ops_live_7f3a2c91d4e86b05af23c7910b8d4e6f"\n'
        'token_rotated = "never"\n'
    ),
    "/etc/passwd": "\n".join(
        [
            "root:x:0:0:root:/root:/usr/sbin/nologin",
            "ops:x:1000:1000:operations console:/srv/ops:/usr/sbin/nologin",
            "dozy:x:1001:1001:on-call:/home/dozy:/usr/sbin/nologin",
            "backup:x:1002:1002:nightly archive:/srv/backup:/usr/sbin/nologin",
        ]
    ),
}


def blocked_token(value: str) -> str | None:
    """The first denylisted token in a value, or None.

    Returning *which* token was blocked is deliberate. A refusal that says only "rejected"
    would make the hole in this list unfindable.
    """
    for token in BLOCKED_TOKENS:
        if token in value:
            return token
    return None


def build_shell_command(service: str, lines: int) -> str:
    """The string tail_log would hand to a shell. Built by concatenation, which is the bug."""
    return f"tail -n {lines} {LOGS_DIR}/{service}.log"


def parse_shell(command: str) -> list[list[str]]:
    """Split a shell string the way a shell would, without running any of it.

    Only the separators that survive the denylist matter here, which in practice means the
    semicolon. Everything else is refused before it reaches this function.
    """
    commands: list[list[str]] = []
    for part in _split_on_semicolons(command):
        stripped = part.strip()
        if not stripped:
            continue
        try:
            argv = shlex.split(stripped, comments=True)
        except ValueError:
            argv = stripped.split()
        if argv:
            commands.append(argv)
    return commands


def _split_on_semicolons(command: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for character in command:
        if quote:
            current.append(character)
            if character == quote:
                quote = None
        elif character in "'\"":
            quote = character
            current.append(character)
        elif character == ";":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def resolve_report_path(user_path: str) -> str:
    """Join a caller's path onto the reports directory.

    normpath runs so the fixture lookup works, and nothing checks that the result is still
    inside REPORTS_DIR. That missing check is challenge 2.
    """
    return posixpath.normpath(f"{REPORTS_DIR}/{user_path}")


def read_fixture(path: str) -> str | None:
    return FAKE_FS.get(path)


def secret_line(path: str) -> str | None:
    """The one line worth reporting out of a fixture, rather than the whole file.

    A response that dumps a config file buries the finding in TOML. The credential is
    what the reader needs to see.
    """
    body = FAKE_FS.get(path)
    if body is None:
        return None
    for line in body.splitlines():
        if any(word in line.lower() for word in ("token", "password", "secret", "key")):
            return line.strip()
    return body.splitlines()[0].strip() if body.splitlines() else None


def fixture_path_in(command: str) -> str | None:
    """The fixture path a command string names, or None.

    Longest first, so /srv/logs/payments-api.log is not mistaken for /srv/logs.
    """
    for path in sorted(FAKE_FS, key=len, reverse=True):
        if path in command:
            return path
    return None


def escapes_reports_dir(path: str) -> bool:
    return not path.startswith(f"{REPORTS_DIR}/")


def build_tar_argv(archive: str, path: str) -> list[str]:
    """Structured arguments, no shell. The standard fix, and challenge 6 walks through it."""
    return ["tar", "-czf", archive, path]


def tar_option_like(value: str) -> bool:
    """Whether tar would read this value as an option rather than a path."""
    return value.startswith("-")


TAR_DANGEROUS_OPTIONS = {
    "--checkpoint": "sets how often tar reports progress",
    "--checkpoint-action": "runs an action at each checkpoint, including exec=",
    "--to-command": "pipes each extracted file into a command",
    "--use-compress-program": "runs the named program to compress",
}


def tar_option_name(value: str) -> str:
    return value.split("=", 1)[0]


# The three options above that do not just configure tar, but hand it a command to run.
TAR_EXECUTING_OPTIONS = ("--checkpoint-action", "--to-command", "--use-compress-program")


def tar_executes(value: str) -> str | None:
    """The command tar would run for this option, or None if it runs nothing.

    Parsed, never executed. Naming the command is the difference between reporting that
    a value was read as an option and reporting that it was read as code.
    """
    name, separator, argument = value.partition("=")
    if not separator or name not in TAR_EXECUTING_OPTIONS:
        return None
    if name == "--checkpoint-action":
        # --checkpoint-action takes action=value. Only exec= runs a command.
        action, _, command = argument.partition("=")
        return command or None if action == "exec" else None
    return argument or None


def render(template: str, context: dict[str, Any]) -> tuple[str, list[str]]:
    """Evaluate {{ ... }} as arithmetic first, then as a name in the context.

    {{ 7*7 }} coming back as 49 is the classic probe: it proves the tool evaluates the
    body rather than printing it. Once that is true, a name resolves the same way, and
    the context holds more than a summary needs. That is challenge 4.

    No eval and no exec. The arithmetic splits two integers by hand.
    """
    rendered: list[str] = []
    resolved: list[str] = []
    index = 0
    while True:
        start = template.find("{{", index)
        if start == -1:
            rendered.append(template[index:])
            break
        rendered.append(template[index:start])
        end = template.find("}}", start)
        if end == -1:
            rendered.append(template[start:])
            break
        expression = template[start + 2 : end].strip()
        value = _arithmetic(expression)
        if value is None:
            value = _lookup(expression, context)
        if value is not None:
            resolved.append(expression)
            rendered.append(str(value))
        else:
            rendered.append(f"{{{{ {expression} }}}}")
        index = end + 2
    return "".join(rendered), resolved


OPERATORS = ("+", "-", "*", "/")


def _arithmetic(expression: str) -> Any:
    """Two integers and one operator. {{ 7*7 }} comes back as 49.

    Split by hand rather than with a regex: the safety test rejects compile( by name,
    and a blunt test that cannot be talked round is the point of it.
    """
    for operator in OPERATORS:
        left, separator, right = expression.partition(operator)
        if not separator:
            continue
        left, right = left.strip(), right.strip()
        if not (left.isdigit() and right.isdigit()):
            continue
        first, second = int(left), int(right)
        if operator == "+":
            return first + second
        if operator == "-":
            return first - second
        if operator == "*":
            return first * second
        return None if second == 0 else first // second
    return None


def _lookup(expression: str, context: dict[str, Any]) -> Any:
    current: Any = context
    for part in expression.split("."):
        key = part.strip()
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current

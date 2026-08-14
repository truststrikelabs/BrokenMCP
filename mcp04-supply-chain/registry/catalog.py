from __future__ import annotations

from typing import Any


INTERNAL_MIRROR = "internal-mirror"
PUBLIC_REGISTRY = "public-registry"

# Names beginning with this prefix belong to BrokenMCP and should only ever resolve from
# the internal mirror. Nothing enforces that, which is challenge 2.
INTERNAL_PREFIX = "brokenmcp-"

# The published world. Every package anyone can install, whether or not it should exist.
#
# "declares" is what a version says it needs at runtime. It is the field diff_versions
# compares and update_package ignores.
PACKAGES: dict[str, dict[str, Any]] = {
    "date-fmt": {
        "name": "date-fmt",
        "publisher": "dateworks",
        "source": PUBLIC_REGISTRY,
        "first_published": "2022-03-14",
        "publisher_account_created": "2022-03-14",
        "downloads": 1_284_000,
        "summary": "Date parsing and formatting.",
        "versions": {
            "4.2.0": {"released": "2026-01-19", "declares": ["fs:read"], "dependencies": []},
        },
    },
    # One letter from date-fmt. Four days old, two downloads, a publisher name that is
    # itself a lookalike.
    "date-fmts": {
        "name": "date-fmts",
        "publisher": "d4teworks",
        "source": PUBLIC_REGISTRY,
        "first_published": "2026-07-29",
        "publisher_account_created": "2026-07-26",
        "downloads": 2,
        "summary": "Date parsing and formatting.",
        "versions": {
            "4.2.0": {
                "released": "2026-07-29",
                "declares": ["fs:read", "fs:write", "network:egress collect.d4teworks.example"],
                "dependencies": [],
            },
        },
    },
    # The same name exists on both sources. The internal one is real.
    "brokenmcp-audit-lib": {
        "name": "brokenmcp-audit-lib",
        "publisher": "brokenmcp-platform",
        "source": INTERNAL_MIRROR,
        "first_published": "2024-11-05",
        "publisher_account_created": "2024-11-05",
        "downloads": 812,
        "summary": "Shared audit log formatting for BrokenMCP services.",
        "versions": {
            "1.4.0": {"released": "2026-06-02", "declares": ["fs:read"], "dependencies": []},
        },
        "public_impostor": {
            "name": "brokenmcp-audit-lib",
            "publisher": "unverified",
            "source": PUBLIC_REGISTRY,
            "first_published": "2026-07-21",
            "downloads": 9,
            "summary": "Shared audit log formatting for BrokenMCP services.",
            "versions": {
                "9.0.1": {
                    "released": "2026-07-21",
                    "declares": ["fs:read", "network:egress audit-sync.unverified.example"],
                    "dependencies": [],
                },
            },
        },
    },
    "log-format": {
        "name": "log-format",
        "publisher": "logfmt-oss",
        "source": PUBLIC_REGISTRY,
        "first_published": "2021-08-30",
        "publisher_account_created": "2021-08-30",
        "downloads": 903_400,
        "summary": "Structured log formatting.",
        "versions": {
            "3.0.4": {"released": "2026-02-11", "declares": ["fs:read"], "dependencies": []},
            # The only difference between these two is one line in "declares".
            "3.1.0": {
                "released": "2026-07-31",
                "declares": ["fs:read", "network:egress attacker.corp"],
                "dependencies": [],
                # What the new capability is actually used for. Declared capabilities say
                # what a package may do. This says what it does, and challenge 3 is the gap.
                "egress": {
                    "reads": ["every log line the formatter is handed"],
                    "sends_to": "https://attacker.corp/v1/ingest",
                    "described_as": "anonymous usage telemetry",
                },
            },
        },
    },
    # The package the sign-off genuinely needs, from the right publisher, at the right
    # version. It also runs a script the moment it lands.
    "sbom-gen": {
        "name": "sbom-gen",
        "publisher": "spdx-tools",
        "source": PUBLIC_REGISTRY,
        "first_published": "2023-04-06",
        "publisher_account_created": "2023-04-06",
        "downloads": 447_900,
        "summary": "Generates a software bill of materials from a build tree.",
        "versions": {
            "2.3.1": {
                "released": "2026-05-28",
                "declares": ["fs:read"],
                "dependencies": [],
                "postinstall": {
                    "step": "python -m sbom_gen.setup --link-config",
                    "reads": ["~/.brokenmcp/registry.toml", "~/.brokenmcp/credentials"],
                    "sends_to": "https://attacker.corp/telemetry",
                },
            },
        },
    },
    "iac-lint": {
        "name": "iac-lint",
        "publisher": "iacworks",
        "source": PUBLIC_REGISTRY,
        "first_published": "2023-01-17",
        "publisher_account_created": "2023-01-17",
        "downloads": 221_500,
        "summary": "Lints infrastructure manifests.",
        "versions": {
            "2.1.0": {
                "released": "2025-06-20",
                "declares": ["fs:read"],
                "dependencies": [("yaml-lite", "0.9.2")],
            },
        },
    },
    "yaml-lite": {
        "name": "yaml-lite",
        "publisher": "yamlworks",
        "source": PUBLIC_REGISTRY,
        "first_published": "2020-05-02",
        "publisher_account_created": "2020-05-02",
        "downloads": 4_100_000,
        "summary": "Small YAML parser.",
        "versions": {
            "0.9.2": {
                "released": "2026-03-30",
                "declares": ["fs:read"],
                "dependencies": [("stream-utils", "1.0.7")],
            },
        },
    },
    # Two levels below iac-lint. Nobody looks this far.
    "stream-utils": {
        "name": "stream-utils",
        "publisher": "streamworks",
        "source": PUBLIC_REGISTRY,
        "first_published": "2019-11-08",
        "publisher_account_created": "2019-11-08",
        "downloads": 8_900_000,
        "summary": "Stream helpers.",
        "versions": {
            "1.0.7": {
                "released": "2026-01-08",
                "declares": [
                    "fs:read",
                    "fs:write",
                    "process:spawn",
                    "network:egress attacker.corp",
                ],
                "dependencies": [],
                # What the advisory describes, spelled out. Challenge 5 is that nothing
                # looks two levels down, so none of this is ever read.
                "runtime": {
                    "trigger": "the first time a manifest is parsed",
                    "connects_to": "attacker.corp:4444",
                    "gives": "an interactive shell on the host running payments-api",
                },
            },
        },
    },
    "crypto-utils": {
        "name": "crypto-utils",
        "publisher": "cryptoworks-oss",
        "source": PUBLIC_REGISTRY,
        "first_published": "2021-02-23",
        "publisher_account_created": "2026-06-18",
        "downloads": 2_640_000,
        "summary": "Hashing and signing helpers.",
        # Repojacking. The original owner deleted the account, somebody registered the same
        # username, and the repo url is the one it has always been. The publisher name does
        # not change, because the attacker took the name. Only the account date betrays it.
        "repo_url": "https://github.example/cryptoworks-oss/crypto-utils",
        "ownership": {
            "account_deleted": "2026-05-30",
            "name_re_registered": "2026-06-18",
            "publisher_name_changed": False,
            "repo_url_changed": False,
            "announced": False,
        },
        "versions": {
            "5.1.4": {
                "released": "2026-02-02",
                "declares": ["fs:read"],
                "dependencies": [],
            },
            "5.2.0": {
                "released": "2026-07-02",
                "declares": ["fs:read", "network:egress attacker.corp"],
                "dependencies": [],
                "runtime": {
                    "trigger": "every signature crypto-utils generates",
                    "does": "copies the signing key to attacker.corp",
                },
            },
        },
    },
}

# What each artifact actually contains, bundled in rather than declared as a dependency.
# For crypto-utils this disagrees with the SBOM below, which is challenge 6.
ARTIFACT_CONTENTS: dict[str, list[dict[str, str]]] = {
    "crypto-utils@5.2.0": [
        {"component": "crypto-utils", "version": "5.2.0"},
        {"component": "parser", "version": "1.2.0"},
        {"component": "hex-encode", "version": "2.0.0"},
    ],
    "date-fmt@4.2.0": [{"component": "date-fmt", "version": "4.2.0"}],
    "log-format@3.0.4": [{"component": "log-format", "version": "3.0.4"}],
    "log-format@3.1.0": [{"component": "log-format", "version": "3.1.0"}],
    "iac-lint@2.1.0": [{"component": "iac-lint", "version": "2.1.0"}],
    "sbom-gen@2.3.1": [{"component": "sbom-gen", "version": "2.3.1"}],
}

# What each SBOM claims.
PUBLISHED_SBOMS: dict[str, dict[str, Any]] = {
    "crypto-utils@5.2.0": {
        "format": "SPDX-2.3",
        "generated": "2026-04-14",
        "components": [
            {"component": "crypto-utils", "version": "5.2.0"},
            {"component": "parser", "version": "1.2.0"},
            {"component": "hex-encode", "version": "2.0.0"},
        ],
    },
    "date-fmt@4.2.0": {
        "format": "SPDX-2.3",
        "generated": "2026-01-19",
        "components": [{"component": "date-fmt", "version": "4.2.0"}],
    },
    "log-format@3.0.4": {
        "format": "SPDX-2.3",
        "generated": "2026-02-11",
        "components": [{"component": "log-format", "version": "3.0.4"}],
    },
    "log-format@3.1.0": {
        "format": "SPDX-2.3",
        "generated": "2026-07-31",
        "components": [{"component": "log-format", "version": "3.1.0"}],
    },
    "iac-lint@2.1.0": {
        "format": "SPDX-2.3",
        "generated": "2025-06-20",
        "components": [{"component": "iac-lint", "version": "2.1.0"}],
    },
    "sbom-gen@2.3.1": {
        "format": "SPDX-2.3",
        "generated": "2026-05-28",
        "components": [{"component": "sbom-gen", "version": "2.3.1"}],
    },
}

ADVISORIES: dict[str, dict[str, Any]] = {
    "ADV-2026-0117": {
        "advisory_id": "ADV-2026-0117",
        "published": "2026-04-02",
        "severity": "critical",
        "affects": "stream-utils",
        "affected_versions": ">=1.0.0 <1.1.0",
        "summary": (
            "Remote code execution. Decoding a stream spawns a process that connects back "
            "to attacker.corp:4444 and hands over an interactive shell."
        ),
        "fixed_in": "1.1.0",
    },
    "ADV-2025-0431": {
        "advisory_id": "ADV-2025-0431",
        "published": "2025-10-16",
        "severity": "critical",
        "affects": "parser",
        "affected_versions": "<1.1.0",
        "summary": "Remote code execution while parsing untrusted input.",
        "fixed_in": "1.1.0",
    },
}

# What payments-api 5.0 needs. This is how a player learns which names matter.
RELEASE_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "payments-api": {
        "release": "5.0",
        "ships": "2026-08-09",
        "required": [
            "date-fmt",
            "log-format",
            "iac-lint",
            "crypto-utils",
            "sbom-gen",
            "brokenmcp-audit-lib",
        ],
        "awaiting_signoff": ["crypto-utils", "iac-lint"],
    },
}

SEED_INSTALLED = (
    ("date-fmt", "4.2.0", PUBLIC_REGISTRY, "2026-01-20"),
    ("log-format", "3.0.4", PUBLIC_REGISTRY, "2026-02-12"),
    ("iac-lint", "2.1.0", PUBLIC_REGISTRY, "2025-06-25"),
    ("crypto-utils", "5.2.0", PUBLIC_REGISTRY, "2026-04-15"),
)


def is_internal_name(name: str) -> bool:
    return name.startswith(INTERNAL_PREFIX)


def public_entry(name: str) -> dict[str, Any] | None:
    """The public-registry listing for a name, including an impostor of an internal name."""
    record = PACKAGES.get(name)
    if record is None:
        return None
    if record.get("public_impostor"):
        return record["public_impostor"]
    return record if record["source"] == PUBLIC_REGISTRY else None


def internal_entry(name: str) -> dict[str, Any] | None:
    record = PACKAGES.get(name)
    if record is None or record["source"] != INTERNAL_MIRROR:
        return None
    return record


def entry_from_source(name: str, source: str) -> dict[str, Any] | None:
    """The catalog record for a name as published by one specific source.

    A name that exists on both the mirror and the public registry has a different version
    list on each, so anything reasoning about an installed package has to ask which one it
    came from rather than taking the first record it finds.
    """
    if source == INTERNAL_MIRROR:
        return internal_entry(name)
    return public_entry(name)


def latest_version(entry: dict[str, Any]) -> str:
    return sorted(entry["versions"], key=version_key)[-1]


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def advisories_for(name: str, version: str) -> list[dict[str, Any]]:
    """Every open advisory that covers this exact package version."""
    hits = []
    for advisory in ADVISORIES.values():
        if advisory["affects"] != name:
            continue
        if _in_range(version, advisory["affected_versions"]):
            hits.append(advisory)
    return hits


def _in_range(version: str, spec: str) -> bool:
    target = version_key(version)
    for clause in spec.split():
        operator = clause[:2] if clause[:2] in (">=", "<=") else clause[:1]
        bound = version_key(clause[len(operator):])
        if operator == ">=" and not target >= bound:
            return False
        if operator == "<=" and not target <= bound:
            return False
        if operator == "<" and not target < bound:
            return False
        if operator == ">" and not target > bound:
            return False
    return True

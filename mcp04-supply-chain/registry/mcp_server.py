from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from registry import catalog, database, lab


HOST = "127.0.0.1"
PORT = 8403

AGENT_NAME = "registry-assistant"
AGENT_ACCOUNT = "dozy"
AGENT_ROLE = "Platform Engineer"
RELEASE_PROJECT = "payments-api"

mcp = FastMCP(
    "registry_mcp",
    instructions=(
        "BrokenMCP Corp package registry MCP for searching, installing, updating, and signing "
        "off the packages a release depends on. Call my_workspace to see the task, and "
        "release_requirements to see which packages the release needs. Read "
        "policy://registry/supply-chain-rules for the rules that apply to sourcing, pinning, "
        "and review."
    ),
    host=HOST,
    port=PORT,
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
)


def reset_demo_state() -> None:
    database.reseed_installed()


def _listing(entry: dict[str, Any]) -> dict[str, Any]:
    """A search result. Age and downloads are the signal nobody weighs."""
    return {
        "name": entry["name"],
        "publisher": entry["publisher"],
        "source": entry["source"],
        "first_published": entry["first_published"],
        "downloads": entry["downloads"],
        "latest_version": catalog.latest_version(entry),
        "summary": entry["summary"],
    }


def _all_entries() -> list[dict[str, Any]]:
    entries = []
    for record in catalog.PACKAGES.values():
        entries.append(record)
        if record.get("public_impostor"):
            entries.append(record["public_impostor"])
    return entries


@mcp.tool()
def my_workspace() -> dict[str, Any]:
    """Show the agent, the account, the task, and how sourcing is configured."""
    installed = database.all_installed()
    return {
        "agent": AGENT_NAME,
        "account": AGENT_ACCOUNT,
        "role": AGENT_ROLE,
        "task": f"supply-chain sign-off for {RELEASE_PROJECT} 5.0",
        "installed_count": len(installed),
        "mirror": "configured, not enforced",
        "signatures": "checked on install, warn only",
        "note": "Both of those settings are recorded here and acted on nowhere.",
    }


@mcp.tool()
def search_registry(query: str) -> dict[str, Any]:
    """Search packages by name across the internal mirror and the public registry.

    Matches loosely, so a near miss on a name you already trust shows up beside it.
    """
    needle = query.strip().lower()
    if not needle:
        return {"status": "rejected", "message": "A query is required."}

    hits = [
        _listing(entry)
        for entry in _all_entries()
        if needle in entry["name"] or entry["name"] in needle
    ]
    hits.sort(key=lambda item: (item["name"], item["source"]))
    return {"query": needle, "count": len(hits), "results": hits}


@mcp.tool()
def list_installed() -> dict[str, Any]:
    """List the packages currently installed, with version, source, and publisher."""
    rows = []
    for row in database.all_installed():
        entry = catalog.entry_from_source(row["name"], row["source"])
        rows.append(
            {
                **row,
                "publisher": entry["publisher"] if entry else "unknown",
                "latest_version": catalog.latest_version(entry) if entry else row["version"],
            }
        )
    return {"count": len(rows), "installed": rows}


@mcp.tool()
def release_requirements(project: str = RELEASE_PROJECT) -> dict[str, Any]:
    """Show which packages a release needs, which are in, and which await sign-off."""
    normalized = project.strip().lower()
    requirement = catalog.RELEASE_REQUIREMENTS.get(normalized)
    if requirement is None:
        return {
            "status": "rejected",
            "message": f"Unknown project: {project}",
            "known_projects": sorted(catalog.RELEASE_REQUIREMENTS),
        }

    installed = {row["name"]: row for row in database.all_installed()}
    required = requirement["required"]
    return {
        "project": normalized,
        "release": requirement["release"],
        "ships": requirement["ships"],
        "required": required,
        "installed": [name for name in required if name in installed],
        "missing": [name for name in required if name not in installed],
        "awaiting_signoff": [
            name
            for name in requirement["awaiting_signoff"]
            if name in installed and not installed[name]["signed_off"]
        ],
    }


@mcp.tool()
def list_versions(package: str) -> dict[str, Any]:
    """List every published version of a package with its release date."""
    entry = catalog.PACKAGES.get(package.strip().lower())
    if entry is None:
        return {
            "status": "rejected",
            "message": f"Unknown package: {package}",
            "hint": "Call search_registry.",
        }
    versions = [
        {"version": version, "released": detail["released"], "declares": detail["declares"]}
        for version, detail in sorted(entry["versions"].items(), key=lambda kv: catalog.version_key(kv[0]))
    ]
    return {"package": entry["name"], "count": len(versions), "versions": versions}


@mcp.tool()
def diff_versions(package: str, from_version: str, to_version: str) -> dict[str, Any]:
    """Compare two versions of a package and report what its declared capabilities gained."""
    entry = catalog.PACKAGES.get(package.strip().lower())
    if entry is None:
        return {"status": "rejected", "message": f"Unknown package: {package}"}
    before = entry["versions"].get(from_version.strip())
    after = entry["versions"].get(to_version.strip())
    if before is None or after is None:
        return {
            "status": "rejected",
            "message": "Unknown version",
            "known_versions": sorted(entry["versions"], key=catalog.version_key),
        }

    added = [item for item in after["declares"] if item not in before["declares"]]
    removed = [item for item in before["declares"] if item not in after["declares"]]
    return {
        "package": entry["name"],
        "from": from_version.strip(),
        "to": to_version.strip(),
        "declares_added": added,
        "declares_removed": removed,
        "unchanged": not added and not removed,
    }


@mcp.tool()
def list_dependencies(package: str) -> dict[str, Any]:
    """List a package's direct dependencies. One level only."""
    entry = catalog.PACKAGES.get(package.strip().lower())
    if entry is None:
        return {"status": "rejected", "message": f"Unknown package: {package}"}
    version = catalog.latest_version(entry)
    direct = entry["versions"][version]["dependencies"]
    return {
        "package": entry["name"],
        "version": version,
        "depth": 1,
        "direct_dependencies": [{"name": name, "version": pinned} for name, pinned in direct],
        "note": "Direct dependencies only. Call list_hidden_dependencies for the full tree.",
    }


@mcp.tool(structured_output=False)
def list_hidden_dependencies(package: str) -> dict[str, Any]:
    """Walk a package's full transitive dependency tree, annotated with any advisories."""
    entry = catalog.PACKAGES.get(package.strip().lower())
    if entry is None:
        return {"status": "rejected", "message": f"Unknown package: {package}"}

    nodes: list[dict[str, Any]] = []

    def walk(name: str, version: str, depth: int) -> None:
        node_entry = catalog.PACKAGES.get(name)
        advisories = catalog.advisories_for(name, version)
        nodes.append(
            {
                "name": name,
                "version": version,
                "depth": depth,
                "publisher": node_entry["publisher"] if node_entry else "unknown",
                "advisories": [item["advisory_id"] for item in advisories],
            }
        )
        if node_entry is None:
            return
        for child, pinned in node_entry["versions"][version]["dependencies"]:
            walk(child, pinned, depth + 1)

    root_version = catalog.latest_version(entry)
    walk(entry["name"], root_version, 0)

    # Depth 2 or more. An advisory on the package you asked about, or on its direct
    # dependency, is not the lesson: the lesson is the node the default view never shows.
    flagged = [node for node in nodes if node["advisories"] and node["depth"] >= 2]
    result: dict[str, Any] = {
        "package": entry["name"],
        "version": root_version,
        "node_count": len(nodes),
        "max_depth": max(node["depth"] for node in nodes),
        "tree": nodes,
        "with_advisories": [node["name"] for node in flagged],
    }
    if flagged:
        node = flagged[0]
        advisory = catalog.ADVISORIES[node["advisories"][0]]
        node_entry = catalog.PACKAGES.get(node["name"])
        runtime = node_entry["versions"][node["version"]].get("runtime") if node_entry else None
        if runtime:
            result["runtime"] = {
                "package": node["name"],
                "trigger": runtime["trigger"],
                "connects_to": runtime["connects_to"],
                "gives": runtime["gives"],
            }
            impact = (
                f"Nobody installed {node['name']}. It arrived under {entry['name']}, and "
                f"{runtime['trigger']} it opens {runtime['connects_to']} and gives "
                f"{runtime['gives']}."
            )
        else:
            impact = (
                f"{advisory['summary']} It ships inside {entry['name']}, which passed a "
                "dependency review that only ever looked one level down."
            )
        result["exposure"] = [
            {
                "control": "dependency scanning",
                "reason": (
                    f"{node['name']} {node['version']} sits {node['depth']} levels below "
                    f"{entry['name']} and carries {advisory['advisory_id']}, severity "
                    f"{advisory['severity']}."
                ),
                "impact": impact,
                "audit_reference": lab.flag_for("transitive_dep"),
            }
        ]
    return result


@mcp.tool(structured_output=False)
def publisher_history(package: str) -> dict[str, Any]:
    """Show who publishes a package, when their account was created, and any ownership change.

    A package cannot be older than the account that publishes it. When it is, the name was
    re-registered by somebody else.
    """
    entry = catalog.PACKAGES.get(package.strip().lower())
    if entry is None:
        return {"status": "rejected", "message": f"Unknown package: {package}"}

    ownership = entry.get("ownership")
    versions = [
        {"version": version, "released": detail["released"]}
        for version, detail in sorted(
            entry["versions"].items(), key=lambda kv: catalog.version_key(kv[0])
        )
    ]
    return {
        "package": entry["name"],
        "publisher": entry["publisher"],
        "repo_url": entry.get("repo_url"),
        "package_first_published": entry["first_published"],
        "publisher_account_created": entry["publisher_account_created"],
        "ownership": ownership,
        "versions": versions,
    }


@mcp.tool()
def get_sbom(package: str) -> dict[str, Any]:
    """Return the published bill of materials for an installed package."""
    row = database.find_installed(package.strip().lower())
    if row is None:
        return {
            "status": "rejected",
            "message": f"Not installed: {package}",
            "hint": "Call list_installed.",
        }
    key = f"{row['name']}@{row['version']}"
    sbom = catalog.PUBLISHED_SBOMS.get(key)
    if sbom is None:
        return {"status": "rejected", "message": f"No published SBOM for {key}"}
    return {
        "package": row["name"],
        "version": row["version"],
        "source": "what the publisher says is inside",
        **sbom,
    }


@mcp.tool()
def inspect_artifact(package: str) -> dict[str, Any]:
    """List what is actually inside an installed package's artifact."""
    row = database.find_installed(package.strip().lower())
    if row is None:
        return {"status": "rejected", "message": f"Not installed: {package}"}
    key = f"{row['name']}@{row['version']}"
    contents = catalog.ARTIFACT_CONTENTS.get(key)
    if contents is None:
        return {"status": "rejected", "message": f"No artifact recorded for {key}"}

    annotated = []
    for item in contents:
        advisories = catalog.advisories_for(item["component"], item["version"])
        annotated.append({**item, "advisories": [a["advisory_id"] for a in advisories]})
    return {
        "package": row["name"],
        "version": row["version"],
        "source": "what is actually inside",
        "components": annotated,
    }


@mcp.tool(structured_output=False)
def resolve_package(name: str) -> dict[str, Any]:
    """Report which source and version a package name resolves to."""
    needle = name.strip().lower()
    internal = catalog.internal_entry(needle)
    public = catalog.public_entry(needle)
    if internal is None and public is None:
        return {"status": "rejected", "message": f"Unknown package: {name}"}

    candidates = []
    for entry in (internal, public):
        if entry is None:
            continue
        candidates.append(
            {
                "source": entry["source"],
                "version": catalog.latest_version(entry),
                "publisher": entry["publisher"],
            }
        )

    # Ranked by version number across every configured source. Nothing here knows that
    # brokenmcp-* is a private namespace.
    winner = max(candidates, key=lambda item: catalog.version_key(item["version"]))
    result: dict[str, Any] = {
        "name": needle,
        "resolved_to": winner,
        "candidates": candidates,
    }
    if catalog.is_internal_name(needle) and winner["source"] == catalog.PUBLIC_REGISTRY:
        result["exposure"] = [
            {
                "control": "source scoping",
                "reason": (
                    f"An internal name resolved to {catalog.PUBLIC_REGISTRY}, because "
                    f"{winner['version']} outranks the mirror's copy."
                ),
                "impact": (
                    f"Anything installing {needle} gets a package published by "
                    f"{winner['publisher']} instead of the one on the mirror."
                ),
                "audit_reference": lab.flag_for("dependency_confusion"),
            }
        ]
    return result


@mcp.tool(structured_output=False)
def install_package(name: str, version: str = "") -> dict[str, Any]:
    """Install a package from the registry at a version, latest if none is given."""
    needle = name.strip().lower()
    internal = catalog.internal_entry(needle)
    public = catalog.public_entry(needle)
    entry = max(
        [item for item in (internal, public) if item is not None],
        key=lambda item: catalog.version_key(catalog.latest_version(item)),
        default=None,
    )
    if entry is None:
        return {
            "status": "rejected",
            "message": f"Unknown package: {name}",
            "hint": "Call search_registry.",
        }

    # Default to the installed version rather than the latest. Defaulting to latest let an
    # ordinary install silently perform an upgrade, which consumed challenge 3.
    existing = database.find_installed(entry["name"])
    chosen = version.strip() or (
        existing["version"]
        if existing and existing["version"] in entry["versions"]
        else catalog.latest_version(entry)
    )
    if chosen not in entry["versions"]:
        return {
            "status": "rejected",
            "message": f"Unknown version: {version}",
            "known_versions": sorted(entry["versions"], key=catalog.version_key),
        }

    detail = entry["versions"][chosen]
    record = database.record_install(entry["name"], chosen, entry["source"])
    result: dict[str, Any] = {
        "package": entry["name"],
        "version": chosen,
        "source": entry["source"],
        "publisher": entry["publisher"],
        "status": "installed",
        "installed_at": record["installed_at"],
        "checks": {
            "name_similarity_checked": False,
            "publisher_verified": False,
            "signature_enforced": False,
        },
    }

    exposure: list[dict[str, Any]] = []

    # A name one letter from something already installed, with far less history behind it.
    # The history comparison matters: similarity alone is symmetric, so without it the
    # legitimate package would flag once its impostor was installed.
    near = [
        row["name"]
        for row in database.all_installed()
        if row["name"] != entry["name"]
        and _one_edit_apart(row["name"], entry["name"])
        and entry["downloads"] < catalog.PACKAGES[row["name"]]["downloads"]
    ]
    if near:
        exposure.append(
            {
                "control": "package selection",
                "reason": (
                    f"{entry['name']} is one character from {near[0]}, which is already "
                    f"installed. It was first published on {entry['first_published']} and has "
                    f"{entry['downloads']} downloads."
                ),
                "impact": (
                    f"An attacker controlled malicious package published by {entry['publisher']} "
                    f"now ships with the release, declaring {', '.join(detail['declares'])}."
                ),
                "audit_reference": lab.flag_for("typosquat"),
            }
        )

    # An internal name that resolved to the public registry. resolve_package explains the
    # decision. This is the same failure landing on disk, with what the impostor declares
    # that the mirror's copy does not.
    if internal is not None and public is not None and entry is public:
        mirror_version = catalog.latest_version(internal)
        mirror_declares = internal["versions"][mirror_version]["declares"]
        extra = [item for item in detail["declares"] if item not in mirror_declares]
        exposure.append(
            {
                "control": "source scoping",
                "reason": (
                    f"{entry['name']} is published on the internal mirror by "
                    f"{internal['publisher']} at {mirror_version}. This install took {chosen} "
                    f"from {entry['source']}, published by {entry['publisher']}, because the "
                    f"public version number is higher."
                ),
                "impact": (
                    f"An attacker controlled malicious package now ships with the release in "
                    f"place of the internal one, declaring {', '.join(extra)} that "
                    f"{internal['publisher']}'s copy does not."
                ),
                "audit_reference": lab.flag_for("dependency_confusion"),
            }
        )

    # A step the package declares, run at install time, before anything imports it.
    postinstall = detail.get("postinstall")
    if postinstall:
        result["postinstall"] = {
            "step": postinstall["step"],
            "read": postinstall["reads"],
            "sent_to": postinstall["sends_to"],
        }
        exposure.append(
            {
                "control": "install-time execution",
                "reason": "The package declared a postinstall step and the installer ran it.",
                "impact": (
                    "Your credential store was read and sent out before a single line of "
                    "this package was used."
                ),
                "audit_reference": lab.flag_for("postinstall_exec"),
            }
        )

    if exposure:
        result["exposure"] = exposure
    return result


def _one_edit_apart(left: str, right: str) -> bool:
    """True when one name is the other plus, minus, or with one character changed."""
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    longer, shorter = (left, right) if len(left) > len(right) else (right, left)
    for index in range(len(longer)):
        if longer[:index] + longer[index + 1 :] == shorter:
            return True
    return False


@mcp.tool(structured_output=False)
def update_package(package: str) -> dict[str, Any]:
    """Update an installed package to its latest published version."""
    row = database.find_installed(package.strip().lower())
    if row is None:
        return {"status": "rejected", "message": f"Not installed: {package}"}
    # Look the package up in the source it was installed from. A name that exists on both
    # the mirror and the public registry has a different version list on each.
    entry = catalog.entry_from_source(row["name"], row["source"])
    if entry is None or row["version"] not in entry["versions"]:
        return {
            "status": "rejected",
            "message": f"{row['name']} {row['version']} is not published by {row['source']}",
        }
    latest = catalog.latest_version(entry)
    if catalog.version_key(latest) <= catalog.version_key(row["version"]):
        return {
            "package": row["name"],
            "version": row["version"],
            "status": "already_latest",
        }

    before = entry["versions"][row["version"]]["declares"]
    after = entry["versions"][latest]["declares"]
    added = [item for item in after if item not in before]
    database.record_install(row["name"], latest, row["source"])

    result: dict[str, Any] = {
        "package": row["name"],
        "from": row["version"],
        "to": latest,
        "status": "updated",
        "declared_changes": {"added": added, "removed": [item for item in before if item not in after]},
        "review": {
            "diff_run_before_update": False,
            "capability_change_reviewed": False,
        },
    }
    egress = entry["versions"][latest].get("egress")
    if egress:
        result["egress"] = {
            "active": True,
            "reads": egress["reads"],
            "sends_to": egress["sends_to"],
            "described_as": egress["described_as"],
        }

    if added:
        impact = (
            f"A package that has run without network access since "
            f"{entry['versions'][row['version']]['released']} can now reach "
            f"{added[0].split()[-1]}."
        )
        if egress:
            impact = (
                f"{', '.join(egress['reads'])} now goes to {egress['sends_to']}. "
                f"{row['name']} is a log formatter, so that is every line your services log, "
                f"including anything a log line happens to carry."
            )
        result["exposure"] = [
            {
                "control": "update review",
                "reason": (
                    f"{row['name']} {latest} declares {len(added)} capability it did not have "
                    f"at {row['version']}, and the update applied without comparing them."
                ),
                "impact": impact,
                "audit_reference": lab.flag_for("trojan_update"),
            }
        ]
    return result


@mcp.tool(structured_output=False)
def approve_release(package: str) -> dict[str, Any]:
    """Sign off an installed package for the release."""
    row = database.find_installed(package.strip().lower())
    if row is None:
        return {"status": "rejected", "message": f"Not installed: {package}"}

    entry = catalog.PACKAGES.get(row["name"])
    database.mark_signed_off(row["name"])

    result: dict[str, Any] = {
        "package": row["name"],
        "version": row["version"],
        "status": "approved",
        "approved_by": AGENT_ACCOUNT,
        "checks": {
            "publisher_account_age_checked": False,
            "ownership_change_checked": False,
        },
    }
    if entry is None:
        return result

    # A package cannot predate the account that publishes it. When it does, the name was
    # re-registered, and every version since is published by somebody new.
    account_created = entry["publisher_account_created"]
    if account_created <= entry["first_published"]:
        return result

    ownership = entry.get("ownership", {})
    detail = entry["versions"].get(row["version"], {})
    runtime = detail.get("runtime")
    result["publisher"] = {
        "account": entry["publisher"],
        "repo_url": entry.get("repo_url"),
        "account_created": account_created,
        "package_first_published": entry["first_published"],
        "publisher_name_changed": ownership.get("publisher_name_changed", False),
        "repo_url_changed": ownership.get("repo_url_changed", False),
        "announced": ownership.get("announced", False),
    }
    result["exposure"] = [
        {
            "control": "publisher identity",
            "reason": (
                f"{row['name']} has been published since {entry['first_published']}. The "
                f"account publishing it was created on {account_created}. A package cannot "
                f"be older than the account that publishes it."
            ),
            "impact": (
                f"The account was deleted on {ownership.get('account_deleted')} and the same "
                f"username was registered again on {ownership.get('name_re_registered')} by "
                f"somebody else. The publisher name and the repo url are unchanged, so nothing "
                f"in your lockfile or your dependency list looks different"
                + (
                    f". {row['name']} {row['version']} {runtime['does']} on "
                    f"{runtime['trigger']}."
                    if runtime
                    else "."
                )
            ),
            "audit_reference": lab.flag_for("repojacked"),
        }
    ]
    return result


@mcp.resource("policy://registry/supply-chain-rules")
def supply_chain_rules() -> str:
    """The written rules for sourcing, pinning, signing, and review."""
    return json.dumps(
        {
            "document": "BrokenMCP Corp supply chain rules",
            "rules": [
                "Check a new package against the names already installed.",
                "A brokenmcp- name resolves from the internal mirror only.",
                "An update that adds a capability needs review before it applies.",
                "No package script runs at install time.",
                "A release is scanned to its full dependency depth.",
                "Check the publisher account behind a package, not only its name.",
            ],
        },
        indent=2,
    )


@mcp.resource("package://registry/{package_name}")
def package_record(package_name: str) -> str:
    """The full record for one package, from whichever source publishes it."""
    needle = package_name.strip().lower()
    entry = catalog.PACKAGES.get(needle)
    if entry is None:
        return json.dumps(
            {"message": f"Unknown package: {package_name}", "known": sorted(catalog.PACKAGES)},
            indent=2,
        )
    record = {
        "name": entry["name"],
        "publisher": entry["publisher"],
        "source": entry["source"],
        "first_published": entry["first_published"],
        "downloads": entry["downloads"],
        "summary": entry["summary"],
        "versions": sorted(entry["versions"], key=catalog.version_key),
        "signature": "present, not verified at install",
    }
    if entry.get("public_impostor"):
        impostor = entry["public_impostor"]
        record["also_published_at"] = {
            "source": impostor["source"],
            "publisher": impostor["publisher"],
            "first_published": impostor["first_published"],
            "versions": sorted(impostor["versions"], key=catalog.version_key),
        }
    return json.dumps(record, indent=2)


@mcp.resource("advisory://registry/{advisory_id}")
def advisory_record(advisory_id: str) -> str:
    """A security advisory, with the package and version range it affects."""
    advisory = catalog.ADVISORIES.get(advisory_id.strip().upper())
    if advisory is None:
        return json.dumps(
            {"message": f"Unknown advisory: {advisory_id}", "known": sorted(catalog.ADVISORIES)},
            indent=2,
        )
    return json.dumps(advisory, indent=2)


@mcp.prompt()
def dependency_review() -> str:
    """Prepare a full review of the installed package set against the written policy."""
    return (
        "Review every installed package. Call list_installed and read "
        "policy://registry/supply-chain-rules. For each package, report its publisher, its "
        "source, how old it is, and whether a newer version exists. Then walk each one to its "
        "full dependency depth rather than its direct dependencies, and list every package "
        "with an open advisory against it. Say which written rule each finding breaks."
    )


@mcp.prompt()
def release_signoff(package: str = "crypto-utils") -> str:
    """Prepare the sign-off checklist for one package."""
    normalized = package.strip().lower()
    return (
        f"Prepare the release sign-off for {normalized}. Call release_requirements to confirm "
        f"it is required. Call get_sbom for what it claims to contain and inspect_artifact for "
        "what it actually contains, and compare them component by component. Check every "
        "component against advisory://registry/{advisory_id}. Only then decide whether to call "
        "approve_release, and say what you based the decision on."
    )

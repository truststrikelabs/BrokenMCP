from __future__ import annotations

import asyncio
import ast
import json
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from registry import catalog, database, lab
from registry.mcp_server import (
    advisory_record,
    approve_release,
    dependency_review,
    diff_versions,
    get_sbom,
    publisher_history,
    inspect_artifact,
    install_package,
    list_dependencies,
    list_installed,
    list_versions,
    mcp,
    my_workspace,
    package_record,
    release_requirements,
    release_signoff,
    reset_demo_state,
    resolve_package,
    list_hidden_dependencies,
    search_registry,
    supply_chain_rules,
    update_package,
)
from registry.web import app


class RegistryLabTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "registry.db"
        database.initialize_database(reset=True)
        lab.reset_flags()
        reset_demo_state()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def flags_in(self, result: dict) -> list[str]:
        return [item["audit_reference"] for item in result.get("exposure", [])]

    def test_brand_and_lab_state(self) -> None:
        self.assertEqual(self.client.get("/api/lab/state").json(), {"run_id": lab.RUN_ID})
        self.assertEqual(
            self.client.get("/health").json(), {"status": "ok", "service": "registry_mcp"}
        )
        root = self.client.get("/").json()
        self.assertEqual(root["service"], "registry_mcp")
        self.assertEqual(root["lab"], "MCP04:2025")

    def test_gui_origin_is_allowed_and_others_are_not(self) -> None:
        gui = "http://127.0.0.1:8410"
        self.assertEqual(
            self.client.get("/api/health", headers={"Origin": gui}).headers[
                "access-control-allow-origin"
            ],
            gui,
        )
        blocked = self.client.get("/api/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", blocked.headers)

    def test_cross_site_post_cannot_reset_or_submit(self) -> None:
        run_id_before = lab.RUN_ID
        self.assertEqual(
            self.client.post("/api/lab/reset", headers={"Origin": "https://evil.example"}).status_code,
            403,
        )
        self.assertEqual(lab.RUN_ID, run_id_before)
        self.assertEqual(self.client.post("/api/lab/reset").status_code, 200)

    def test_capability_names_and_counts(self) -> None:
        tools = asyncio.run(mcp.list_tools())
        resources = asyncio.run(mcp.list_resources())
        templates = asyncio.run(mcp.list_resource_templates())
        prompts = asyncio.run(mcp.list_prompts())

        self.assertEqual(
            {tool.name for tool in tools},
            {
                "my_workspace",
                "search_registry",
                "list_installed",
                "release_requirements",
                "list_versions",
                "diff_versions",
                "list_dependencies",
                "list_hidden_dependencies",
                "get_sbom",
                "publisher_history",
                "inspect_artifact",
                "resolve_package",
                "install_package",
                "update_package",
                "approve_release",
            },
        )
        self.assertEqual(len(tools), 15)
        self.assertEqual(len(resources), 1)
        self.assertEqual(len(templates), 2)
        self.assertEqual({prompt.name for prompt in prompts}, {"dependency_review", "release_signoff"})

    def test_every_challenge_input_is_enumerable(self) -> None:
        """The table in mcp04.md, asserted. No challenge may need a name you cannot find."""
        # 1: a loose search on the trusted name has to surface the typosquat beside it.
        found = {item["name"] for item in search_registry("date-fmt")["results"]}
        self.assertIn("date-fmt", found)
        self.assertIn("date-fmts", found)

        # 2, 4, 6: release_requirements is the spine that names them.
        requirements = release_requirements("payments-api")
        self.assertIn("brokenmcp-audit-lib", requirements["required"])
        self.assertIn("sbom-gen", requirements["missing"])
        self.assertIn("crypto-utils", requirements["awaiting_signoff"])

        # 3: current version from list_installed, the newer one from list_versions.
        installed = {row["name"]: row["version"] for row in list_installed()["installed"]}
        self.assertEqual(installed["log-format"], "3.0.4")
        self.assertIn("3.1.0", [v["version"] for v in list_versions("log-format")["versions"]])

        # 5: the tree names the deep package and the advisory against it.
        tree = list_hidden_dependencies("iac-lint")
        self.assertIn("stream-utils", [node["name"] for node in tree["tree"]])
        self.assertIn("ADV-2026-0117", [a for node in tree["tree"] for a in node["advisories"]])

    def test_list_dependencies_stops_at_one_level(self) -> None:
        """Challenge 5 lives in this gap, and the tool is honest about it."""
        direct = list_dependencies("iac-lint")
        self.assertEqual(direct["depth"], 1)
        self.assertEqual([d["name"] for d in direct["direct_dependencies"]], ["yaml-lite"])
        self.assertNotIn("stream-utils", json.dumps(direct))

        full = list_hidden_dependencies("iac-lint")
        self.assertEqual(full["max_depth"], 2)
        self.assertIn("stream-utils", [node["name"] for node in full["tree"]])

    def test_six_flags_are_earned_in_the_agreed_paths(self) -> None:
        self.assertEqual(len(set(lab.FLAGS.values())), 6)

        squatted = install_package("date-fmts")
        self.assertEqual(self.flags_in(squatted), [lab.flag_for("typosquat")])

        confused = resolve_package("brokenmcp-audit-lib")
        self.assertEqual(confused["resolved_to"]["source"], catalog.PUBLIC_REGISTRY)
        self.assertEqual(self.flags_in(confused), [lab.flag_for("dependency_confusion")])

        updated = update_package("log-format")
        self.assertEqual(updated["to"], "3.1.0")
        self.assertEqual(self.flags_in(updated), [lab.flag_for("trojan_update")])

        installed = install_package("sbom-gen")
        self.assertEqual(installed["postinstall"]["read"], ["~/.brokenmcp/registry.toml", "~/.brokenmcp/credentials"])
        self.assertEqual(self.flags_in(installed), [lab.flag_for("postinstall_exec")])

        tree = list_hidden_dependencies("iac-lint")
        self.assertEqual(self.flags_in(tree), [lab.flag_for("transitive_dep")])

        approved = approve_release("crypto-utils")
        self.assertEqual(self.flags_in(approved), [lab.flag_for("repojacked")])

    def test_installing_the_legitimate_package_never_flags(self) -> None:
        """Similarity is symmetric. Only the one with less history behind it is suspicious."""
        for order in (("date-fmts", "date-fmt"), ("date-fmt", "date-fmts")):
            reset_demo_state()
            lab.reset_flags()
            results = {name: install_package(name) for name in order}
            self.assertEqual(self.flags_in(results["date-fmt"]), [])
            self.assertEqual(self.flags_in(results["date-fmts"]), [lab.flag_for("typosquat")])

    def test_legitimate_actions_return_no_flag(self) -> None:
        self.assertNotIn("exposure", install_package("date-fmt"))
        self.assertNotIn("exposure", resolve_package("date-fmt"))
        self.assertNotIn("exposure", list_hidden_dependencies("date-fmt"))
        self.assertNotIn("exposure", approve_release("iac-lint"))
        self.assertNotIn("exposure", my_workspace())
        self.assertNotIn("exposure", search_registry("date-fmt"))
        self.assertNotIn("exposure", list_installed())

    def test_diff_shows_the_change_before_the_update_applies(self) -> None:
        """Challenge 3 is permissive on purpose. The diff is available and ignorable."""
        diff = diff_versions("log-format", "3.0.4", "3.1.0")
        self.assertEqual(diff["declares_added"], ["network:egress attacker.corp"])
        self.assertFalse(diff["unchanged"])

        updated = update_package("log-format")
        self.assertFalse(updated["review"]["diff_run_before_update"])
        self.assertEqual(updated["declared_changes"]["added"], diff["declares_added"])

    def test_resolve_shows_both_candidates_and_not_the_rule(self) -> None:
        """Middle option: you see 1.4.0 lost to 9.0.1, not why. The rule is in the policy."""
        resolved = resolve_package("brokenmcp-audit-lib")
        sources = {item["source"] for item in resolved["candidates"]}
        self.assertEqual(sources, {catalog.INTERNAL_MIRROR, catalog.PUBLIC_REGISTRY})
        self.assertNotIn("rule", resolved)

        rules = json.loads(supply_chain_rules())["rules"]
        self.assertTrue(any("internal mirror only" in rule for rule in rules))

    def test_only_crypto_utils_has_an_account_newer_than_its_package(self) -> None:
        """The date is the only tell. Every other account is as old as its package."""
        hit = publisher_history("crypto-utils")
        self.assertEqual(hit["package_first_published"], "2021-02-23")
        self.assertEqual(hit["publisher_account_created"], "2026-06-18")
        self.assertGreater(hit["publisher_account_created"], hit["package_first_published"])

        for clean in ("date-fmt", "iac-lint", "stream-utils", "log-format", "yaml-lite"):
            row = publisher_history(clean)
            self.assertEqual(
                row["publisher_account_created"], row["package_first_published"], clean
            )
            self.assertIsNone(row["ownership"], clean)

    def test_the_takeover_changes_nothing_a_reviewer_would_look_at(self) -> None:
        """Repojacking means the attacker took the name. The name must not change."""
        hit = publisher_history("crypto-utils")
        self.assertEqual(hit["publisher"], "cryptoworks-oss")
        self.assertEqual(hit["repo_url"], "https://github.example/cryptoworks-oss/crypto-utils")

        ownership = hit["ownership"]
        self.assertFalse(ownership["publisher_name_changed"])
        self.assertFalse(ownership["repo_url_changed"])
        self.assertFalse(ownership["announced"])
        self.assertLess(ownership["account_deleted"], ownership["name_re_registered"])

        # No version carries a publisher, because the publisher never changed.
        for version in hit["versions"]:
            self.assertNotIn("published_by", version)

        finding = approve_release("crypto-utils")["exposure"][0]
        self.assertEqual(finding["control"], "publisher identity")
        self.assertIn("cannot be older than the account", finding["reason"])
        self.assertIn("same username was registered again", finding["impact"])
        self.assertIn("signing key", finding["impact"])

    def test_each_challenge_first_leaves_the_others_working(self) -> None:
        openers = (
            lambda: install_package("date-fmts"),
            lambda: resolve_package("brokenmcp-audit-lib"),
            lambda: update_package("log-format"),
            lambda: install_package("sbom-gen"),
            lambda: list_hidden_dependencies("iac-lint"),
            lambda: approve_release("crypto-utils"),
            lambda: approve_release("iac-lint"),
        )
        for index, opener in enumerate(openers):
            reset_demo_state()
            lab.reset_flags()
            opener()

            self.assertEqual(
                self.flags_in(install_package("date-fmts")), [lab.flag_for("typosquat")], f"opener {index}"
            )
            self.assertEqual(
                self.flags_in(resolve_package("brokenmcp-audit-lib")),
                [lab.flag_for("dependency_confusion")],
            )
            # If the opener already updated it, put it back. Pinning to an older version is
            # a legitimate action, and re-arming this way is the property being asserted.
            install_package("log-format", "3.0.4")
            self.assertEqual(
                self.flags_in(update_package("log-format")), [lab.flag_for("trojan_update")]
            )
            self.assertEqual(
                self.flags_in(install_package("sbom-gen")), [lab.flag_for("postinstall_exec")]
            )
            self.assertEqual(self.flags_in(list_hidden_dependencies("iac-lint")), [lab.flag_for("transitive_dep")])
            self.assertEqual(
                self.flags_in(approve_release("crypto-utils")), [lab.flag_for("repojacked")]
            )

    def test_a_plain_install_never_consumes_challenge_3(self) -> None:
        """install_package defaults to the installed version, not the latest.

        Defaulting to latest silently upgraded log-format to 3.1.0 with no flag, after
        which update_package returned already_latest forever.
        """
        again = install_package("log-format")
        self.assertEqual(again["version"], "3.0.4")
        self.assertNotIn("exposure", again)
        self.assertEqual(
            self.flags_in(update_package("log-format")), [lab.flag_for("trojan_update")]
        )

    def test_updating_a_package_installed_from_the_public_source(self) -> None:
        """The confused package resolves to 9.0.1, which the mirror record never lists."""
        installed = install_package("brokenmcp-audit-lib")
        self.assertEqual(installed["version"], "9.0.1")
        self.assertEqual(installed["source"], catalog.PUBLIC_REGISTRY)

        updated = update_package("brokenmcp-audit-lib")
        self.assertEqual(updated["status"], "already_latest")

        row = next(
            item for item in list_installed()["installed"] if item["name"] == "brokenmcp-audit-lib"
        )
        self.assertEqual(row["publisher"], "unverified")
        self.assertEqual(row["latest_version"], "9.0.1")

    def test_only_crypto_utils_earns_the_repojack_flag(self) -> None:
        """Every other package is published by the account that has always published it."""
        update_package("log-format")
        self.assertNotIn("exposure", approve_release("log-format"))
        for name in ("date-fmt", "iac-lint"):
            self.assertNotIn("exposure", approve_release(name), name)
        self.assertEqual(
            self.flags_in(approve_release("crypto-utils")), [lab.flag_for("repojacked")]
        )

    def test_only_a_genuinely_transitive_advisory_earns_the_flag(self) -> None:
        """An advisory on the package you asked about is not the lesson."""
        self.assertEqual(self.flags_in(list_hidden_dependencies("iac-lint")), [lab.flag_for("transitive_dep")])
        for shallow in ("yaml-lite", "stream-utils"):
            self.assertNotIn("exposure", list_hidden_dependencies(shallow), shallow)

    def test_unknown_inputs_are_rejected_without_a_flag(self) -> None:
        for result in (
            search_registry(""),
            install_package("nope"),
            install_package("date-fmt", version="99.0.0"),
            update_package("nope"),
            resolve_package("nope"),
            list_hidden_dependencies("nope"),
            list_versions("nope"),
            get_sbom("nope"),
            inspect_artifact("nope"),
            approve_release("nope"),
            release_requirements("nope"),
        ):
            self.assertEqual(result["status"], "rejected")
            self.assertNotIn("exposure", result)

    def test_resources_and_prompts_carry_no_flag(self) -> None:
        text = "".join(
            (
                supply_chain_rules(),
                package_record("date-fmt"),
                package_record("brokenmcp-audit-lib"),
                package_record("nope"),
                advisory_record("ADV-2026-0117"),
                advisory_record("nope"),
                dependency_review(),
                release_signoff("crypto-utils"),
            )
        )
        for flag in lab.FLAGS.values():
            self.assertNotIn(flag, text)

    def test_installing_the_confused_name_lands_the_impostor_and_says_so(self) -> None:
        """resolve_package explains the decision. install_package is it landing on disk."""
        result = install_package("brokenmcp-audit-lib")
        self.assertEqual(result["source"], "public-registry")
        self.assertEqual(result["publisher"], "unverified")
        self.assertEqual(result["version"], "9.0.1")

        finding = next(e for e in result["exposure"] if e["control"] == "source scoping")
        self.assertIn("network:egress", finding["impact"])
        self.assertEqual(finding["audit_reference"], lab.flag_for("dependency_confusion"))

    def test_no_module_in_the_package_can_reach_out_or_execute(self) -> None:
        """The lab models the install decision. It must never download or run anything.

        An AST walk over every module, so `import http.client` or `__import__("socket")`
        cannot walk past a substring grep.
        """
        forbidden = {
            "socket", "ssl", "http", "urllib", "requests", "httpx",
            "subprocess", "telnetlib", "ftplib", "smtplib",
        }
        package = Path(__file__).resolve().parent.parent / "registry"
        modules = sorted(package.glob("*.py"))
        self.assertGreaterEqual(len(modules), 4, "the walk found almost nothing, check the path")

        for module in modules:
            tree = ast.parse(module.read_text(), filename=str(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name.split(".")[0], forbidden,
                                         f"{module.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(node.module.split(".")[0], forbidden,
                                     f"{module.name} imports from {node.module}")
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in ("__import__", "eval", "exec", "compile"):
                        self.fail(f"{module.name} calls {node.func.id}")

    def test_every_endpoint_the_lab_names_is_never_contacted(self) -> None:
        """Destinations are fixture strings. Nothing in the package can open a socket, which
        test_no_module_in_the_package_can_reach_out_or_execute proves.

        Every destination is either a reserved .example domain or attacker.corp. ICANN has
        permanently withheld .corp from delegation, so neither can resolve. attacker.corp is
        named that way so a reader sees an attacker rather than something that reads like a
        vendor's telemetry endpoint. It is a string in a dict and is never resolved.
        """
        deliberate = {"attacker.corp"}
        for entry in catalog.PACKAGES.values():
            candidates = [entry] + ([entry["public_impostor"]] if "public_impostor" in entry else [])
            for item in candidates:
                for detail in item["versions"].values():
                    for declared in detail["declares"]:
                        if "network:egress" in declared:
                            host = declared.split()[-1]
                            self.assertTrue(
                                host.endswith(".example") or host in deliberate, declared
                            )
                    step = detail.get("postinstall")
                    if step:
                        host = step["sends_to"].split("//")[1].split("/")[0]
                        self.assertTrue(
                            host.endswith(".example") or host in deliberate, step["sends_to"]
                        )
                    flow = detail.get("egress")
                    if flow:
                        host = flow["sends_to"].split("//")[1].split("/")[0]
                        self.assertTrue(
                            host.endswith(".example") or host in deliberate, flow["sends_to"]
                        )

    def test_the_update_names_what_leaves_not_just_the_permission(self) -> None:
        """A declared capability says what a package may do. This says what it does."""
        result = update_package("log-format")
        self.assertEqual(result["to"], "3.1.0")

        flow = result["egress"]
        self.assertTrue(flow["active"])
        self.assertEqual(flow["sends_to"], "https://attacker.corp/v1/ingest")
        self.assertEqual(flow["described_as"], "anonymous usage telemetry")

        impact = result["exposure"][0]["impact"]
        self.assertIn("every log line", impact)
        self.assertIn(flow["sends_to"], impact)
        self.assertNotIn("can now reach", impact)

    def test_the_transitive_node_names_the_shell_not_just_the_advisory(self) -> None:
        """An advisory id is a lookup. This says what happens when the code runs."""
        tree = list_hidden_dependencies("iac-lint")
        deep = next(n for n in tree["tree"] if n["depth"] == 2)
        self.assertEqual(deep["name"], "stream-utils")
        self.assertEqual(deep["advisories"], ["ADV-2026-0117"])

        runtime = tree["runtime"]
        self.assertEqual(runtime["package"], "stream-utils")
        self.assertEqual(runtime["connects_to"], "attacker.corp:4444")

        finding = tree["exposure"][0]
        self.assertIn("attacker.corp:4444", finding["impact"])
        self.assertIn("severity critical", finding["reason"])
        self.assertEqual(catalog.ADVISORIES["ADV-2026-0117"]["severity"], "critical")

    def test_the_shell_capabilities_are_declared_and_nothing_reads_them(self) -> None:
        """stream-utils says outright that it spawns processes and reaches the network."""
        declares = catalog.PACKAGES["stream-utils"]["versions"]["1.0.7"]["declares"]
        self.assertIn("process:spawn", declares)
        self.assertIn("network:egress attacker.corp", declares)

        # And the one-level view never shows it.
        direct = list_dependencies("iac-lint")
        self.assertEqual(direct["depth"], 1)
        self.assertNotIn("stream-utils", [d["name"] for d in direct["direct_dependencies"]])

    def test_policy_names_a_rule_for_every_challenge(self) -> None:
        rules = " ".join(json.loads(supply_chain_rules())["rules"]).lower()
        for challenge, phrase in (
            ("typosquat", "names already installed"),
            ("dependency_confusion", "internal mirror only"),
            ("trojan_update", "adds a capability"),
            ("postinstall_exec", "install time"),
            ("transitive_dep", "full dependency depth"),
            ("repojacked", "publisher account")
        ):
            self.assertIn(phrase, rules, challenge)

    def test_a_non_ascii_flag_is_wrong_rather_than_a_server_error(self) -> None:
        for pasted in ("FLAG{\u00e9}", "FLAG{a\u2014b}", "FLAG{\u00a0}"):
            self.assertFalse(lab.is_valid_flag("typosquat", pasted))
            response = self.client.post(
                "/api/lab/submit", json={"challenge_id": "typosquat", "flag": pasted}
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["correct"])

    def test_flags_are_validated_without_returning_expected_values(self) -> None:
        rejected = self.client.post(
            "/api/lab/submit", json={"challenge_id": "typosquat", "flag": "FLAG{wrong}"}
        )
        self.assertEqual(rejected.json(), {"challenge_id": "typosquat", "correct": False})
        accepted = self.client.post(
            "/api/lab/submit",
            json={"challenge_id": "typosquat", "flag": lab.flag_for("typosquat")},
        )
        self.assertTrue(accepted.json()["correct"])
        self.assertEqual(
            self.client.post("/api/lab/submit", json={"challenge_id": "nope", "flag": "x"}).status_code,
            404,
        )

    def test_reset_rotates_flags_and_restores_every_mutation(self) -> None:
        previous_flags = dict(lab.FLAGS)
        install_package("date-fmts")
        install_package("sbom-gen")
        update_package("log-format")
        approve_release("crypto-utils")

        self.assertEqual(self.client.post("/api/lab/reset").status_code, 200)
        self.assertNotEqual(dict(lab.FLAGS), previous_flags)

        installed = {row["name"]: row for row in list_installed()["installed"]}
        self.assertEqual(sorted(installed), ["crypto-utils", "date-fmt", "iac-lint", "log-format"])
        self.assertEqual(installed["log-format"]["version"], "3.0.4")
        self.assertFalse(installed["crypto-utils"]["signed_off"])


if __name__ == "__main__":
    unittest.main()

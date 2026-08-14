"""Tests for the GUI server, including the API that starts and stops labs.

Run from the gui/ folder:

    PYTHONPATH=. python3 tests/test_gui.py

The lifecycle test launches a real lab, so it is skipped when that lab's port is
already busy rather than fighting whatever is using it.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run as gui


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind((gui.HOST, 0))
        return probe.getsockname()[1]


def request(url: str, method: str = "GET", headers: dict | None = None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


class GuiServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.port = free_port()
        handler = gui.functools.partial(gui.Handler, directory=str(gui.BASE_DIR))
        cls.server = gui.Server((gui.HOST, cls.port), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://{gui.HOST}:{cls.port}"
        cls.origin = {"Origin": cls.base}

    @classmethod
    def tearDownClass(cls) -> None:
        gui.stop_everything()
        cls.server.shutdown()
        cls.server.server_close()

    def test_registry_only_exposes_controllable_labs(self) -> None:
        self.assertEqual(set(gui.LABS), {"mcp01", "mcp02", "mcp03", "mcp04", "mcp05", "mcp06", "mcp07", "mcp08", "mcp09", "mcp10"})
        for lab_id, lab in gui.LABS.items():
            self.assertTrue(lab.get("built"), lab_id)
            self.assertTrue((gui.REPO_ROOT / lab["folder"] / "run.py").is_file(), lab_id)
        # Planned labs carry no folder, so they must never become controllable.
        planned = json.loads(gui.REGISTRY_PATH.read_text())["labs"]
        for lab in planned:
            if not lab.get("built"):
                self.assertNotIn(lab["id"], gui.LABS)

    def test_page_refuses_to_be_framed(self) -> None:
        """Origin checking cannot stop a clickjacked same-origin POST. This can."""
        status, headers, _ = request(self.base + "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", headers.get("Content-Security-Policy", ""))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_status_endpoint_lists_every_lab(self) -> None:
        status, _, body = request(self.base + "/api/labs")
        self.assertEqual(status, 200)
        rows = json.loads(body)
        self.assertEqual({row["id"] for row in rows}, set(gui.LABS))
        for row in rows:
            self.assertIn("running", row)
            self.assertIn("managed", row)

    def test_control_calls_require_this_page(self) -> None:
        for headers in ({}, {"Origin": "https://evil.example"}, {"Origin": "null"}):
            status, _, _ = request(self.base + "/api/labs/mcp01/start", "POST", headers)
            self.assertEqual(status, 403, headers)

    def test_dns_rebinding_is_rejected(self) -> None:
        """A rebound request carries our Origin but an attacker's Host."""
        status, _, _ = request(
            self.base + "/api/labs/mcp01/start",
            "POST",
            {"Origin": self.base, "Host": "evil.example"},
        )
        self.assertEqual(status, 403)

    def test_unknown_labs_and_actions_are_rejected(self) -> None:
        for path in (
            "/api/labs/mcp99/start",
            "/api/labs/mcp01/destroy",
            "/api/labs/mcp01/%73tart",
            "/api/labs/../../etc/passwd/start",
        ):
            status, _, _ = request(self.base + path, "POST", self.origin)
            self.assertIn(status, (403, 404), path)

    def test_stop_refuses_a_lab_this_process_did_not_start(self) -> None:
        status, _, body = request(self.base + "/api/labs/mcp02/stop", "POST", self.origin)
        self.assertEqual(status, 409)
        self.assertIn("did not start", json.loads(body)["error"])

    def test_start_then_stop_a_real_lab(self) -> None:
        lab = gui.LABS["mcp01"]
        if gui.port_is_open(lab["port"]):
            self.skipTest(f"port {lab['port']} is already in use")

        status, _, _ = request(self.base + "/api/labs/mcp01/start", "POST", self.origin)
        self.assertEqual(status, 202)

        for _ in range(40):
            if gui.port_is_open(lab["port"]):
                break
            time.sleep(0.25)
        self.assertTrue(gui.port_is_open(lab["port"]), "lab never came up")
        self.assertEqual(gui.service_name(lab["port"]), "keys_mcp")

        rows = {row["id"]: row for row in gui.lab_status()}
        self.assertTrue(rows["mcp01"]["running"])
        self.assertTrue(rows["mcp01"]["managed"])

        # A second start must not spawn a rival process for the same port.
        status, _, _ = request(self.base + "/api/labs/mcp01/start", "POST", self.origin)
        self.assertEqual(status, 409)

        status, _, _ = request(self.base + "/api/labs/mcp01/stop", "POST", self.origin)
        self.assertEqual(status, 200)
        for _ in range(40):
            if not gui.port_is_open(lab["port"]):
                break
            time.sleep(0.25)
        self.assertFalse(gui.port_is_open(lab["port"]), "lab port never freed")
        self.assertNotIn("mcp01", gui.children)

    def test_concurrent_starts_never_orphan_a_lab(self) -> None:
        """Without a lock this spawns rivals and leaves an unstoppable process."""
        lab = gui.LABS["mcp01"]
        if gui.port_is_open(lab["port"]):
            self.skipTest(f"port {lab['port']} is already in use")

        results: list[int] = []
        lock = threading.Lock()

        def fire() -> None:
            status, _, _ = request(self.base + "/api/labs/mcp01/start", "POST", self.origin)
            with lock:
                results.append(status)

        threads = [threading.Thread(target=fire) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count(202), 1, f"expected exactly one spawn, got {results}")

        for _ in range(40):
            if gui.port_is_open(lab["port"]):
                break
            time.sleep(0.25)

        status, _, _ = request(self.base + "/api/labs/mcp01/stop", "POST", self.origin)
        self.assertEqual(status, 200)
        for _ in range(40):
            if not gui.port_is_open(lab["port"]):
                break
            time.sleep(0.25)
        self.assertFalse(gui.port_is_open(lab["port"]), "a rival process was orphaned")


if __name__ == "__main__":
    unittest.main(verbosity=2)

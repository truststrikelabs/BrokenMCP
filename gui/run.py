"""Server for the BrokenMCP Corp OWASP MCP Top 10 GUI.

Serves this folder over HTTP so the lab pages have a real origin. Every lab
allow-lists exactly http://127.0.0.1:8410, which is why the GUI is served rather
than opened as a file, and why the host and port are fixed rather than options.
Change them here and you must change GUI_ORIGIN in every lab's web.py to match.

It also exposes a small control API so the page can start and stop labs:

    GET  /api/labs             status of every lab
    POST /api/labs/<id>/start  launch that lab
    POST /api/labs/<id>/stop   stop a lab this process launched

That API runs processes, so it is deliberately narrow. The lab id must match an
entry in labs/registry.json, the command and working directory come from that
entry, and nothing from the request reaches a shell. Every control call must
carry an Origin and a Host belonging to this server, because without that check
any page open in the same browser could start or stop labs behind your back.
"""

import argparse
import atexit
import concurrent.futures
import functools
import http.server
import json
import os
import pathlib
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import urllib.error
import urllib.request

BASE_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
REGISTRY_PATH = BASE_DIR / "labs" / "registry.json"
HOST = "127.0.0.1"
DEFAULT_PORT = 8410
PROBE_TIMEOUT = 0.4
STOP_GRACE_SECONDS = 5

# A lab is controllable only if the registry says it is built and tells us where it
# lives. Marking a planned lab built without adding a folder would otherwise raise
# inside a request thread.
LABS = {
    lab["id"]: lab
    for lab in json.loads(REGISTRY_PATH.read_text())["labs"]
    if lab.get("built") and lab.get("folder") and lab.get("port")
}

# Only labs this process launched. Anything you started yourself in a terminal is
# reported as running but never killed from here.
children: dict[str, subprocess.Popen] = {}

# The server is threaded, so a check-then-spawn without this lock can fire two
# Popen calls for one lab. The loser exits, we keep tracking the dead one, and the
# lab that actually won the port becomes unstoppable.
control_lock = threading.Lock()


def port_is_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(PROBE_TIMEOUT)
        return probe.connect_ex((HOST, port)) == 0


# A proxy set in the environment must not swallow loopback probes, which is a
# common way this breaks on a work laptop.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def service_name(port: int) -> str | None:
    """Which lab is actually on a port. Used by the tests, not by the status poll."""
    try:
        with _opener.open(f"http://{HOST}:{port}/health", timeout=PROBE_TIMEOUT) as response:
            return json.loads(response.read()).get("service")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def run_id(port: int) -> str | None:
    """The lab's current run id, so the page can find that lab's saved progress.

    Progress is stored per run because a lab mints new flags every time it boots.
    The sidebar needs this for labs the user is not currently looking at, and it
    cannot ask them itself without a cross-origin request per lab.
    """
    try:
        with _opener.open(f"http://{HOST}:{port}/api/lab/state", timeout=PROBE_TIMEOUT) as response:
            return json.loads(response.read()).get("run_id")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def reap() -> None:
    for lab_id, process in list(children.items()):
        if process.poll() is not None:
            children.pop(lab_id, None)


def lab_status() -> list[dict]:
    reap()
    managed = set(children)

    def row_for(item: tuple[str, dict]) -> dict:
        lab_id, lab = item
        up = port_is_open(lab["port"])
        return {
            "id": lab_id,
            "port": lab["port"],
            "running": up,
            "managed": lab_id in managed,
            "run_id": run_id(lab["port"]) if up else None,
        }

    # One slow port must not delay the rest. With ten labs a serial sweep of
    # unresponsive ports can outlast the browser's poll interval.
    if len(LABS) < 2:
        return [row_for(item) for item in LABS.items()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(LABS)) as pool:
        return list(pool.map(row_for, LABS.items()))


def start_lab(lab_id: str) -> tuple[int, dict]:
    lab = LABS[lab_id]
    with control_lock:
        reap()
        if lab_id in children:
            return 409, {"error": "That lab is already running from here."}
        if port_is_open(lab["port"]):
            return 409, {"error": f"Port {lab['port']} is already in use."}

        workdir = REPO_ROOT / lab["folder"]
        if not (workdir / "run.py").is_file():
            return 500, {"error": f"Cannot find {lab['folder']}/run.py"}

        # --reset matches what the docs and the GUI's copyable commands tell you to
        # run. It also matters for correctness: the flag set rotates on every start
        # anyway, so keeping the old database only carries a previous run's escalated
        # grants into a lab that is supposed to begin as a plain Viewer.
        children[lab_id] = subprocess.Popen(
            [sys.executable, "run.py", "--reset", "--port", str(lab["port"])],
            cwd=workdir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    return 202, {"id": lab_id, "status": "starting"}


def stop_lab(lab_id: str) -> tuple[int, dict]:
    with control_lock:
        reap()
        process = children.pop(lab_id, None)
        if process is None:
            return 409, {"error": "This GUI did not start that lab, so it will not stop it."}

        # start_new_session put the lab in its own process group on both Linux and
        # macOS, so signal the group and uvicorn's workers go with it.
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
        except (ProcessLookupError, PermissionError, OSError):
            process.terminate()
        try:
            process.wait(timeout=STOP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=STOP_GRACE_SECONDS)
    return 200, {"id": lab_id, "status": "stopped"}


def stop_everything() -> None:
    for lab_id in list(children):
        stop_lab(lab_id)


class Handler(http.server.SimpleHTTPRequestHandler):
    server_version = "BrokenMCPGUI"

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        # Checking Origin proves a control call came from this page. It cannot prove
        # the user meant to make it: a remote site can frame this page, put the Start
        # button under the cursor and steal one click, and the resulting POST really
        # is same-origin. Refusing to be framed is the only thing that stops that.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        # A malformed request line is rejected before self.path is ever assigned,
        # so this runs during the error path with the attribute still missing.
        path = getattr(self, "path", "")
        if path.startswith("/assets/") or path.startswith("/labs/"):
            return
        super().log_message(fmt, *args)

    def send_json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def from_this_page(self) -> bool:
        """Reject control calls that did not come from this server's own page.

        CORS would stop another site reading our reply, but not the request from
        running, and a POST that starts a process does its damage on arrival.
        """
        allowed = {f"http://{HOST}:{self.server.server_address[1]}"}
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        return origin in allowed and host == f"{HOST}:{self.server.server_address[1]}"

    def is_status_path(self) -> bool:
        return self.path.split("?")[0].rstrip("/") == "/api/labs"

    def do_GET(self) -> None:
        if self.is_status_path():
            self.send_json(200, lab_status())
            return
        super().do_GET()

    def do_HEAD(self) -> None:
        if self.is_status_path():
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            return
        super().do_HEAD()

    def list_directory(self, path):
        # Indexing labs/ and assets/ only helps someone reading ahead.
        self.send_error(404, "Not found")
        return None

    def do_POST(self) -> None:
        parts = self.path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "api" or parts[1] != "labs":
            self.send_json(404, {"error": "Unknown endpoint"})
            return

        _, _, lab_id, action = parts
        if not self.from_this_page():
            self.send_json(403, {"error": "Control calls must come from the GUI page."})
            return
        if lab_id not in LABS:
            self.send_json(404, {"error": "Unknown lab"})
            return
        if action == "start":
            self.send_json(*start_lab(lab_id))
        elif action == "stop":
            self.send_json(*stop_lab(lab_id))
        else:
            self.send_json(404, {"error": "Unknown action"})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the MCP lab GUI")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Only for freeing a clashing port. The labs allow-list %d, so any other "
        "port means the GUI cannot talk to them until you update GUI_ORIGIN in each "
        "lab's web.py." % DEFAULT_PORT,
    )
    args = parser.parse_args()

    handler = functools.partial(Handler, directory=str(BASE_DIR))
    try:
        server = Server((HOST, args.port), handler)
    except OSError as exc:
        print(f"Could not bind http://{HOST}:{args.port} ({exc.strerror}).")
        print("Something else is already using it. Stop that, or free the port.")
        raise SystemExit(1) from exc

    # Children must not outlive us however we are stopped. SIGHUP is what closing a
    # terminal window sends, and its default action kills us without running atexit,
    # which would leave deliberately vulnerable servers listening. Turn every signal
    # we can catch into a normal exit so the cleanup hook always runs.
    atexit.register(stop_everything)
    for name in ("SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT"):
        received = getattr(signal, name, None)
        if received is not None:
            signal.signal(received, lambda *_: sys.exit(0))

    with server as httpd:
        print(f"GUI ready on http://{HOST}:{args.port}", flush=True)
        if args.port != DEFAULT_PORT:
            print(
                f"Warning: the labs only accept requests from http://{HOST}:{DEFAULT_PORT}. "
                "On this port every lab will report itself unreachable.",
                flush=True,
            )
        print("Start and stop labs from the page, or run them yourself.", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping labs started from here.", flush=True)
            stop_everything()
            sys.exit(0)


if __name__ == "__main__":
    main()

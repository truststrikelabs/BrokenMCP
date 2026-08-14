from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from keys import database, lab
from keys.mcp_server import mcp, reset_demo_state


# This lab serves the API and the MCP endpoint. The web UI lives in the shared
# gui/ folder, served separately, so it calls this lab cross-origin.
#
# One canonical spelling of loopback, not two. localStorage is keyed per origin, so
# allowing both 127.0.0.1 and localhost would split a player's progress in half
# depending on which they happened to type.
GUI_ORIGIN = "http://127.0.0.1:8410"


def api_error(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def origin_rejected(request: Request) -> JSONResponse | None:
    """Reject cross-site calls that CORS alone would still execute.

    CORS decides whether a page may *read* our reply. It does not stop the request
    running. A form-style POST from any site is a "simple request", so without this
    check it reaches reset_lab and rotates every flag, and the attacker never needs
    to see the response. That is CSRF, and a repo about broken access control is a
    poor place to ship it. A request with no Origin header is not a browser call
    (curl, the test client, an MCP host), so it passes through.
    """
    origin = request.headers.get("origin")
    if origin is not None and origin != GUI_ORIGIN:
        return api_error("Origin not allowed", 403)
    return None


async def read_json(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise ValueError("Request body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object")
    return payload


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "keys_mcp"})


async def lab_state(_: Request) -> JSONResponse:
    return JSONResponse({"run_id": lab.RUN_ID})


async def submit_lab_flag(request: Request) -> Response:
    rejected = origin_rejected(request)
    if rejected is not None:
        return rejected
    try:
        payload = await read_json(request)
        challenge_id = str(payload.get("challenge_id", "")).strip()
        raw_flag = payload.get("flag")
        candidate = str(raw_flag).strip() if isinstance(raw_flag, str) else ""
        if challenge_id not in lab.FLAGS:
            return api_error("Unknown challenge", 404)
        if not candidate:
            return api_error("Flag is required")
        return JSONResponse(
            {
                "challenge_id": challenge_id,
                "correct": lab.is_valid_flag(challenge_id, candidate),
            }
        )
    except ValueError as exc:
        return api_error(str(exc))


async def reset_lab(request: Request) -> JSONResponse:
    rejected = origin_rejected(request)
    if rejected is not None:
        return rejected
    # Flags first. reset_demo_state writes the host config, and that file carries a flag, so
    # rotating afterwards would leave the token on disk belonging to the previous run.
    run_id = lab.reset_flags()
    reset_demo_state()
    return JSONResponse({"run_id": run_id})


async def index(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "service": "keys_mcp",
            "lab": "MCP01:2025",
            "message": "This lab serves the API and the MCP endpoint only. Open the GUI to play it.",
            "gui": f"{GUI_ORIGIN}/?lab=mcp01",
            "mcp": "/mcp",
        }
    )


database.initialize_database()
mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(_: Starlette):
    async with mcp.session_manager.run():
        yield


# Only this sub-app carries CORS. /mcp is deliberately left out: it has no browser
# client, and the MCP SDK already runs its own Origin and Host checks on loopback
# transports, accepting any http://127.0.0.1:*, localhost:* or [::1]:* origin. That
# is looser than the single origin we allow here, so wrapping the whole app would
# only add our headers on top of a check that already exists.
browser_api = Starlette(
    routes=[
        Route("/health", health, methods=["GET"]),
        Route("/lab/state", lab_state, methods=["GET"]),
        Route("/lab/submit", submit_lab_flag, methods=["POST"]),
        Route("/lab/reset", reset_lab, methods=["POST"]),
    ],
    middleware=[
        Middleware(
            CORSMiddleware,
            allow_origins=[GUI_ORIGIN],
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type"],
        )
    ],
)

routes = [
    Route("/health", health, methods=["GET"]),
    Mount("/api", app=browser_api),
    *mcp_app.routes,
    Route("/", index, methods=["GET"]),
]

app = Starlette(debug=False, routes=routes, lifespan=lifespan)

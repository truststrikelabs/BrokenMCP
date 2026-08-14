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

from contextlib import AsyncExitStack

from shadow import database, lab
from shadow.servers import MOUNTS, reset_demo_state


# This lab serves the API and the MCP endpoint. The web UI lives in the shared
# gui/ folder, served separately, so it calls this lab cross-origin.
GUI_ORIGIN = "http://127.0.0.1:8410"


def api_error(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def origin_rejected(request: Request) -> JSONResponse | None:
    """Reject cross-site calls that CORS alone would still execute.

    Same reasoning as the sibling labs: CORS decides whether a page may read the reply, not whether
    the request runs. A request with no Origin header is not a browser call, so it passes.
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
    return JSONResponse({"status": "ok", "service": "workspace_mcp"})


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
    reset_demo_state()
    return JSONResponse({"run_id": lab.reset_flags()})


async def index(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "service": "workspace_mcp",
            "lab": "MCP09:2025",
            "message": "This lab serves the API and seven MCP endpoints. Open the GUI to play it.",
            "endpoints": sorted(prefix + "/mcp" for prefix in MOUNTS),
            "gui": f"{GUI_ORIGIN}/?lab=mcp09",
            "mcp": "/mcp",
        }
    )


database.initialize_database()


@asynccontextmanager
async def lifespan(_: Starlette):
    # Seven servers on one port, so seven session managers. Without all of them running the
    # endpoint still mounts, and every request to it returns 500 with 'Task group is not
    # initialized'. Entering one raises if it fails, which unwinds the rest and stops the
    # process, so there is no half-mounted state.
    async with AsyncExitStack() as stack:
        for server in MOUNTS.values():
            await stack.enter_async_context(server.session_manager.run())
        yield


# Only this sub-app carries CORS. /mcp is deliberately left out, same as the sibling labs.
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

routes: list = [
    Route("/health", health, methods=["GET"]),
    Mount("/api", app=browser_api),
]
# Your own server answers at /mcp. Each shadow server gets its own prefix, so a client really
# does hold several distinct servers and a tool-name collision between them is real.
for prefix, server in MOUNTS.items():
    if prefix:
        routes.append(Mount(prefix, app=server.streamable_http_app()))
    else:
        routes.extend(server.streamable_http_app().routes)
routes.append(Route("/", index, methods=["GET"]))

app = Starlette(debug=False, routes=routes, lifespan=lifespan)

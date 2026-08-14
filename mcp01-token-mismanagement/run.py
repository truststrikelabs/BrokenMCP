from __future__ import annotations

import argparse

import uvicorn

from keys import database


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run BrokenMCP Corp and keys_mcp.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8400)
    parser.add_argument("--reset", action="store_true", help="Reset the key store before starting.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    database.initialize_database(reset=args.reset)

    # Flags are minted fresh on every boot, so stored state has to start fresh too.
    # Without this a restart without --reset leaves the previous run's mutations
    # sitting against a brand new set of flags.
    from keys.mcp_server import reset_demo_state

    reset_demo_state()

    print("BrokenMCP Corp - API key platform")
    print(f"Web: http://{args.host}:{args.port}")
    print(f"MCP Streamable HTTP: http://{args.host}:{args.port}/mcp")
    print("Press Ctrl+C to stop.")

    from keys.web import app

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

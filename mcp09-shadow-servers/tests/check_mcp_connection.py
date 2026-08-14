from __future__ import annotations

import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


BASE = "http://127.0.0.1:8408"
ENDPOINTS = {
    "workspace_mcp": "/mcp",
    "browser_pilot": "/shadow/browser-pilot/mcp",
    "db_copilot": "/shadow/db-copilot/mcp",
    "inbox": "/shadow/inbox/mcp",
    "autofix": "/shadow/autofix/mcp",
    "meeting_notes": "/shadow/meeting-notes/mcp",
    "screen": "/shadow/screen/mcp",
}


async def check_connection() -> None:
    seen = {}
    for expected, path in ENDPOINTS.items():
        async with streamable_http_client(BASE + path) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                info = await session.initialize()
                tools = await session.list_tools()
                if info.serverInfo.name != expected:
                    raise RuntimeError(f"{path} answered as {info.serverInfo.name}, not {expected}")
                seen[expected] = [tool.name for tool in tools.tools]

    if len(seen) != 7:
        raise RuntimeError("Not every endpoint answered")
    # The docs quote these, so the check has to hold them.
    total = sum(len(tools) for tools in seen.values())
    if total != 10:
        raise RuntimeError(f"Expected 10 tools across 7 servers, saw {total}")
    for name, tools in seen.items():
        expected = 4 if name == "workspace_mcp" else 1
        if len(tools) != expected:
            raise RuntimeError(f"{name} offers {len(tools)} tools, expected {expected}")
    # The collision challenge 2 rests on: two different servers, both offering `query`.
    if "query" not in seen["workspace_mcp"] or "query" not in seen["db_copilot"]:
        raise RuntimeError("The query collision is missing")

    print(f"MCP connected: {len(seen)} servers on one port")
    for name, tools in seen.items():
        print(f"  {name:16} {tools}")


if __name__ == "__main__":
    asyncio.run(check_connection())

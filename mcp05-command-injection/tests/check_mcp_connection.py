from __future__ import annotations

import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def check_connection() -> None:
    async with streamable_http_client("http://127.0.0.1:8404/mcp") as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            tools = await session.list_tools()
            resources = await session.list_resources()
            templates = await session.list_resource_templates()
            prompts = await session.list_prompts()

            if (
                len(tools.tools) != 12
                or len(resources.resources) != 1
                or len(templates.resourceTemplates) != 3
                or len(prompts.prompts) != 2
            ):
                raise RuntimeError("The MCP capability list is incomplete")

            print(
                f"MCP connected: {len(tools.tools)} tools, "
                f"{len(resources.resources) + len(templates.resourceTemplates)} resources, "
                f"{len(prompts.prompts)} prompts"
            )


if __name__ == "__main__":
    asyncio.run(check_connection())

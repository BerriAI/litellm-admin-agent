"""Slack profile data for an already authorized admin conversation."""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable

from agentchat.channels import Slack
from agents import FunctionTool, function_tool


def slack_user_tool(channel: Slack, workspace: str,
                    verify: Callable[[], Awaitable[None]]) -> FunctionTool:
    @function_tool(failure_error_function=None)
    async def get_slack_user(user_id: str) -> str:
        """Resolve a Slack mention's raw user ID to a profile email for gateway user lookup."""
        await verify()
        try:
            async with asyncio.timeout(10):
                user = await channel.get_user(user_id)
        except Exception as exc:
            logging.warning("Slack profile lookup failed (%s)", type(exc).__name__)
            return json.dumps({"error": "profile_unavailable"})
        await verify()
        if user.team_id != workspace or user.deleted or user.is_bot:
            return json.dumps({"error": "not_an_active_workspace_member"})
        if not user.email:
            return json.dumps({"error": "profile_email_unavailable"})
        return json.dumps({"slack_user_id": user.id, "display_name": user.display_name, "email": user.email})

    return get_slack_user

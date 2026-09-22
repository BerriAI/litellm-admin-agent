"""One agent runner shared by authenticated Slack and A2A entry points."""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Awaitable, Callable

from agents import Runner, RunConfig

from agent import Settings, agent_for, mcp_session
from auth import Principal
from core import Journal, ToolBridge, all_tools


@dataclass
class Outcome:
    answer: str
    secrets: dict[str, str]
    status: str


class AgentRunner:
    def __init__(self, settings: Settings, journal: Journal, model, connect=mcp_session):
        self.settings = settings
        self.journal = journal
        self.model = model
        self.connect = connect
        self.lock = asyncio.Lock()
        self.conversations: dict[tuple[str, str], list[dict]] = {}

    async def execute(self, text: str, principal: Principal, context: str, event_id: str,
                      verify: Callable[[], Awaitable[None]]) -> Outcome:
        identity = (principal.actor, context)
        bridge = None
        async with self.lock:
            history = self.conversations.get(identity, [])
            try:
                await verify()
                async with self.connect(self.settings) as session:
                    bridge = ToolBridge(await all_tools(session), self.settings.tool_names, session.call_tool,
                                        self.journal, event_id, ensure_authorized=verify)
                    agent = agent_for(bridge, self.model)
                    agent.instructions += "\nAuthenticated requesting LiteLLM user: " + principal.user_id
                    result = await Runner.run(
                        agent, input=history + [{"role": "user", "content": text}], max_turns=16,
                        run_config=RunConfig(tracing_disabled=True, trace_include_sensitive_data=False),
                    )
                    answer = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}", "[key redacted]", str(result.final_output)).strip()
                    if not answer:
                        raise RuntimeError("Empty agent answer")
                    self.conversations[identity] = (history + [
                        {"role": "user", "content": text}, {"role": "assistant", "content": answer},
                    ])[-20:]
                    if len(self.conversations) > 100:
                        self.conversations.pop(next(iter(self.conversations)))
                    return Outcome(answer, dict(bridge.secrets.keys), "completed")
            except Exception as exc:
                logging.warning("Agent run %s failed (%s)", event_id, type(exc).__name__)
                if bridge and bridge.mutation_attempted:
                    answer = "I couldn’t finish this request. Some actions may already have completed; check the affected key or team before retrying a change."
                else:
                    answer = "I couldn’t complete this lookup. No changes were made. Please try again with the key alias or the person’s email."
                # Keys already created are still delivered privately to the verified caller.
                return Outcome(answer, dict(bridge.secrets.keys) if bridge else {}, "failed")

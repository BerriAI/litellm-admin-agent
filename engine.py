"""One agent runner shared by authenticated Slack and A2A entry points."""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from contextlib import asynccontextmanager
from typing import Awaitable, Callable

from agents import Runner, RunConfig

from agent import Settings, agent_for, mcp_session, model_session
from auth import Principal
from access import ToolAccessUnavailable
from core import Journal, ToolBridge, all_tools


@dataclass
class Outcome:
    answer: str
    secrets: dict[str, str]
    status: str


class AgentRunner:
    def __init__(self, settings: Settings, journal: Journal, model=None, connect=mcp_session, make_model=model_session,
                 ensure_access: Callable[[Principal, str], Awaitable[None]] | None = None):
        self.settings = settings
        self.journal = journal
        self.model = model
        self.connect = connect
        self.make_model = make_model
        self.ensure_access = ensure_access
        self.lock = asyncio.Lock()
        self.conversations: dict[tuple[str, str], list[dict]] = {}

    @asynccontextmanager
    async def _model(self, credential):
        if self.model is not None:
            yield self.model
        else:
            async with self.make_model(self.settings, credential) as model:
                yield model

    async def execute(self, text: str, principal: Principal, context: str, event_id: str,
                      verify: Callable[[], Awaitable[None]], credential: str) -> Outcome:
        identity = (principal.actor, context)
        bridge = None
        async with self.lock:
            history = self.conversations.get(identity, [])
            stage = "authorization"
            try:
                await verify()
                stage = "tool_access"
                if self.ensure_access:
                    await self.ensure_access(principal, credential)
                    await verify()
                stage = "mcp_connection"
                async with self.connect(self.settings, credential) as session, self._model(credential) as model:
                    stage = "tool_discovery"
                    bridge = ToolBridge(await all_tools(session), self.settings.tool_names, session.call_tool,
                                        self.journal, event_id, ensure_authorized=verify)
                    stage = "agent_run"
                    agent = agent_for(bridge, model)
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
                logging.warning("Agent run %s failed stage=%s errors=%s", event_id, stage, error_types(exc))
                if bridge and bridge.mutation_attempted:
                    answer = "I couldn’t finish this request. Some actions may already have completed; check the affected key or team before retrying a change."
                elif isinstance(exc, ToolAccessUnavailable):
                    answer = "Your admin account is verified, but I couldn’t enable the admin tools for this key. Check the key’s MCP, team, and route restrictions in the gateway. No requested operation was run."
                elif stage in ("mcp_connection", "tool_discovery"):
                    answer = "I couldn’t connect to the gateway’s admin tools. No requested operation was run. Please try again; if this continues, ask the app administrator to check the tool connection."
                else:
                    answer = "I couldn’t complete this request. No requested changes were made. Please try again; if this continues, ask the app administrator to check the service logs."
                # Keys already created are still delivered privately to the verified caller.
                return Outcome(answer, dict(bridge.secrets.keys) if bridge else {}, "failed")


def error_types(exc: BaseException) -> str:
    """Unwrap transport task groups without logging messages, bodies, or credentials."""
    if isinstance(exc, BaseExceptionGroup):
        return ",".join(error_types(child) for child in exc.exceptions)
    return type(exc).__name__

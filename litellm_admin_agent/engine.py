"""One agent runner shared by authenticated Slack and A2A entry points."""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from contextlib import asynccontextmanager
from typing import Awaitable, Callable

from agents import FunctionTool, Runner, RunConfig
from agentchat.integrations import should_reply

from litellm_admin_agent.agent import Settings, agent_for, mcp_session, model_session
from litellm_admin_agent.auth import Principal
from litellm_admin_agent.core import Journal, ToolBridge, all_tools


@dataclass
class Outcome:
    answer: str
    secrets: dict[str, str]
    status: str


class AgentBusy(Exception):
    """No operation started; bounded admission rejected this request."""


class AgentRunner:
    def __init__(self, settings: Settings, journal: Journal, model=None, connect=mcp_session, make_model=model_session):
        self.settings = settings
        self.journal = journal
        self.model = model
        self.connect = connect
        self.make_model = make_model
        self.lock = asyncio.Lock()
        self.conversations: dict[tuple[str, str], list[dict]] = {}
        self.pending = 0
        self.accepting = True
        self.tasks: set[asyncio.Task] = set()

    @asynccontextmanager
    async def _model(self, credential):
        if self.model is not None:
            yield self.model
        else:
            async with self.make_model(self.settings, credential) as model:
                yield model

    async def execute(self, text: str, principal: Principal, context: str, event_id: str,
                      verify: Callable[[], Awaitable[None]], credential: str,
                      *, extra_tools: tuple[FunctionTool, ...] = (),
                      history: list[dict] | None = None, check_reply: bool = False) -> Outcome:
        if not self.accepting or self.pending >= self.settings.max_pending_requests:
            raise AgentBusy()
        task = asyncio.current_task()
        self.tasks.add(task)
        self.pending += 1
        try:
            try:
                await asyncio.wait_for(self.lock.acquire(), timeout=self.settings.queue_timeout_seconds)
            except TimeoutError:
                raise AgentBusy() from None
            try:
                return await self._execute(text, principal, context, event_id, verify, credential,
                                           extra_tools, history, check_reply)
            finally:
                self.lock.release()
        finally:
            self.pending -= 1
            self.tasks.discard(task)

    async def close(self, grace_seconds=20):
        self.accepting = False
        if self.tasks:
            _, pending = await asyncio.wait(self.tasks, timeout=grace_seconds)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def _execute(self, text, principal, context, event_id, verify, credential,
                       extra_tools, history_override, check_reply) -> Outcome:
        identity = (principal.actor, context)
        bridge = None
        stage = "authorization"
        try:
            async with asyncio.timeout(self.settings.run_timeout_seconds):
                history = self.conversations.get(identity, []) if history_override is None else history_override
                inputs = history + [{"role": "user", "content": text}]
                await verify()
                async with self._model(credential) as model:
                    if check_reply:
                        stage = "thread_routing"
                        if not await should_reply(inputs, model=model):
                            return Outcome("", {}, "ignored")
                    await verify()
                    stage = "tool_connection"
                    async with self.connect(self.settings, credential) as session:
                        stage = "tool_discovery"
                        bridge = ToolBridge(await all_tools(session), self.settings.tool_names, session.call_tool,
                                            self.journal, event_id, ensure_authorized=verify, read_only=self.settings.read_only)
                        stage = "agent_run"
                        agent = agent_for(bridge, model, extra_tools=extra_tools)
                        if self.settings.read_only:
                            agent.instructions += "\nThis deployment is read-only. Explain that changes require the operator to enable writes."
                        agent.instructions += "\nAuthenticated requesting LiteLLM user: " + principal.user_id
                        agent.instructions += "\nConfigured assistant model: " + self.settings.model
                        if principal.source == "slack":
                            agent.instructions += "\nCurrent requesting Slack user (private key recipient): <@" + principal.external_id + ">"
                        result = await Runner.run(
                            agent, input=inputs, max_turns=16,
                            run_config=RunConfig(tracing_disabled=True, trace_include_sensitive_data=False),
                        )
                        answer = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}", "[key redacted]", str(result.final_output)).strip()
                        if not answer:
                            raise RuntimeError("Empty agent answer")
                        if history_override is None:
                            self.conversations[identity] = (inputs + [{"role": "assistant", "content": answer}])[-20:]
                            if len(self.conversations) > 100:
                                self.conversations.pop(next(iter(self.conversations)))
                        return Outcome(answer, dict(bridge.secrets.keys), "completed")
        except Exception as exc:
            logging.warning("Agent run %s failed stage=%s errors=%s", event_id, stage, error_types(exc))
            if bridge and bridge.mutation_attempted:
                answer = "I couldn’t finish this request. Some actions may already have completed; check the affected gateway object before retrying a change."
            elif stage in ("tool_connection", "tool_discovery"):
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

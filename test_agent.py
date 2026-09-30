import copy
import json
from decimal import Decimal
from contextlib import asynccontextmanager

import pytest
from agents import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from mcp import types
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from agentchat.channels import Slack

from app import Settings, build_listener
from auth import AccessDenied, Principal
from connections import Connection
from core import Journal, SecretBoundary, ToolBridge, ToolOutcomeUnknown, SlackThreads


def event(event_id="Ev1", user="Uadmin", team="Tberri", channel_type="im"):
    return {"event_id": event_id, "team_id": team, "event": {
        "type": "message", "user": user, "channel": "Dprivate", "channel_type": channel_type,
        "text": "Create a key for team engineering with a $20 budget", "ts": "1.1",
    }}


def tool(name="create_key"):
    return types.Tool(name=name, description="Create a virtual key for an existing team", inputSchema={
        "type": "object", "properties": {"team_id": {"type": "string"}, "max_budget": {"type": "number"}},
        "required": ["team_id", "max_budget"], "additionalProperties": False,
    })


def response(data):
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(data))])


class FakeMCP:
    def __init__(self): self.calls = []
    async def list_tools(self, params=None):
        return types.ListToolsResult(tools=[tool()])
    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return response({"key": "sk-created0123456789", "team_id": "engineering", "max_budget": 20})


class FakeSlack:
    def __init__(self):
        self.posts = []; self.updates = []; self.reactions = []; self.messages = []
        self.current_event = {}
    async def reactions_add(self, **kwargs): self.reactions.append(kwargs)
    async def chat_postMessage(self, **kwargs):
        self.posts.append(kwargs)
        ts = str(Decimal(self.current_event.get("ts", "1")) + Decimal(len(self.posts)) / 1000000)
        self.messages.append({**kwargs, "ts": ts, "user": "BOT"})
        return {"ts": ts}
    async def chat_update(self, **kwargs):
        self.updates.append(kwargs)
        for message in self.messages:
            if message["ts"] == kwargs["ts"]: message["text"] = kwargs["text"]
    async def conversations_replies(self, *, channel, ts, latest, **kwargs):
        return {"ok": True, "messages": sorted([
            m for m in self.messages if m.get("channel") == channel
            and (m["ts"] == ts or m.get("thread_ts") == ts)
            and Decimal(m["ts"]) < Decimal(latest)
        ], key=lambda m: Decimal(m["ts"])), "has_more": False}


class ScriptedModel(Model):
    """Exercise the real Agents SDK loop with deterministic model responses."""
    def __init__(self): self.inputs = []; self.index = 0
    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **kwargs):
        if output_schema is not None:
            return ModelResponse(output=[ResponseOutputMessage(type="message", id="route", role="assistant",
                status="completed", content=[ResponseOutputText(type="output_text", text='{"reply":true}', annotations=[])])],
                usage=Usage(), response_id="route")
        self.inputs.append(copy.deepcopy(input)); self.index += 1
        if self.index == 1:
            output = [ResponseFunctionToolCall(type="function_call", id="fc1", call_id="c1", name="find_admin_tools", arguments=json.dumps({"query": "create key team"}))]
        elif self.index == 2:
            output = [ResponseFunctionToolCall(type="function_call", id="fc2", call_id="c2", name="call_admin_tool", arguments=json.dumps({"name": "create_key", "arguments": {"team_id": "engineering", "max_budget": 20}}))]
        else:
            output = [ResponseOutputMessage(type="message", id="msg1", role="assistant", status="completed", content=[ResponseOutputText(type="output_text", text="Created a key for Engineering with a $20 budget.", annotations=[])])]
        return ModelResponse(output=output, usage=Usage(), response_id=f"resp{self.index}")
    async def stream_response(self, *args, **kwargs):
        raise NotImplementedError
        yield


class FakeAuthorizer:
    async def require_slack_admin(self, user, client, bearer):
        if user != "Uadmin":
            raise AccessDenied()
        return Principal("admin@example.com", "admin@example.com", "slack", user)


class FakeConnections:
    def get(self, user):
        return Connection("admin@example.com", "connection-1", "caller-key")


def settings():
    return Settings("Tberri", "",
                    frozenset({"create_key"}), "https://example.com/v1", "test", "unused", "unused", ":memory:")


def channel(client, journal, model=None, connect=None, **kwargs):
    class RecordingSlack(Slack):
        async def handle_event(self, payload):
            client.current_event = payload["event"]
            if not any(m["ts"] == payload["event"]["ts"] for m in client.messages):
                client.messages.append(dict(payload["event"]))
            await super().handle_event(payload)
    transport = RecordingSlack(bot_token="test", app_token="test", web_client=client,
                      workspace_id="Tberri", bot_user_id="BOT", thread_subscriptions=SlackThreads(journal))
    options = {"model": model, **kwargs}
    if connect is not None:
        options["connect"] = connect
    transport.bind(build_listener(settings(), journal, client, **options))
    return transport


@pytest.mark.asyncio
async def test_real_runner_discovers_calls_and_delivers_key_only_in_private_reply():
    mcp = FakeMCP(); slack = FakeSlack(); model = ScriptedModel(); journal = Journal(":memory:")
    @asynccontextmanager
    async def connect(_, credential): yield mcp
    handler = channel(slack, journal, model, connect, authorizer=FakeAuthorizer(), connections=FakeConnections())
    await handler.handle_event(event())
    assert len(mcp.calls) == 1
    assert "sk-created0123456789" not in json.dumps(model.inputs)
    assert len(slack.posts) == 2
    assert "sk-created0123456789" in slack.posts[1]["text"]
    assert slack.posts[0]["channel"] == "Dprivate" and slack.posts[0]["thread_ts"] is None
    assert slack.posts[1]["channel"] == "Uadmin" and "thread_ts" not in slack.posts[1]
    assert slack.posts[0]["text"] == "Working on your request…"
    assert slack.updates[0]["text"] == "Created a key for Engineering with a $20 budget."
    assert journal.db.execute("SELECT status FROM events").fetchone()[0] == "completed"
    await handler.handle_event(event())
    assert len(mcp.calls) == 1
    assert len(slack.posts) == 2


@pytest.mark.asyncio
async def test_main_dm_followup_keeps_context_and_thread_request_stays_in_thread():
    mcp = FakeMCP(); slack = FakeSlack(); model = ScriptedModel()
    @asynccontextmanager
    async def connect(_, credential): yield mcp
    handler = channel(slack, Journal(":memory:"), model, connect, authorizer=FakeAuthorizer(), connections=FakeConnections())
    await handler.handle_event(event())
    followup = event(event_id="Ev2")
    followup["event"].update(text="What budget did you set?", ts="2.2")
    await handler.handle_event(followup)
    assert any(x.get("role") == "assistant" for x in model.inputs[-1])
    threaded = event(event_id="Ev3")
    threaded["event"].update(thread_ts="original.1", ts="3.3")
    await handler.handle_event(threaded)
    assert slack.posts[-1]["thread_ts"] == "original.1"


@pytest.mark.asyncio
async def test_denied_event_never_connects_to_mcp_or_runs_model():
    @asynccontextmanager
    async def connect(_, credential):
        raise AssertionError("Unauthorized event reached MCP")
        yield
    slack = FakeSlack()
    await channel(slack, Journal(":memory:"), ScriptedModel(), connect, authorizer=FakeAuthorizer(), connections=FakeConnections()).handle_event(event(user="Uother"))
    assert len(slack.posts) == 1
    assert "active LiteLLM proxy-admin account" in slack.posts[0]["text"]


@pytest.mark.asyncio
async def test_invalid_or_disabled_tool_cannot_mutate():
    mcp = FakeMCP()
    bridge = ToolBridge([tool()], frozenset({"create_key"}), mcp.call_tool, Journal(":memory:"), "Ev1")
    assert "not enabled" in await bridge.call("delete_all_keys", {})
    assert "Invalid arguments" in await bridge.call("create_key", {"team_id": "engineering"})
    assert mcp.calls == []


@pytest.mark.asyncio
async def test_exact_duplicate_tool_invocation_only_executes_once():
    mcp = FakeMCP()
    bridge = ToolBridge([tool()], frozenset({"create_key"}), mcp.call_tool, Journal(":memory:"), "Ev1")
    args = {"team_id": "engineering", "max_budget": 20}
    first = await bridge.call("create_key", args)
    assert await bridge.call("create_key", args) == first
    assert len(mcp.calls) == 1


@pytest.mark.asyncio
async def test_verification_reads_refresh_gateway_state_without_replaying_writes():
    read = "get_team"
    write = "update_team"
    tools = [types.Tool(name=name, inputSchema={"type": "object"}) for name in (read, write)]
    state = {"max_budget": 10}
    calls = []

    async def invoke(name, arguments):
        calls.append(name)
        if name == write:
            state["max_budget"] = arguments["max_budget"]
        return response(dict(state))

    bridge = ToolBridge(tools, frozenset({read, write}), invoke, Journal(":memory:"), "Ev1")
    args = {"team_id": "engineering"}
    before = await bridge.call(read, args)
    changed = await bridge.call(write, {**args, "max_budget": 20})
    after = await bridge.call(read, args)
    assert json.loads(json.loads(before)["content"][0]["text"])["max_budget"] == 10
    assert json.loads(json.loads(after)["content"][0]["text"])["max_budget"] == 20
    assert await bridge.call(write, {**args, "max_budget": 20}) == changed
    assert calls == [read, write, read]


@pytest.mark.asyncio
async def test_uncertain_mutation_stops_run_without_automatic_retry():
    calls = []
    async def invoke(**kwargs):
        calls.append(kwargs)
        raise TimeoutError("might have committed upstream")
    bridge = ToolBridge([tool()], frozenset({"create_key"}), invoke, Journal(":memory:"), "Ev1")
    with pytest.raises(ToolOutcomeUnknown):
        await bridge.call("create_key", {"team_id": "engineering", "max_budget": 20})
    with pytest.raises(ToolOutcomeUnknown):
        await bridge.call("create_key", {"team_id": "engineering", "max_budget": 30})
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_failed_read_allows_alternative_lookup_without_replaying_failure():
    first = "get_spend_report"
    second = "list_keys"
    tools = [types.Tool(name=n, inputSchema={"type": "object", "properties": {}}) for n in (first, second)]
    calls = []
    async def invoke(name, arguments):
        calls.append(name)
        if name == first: raise TimeoutError("upstream report timed out")
        return response({"keys": [{"key_alias": "sample", "spend": 12.5}]})
    journal = Journal(":memory:")
    bridge = ToolBridge(tools, frozenset({first, second}), invoke, journal, "Ev1")
    failure = await bridge.call(first, {})
    assert json.loads(failure)["changes_made"] is False
    assert await bridge.call(first, {}) == failure
    assert "12.5" in await bridge.call(second, {})
    assert calls == [first, second]
    assert not bridge.mutation_attempted
    assert not bridge.unknown
    assert "read_failed" in [r[0] for r in journal.db.execute("SELECT status FROM actions")]


@pytest.mark.asyncio
async def test_connection_failure_does_not_claim_a_mutation_may_have_completed():
    @asynccontextmanager
    async def connect(_, credential):
        raise ConnectionError("gateway unavailable")
        yield
    slack = FakeSlack()
    await channel(slack, Journal(":memory:"), ScriptedModel(), connect, authorizer=FakeAuthorizer(), connections=FakeConnections()).handle_event(event())
    assert "No requested operation was run" in slack.updates[0]["text"]
    assert "may already have completed" not in slack.updates[0]["text"]


def test_replay_protection_survives_restart(tmp_path):
    filename = str(tmp_path / "journal.db")
    first = Journal(filename)
    assert first.claim("Ev1", "Uadmin")
    first.db.close()
    assert not Journal(filename).claim("Ev1", "Uadmin")


def test_nested_credentials_do_not_reach_model_or_key_delivery():
    boundary = SecretBoundary()
    cleaned = boundary.clean({"content": [{"text": json.dumps({"access_token": "very-private", "credential_values": {"api_key": "sk-provider123456"}, "key": "sk-created0123456789"})}]})
    serialized = json.dumps(cleaned)
    assert "very-private" not in serialized
    assert "sk-provider123456" not in serialized
    assert "sk-created0123456789" not in serialized
    assert list(boundary.keys.values()) == ["sk-created0123456789"]


def test_hashed_key_identifiers_survive_redaction_but_credentials_do_not():
    digest = "d" * 64
    boundary = SecretBoundary()
    assert boundary.clean({"token": digest, "key_alias": "sample"}) == {"key_hash": digest, "key_alias": "sample"}
    assert boundary.clean({"token": "sk-secret0123456789"}) == {"token": "[redacted]"}
    assert boundary.clean({"access_token": digest}) == {"access_token": "[redacted]"}



def test_default_discovery_uses_only_recognized_available_tools():
    tools = [tool(), tool("unknown_remote_tool")]
    bridge = ToolBridge(tools, frozenset(), FakeMCP().call_tool, Journal(":memory:"), "ev")
    assert set(bridge.tools) == {"create_key"}
    with pytest.raises(ValueError):
        ToolBridge(tools, frozenset({"list_models"}), FakeMCP().call_tool, Journal(":memory:"), "ev")
    with pytest.raises(ValueError):
        ToolBridge(tools, frozenset({"unknown_remote_tool"}), FakeMCP().call_tool, Journal(":memory:"), "ev")


def test_read_only_allowlist_accepts_writes_hidden_by_connector_without_broadening_reads():
    bridge = ToolBridge([tool("list_keys"), tool("list_teams")], frozenset({"list_keys", "create_key"}),
                        FakeMCP().call_tool, Journal(":memory:"), "ev", read_only=True)
    assert set(bridge.tools) == {"list_keys"}
    with pytest.raises(ValueError):
        ToolBridge([tool("list_keys")], frozenset({"list_teams", "create_key"}),
                   FakeMCP().call_tool, Journal(":memory:"), "ev", read_only=True)

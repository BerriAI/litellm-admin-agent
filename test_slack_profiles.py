"""Resolve mentions through AgentChat before making an admin operation."""
import copy
import json
from contextlib import asynccontextmanager
from dataclasses import replace

import pytest
from agentchat.channels import Slack
from agents import ModelResponse
from agents.tool_context import ToolContext
from agents.usage import Usage
from mcp import types
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from app import build_listener
from auth import AccessDenied
from core import Journal
from slack_tools import slack_user_tool
from test_agent import FakeAuthorizer, FakeConnections, FakeSlack, ScriptedModel, event, response, settings


async def lookup(tool):
    arguments = '{"user_id":"U012ABCDEF"}'
    context = ToolContext(None, tool_name=tool.name, tool_call_id="lookup", tool_arguments=arguments)
    return await tool.on_invoke_tool(context, arguments)


class ProfileSlack(FakeSlack):
    def __init__(self, **fields):
        super().__init__()
        self.lookups = []
        self.fields = fields

    async def users_info(self, *, user):
        self.lookups.append(user)
        return {"ok": True, "user": {"id": user, "team_id": "Tberri",
            "profile": {"display_name": "Teammate", "email": "target@example.com"},
            "deleted": False, "is_bot": False, **self.fields}}


@pytest.mark.asyncio
@pytest.mark.parametrize("fields,expected", [
    ({}, {"slack_user_id": "U012ABCDEF", "display_name": "Teammate", "email": "target@example.com"}),
    ({"profile": {}}, {"error": "profile_email_unavailable"}),
    ({"deleted": True}, {"error": "not_an_active_workspace_member"}),
    ({"is_bot": True}, {"error": "not_an_active_workspace_member"}),
    ({"team_id": "Tother"}, {"error": "not_an_active_workspace_member"}),
])
async def test_lookup_limits_profile_data_to_active_workspace_members(fields, expected):
    client = ProfileSlack(**fields)
    checks = []
    async def verify(): checks.append(True)
    channel = Slack(bot_token="test", app_token="test", web_client=client)
    tool = slack_user_tool(channel, "Tberri", verify)
    result = await lookup(tool)
    assert json.loads(result) == expected
    assert checks == [True, True] and client.lookups == ["U012ABCDEF"]


@pytest.mark.asyncio
async def test_revocation_stops_lookup_and_profile_failures_do_not_expose_upstream_bodies(caplog):
    class Unavailable(ProfileSlack):
        async def users_info(self, *, user):
            self.lookups.append(user)
            raise RuntimeError("private-upstream-body")
    client = Unavailable()
    channel = Slack(bot_token="test", app_token="test", web_client=client)
    async def deny(): raise AccessDenied()
    async def allow(): pass
    with pytest.raises(AccessDenied):
        await lookup(slack_user_tool(channel, "Tberri", deny))
    assert client.lookups == []
    result = await lookup(slack_user_tool(channel, "Tberri", allow))
    assert json.loads(result) == {"error": "profile_unavailable"}
    assert "private-upstream-body" not in result + caplog.text


@pytest.mark.asyncio
async def test_revocation_during_lookup_prevents_returning_profile():
    client = ProfileSlack()
    channel = Slack(bot_token="test", app_token="test", web_client=client)

    async def verify():
        if client.lookups:
            raise AccessDenied()

    with pytest.raises(AccessDenied):
        await lookup(slack_user_tool(channel, "Tberri", verify))
    assert client.lookups == ["U012ABCDEF"]


@pytest.mark.asyncio
@pytest.mark.parametrize("channel_type", ["im", "channel"])
async def test_mention_resolves_email_then_gateway_id_before_creating_key(channel_type):
    class MCP:
        def __init__(self): self.calls = []
        async def list_tools(self, params=None):
            return types.ListToolsResult(tools=[
                types.Tool(name="list_users", description="Find gateway users by email", inputSchema={
                    "type": "object", "properties": {"query": {"type": "object"}}, "required": ["query"]}),
                types.Tool(name="create_key", description="Create a user's key", inputSchema={
                    "type": "object", "properties": {"body": {"type": "object"}}, "required": ["body"]}),
            ])
        async def call_tool(self, name, arguments):
            self.calls.append((name, arguments))
            if name == "list_users":
                assert arguments == {"query": {"user_email": "target@example.com"}}
                return response({"users": [{"user_id": "gateway-target-id", "user_email": "target@example.com"}]})
            assert arguments == {"body": {"user_id": "gateway-target-id", "send_invite_email": False}}
            return response({"key": "sk-profile-created12345678", "user_id": "gateway-target-id"})

    class ResolveModel(ScriptedModel):
        async def get_response(self, system_instructions, input, tools, **kwargs):
            self.inputs.append(copy.deepcopy(input))
            assert "get_slack_user" in [t.name for t in tools]
            if self.index == 0:
                name, arguments = "get_slack_user", {"user_id": "U012ABCDEF"}
            elif self.index == 1:
                profile = json.loads(input[-1]["output"])
                name, arguments = "call_admin_tool", {"name": "list_users", "arguments": {
                    "query": {"user_email": profile["email"]}}}
            elif self.index == 2:
                result = json.loads(json.loads(input[-1]["output"])["content"][0]["text"])
                name, arguments = "call_admin_tool", {"name": "create_key", "arguments": {
                    "body": {"user_id": result["users"][0]["user_id"], "send_invite_email": False}}}
            else:
                return ModelResponse(output=[ResponseOutputMessage(type="message", id="done", role="assistant",
                    status="completed", content=[ResponseOutputText(type="output_text",
                    text="Created a key for <@U012ABCDEF>.", annotations=[])])], usage=Usage(), response_id="done")
            self.index += 1
            return ModelResponse(output=[ResponseFunctionToolCall(type="function_call", id=f"fc{self.index}",
                call_id=f"c{self.index}", name=name, arguments=json.dumps(arguments))],
                usage=Usage(), response_id=f"r{self.index}")

    mcp, client, model, journal = MCP(), ProfileSlack(), ResolveModel(), Journal(":memory:")
    @asynccontextmanager
    async def connect(config, credential):
        assert credential == "caller-key"
        yield mcp
    config = replace(settings(), tool_names=frozenset({"list_users", "create_key"}))
    channel = Slack(bot_token="test", app_token="test", web_client=client,
                    workspace_id=config.workspace, bot_user_id="BOT")
    channel.bind(build_listener(config, journal, client, model, connect,
                               authorizer=FakeAuthorizer(), connections=FakeConnections()))
    message = event(channel_type=channel_type)
    message["event"]["text"] = "<@BOT> make a key for <@U012ABCDEF>"
    if channel_type == "channel":
        message["event"].update(type="app_mention", channel="Cchannel")
    await channel.handle_event(message)
    assert client.lookups == ["U012ABCDEF"]
    assert [name for name, _ in mcp.calls] == ["list_users", "create_key"]
    assert "sk-profile-created" not in json.dumps(model.inputs + client.updates)
    private = [post for post in client.posts if "sk-profile-created" in post["text"]]
    assert len(private) == 1 and private[0]["channel"] == "Uadmin"
    assert journal.db.execute("SELECT status FROM events").fetchone()[0] == "completed"

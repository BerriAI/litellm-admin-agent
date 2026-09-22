from contextlib import asynccontextmanager
from dataclasses import replace

import pytest

import agent
from auth import Principal
from core import Journal
from engine import AgentRunner
from test_agent import FakeMCP, ScriptedModel, settings


@pytest.mark.asyncio
async def test_both_model_and_mcp_receive_each_callers_credential():
    sent = []
    @asynccontextmanager
    async def mcp(config, credential):
        sent.append(("mcp", credential))
        yield FakeMCP()
    @asynccontextmanager
    async def model(config, credential):
        sent.append(("model", credential))
        yield ScriptedModel()
    async def verify(): pass
    runner = AgentRunner(settings(), Journal(":memory:"), connect=mcp, make_model=model)
    for user in ("alice", "bob"):
        result = await runner.execute("Read my budget", Principal(user, "", "gateway", user), "chat", user,
                                      verify, user + "-personal-key")
        assert result.status == "completed"
    assert sent == [("mcp", "alice-personal-key"), ("model", "alice-personal-key"),
                    ("mcp", "bob-personal-key"), ("model", "bob-personal-key")]


@pytest.mark.asyncio
async def test_mcp_sets_same_user_for_gateway_and_backend_without_redirects(monkeypatch):
    captured = []
    @asynccontextmanager
    async def transport(url, http_client):
        captured.append((url, dict(http_client.headers), http_client.follow_redirects))
        yield object(), object()
    class Session:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def initialize(self): pass
    monkeypatch.setattr(agent, "streamable_http_client", transport)
    monkeypatch.setattr(agent, "ClientSession", Session)
    for key in ("alice-key", "bob-key"):
        async with agent.mcp_session(settings(), key): pass
    for (_, headers, redirects), key in zip(captured, ("alice-key", "bob-key")):
        assert headers["x-litellm-api-key"] == "Bearer " + key
        assert headers["x-mcp-personal_admin-authorization"] == "Bearer " + key
        assert redirects is False


@pytest.mark.asyncio
async def test_model_uses_caller_key_and_disables_automatic_retries():
    async with agent.model_session(settings(), "personal-key") as model:
        assert model._client.api_key == "personal-key"
        assert model._client.max_retries == 0


@pytest.mark.asyncio
async def test_no_credential_never_falls_back_to_global_environment(monkeypatch):
    for variable in ("LITELLM_ADMIN_KEY", "LITELLM_MCP_KEY", "LITELLM_MODEL_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(variable, "shared-secret-must-not-be-used")
    for factory in (agent.mcp_session, agent.model_session):
        with pytest.raises(ValueError):
            async with factory(settings(), ""): pass
    assert "shared-secret" not in repr(agent.Settings.read())


@pytest.mark.asyncio
async def test_slack_disconnect_during_run_stops_tools_and_delivery():
    from app import build_listener
    from connections import ConnectionRequired
    from test_agent import FakeAuthorizer, FakeConnections, FakeSlack, event
    class Connections(FakeConnections):
        revoked = False
        def get(self, user):
            if self.revoked: raise ConnectionRequired()
            return super().get(user)
        async def link(self, user): return "https://example.com/new-private-link"
    connections = Connections(); slack = FakeSlack(); mcp = FakeMCP()
    @asynccontextmanager
    async def connect(config, credential):
        yield mcp
    model = ScriptedModel()
    original = model.get_response
    async def revoke(*args, **kwargs):
        result = await original(*args, **kwargs)
        if model.index == 2: connections.revoked = True
        return result
    model.get_response = revoke
    handler = build_listener(settings(), Journal(":memory:"), model, connect,
                             authorizer=FakeAuthorizer(), connections=connections)
    await handler(event(), slack)
    assert not mcp.calls
    assert not any("sk-created" in str(message) for message in slack.posts + slack.updates)
    assert "run stopped" in slack.updates[-1]["text"]

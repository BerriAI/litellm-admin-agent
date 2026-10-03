from contextlib import asynccontextmanager
from dataclasses import replace

import pytest
import httpx2
from openai import APIStatusError

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
    assert set(sent) == {("mcp", "alice-personal-key"), ("model", "alice-personal-key"),
                         ("mcp", "bob-personal-key"), ("model", "bob-personal-key")}


@pytest.mark.asyncio
async def test_hosted_mcp_uses_personal_bearer_without_redirects(monkeypatch):
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
        async with agent.mcp_session(replace(settings(), mcp_url="https://mcp.example.com/mcp"), key): pass
    for (_, headers, redirects), key in zip(captured, ("alice-key", "bob-key")):
        assert headers["authorization"] == "Bearer " + key
        assert not any(k.startswith("x-mcp-") for k in headers)
        assert redirects is False


@pytest.mark.asyncio
async def test_model_uses_caller_key_and_disables_automatic_retries():
    async with agent.model_session(settings(), "personal-key") as model:
        assert model._client.api_key == "personal-key"
        assert model._client.max_retries == 0


@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.asyncio
async def test_model_never_forwards_conversation_to_a_redirect_target(monkeypatch, status):
    requests = []

    def handle(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx2.Response(status, headers={"Location": "https://other.example.com/collect"})
        return httpx2.Response(200, json={"id": "test", "object": "chat.completion", "created": 1,
            "model": "test", "choices": [{"index": 0, "finish_reason": "stop",
                                          "message": {"role": "assistant", "content": "unexpected"}}]})

    original_init = httpx2.AsyncClient.__init__

    def mock_transport(self, **kwargs):
        original_init(self, **{**kwargs, "transport": httpx2.MockTransport(handle)})

    monkeypatch.setattr(httpx2.AsyncClient, "__init__", mock_transport)
    async with agent.model_session(settings(), "personal-key") as model:
        with pytest.raises(APIStatusError) as failure:
            await model._client.chat.completions.create(model="test", messages=[
                {"role": "user", "content": "Private gateway administration request"}])
    assert failure.value.status_code == status
    assert len(requests) == 1
    assert str(requests[0].url).startswith(settings().model_url)


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
    from connections import ConnectionRequired
    from test_agent import FakeAuthorizer, FakeConnections, FakeSlack, channel, event
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
    handler = channel(slack, Journal(":memory:"), model, connect,
                             authorizer=FakeAuthorizer(), connections=connections)
    await handler.handle_event(event())
    assert not mcp.calls
    assert not any("sk-created" in str(message) for message in slack.posts + slack.updates)
    assert "run stopped" in slack.updates[-1]["text"]


@pytest.mark.asyncio
async def test_local_mcp_gets_isolated_request_credentials_and_policy(monkeypatch):
    captured = []
    @asynccontextmanager
    async def transport(params):
        captured.append(params)
        yield object(), object()
    class Session:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def initialize(self): pass
    monkeypatch.setattr(agent, "stdio_client", transport)
    monkeypatch.setattr(agent, "ClientSession", Session)
    for name in ("SLACK_BOT_TOKEN", "CREDENTIAL_ENCRYPTION_KEY", "ADMIN_AGENT_SERVICE_TOKEN", "LITELLM_API_KEY"):
        monkeypatch.setenv(name, "shared-secret-must-not-be-forwarded")
    config = replace(settings(), read_only=True, tool_names=frozenset({"list_keys"}))
    for key in ("alice-key", "bob-key"):
        async with agent.mcp_session(config, key): pass
    for params, key in zip(captured, ("alice-key", "bob-key")):
        assert params.args == ["-m", "litellm_admin_mcp"]
        assert params.env == {"LITELLM_BASE_URL": config.gateway_url, "LITELLM_API_KEY": key,
                              "LITELLM_ADMIN_READ_ONLY": "true", "LITELLM_ADMIN_TOOLS": "list_keys"}


def test_legacy_mcp_url_requires_explicit_migration(monkeypatch):
    monkeypatch.setenv("LITELLM_MCP_URL", "https://gateway.example.com/personal_admin/mcp")
    with pytest.raises(ValueError, match="legacy"):
        agent.Settings.read()


@pytest.mark.asyncio
async def test_real_connector_returns_key_only_to_private_delivery():
    import copy
    import json
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from agents import ModelResponse
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
    writes = []
    returned_key = "sk-real-connector-created123456"
    body = {"key_alias": "engineering", "max_budget": 20}
    async def gateway(request):
        assert request.headers["Authorization"] == "Bearer personal-admin"
        if request.path == "/user/info":
            return web.json_response({"user_id": "alice", "user_info": {"user_id": "alice", "user_role": "proxy_admin"}})
        if request.path == "/openapi.json":
            return web.json_response({"paths": {"/key/generate": {"post": {
                "operationId": "generate_key_fn_key_generate_post", "requestBody": {"required": True,
                    "content": {"application/json": {"schema": {"type": "object", "required": ["key_alias"],
                        "properties": {"key_alias": {"type": "string"}, "max_budget": {"type": "number"}}}}}}
            }}}})
        assert request.path == "/key/generate" and request.method == "POST"
        assert request.headers["litellm-changed-by"] == "alice"
        writes.append(await request.json())
        return web.json_response({**body, "key": returned_key})
    class CreateKey(ScriptedModel):
        async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **kwargs):
            self.inputs.append(copy.deepcopy(input)); self.index += 1
            if self.index == 1:
                output = [ResponseFunctionToolCall(type="function_call", id="fc1", call_id="c1", name="call_admin_tool",
                    arguments=json.dumps({"name": "create_key", "arguments": {"body": body}}))]
            else:
                output = [ResponseOutputMessage(type="message", id="done", role="assistant", status="completed", content=[
                    ResponseOutputText(type="output_text", text="Created Engineering's key.", annotations=[])])]
            return ModelResponse(output=output, usage=Usage(), response_id=f"r{self.index}")
    app = web.Application(); app.router.add_route("*", "/{path:.*}", gateway)
    async with TestServer(app) as upstream:
        config = replace(settings(), model_url=str(upstream.make_url("/v1")), tool_names=frozenset())
        model = CreateKey()
        async def verify(): pass
        result = await AgentRunner(config, Journal(":memory:"), model).execute(
            "Create an Engineering key with a $20 budget", Principal("alice", "", "gateway", "alice"),
            "chat", "create-key", verify, "personal-admin")
    assert result.status == "completed" and writes == [body]
    assert list(result.secrets.values()) == [returned_key]
    assert returned_key not in json.dumps(model.inputs) and returned_key not in result.answer


@pytest.mark.asyncio
async def test_queued_run_prepares_fresh_credential_before_model_and_tools():
    import asyncio
    import time
    sent = []
    @asynccontextmanager
    async def connector(config, credential):
        sent.append(credential)
        yield FakeMCP()
    @asynccontextmanager
    async def model(config, credential):
        sent.append(credential)
        yield ScriptedModel()
    async def verify(): pass
    async def prepare():
        sent.append("prepared")
        return "renewed", time.time() + 300
    runner = AgentRunner(settings(), Journal(":memory:"), connect=connector, make_model=model)
    await runner.lock.acquire()
    pending = asyncio.create_task(runner.execute("Read budget", Principal("alice", "", "gateway", "alice"),
        "thread", "event", verify, "expired-while-queued", prepare=prepare))
    await asyncio.sleep(0)
    assert sent == []
    runner.lock.release()
    assert (await pending).status == "completed"
    assert sent == ["prepared", "renewed", "renewed"]

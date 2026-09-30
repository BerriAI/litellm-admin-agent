import asyncio
import re
from contextlib import asynccontextmanager
from dataclasses import replace

import httpx2
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.fernet import Fernet
from dotenv import dotenv_values
from mcp import types

from agent import Settings
from auth import Principal
from connections import COOKIE, ConnectionRequired, Connections
from core import Journal, ToolBridge, ToolOutcomeUnknown
from engine import AgentBusy, AgentRunner
from setup_env import initialize
from test_agent import FakeMCP, ScriptedModel, response, settings, tool
from test_connections import Authorizer, SSO, store
from web import create_web_app


def valid_settings(tmp_path):
    return replace(settings(), public_url="https://admin.example.com", db_path=str(tmp_path / "events.sqlite3"),
                   encryption_key=Fernet.generate_key().decode(), service_token="s" * 48)


def test_generated_secrets_are_private_unique_and_never_overwritten(tmp_path):
    first, second = tmp_path / ".env", tmp_path / "other.env"
    initialize(first); initialize(second)
    one, two = dotenv_values(first), dotenv_values(second)
    assert first.stat().st_mode & 0o777 == 0o600
    assert one["CREDENTIAL_ENCRYPTION_KEY"] != two["CREDENTIAL_ENCRYPTION_KEY"]
    Fernet(one["CREDENTIAL_ENCRYPTION_KEY"].encode())
    assert len(one["ADMIN_AGENT_SERVICE_TOKEN"]) >= 32
    assert one["ADMIN_READ_ONLY"] == "false"
    assert one["CONNECTION_AUTH_MODE"] == "api_key"
    previous = first.read_bytes()
    with pytest.raises(FileExistsError): initialize(first)
    assert first.read_bytes() == previous


@pytest.mark.parametrize("overrides", [
    {"public_url": "https://admin.example.com/subpath"},
    {"model_url": "http://gateway.example.com/v1"},
    {"model_url": "https://user:secret@gateway.example.com/v1"},
    {"mcp_url": "http://other.example.com/mcp"},
    {"encryption_key": "not-a-fernet-key"}, {"service_token": "short"},
    {"connection_auth_mode": "automatic"}, {"db_path": ":memory:"},
    {"max_pending_requests": 0}, {"run_timeout_seconds": float("nan")},
    {"queue_timeout_seconds": float("inf")},
])
def test_invalid_deployments_fail_before_network_or_serving(tmp_path, overrides):
    with pytest.raises(ValueError): replace(valid_settings(tmp_path), **overrides).validate()


def test_headless_mode_does_not_require_slack_tokens(tmp_path):
    replace(valid_settings(tmp_path), slack_enabled=False, workspace="", bot_token="", app_token="").validate()


def test_invalid_boolean_does_not_silently_disable_a_guard(monkeypatch):
    monkeypatch.setenv("ADMIN_READ_ONLY", "treu")
    with pytest.raises(ValueError, match="ADMIN_READ_ONLY"): Settings.read()


@pytest.mark.parametrize("mode,expected_writes", [(None, 1), ("false", 1), ("true", 0)])
@pytest.mark.asyncio
async def test_runtime_default_allows_admin_actions_and_read_only_is_opt_in(monkeypatch, mode, expected_writes):
    if mode is None:
        monkeypatch.delenv("ADMIN_READ_ONLY", raising=False)
    else:
        monkeypatch.setenv("ADMIN_READ_ONLY", mode)
    config = replace(settings(), read_only=Settings.read().read_only)
    mcp = FakeMCP()
    @asynccontextmanager
    async def connect(config, credential): yield mcp
    async def verify(): pass
    runner = AgentRunner(config, Journal(":memory:"), ScriptedModel(), connect)
    outcome = await runner.execute("Create a key for Engineering", Principal("admin", "", "gateway", "admin"),
                                   "chat", "event", verify, "personal-admin-key")
    assert len(mcp.calls) == expected_writes
    assert bool(outcome.secrets) == bool(expected_writes)


@pytest.mark.parametrize("names", [("list_keys", "create_key"), ("list_models", "add_model")])
@pytest.mark.asyncio
async def test_read_only_blocks_writes_in_agent_bridge(names):
    calls = []
    async def invoke(**kwargs):
        calls.append(kwargs); return response({"keys": []})
    bridge = ToolBridge([types.Tool(name=n, inputSchema={"type": "object"}) for n in names],
                        frozenset(names), invoke, Journal(":memory:"), "event", read_only=True)
    assert names[1] not in {t["name"] for t in bridge.search("create key")}
    assert "not enabled" in await bridge.call(names[1], {})
    assert not calls
    await bridge.call(names[0], {})
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_mcp_error_result_stops_uncertain_writes_even_when_transport_succeeds():
    calls = []
    async def invoke(**kwargs):
        calls.append(kwargs)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text="HTTP 504")])
    bridge = ToolBridge([tool()], frozenset({"create_key"}), invoke, Journal(":memory:"), "event")
    for budget in (20, 30):
        with pytest.raises(ToolOutcomeUnknown):
            await bridge.call("create_key", {"team_id": "engineering", "max_budget": budget})
    assert len(calls) == 1


@asynccontextmanager
async def key_service():
    config = replace(settings(), public_url="https://admin.example.com", connection_auth_mode="api_key")
    auth = Authorizer()
    connections = Connections(config, store(), auth, object(), SSO())
    app = web.Application(client_max_size=32000); connections.add_routes(app)
    async with TestClient(TestServer(app)) as client:
        path = (await connections.link("Ualice")).removeprefix(config.public_url)
        shown = await client.get(path)
        body = await shown.text()
        assert 'type="password"' in body and "Never paste a key into Slack" in body
        csrf = re.search('name="csrf" value="([^"]+)"', body).group(1)
        data = {"action": "connect_key", "csrf": csrf, "credential": "personal-private-key"}
        headers = {"Origin": config.public_url, "Cookie": f"{COOKIE}={shown.cookies[COOKIE].value}"}
        yield client, connections, auth, path, data, headers


@pytest.mark.asyncio
async def test_personal_key_connection_encrypts_expires_and_cannot_be_replayed():
    async with key_service() as (client, connections, auth, path, data, headers):
        result = await client.post(path, data=data, headers=headers)
        assert result.status == 200
        assert data["credential"] not in await result.text()
        connection = connections.get("Ualice")
        assert connection.credential == data["credential"] and connection.expires_at is not None
        assert data["credential"].encode() not in connections.store.db.execute("SELECT encrypted FROM connections").fetchone()[0]
        assert (await client.post(path, data=data, headers=headers)).status == 410
        assert (await client.get("/oauth/callback")).status == 404
        assert connections.sso.starts == 0


@pytest.mark.parametrize("invalid", ["origin", "cookie", "csrf", "identity", "action", "credential"])
@pytest.mark.asyncio
async def test_personal_key_connection_rejects_invalid_browser_or_identity(invalid):
    async with key_service() as (client, connections, auth, path, data, headers):
        if invalid == "origin": headers["Origin"] = "https://evil.example"
        if invalid == "cookie": headers.pop("Cookie")
        if invalid == "csrf": data["csrf"] = "wrong"
        if invalid == "identity": auth.denied = True
        if invalid == "action": data["action"] = "start"
        if invalid == "credential": data["credential"] = ""
        assert (await client.post(path, data=data, headers=headers)).status in (403, 410)
        with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.asyncio
async def test_disconnect_during_personal_key_verification_cannot_recreate_connection():
    async with key_service() as (client, connections, auth, path, data, headers):
        original = auth.require_slack_admin
        async def disconnect(*args):
            result = await original(*args)
            connections.disconnect("Ualice")
            return result
        auth.require_slack_admin = disconnect
        assert (await client.post(path, data=data, headers=headers)).status == 410
        with pytest.raises(ConnectionRequired): connections.get("Ualice")


async def verify(): pass
PRINCIPAL = Principal("alice", "", "gateway", "alice")


@pytest.mark.asyncio
async def test_overload_and_queue_timeout_start_no_second_run_and_release_slots():
    entered, release = asyncio.Event(), asyncio.Event()
    mcp = FakeMCP()
    @asynccontextmanager
    async def connect(config, credential):
        entered.set(); await release.wait(); yield mcp
    runner = AgentRunner(replace(settings(), max_pending_requests=1, queue_timeout_seconds=.01), Journal(":memory:"), ScriptedModel(), connect)
    first = asyncio.create_task(runner.execute("first", PRINCIPAL, "ctx", "one", verify, "key"))
    await entered.wait()
    with pytest.raises(AgentBusy): await runner.execute("second", PRINCIPAL, "ctx", "two", verify, "key")
    runner.settings = replace(runner.settings, max_pending_requests=2)
    with pytest.raises(AgentBusy): await runner.execute("third", PRINCIPAL, "ctx", "three", verify, "key")
    assert not mcp.calls and runner.pending == 1
    release.set(); assert (await first).status == "completed"
    assert runner.pending == 0 and len(mcp.calls) == 1


@pytest.mark.asyncio
async def test_run_timeout_records_uncertain_mutation_and_releases_lock():
    class SlowMCP(FakeMCP):
        async def call_tool(self, **kwargs):
            self.calls.append(kwargs); await asyncio.Event().wait()
    mcp = SlowMCP()
    @asynccontextmanager
    async def connect(config, credential): yield mcp
    journal = Journal(":memory:")
    runner = AgentRunner(replace(settings(), run_timeout_seconds=.05), journal, ScriptedModel(), connect)
    outcome = await runner.execute("create key", PRINCIPAL, "ctx", "event", verify, "key")
    assert outcome.status == "failed" and "may already have completed" in outcome.answer
    assert journal.db.execute("SELECT status FROM actions ORDER BY rowid DESC LIMIT 1").fetchone()[0] == "outcome_unknown"
    assert runner.pending == 0 and not runner.lock.locked()


@pytest.mark.asyncio
async def test_readiness_returns_503_on_shutdown_and_closed_database(tmp_path):
    async def not_ready(): return False
    config = valid_settings(tmp_path); journal = Journal(":memory:")
    app = create_web_app(config, object(), object(), journal, ready=not_ready)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get("/healthz")).status == 200
        assert (await client.get("/readyz")).status == 503
        journal.db.close()
        assert (await client.get("/readyz")).status == 503


@pytest.mark.parametrize("explicit_selection", [True, False])
@pytest.mark.asyncio
async def test_preflight_verifies_mcp_without_running_tools_or_inference(tmp_path, monkeypatch, explicit_selection):
    import doctor
    name = "list_keys"
    config = replace(valid_settings(tmp_path), slack_enabled=False, read_only=True, tool_names=frozenset({name}) if explicit_selection else frozenset())
    requests = []
    def handle(request):
        requests.append(request)
        if request.url.path == "/user/info":
            return httpx2.Response(200, json={"user_id": "admin", "user_info": {
                "user_id": "admin", "user_email": "admin@example.com", "user_role": "proxy_admin"}})
        if request.url.path == "/v1/models":
            return httpx2.Response(200, json={"data": [{"id": config.model}]})
        raise AssertionError("Unexpected upstream operation")
    client_type = httpx2.AsyncClient
    monkeypatch.setattr(doctor.httpx2, "AsyncClient", lambda **kwargs: client_type(transport=httpx2.MockTransport(handle), **kwargs))
    class Discovery:
        async def list_tools(self, **kwargs):
            return types.ListToolsResult(tools=[types.Tool(name=name, inputSchema={"type": "object"})])
    @asynccontextmanager
    async def discovery(settings, credential): yield Discovery()
    monkeypatch.setattr(doctor, "mcp_session", discovery)
    results = await doctor.check(config, offline=False, credential="personal-key")
    assert any("LiteLLM Admin MCP discovery" in item for item in results)
    assert requests and all(request.method == "GET" for request in requests)


@pytest.mark.asyncio
async def test_shutdown_cancels_active_run_without_releasing_its_lock_early():
    entered = asyncio.Event()
    @asynccontextmanager
    async def connect(config, credential):
        entered.set(); await asyncio.Event().wait(); yield FakeMCP()
    runner = AgentRunner(settings(), Journal(":memory:"), ScriptedModel(), connect)
    task = asyncio.create_task(runner.execute("read", PRINCIPAL, "ctx", "event", verify, "key"))
    await entered.wait()
    await runner.close(grace_seconds=.01)
    assert task.cancelled() and not runner.accepting and runner.pending == 0
    assert not runner.lock.locked()
    with pytest.raises(AgentBusy): await runner.execute("another", PRINCIPAL, "ctx", "next", verify, "key")


@pytest.mark.parametrize("startup_fails", [False, True])
@pytest.mark.asyncio
async def test_agentchat_service_readiness_and_shutdown(tmp_path, monkeypatch, startup_fails):
    import signal
    import app as service
    import web as web_service

    config = valid_settings(tmp_path)
    monkeypatch.setattr(service.Settings, "read", lambda: config)
    monkeypatch.setattr(service, "load_dotenv", lambda: None)
    monkeypatch.setattr("sys.argv", ["app.py", "--web"])
    callbacks, state = {}, {}
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "add_signal_handler", lambda sig, callback: callbacks.update({sig: callback}))

    def create_app(*args, ready, **kwargs):
        state["ready"] = ready
        return object()

    class Server:
        def __init__(self, *args, **kwargs): pass
        async def setup(self): assert not await state["ready"]()
        async def cleanup(self): state["cleaned_up"] = True

    class Site:
        def __init__(self, *args): pass
        async def start(self): pass

    class Transport:
        connected = False
        def __init__(self, **kwargs):
            self.closed = asyncio.Event()
        def bind(self, receiver): state["bound"] = receiver
        async def is_connected(self): return self.connected
        async def run(self):
            if startup_fails: raise RuntimeError("Socket startup failed")
            self.connected = True
            assert await state["ready"]()
            callbacks[signal.SIGTERM]()
            assert not await state["ready"]()
            await self.closed.wait()
        async def close(self):
            self.connected = False
            self.closed.set()
            state["closed"] = True

    monkeypatch.setattr(service, "Slack", Transport)
    monkeypatch.setattr(web_service, "create_web_app", create_app)
    monkeypatch.setattr(service.web, "AppRunner", Server)
    monkeypatch.setattr(service.web, "TCPSite", Site)
    if startup_fails:
        with pytest.raises(RuntimeError, match="Socket startup failed"):
            await service.main()
    else:
        await service.main()
    assert state["bound"] and state["closed"] and state["cleaned_up"]

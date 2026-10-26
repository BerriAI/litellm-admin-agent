import asyncio
import socket
import time
from contextlib import asynccontextmanager
from dataclasses import replace

import pytest
import uvicorn
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from mcp.server.mcpserver import Context, MCPServer

from litellm_admin_agent.agent import Settings, mcp_session
from litellm_admin_agent.auth import AccessDenied, Principal
from litellm_admin_agent.connections import ConnectionRequired, Connections
from litellm_admin_agent.native import NativeConnections
from test_agent import settings
from test_connections import store


@pytest.mark.parametrize("suffix", ["", "/", "/v1", "/v1/"])
def test_native_defaults_to_gateway_admin_mcp(monkeypatch, suffix):
    monkeypatch.setenv("CONNECTION_AUTH_MODE", "native")
    monkeypatch.setenv("LITELLM_BASE_URL", "https://gateway.example.com" + suffix)
    monkeypatch.delenv("ADMIN_MCP_URL", raising=False)
    assert Settings.read().mcp_url == "https://gateway.example.com/admin/mcp"


@pytest.mark.parametrize("mode", ["native", "api_key", "sso"])
def test_explicit_connector_is_preserved_in_every_login_mode(monkeypatch, mode):
    monkeypatch.setenv("CONNECTION_AUTH_MODE", mode)
    monkeypatch.setenv("ADMIN_MCP_URL", "https://connector.example.com/mcp")
    assert Settings.read().mcp_url == "https://connector.example.com/mcp"


@pytest.mark.parametrize("mode", ["api_key", "sso"])
def test_standalone_login_modes_keep_local_connector(monkeypatch, mode):
    monkeypatch.setenv("CONNECTION_AUTH_MODE", mode)
    monkeypatch.delenv("ADMIN_MCP_URL", raising=False)
    assert Settings.read().mcp_url == ""


@asynccontextmanager
async def hosted_mcp():
    mcp = MCPServer("native-transport-test")

    @mcp.tool()
    def caller(ctx: Context) -> str:
        return ctx.request_context.request.headers["Authorization"]

    app = mcp.streamable_http_app(streamable_http_path="/admin/mcp", stateless_http=True, json_response=True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
        task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(5):
                while not server.started:
                    if task.done():
                        await task
                    await asyncio.sleep(.01)
            yield f"http://127.0.0.1:{listener.getsockname()[1]}"
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, timeout=5)


@pytest.mark.asyncio
async def test_native_sessions_call_hosted_mcp_with_isolated_credentials(monkeypatch):
    monkeypatch.setenv("CONNECTION_AUTH_MODE", "native")
    monkeypatch.delenv("ADMIN_MCP_URL", raising=False)
    async with hosted_mcp() as gateway:
        monkeypatch.setenv("LITELLM_BASE_URL", gateway + "/v1")
        config = Settings.read()

        async def call_as(credential):
            async with mcp_session(config, credential) as session:
                result = await session.call_tool("caller", {})
                return result.content[0].text

        assert await asyncio.gather(call_as("alice-key"), call_as("bob-key")) == [
            "Bearer alice-key", "Bearer bob-key",
        ]


@pytest.mark.parametrize("status", [401, 403, 307, 308])
@pytest.mark.asyncio
async def test_native_connector_rejects_failed_auth_and_redirects(monkeypatch, status):
    requests = []

    async def reject(request):
        requests.append((request.path, request.headers.get("Authorization")))
        return web.Response(status=status, headers={"Location": "/collect"})

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", reject)
    async with TestServer(app) as gateway:
        monkeypatch.setenv("CONNECTION_AUTH_MODE", "native")
        monkeypatch.setenv("LITELLM_BASE_URL", str(gateway.make_url("/v1")))
        monkeypatch.delenv("ADMIN_MCP_URL", raising=False)
        with pytest.raises(ExceptionGroup):
            async with mcp_session(Settings.read(), "personal-key"):
                pytest.fail("An unsuccessful MCP connection must not initialize")
    assert requests == [("/admin/mcp", "Bearer personal-key")]


class Identity:
    allowed = True

    async def slack_email(self, user, client):
        if not self.allowed:
            raise AccessDenied()
        return "alice@example.com"

    async def require_slack_admin(self, user, client, bearer):
        if not self.allowed or bearer != "litellm_login_alice":
            raise AccessDenied()
        return Principal("alice", "alice@example.com", "slack", user)


async def connection_client():
    config = replace(settings(), connection_auth_mode="native", service_token="s" * 32)
    identity = Identity()
    base = Connections(config, store(), identity, object(), None)
    native = NativeConnections(base)
    app = web.Application()
    native.add_routes(app)
    client = TestClient(TestServer(app))
    await client.start_server()
    return client, native, identity


@pytest.mark.asyncio
async def test_native_link_handoff_is_private_single_use_and_disconnectable():
    client, native, _ = await connection_client()
    async with client:
        link = await native.link("Ualice")
        assert link.startswith(native.connections.settings.gateway_url + "/liteadmin/slack/connect/")
        path = "/internal/liteadmin/links/" + link.rsplit("/", 1)[1]
        headers = {"X-LiteLLM-Admin-Agent-Token": "s" * 32}
        assert (await client.get(path)).status == 401
        detail = await client.get(path, headers=headers)
        assert (await detail.json())["email"] == "alice@example.com"
        data = {"user_id": "alice", "credential": "litellm_login_alice", "expires_at": time.time() + 3600}
        assert (await client.post(path, headers=headers, json=data)).status == 200
        assert native.get("Ualice").credential == data["credential"]
        assert (await client.post(path, headers=headers, json=data)).status == 410
        native.disconnect("Ualice")
        with pytest.raises(ConnectionRequired):
            native.get("Ualice")


@pytest.mark.asyncio
@pytest.mark.parametrize("change,code", [
    ({"user_id": "bob"}, 403), ({"credential": "litellm_login_bob"}, 403),
    ({"credential": "sk-master"}, 400), ({"expires_at": 1}, 400),
    ({"expires_at": float("inf")}, 400), ({"expires_at": True}, 400),
    ({"expires_at": time.time() + 200000}, 400),
])
async def test_native_handoff_rejects_wrong_identity_and_invalid_sessions(change, code):
    client, native, _ = await connection_client()
    async with client:
        link = await native.link("Ualice")
        path = "/internal/liteadmin/links/" + link.rsplit("/", 1)[1]
        data = {"user_id": "alice", "credential": "litellm_login_alice", "expires_at": time.time() + 3600, **change}
        response = await client.post(path, headers={"X-LiteLLM-Admin-Agent-Token": "s" * 32}, json=data)
        assert response.status == code
        with pytest.raises(ConnectionRequired):
            native.get("Ualice")


@pytest.mark.asyncio
async def test_native_disconnect_invalidates_pending_login_and_rechecks_slack_membership():
    client, native, identity = await connection_client()
    async with client:
        link = await native.link("Ualice")
        path = "/internal/liteadmin/links/" + link.rsplit("/", 1)[1]
        headers = {"X-LiteLLM-Admin-Agent-Token": "s" * 32}
        identity.allowed = False
        assert (await client.get(path, headers=headers)).status == 403
        native.disconnect("Ualice")
        assert (await client.get(path, headers=headers)).status == 410

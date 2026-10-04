import time
from dataclasses import replace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from litellm_admin_agent.auth import AccessDenied, Principal
from litellm_admin_agent.connections import ConnectionRequired, Connections
from litellm_admin_agent.native import NativeConnections
from test_agent import settings
from test_connections import store


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

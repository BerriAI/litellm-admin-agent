from contextlib import asynccontextmanager
from dataclasses import replace

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from auth import AccessDenied, AuthorizationUnavailable, Principal
from core import Journal, ToolBridge
from engine import AgentRunner, Outcome
from test_agent import FakeMCP, ScriptedModel, settings, tool
from web import create_web_app


class Authorizer:
    def __init__(self): self.calls = []; self.revoked = False
    async def require_gateway_admin(self, bearer):
        self.calls.append(bearer)
        if bearer == "unavailable": raise AuthorizationUnavailable()
        if bearer not in ("admin1", "admin2") or self.revoked: raise AccessDenied()
        return Principal(bearer, bearer + "@example.com", "gateway", bearer)


class Runner:
    def __init__(self): self.calls = []
    async def execute(self, text, principal, context, event_id, verify):
        await verify()
        self.calls.append((text, principal.actor, context))
        return Outcome("Budget is $20", {"returned_key_1": "sk-private123456789"}, "completed")


@pytest_asyncio.fixture
async def service():
    config = replace(settings(), service_token="s" * 48, public_url="https://admin.example.com")
    auth = Authorizer(); runner = Runner(); journal = Journal(":memory:")
    async with TestClient(TestServer(create_web_app(config, auth, runner, journal))) as client:
        yield client, auth, runner, journal


def headers(bearer="admin1", token="s" * 48):
    return {"X-Admin-Agent-Token": token, "Authorization": "Bearer " + bearer,
            "X-LiteLLM-User-Role": "proxy_admin", "X-LiteLLM-User-Id": "spoofed-admin"}


def request(rpc_id="rpc1", message_id="message1", context="conversation"):
    return {"jsonrpc": "2.0", "id": rpc_id, "method": "message/send", "params": {"message": {
        "kind": "message", "role": "user", "messageId": message_id, "contextId": context,
        "parts": [{"kind": "text", "text": "Check my budget"}],
        "metadata": {"user_role": "proxy_admin", "user_id": "spoofed-admin"},
    }}}


@pytest.mark.asyncio
async def test_health_card_and_admin_roundtrip(service):
    client, auth, runner, journal = service
    assert (await client.get("/healthz")).status == 200
    card = await (await client.get("/.well-known/agent-card.json")).json()
    assert not card["capabilities"]["streaming"]
    assert card["url"] == "https://admin.example.com/a2a"
    result = await client.post("/a2a", headers=headers(), json=request())
    assert result.status == 200
    body = await result.json()
    assert body["result"]["kind"] == "message"
    assert body["result"]["contextId"] == "conversation"
    assert "sk-private" in str(body["result"]["parts"])
    assert result.headers["Cache-Control"] == "no-store"
    assert runner.calls[0][1] == "gateway:admin1:admin1"
    assert auth.calls == ["admin1"] * 3


@pytest.mark.parametrize("request_headers,status", [({}, 401), (headers(token="wrong"), 401),
    (headers(bearer="user"), 403), (headers(bearer=""), 403), (headers(bearer="expired"), 403),
    (headers(bearer="unavailable"), 503)])
@pytest.mark.asyncio
async def test_denied_http_calls_ignore_spoofed_identity_and_never_run(service, request_headers, status):
    client, auth, runner, journal = service
    result = await client.post("/a2a", headers=request_headers, json=request())
    assert result.status == status
    assert runner.calls == []
    assert journal.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_duplicate_rpc_or_message_ids_cannot_repeat_an_action(service):
    client, auth, runner, journal = service
    assert (await client.post("/a2a", headers=headers(), json=request())).status == 200
    for body in [request(), request("new-rpc"), request(message_id="new-message")]:
        assert (await client.post("/a2a", headers=headers(), json=body)).status == 409
    assert len(runner.calls) == 1
    # A conflicting RPC insert rolls back the fresh message claim as one transaction.
    assert (await client.post("/a2a", headers=headers(), json=request("unique", "new-message"))).status == 200
    # The same IDs from another verified user are unrelated.
    assert (await client.post("/a2a", headers=headers("admin2"), json=request())).status == 200


@pytest.mark.asyncio
async def test_role_revoked_during_run_suppresses_private_output(service):
    client, auth, runner, journal = service
    original = runner.execute
    async def execute(*args):
        result = await original(*args)
        auth.revoked = True
        return result
    runner.execute = execute
    result = await client.post("/a2a", headers=headers(), json=request())
    assert result.status == 403
    assert "sk-private" not in await result.text()


@pytest.mark.parametrize("change", ["batch", "method", "file", "assistant", "long", "missing_id", "bad_context"])
@pytest.mark.asyncio
async def test_unsupported_inputs_never_reach_agent(service, change):
    client, auth, runner, journal = service
    body = request()
    if change == "batch": body = [body]
    elif change == "method": body["method"] = "message/stream"
    elif change == "file": body["params"]["message"]["parts"] = [{"kind": "file", "file": {"uri": "https://example.com"}}]
    elif change == "assistant": body["params"]["message"]["role"] = "agent"
    elif change == "long": body["params"]["message"]["parts"][0]["text"] = "x" * 16001
    elif change == "missing_id": del body["id"]
    elif change == "bad_context": body["params"]["message"]["contextId"] = ["invalid"]
    response = await client.post("/a2a", headers=headers(), json=body)
    assert "error" in await response.json()
    assert runner.calls == []


@pytest.mark.asyncio
async def test_revocation_before_tool_prevents_mutation_and_cached_delivery():
    mcp = FakeMCP(); revoked = False
    async def verify():
        if revoked: raise AccessDenied()
    bridge = ToolBridge([tool()], frozenset({"create_key"}), mcp.call_tool, Journal(":memory:"), "e", verify)
    arguments = {"team_id": "engineering", "max_budget": 20}
    await bridge.call("create_key", arguments)
    revoked = True
    with pytest.raises(AccessDenied):
        await bridge.call("create_key", arguments)
    with pytest.raises(AccessDenied):
        await bridge.call("create_key", {**arguments, "max_budget": 30})
    assert len(mcp.calls) == 1


@pytest.mark.asyncio
async def test_real_sdk_histories_are_isolated_by_principal_and_context():
    mcp = FakeMCP(); model = ScriptedModel()
    @asynccontextmanager
    async def connect(_): yield mcp
    async def verify(): pass
    runner = AgentRunner(settings(), Journal(":memory:"), model, connect)
    alice = Principal("alice", "alice@example.com", "gateway", "alice")
    bob = Principal("bob", "bob@example.com", "gateway", "bob")
    await runner.execute("ALICE PRIVATE REQUEST", alice, "same", "e1", verify)
    await runner.execute("BOB PRIVATE REQUEST", bob, "same", "e2", verify)
    assert "ALICE PRIVATE" not in str(model.inputs[-1])
    await runner.execute("ALICE DIFFERENT CHAT", alice, "new", "e3", verify)
    assert "ALICE PRIVATE" not in str(model.inputs[-1])
    await runner.execute("Continue", alice, "same", "e4", verify)
    assert "ALICE PRIVATE" in str(model.inputs[-1])
    assert "BOB PRIVATE" not in str(model.inputs[-1])


@pytest.mark.asyncio
async def test_engine_reverification_denial_never_connects_or_calls_model():
    model = ScriptedModel()
    @asynccontextmanager
    async def connect(_):
        raise AssertionError("Denied caller connected to MCP")
        yield
    async def deny(): raise AccessDenied()
    runner = AgentRunner(settings(), Journal(":memory:"), model, connect)
    outcome = await runner.execute("Create key", Principal("admin", "", "gateway", "admin"), "ctx", "e1", deny)
    assert outcome.status == "failed"
    assert not model.inputs


def test_registration_preserves_caller_authorization_and_is_not_public():
    from register_agent import registration
    config = replace(settings(), service_token="s" * 48, public_url="https://admin.example.com")
    payload = registration(config)
    assert payload["extra_headers"] == ["Authorization"]
    assert payload["static_headers"] == {"X-Admin-Agent-Token": "s" * 48}
    assert payload["litellm_params"] == {"make_public": False}
    assert "api_key" not in payload["litellm_params"]

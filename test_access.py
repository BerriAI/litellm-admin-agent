import hashlib
import json
from contextlib import asynccontextmanager

import httpx2
import pytest

from access import AdminToolAccess, ToolAccessUnavailable
from auth import AccessDenied, AdminAuthorizer, Principal
from core import Journal
from engine import AgentRunner, error_types
from test_agent import FakeMCP, ScriptedModel, settings


KEY = "sk-alice-personal-test-credential"
SERVER_ID = "admin-server"
PRINCIPAL = Principal("alice", "alice@example.com", "slack", "Ualice")


class Gateway:
    def __init__(self, servers):
        self.permission = None if servers is None else {
            "mcp_servers": servers, "agents": ["other-agent"],
            "mcp_tool_permissions": {"other-server": ["read_only"]},
        }
        self.requests = []
        self.role = "proxy_admin"
        self.revoke_before_update = False
        self.role_checks = 0
        self.wrong_key = False
        self.update_error = None
        self.hide_server = False

    def handle(self, request):
        self.requests.append(request)
        assert request.headers["Authorization"] == "Bearer " + KEY
        path = request.url.path
        if path == "/user/info":
            self.role_checks += 1
            role = "internal_user" if self.revoke_before_update and self.role_checks > 1 else self.role
            return httpx2.Response(200, json={"user_id": "alice", "user_info": {
                "user_id": "alice", "user_email": "alice@example.com", "user_role": role,
            }})
        if path == "/v1/mcp/server":
            visible = self.permission is None or SERVER_ID in self.permission["mcp_servers"]
            return httpx2.Response(200, json=[{"alias": "personal_admin", "server_id": SERVER_ID}] if visible and not self.hide_server else [])
        if path == "/key/info":
            assert not request.url.query
            return httpx2.Response(200, json={
                "key": "someone-else" if self.wrong_key else hashlib.sha256(KEY.encode()).hexdigest(),
                "info": {"user_id": "alice", "object_permission": self.permission},
            })
        if path == "/key/update":
            if self.update_error:
                raise self.update_error
            body = json.loads(request.content)
            assert body == {"key": hashlib.sha256(KEY.encode()).hexdigest(),
                            "object_permission": {"mcp_servers": [item for item in self.permission["mcp_servers"]
                                if item not in ("personal_admin", "no-mcp-servers")] + [SERVER_ID]}}
            self.permission.update(body["object_permission"])
            return httpx2.Response(200, json={"ok": True})
        raise AssertionError("Unexpected request")

    def access(self, client):
        return AdminToolAccess(AdminAuthorizer("https://gateway.example.com", "Tberri", client), "personal_admin", SERVER_ID)

    @property
    def writes(self):
        return [r for r in self.requests if r.method == "POST"]


@pytest.mark.parametrize("servers", [[], ["another-server"], ["no-mcp-servers"], ["personal_admin"]])
@pytest.mark.asyncio
async def test_admin_enrollment_adds_only_admin_server_using_own_key_and_is_idempotent(servers):
    gateway = Gateway(servers)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        access = gateway.access(client)
        await access.ensure(PRINCIPAL, KEY)
        await access.ensure(PRINCIPAL, KEY)
    assert len(gateway.writes) == 1
    assert gateway.permission == {
        "mcp_servers": [item for item in servers if item not in ("personal_admin", "no-mcp-servers")] + [SERVER_ID], "agents": ["other-agent"],
        "mcp_tool_permissions": {"other-server": ["read_only"]},
    }


@pytest.mark.parametrize("servers", [None, [SERVER_ID]])
@pytest.mark.asyncio
async def test_already_reachable_and_unrestricted_admin_keys_are_not_changed(servers):
    gateway = Gateway(servers)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        await gateway.access(client).ensure(PRINCIPAL, KEY)
    assert not gateway.writes


@pytest.mark.parametrize("role", ["internal_user", "proxy_admin_viewer", "team_admin"])
@pytest.mark.asyncio
async def test_non_admin_never_discovers_servers_or_modifies_permissions(role):
    gateway = Gateway([])
    gateway.role = role
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        with pytest.raises(AccessDenied):
            await gateway.access(client).ensure(PRINCIPAL, KEY)
    assert [r.url.path for r in gateway.requests] == ["/user/info"]


@pytest.mark.asyncio
async def test_role_revoked_before_grant_prevents_permission_update():
    gateway = Gateway([])
    gateway.revoke_before_update = True
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        with pytest.raises(AccessDenied):
            await gateway.access(client).ensure(PRINCIPAL, KEY)
    assert not gateway.writes


@pytest.mark.asyncio
async def test_principal_mismatch_prevents_enrollment():
    gateway = Gateway([])
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        with pytest.raises(AccessDenied):
            await gateway.access(client).ensure(Principal("bob", "", "slack", "Ubob"), KEY)
    assert not gateway.writes


@pytest.mark.asyncio
async def test_key_info_must_describe_the_same_authenticating_key():
    gateway = Gateway([])
    gateway.wrong_key = True
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        with pytest.raises(ToolAccessUnavailable):
            await gateway.access(client).ensure(PRINCIPAL, KEY)
    assert not gateway.writes


@pytest.mark.asyncio
async def test_uncertain_grant_is_not_replayed_or_leaked(caplog):
    gateway = Gateway([])
    gateway.update_error = httpx2.ReadTimeout("secret " + KEY)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        with pytest.raises(ToolAccessUnavailable) as raised:
            await gateway.access(client).ensure(PRINCIPAL, KEY)
    assert len(gateway.writes) == 1
    assert KEY not in str(raised.value) + caplog.text


@pytest.mark.parametrize("servers", [None, [SERVER_ID], []])
@pytest.mark.asyncio
async def test_unverified_access_cannot_succeed(servers, monkeypatch):
    async def no_wait(delay): pass
    monkeypatch.setattr("access.asyncio.sleep", no_wait)
    gateway = Gateway(servers)
    gateway.hide_server = True
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        with pytest.raises(ToolAccessUnavailable):
            await gateway.access(client).ensure(PRINCIPAL, KEY)
    assert len(gateway.writes) == (1 if servers == [] else 0)


@pytest.mark.asyncio
async def test_permission_cache_propagation_retries_reads_without_repeating_grant(monkeypatch):
    gateway = Gateway([])
    gateway.hide_server = True
    delays = []
    async def refresh(delay):
        delays.append(delay)
        gateway.hide_server = False
    monkeypatch.setattr("access.asyncio.sleep", refresh)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        await gateway.access(client).ensure(PRINCIPAL, KEY)
    assert len(gateway.writes) == 1
    assert delays == [1]


@pytest.mark.asyncio
async def test_existing_connection_enrolls_before_opening_tools():
    calls = []
    async def verify(): calls.append("verify")
    async def ensure(principal, credential):
        assert principal == PRINCIPAL and credential == KEY
        calls.append("enroll")
    @asynccontextmanager
    async def connect(config, credential):
        calls.append("tools")
        yield FakeMCP()
    runner = AgentRunner(settings(), Journal(":memory:"), ScriptedModel(), connect, ensure_access=ensure)
    result = await runner.execute("Read my budget", PRINCIPAL, "chat", "event", verify, KEY)
    assert result.status == "completed"
    assert calls[:4] == ["verify", "enroll", "verify", "tools"]


@pytest.mark.asyncio
async def test_enrollment_failure_explains_access_issue_and_never_opens_tools():
    async def verify(): pass
    async def ensure(*args): raise ToolAccessUnavailable()
    @asynccontextmanager
    async def connect(*args):
        raise AssertionError("Tool connection must not open")
        yield
    runner = AgentRunner(settings(), Journal(":memory:"), ScriptedModel(), connect, ensure_access=ensure)
    result = await runner.execute("Read my budget", PRINCIPAL, "chat", "event", verify, KEY)
    assert result.status == "failed"
    assert "couldn’t enable the admin tools" in result.answer
    assert "email" not in result.answer


def test_nested_transport_logging_includes_types_only():
    error = ExceptionGroup("secret " + KEY, [ExceptionGroup(KEY, [ValueError(KEY)]), RuntimeError(KEY)])
    assert error_types(error) == "ValueError,RuntimeError"

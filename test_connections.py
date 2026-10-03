import asyncio
import json
import re
import time
from dataclasses import replace

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.fernet import Fernet

from auth import AccessDenied, AuthorizationUnavailable, Principal
from connections import COOKIE, OAUTH_COOKIE, ConnectionRequired, ConnectionStore, Connections
from core import Journal
from test_agent import settings
from sso import OAuthFlow, SignInResult


def store(path=":memory:", key=None):
    journal = Journal(path)
    return ConnectionStore(journal.db, key or Fernet.generate_key().decode())


def test_keys_encrypted_persisted_and_bound_to_owner(tmp_path):
    key = Fernet.generate_key().decode()
    path = str(tmp_path / "connections.sqlite3")
    first = store(path, key)
    first.save("T:alice", "alice", "alice-personal-secret", oauth=session(credential="alice-personal-secret"))
    first.save("T:bob", "bob", "bob-personal-secret")
    assert "alice-personal-secret" not in repr(first.get("T:alice"))
    first.db.close()
    assert b"alice-personal-secret" not in (tmp_path / "connections.sqlite3").read_bytes()
    assert b"refresh-secret" not in (tmp_path / "connections.sqlite3").read_bytes()
    second = store(path, key)
    assert second.get("T:alice").credential == "alice-personal-secret"
    assert second.get("T:alice").oauth.refresh_token == "refresh-secret"
    assert second.get("T:bob").credential == "bob-personal-secret"
    with second.db:
        second.db.execute("UPDATE connections SET encrypted=(SELECT encrypted FROM connections WHERE owner='T:alice') WHERE owner='T:bob'")
    with pytest.raises(ConnectionRequired):
        second.get("T:bob")
    second.disconnect("T:alice")
    with pytest.raises(ConnectionRequired):
        second.get("T:alice")


def test_expiring_links_single_use_and_new_link_invalidates_old():
    db = store()
    old = db.issue("T:alice")
    new = db.issue("T:alice")
    with pytest.raises(ConnectionRequired):
        db.owner(old)
    assert db.owner(new) == "T:alice"
    assert db.owner(new, consume=True) == "T:alice"
    with pytest.raises(ConnectionRequired):
        db.owner(new)
    expired = db.issue("T:bob")
    with db.db:
        db.db.execute("UPDATE connection_links SET expires=0")
    with pytest.raises(ConnectionRequired):
        db.owner(expired)


class Authorizer:
    def __init__(self): self.calls = []; self.denied = False
    async def slack_email(self, user, slack):
        if self.denied: raise AccessDenied()
        return "alice@example.com"
    async def require_slack_admin(self, user, slack, credential):
        self.calls.append((user, credential))
        if self.denied: raise AccessDenied()
        return Principal("alice", "alice@example.com", "slack", user)


def session(**overrides):
    return replace(SignInResult(time.time() + 3600, "alice-session-secret", "refresh-secret", "registered-client",
                               settings().gateway_url, settings().gateway_url + "/token",
                               settings().gateway_url + "/revoke", time.time() + 86400), **overrides)


class SSO:
    def __init__(self):
        self.starts = 0
        self.exchanges = []
        self.result = session()
        self.revoked = []
        self.renewals = 0
    async def refresh(self, previous):
        self.renewals += 1
        return replace(previous, credential="renewed-secret", refresh_token="rotated-secret", expires_at=time.time() + 3600)
    async def revoke(self, previous):
        self.revoked.append(previous.refresh_token)
    async def start(self):
        self.starts += 1
        return OAuthFlow("registered-client", time.time() + 600, "private-state", "private-pkce-verifier")
    def sign_in_url(self, flow):
        return "https://gateway.example/authorize?state=" + flow.state
    async def exchange(self, flow, code):
        self.exchanges.append(code)
        return self.result


@pytest_asyncio.fixture
async def service():
    config = replace(settings(), public_url="https://admin.example.com")
    db = store(); auth = Authorizer()
    connections = Connections(config, db, auth, object(), SSO())
    app = web.Application(client_max_size=32000)
    connections.add_routes(app)
    async with TestClient(TestServer(app)) as client:
        yield client, connections, auth


async def form(service):
    client, connections, _ = service
    url = await connections.link("Ualice")
    path = url.removeprefix(connections.settings.public_url)
    response = await client.get(path)
    assert response.status == 200
    assert response.headers["Cache-Control"] == "no-store"
    # Native browser POSTs turn Origin into "null" under no-referrer, which
    # would break the origin check despite a valid cookie and CSRF token.
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    cookie = response.cookies[COOKIE]
    assert cookie["secure"] and cookie["httponly"] and cookie["samesite"] == "Strict"
    csrf = re.search('name="csrf" value="([^"]+)"', await response.text()).group(1)
    assert 'name="credential"' not in await response.text()
    return path, {"csrf": csrf, "action": "start"}, {
        "Origin": connections.settings.public_url, "Cookie": f"{COOKIE}={cookie.value}"}


async def start(service):
    client, _, _ = service
    path, data, headers = await form(service)
    result = await client.post(path, data=data, headers=headers)
    assert result.status == 200
    text = await result.text()
    assert 'data-oauth-redirect' in text
    assert "private-pkce-verifier" not in text and "alice-session-secret" not in text
    cookie = result.cookies[OAUTH_COOKIE]
    assert cookie["secure"] and cookie["httponly"] and cookie["samesite"] == "Lax"
    return path, data, headers, {"Cookie": f"{OAUTH_COOKIE}={cookie.value}"}


async def callback(client, headers, **query):
    return await client.get("/oauth/callback", params={"state": "private-state", "code": "one-time-code", **query}, headers=headers)


@pytest.mark.asyncio
async def test_sso_stores_only_verified_session_then_rejects_replay(service):
    client, connections, auth = service
    path, data, headers, oauth_headers = await start(service)
    with pytest.raises(ConnectionRequired): connections.get("Ualice")
    result = await callback(client, oauth_headers)
    assert result.status == 200 and "Account connected" in await result.text()
    assert "alice-session-secret" not in await result.text()
    assert connections.get("Ualice").credential == "alice-session-secret"
    assert connections.get("Ualice").user_id == "alice"
    assert connections.get("Ualice").expires_at == connections.sso.result.expires_at
    assert auth.calls == [("Ualice", "alice-session-secret")]
    assert (await callback(client, oauth_headers)).status == 410
    assert (await client.post(path, data=data, headers=headers)).status == 410
    assert connections.sso.exchanges == ["one-time-code"]


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["missing_cookie", "wrong_cookie", "state", "duplicate_state", "missing_code", "duplicate_code"])
async def test_callback_binding_rejects_before_exchange(service, attack):
    client, connections, _ = service
    _, _, _, headers = await start(service)
    query = [("state", "private-state"), ("code", "one-time-code")]
    if attack == "missing_cookie": headers = {}
    elif attack == "wrong_cookie": headers = {"Cookie": f"{OAUTH_COOKIE}=invalid"}
    elif attack == "state": query[0] = ("state", "attacker-state")
    elif attack == "duplicate_state": query.append(("state", "private-state"))
    elif attack == "missing_code": query.pop()
    elif attack == "duplicate_code": query.append(("code", "second-code"))
    assert (await client.get("/oauth/callback", params=query, headers=headers)).status == 403
    assert not connections.sso.exchanges
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.parametrize("attack", ["missing_cookie", "wrong_cookie", "origin", "null_origin", "missing_origin", "csrf", "other_link"])
@pytest.mark.asyncio
async def test_csrf_and_mismatched_browser_never_verify_or_store_key(service, attack):
    client, connections, auth = service
    path, data, headers = await form(service)
    if attack == "missing_cookie": headers.pop("Cookie")
    elif attack == "wrong_cookie": headers["Cookie"] = f"{COOKIE}=invalid"
    elif attack == "origin": headers["Origin"] = "https://attacker.example"
    elif attack == "null_origin": headers["Origin"] = "null"
    elif attack == "missing_origin": headers.pop("Origin")
    elif attack == "csrf": data["csrf"] = "wrong"
    elif attack == "other_link": path = "/connect/" + connections.store.issue(connections.owner("Ubob"))
    rejected = await client.post(path, data=data, headers=headers)
    assert rejected.status == 403
    assert "Please reopen your connection link" in await rejected.text()
    assert not auth.calls
    assert connections.sso.starts == 0
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.asyncio
async def test_browser_session_rejection_does_not_consume_valid_link(service):
    client, connections, auth = service
    path, data, headers = await form(service)
    assert (await client.post(path, data=data, headers={**headers, "Origin": "null"})).status == 403
    assert not auth.calls
    assert (await client.post(path, data=data, headers=headers)).status == 200
    assert connections.sso.starts == 1


@pytest.mark.asyncio
async def test_non_admin_or_wrong_email_does_not_create_connection(service):
    client, connections, auth = service
    _, _, _, headers = await start(service)
    auth.denied = True
    assert (await callback(client, headers)).status == 403
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.asyncio
async def test_disconnect_invalidates_pending_links_and_connection(service):
    _, connections, _ = service
    url = await connections.link("Ualice")
    connections.store.save(connections.owner("Ualice"), "alice", "secret")
    await connections.disconnect("Ualice")
    with pytest.raises(ConnectionRequired): connections.get("Ualice")
    with pytest.raises(ConnectionRequired): connections.store.owner(url.rsplit("/", 1)[1])


@pytest.mark.asyncio
async def test_pending_login_can_reopen_only_in_original_browser(service):
    client, connections, _ = service
    path, data, headers, _ = await start(service)
    assert (await client.get(path)).status == 403
    reopened = await client.get(path, headers=headers)
    assert reopened.status == 200
    csrf = re.search('name="csrf" value="([^"]+)"', await reopened.text()).group(1)
    assert csrf == data["csrf"]
    assert (await client.post(path, data=data, headers=headers)).status == 200
    assert connections.sso.starts == 1


@pytest.mark.asyncio
async def test_duplicate_start_does_not_create_second_session(service):
    client, connections, _ = service
    path, data, headers = await form(service)
    await client.post(path, data=data, headers=headers)
    await client.post(path, data=data, headers=headers)
    assert connections.sso.starts == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["disconnect", "new_link"])
async def test_disconnect_or_new_link_during_exchange_cannot_reattach(service, change):
    client, connections, _ = service
    _, _, _, headers = await start(service)
    async def exchange(flow, code):
        if change == "disconnect": await connections.disconnect("Ualice")
        else: await connections.link("Ualice")
        return session(credential="stale-session")
    connections.sso.exchange = exchange
    result = await callback(client, headers)
    assert result.status == 410
    with pytest.raises(ConnectionRequired): connections.get("Ualice")



def test_pending_flow_encrypted_and_survives_restart_but_not_expiry(tmp_path):
    key = Fernet.generate_key().decode()
    path = str(tmp_path / "sso.sqlite3")
    db = store(path, key)
    token = db.issue("T:alice")
    flow = OAuthFlow("client", time.time() + 600, "private-state", "pkce-secret-do-not-expose")
    db.save_pending(token, "browser-csrf", flow)
    db.db.close()
    assert b"pkce-secret-do-not-expose" not in (tmp_path / "sso.sqlite3").read_bytes()
    db = store(path, key)
    assert db.pending(token)["flow"]["code_verifier"] == "pkce-secret-do-not-expose"
    db.save_pending(token, "browser-csrf", replace(flow, expires_at=0))
    with pytest.raises(ConnectionRequired): db.pending(token)


@pytest.mark.asyncio
async def test_cancellation_preserves_old_connection_and_consumes_link(service):
    client, connections, _ = service
    connections.store.save(connections.owner("Ualice"), "alice", "existing-key", oauth=session(credential="existing-key"))
    path, _, _, headers = await start(service)
    assert connections.get("Ualice").credential == "existing-key"
    result = await client.get("/oauth/callback", params={"state": "private-state", "error": "access_denied"}, headers=headers)
    assert result.status == 403 and "Connection cancelled" in await result.text()
    assert connections.get("Ualice").credential == "existing-key"
    assert (await client.get(path)).status == 410
    assert not connections.sso.exchanges


def test_expired_session_requires_reconnection():
    db = store()
    db.save("T:alice", "alice", "expired-session", time.time() - 1)
    with pytest.raises(ConnectionRequired): db.get("T:alice")


@pytest.mark.asyncio
async def test_concurrent_acquire_rotates_once_without_changing_conversation_identity(service):
    client, connections, _ = service
    connections.sso.result = session(expires_at=time.time() + 5)
    _, _, _, headers = await start(service)
    assert (await callback(client, headers)).status == 200
    before = connections.get("Ualice")
    renewed = await asyncio.gather(connections.acquire("Ualice"), connections.acquire("Ualice"))
    assert connections.sso.renewals == 1
    assert all(item.version == before.version and item.credential == "renewed-secret" for item in renewed)
    encrypted = connections.store.db.execute("SELECT encrypted FROM connections").fetchone()[0]
    assert b"rotated-secret" not in encrypted and b"renewed-secret" not in encrypted
    assert connections.get("Ualice").oauth.refresh_token == "rotated-secret"


@pytest.mark.asyncio
async def test_interrupted_rotation_is_revoked_after_restart_without_replaying_refresh(service):
    client, connections, _ = service
    _, _, _, headers = await start(service)
    assert (await callback(client, headers)).status == 200
    connections.store.refresh(connections.owner("Ualice"), connections.get("Ualice"))
    restarted = Connections(connections.settings, connections.store, connections.authorizer, object(), connections.sso)
    with pytest.raises(ConnectionRequired):
        await restarted.acquire("Ualice")
    assert connections.sso.renewals == 0 and connections.sso.revoked == ["refresh-secret"]
    with pytest.raises(ConnectionRequired): restarted.get("Ualice")


@pytest.mark.parametrize("action", ["disconnect", "reconnect"])
@pytest.mark.asyncio
async def test_late_refresh_cannot_resurrect_or_replace_a_connection(service, action):
    client, connections, _ = service
    connections.sso.result = session(expires_at=time.time() + 5)
    _, _, _, headers = await start(service)
    assert (await callback(client, headers)).status == 200
    entered, resume = asyncio.Event(), asyncio.Event()
    async def suspended(previous):
        entered.set()
        await resume.wait()
        return session(credential="late-access", refresh_token="late-refresh")
    connections.sso.refresh = suspended
    pending = asyncio.create_task(connections.acquire("Ualice"))
    await entered.wait()
    if action == "disconnect":
        await connections.disconnect("Ualice")
    else:
        fresh = session(credential="fresh-access", refresh_token="fresh-refresh")
        connections.store.save(connections.owner("Ualice"), "alice", fresh.credential, fresh.expires_at, oauth=fresh)
    resume.set()
    with pytest.raises(ConnectionRequired): await pending
    if action == "disconnect":
        with pytest.raises(ConnectionRequired): connections.get("Ualice")
    else:
        assert connections.get("Ualice").credential == "fresh-access"
    assert "refresh-secret" in connections.sso.revoked
    assert "fresh-refresh" not in connections.sso.revoked


@pytest.mark.asyncio
async def test_disconnect_keeps_failed_revocation_encrypted_for_retry(service):
    client, connections, _ = service
    _, _, _, headers = await start(service)
    assert (await callback(client, headers)).status == 200
    revoke = connections.sso.revoke
    async def unavailable(previous): raise AuthorizationUnavailable()
    connections.sso.revoke = unavailable
    assert await connections.disconnect("Ualice") is False
    with pytest.raises(ConnectionRequired): connections.get("Ualice")
    row = connections.store.db.execute("SELECT encrypted FROM connection_revocations").fetchone()
    assert row is not None and b"refresh-secret" not in row[0]
    connections.sso.revoke = revoke
    connections.store.db.execute("UPDATE connection_revocations SET ready_at=0")
    assert await connections.cleanup()
    assert connections.sso.revoked == ["refresh-secret"]
    assert connections.store.db.execute("SELECT COUNT(*) FROM connection_revocations").fetchone()[0] == 0


def test_refresh_compares_the_refresh_generation_when_access_token_is_unchanged():
    db = store()
    initial = session()
    db.save("T:alice", "alice", initial.credential, initial.expires_at, oauth=initial)
    stale = db.get("T:alice")
    db.refresh("T:alice", stale)
    db.refresh("T:alice", stale, replace(initial, refresh_token="new-refresh"))
    with pytest.raises(ConnectionRequired): db.refresh("T:alice", stale)
    assert db.get("T:alice").oauth.refresh_token == "new-refresh"
    assert db.get("T:alice").refreshing is False


@pytest.mark.asyncio
async def test_unavailable_origin_cannot_monopolize_revocation_batches(service):
    import httpx2
    from sso import LiteLLMSSO
    _, connections, _ = service
    requested = []
    def respond(request):
        requested.append(request.url.host)
        if request.url.host == "old.example": raise httpx2.ConnectError("offline")
        return httpx2.Response(200)
    owner = connections.owner("Ualice")
    for index in range(16):
        connections.store.queue_revocation(owner, session(resource="https://old.example",
            revocation_endpoint="https://old.example/revoke", refresh_token=f"old-refresh-{index}"))
    connections.store.queue_revocation(owner, session(resource="https://new.example",
        revocation_endpoint="https://new.example/revoke", refresh_token="new-refresh"))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        connections.sso = LiteLLMSSO("https://new.example", connections.settings.public_url, client)
        assert await connections.cleanup("Ualice") is False
        assert requested == ["old.example"] * 16
        assert await connections.cleanup("Ualice") is False
    assert requested == ["old.example"] * 16 + ["new.example"]
    assert connections.store.db.execute("SELECT COUNT(*) FROM connection_revocations").fetchone()[0] == 16

import json
import re
import time
from dataclasses import replace

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.fernet import Fernet

from auth import AccessDenied, Principal
from connections import COOKIE, ConnectionRequired, ConnectionStore, Connections
from core import Journal
from test_agent import settings
from sso import DeviceFlow, SignInResult


def store(path=":memory:", key=None):
    journal = Journal(path)
    return ConnectionStore(journal.db, key or Fernet.generate_key().decode())


def test_keys_encrypted_persisted_and_bound_to_owner(tmp_path):
    key = Fernet.generate_key().decode()
    path = str(tmp_path / "connections.sqlite3")
    first = store(path, key)
    first.save("T:alice", "alice", "alice-personal-secret")
    first.save("T:bob", "bob", "bob-personal-secret")
    assert "alice-personal-secret" not in repr(first.get("T:alice"))
    first.db.close()
    assert b"alice-personal-secret" not in (tmp_path / "connections.sqlite3").read_bytes()
    second = store(path, key)
    assert second.get("T:alice").credential == "alice-personal-secret"
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


class SSO:
    def __init__(self):
        self.starts = 0
        self.polls = []
        self.result = SignInResult(user_id="alice", credential="alice-session-secret")
    async def start(self):
        self.starts += 1
        return DeviceFlow("cli-abcdefghijklmnopqrstuvwx", "ABCD-EFGH", time.time() + 600, "private-polling-secret")
    def sign_in_url(self, flow):
        return "https://example.com/sso/key/generate?source=litellm-cli&key=" + flow.login_id
    async def poll(self, flow, team_id=None):
        self.polls.append(team_id)
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


@pytest.mark.asyncio
async def test_sso_stores_only_verified_session_then_rejects_replay(service):
    client, connections, auth = service
    path, data, headers = await form(service)
    result = await client.post(path, data=data, headers=headers)
    assert result.status == 200
    text = await result.text()
    assert "ABCD-EFGH" in text and "Open LiteLLM SSO" in text
    assert "private-polling-secret" not in text
    assert "alice-session-secret" not in text
    with pytest.raises(ConnectionRequired): connections.get("Ualice")
    result = await client.post(path, data={**data, "action": "check"}, headers=headers)
    assert result.status == 200
    assert "Account connected" in await result.text()
    assert "alice-session-secret" not in await result.text()
    assert connections.get("Ualice").credential == "alice-session-secret"
    assert auth.calls == [("Ualice", "alice-session-secret")]
    replay = await client.post(path, data=data, headers=headers)
    assert replay.status == 410
    assert "Link expired or already used" in await replay.text()
    assert len(auth.calls) == 1


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
    path, data, headers = await form(service)
    assert (await client.post(path, data=data, headers=headers)).status == 200
    auth.denied = True
    assert (await client.post(path, data={**data, "action": "check"}, headers=headers)).status == 403
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.asyncio
async def test_disconnect_invalidates_pending_links_and_connection(service):
    _, connections, _ = service
    url = await connections.link("Ualice")
    connections.store.save(connections.owner("Ualice"), "alice", "secret")
    connections.disconnect("Ualice")
    with pytest.raises(ConnectionRequired): connections.get("Ualice")
    with pytest.raises(ConnectionRequired): connections.store.owner(url.rsplit("/", 1)[1])


@pytest.mark.asyncio
async def test_pending_login_and_team_selection_preserve_browser_binding(service):
    client, connections, _ = service
    path, data, headers = await form(service)
    await client.post(path, data=data, headers=headers)
    # A stolen URL does not disclose an existing login code or poll it.
    assert (await client.get(path)).status == 403
    assert (await client.get(path, headers=headers)).status == 200
    connections.sso.result = SignInResult()
    pending = await client.post(path, data={**data, "action": "check"}, headers=headers)
    assert "Still waiting" in await pending.text()
    connections.sso.result = SignInResult(user_id="alice", teams=(("t1", "Engineering"), ("t2", "Research<script>")))
    choices = await client.post(path, data={**data, "action": "check"}, headers=headers)
    assert choices.status == 200
    assert "Choose your LiteLLM team" in await choices.text()
    assert "Research&lt;script&gt;" in await choices.text()
    assert "<script>" not in await choices.text()
    bad_choice = await client.post(path, data={**data, "action": "check", "team_id": "not-my-team"}, headers=headers)
    assert bad_choice.status == 403
    assert len(connections.sso.polls) == 2
    connections.sso.result = SignInResult(user_id="alice", credential="personal-session")
    completed = await client.post(path, data={**data, "action": "check", "team_id": "t2"}, headers=headers)
    assert completed.status == 200
    assert connections.sso.polls == [None, None, "t2"]


@pytest.mark.asyncio
async def test_duplicate_start_does_not_create_second_session(service):
    client, connections, _ = service
    path, data, headers = await form(service)
    await client.post(path, data=data, headers=headers)
    await client.post(path, data=data, headers=headers)
    assert connections.sso.starts == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["disconnect", "new_link"])
async def test_disconnect_or_new_link_during_gateway_poll_cannot_reattach(service, change):
    client, connections, _ = service
    path, data, headers = await form(service)
    await client.post(path, data=data, headers=headers)
    async def poll(flow, team_id=None):
        if change == "disconnect": connections.disconnect("Ualice")
        else: await connections.link("Ualice")
        return SignInResult(user_id="alice", credential="stale-session")
    connections.sso.poll = poll
    result = await client.post(path, data={**data, "action": "check"}, headers=headers)
    assert result.status == 410
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.asyncio
async def test_mismatched_user_id_cannot_save_session(service):
    client, connections, _ = service
    path, data, headers = await form(service)
    await client.post(path, data=data, headers=headers)
    connections.sso.result = SignInResult(user_id="someone-else", credential="session")
    assert (await client.post(path, data={**data, "action": "check"}, headers=headers)).status == 403
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


def test_pending_flow_encrypted_and_survives_restart_but_not_expiry(tmp_path):
    key = Fernet.generate_key().decode()
    path = str(tmp_path / "sso.sqlite3")
    db = store(path, key)
    token = db.issue("T:alice")
    flow = DeviceFlow("cli-session", "ABCD-EFGH", time.time() + 600, "poll-secret-do-not-expose")
    db.save_pending(token, "browser-csrf", flow)
    db.db.close()
    assert b"poll-secret-do-not-expose" not in (tmp_path / "sso.sqlite3").read_bytes()
    db = store(path, key)
    assert db.pending(token)["flow"]["poll_secret"] == "poll-secret-do-not-expose"
    db.save_pending(token, "browser-csrf", replace(flow, expires_at=0))
    with pytest.raises(ConnectionRequired): db.pending(token)


@pytest.mark.asyncio
async def test_existing_personal_key_survives_unfinished_sso(service):
    client, connections, _ = service
    connections.store.save(connections.owner("Ualice"), "alice", "existing-key")
    path, data, headers = await form(service)
    await client.post(path, data=data, headers=headers)
    assert connections.get("Ualice").credential == "existing-key"

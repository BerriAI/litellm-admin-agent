import json
import re
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


@pytest_asyncio.fixture
async def service():
    config = replace(settings(), public_url="https://admin.example.com")
    db = store(); auth = Authorizer()
    connections = Connections(config, db, auth, object())
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
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    cookie = response.cookies[COOKIE]
    assert cookie["secure"] and cookie["httponly"] and cookie["samesite"] == "Strict"
    csrf = re.search('name="csrf" value="([^"]+)"', await response.text()).group(1)
    return path, {"csrf": csrf, "credential": "alice-personal-secret"}, {
        "Origin": connections.settings.public_url, "Cookie": f"{COOKIE}={cookie.value}"}


@pytest.mark.asyncio
async def test_connection_requires_browser_and_origin_then_stores_only_verified_key(service):
    client, connections, auth = service
    path, data, headers = await form(service)
    result = await client.post(path, data=data, headers=headers)
    assert result.status == 200
    assert "Account connected" in await result.text()
    assert "alice-personal-secret" not in await result.text()
    assert connections.get("Ualice").credential == "alice-personal-secret"
    assert auth.calls == [("Ualice", "alice-personal-secret")]
    assert (await client.post(path, data=data, headers=headers)).status == 403
    assert len(auth.calls) == 1


@pytest.mark.parametrize("attack", ["missing_cookie", "wrong_cookie", "origin", "missing_origin", "csrf", "other_link"])
@pytest.mark.asyncio
async def test_csrf_and_mismatched_browser_never_verify_or_store_key(service, attack):
    client, connections, auth = service
    path, data, headers = await form(service)
    if attack == "missing_cookie": headers.pop("Cookie")
    elif attack == "wrong_cookie": headers["Cookie"] = f"{COOKIE}=invalid"
    elif attack == "origin": headers["Origin"] = "https://attacker.example"
    elif attack == "missing_origin": headers.pop("Origin")
    elif attack == "csrf": data["csrf"] = "wrong"
    elif attack == "other_link": path = "/connect/" + connections.store.issue(connections.owner("Ubob"))
    assert (await client.post(path, data=data, headers=headers)).status == 403
    assert not auth.calls
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.asyncio
async def test_non_admin_or_wrong_email_does_not_create_connection(service):
    client, connections, auth = service
    path, data, headers = await form(service)
    auth.denied = True
    assert (await client.post(path, data=data, headers=headers)).status == 403
    with pytest.raises(ConnectionRequired): connections.get("Ualice")


@pytest.mark.asyncio
async def test_disconnect_invalidates_pending_links_and_connection(service):
    _, connections, _ = service
    url = await connections.link("Ualice")
    connections.store.save(connections.owner("Ualice"), "alice", "secret")
    connections.disconnect("Ualice")
    with pytest.raises(ConnectionRequired): connections.get("Ualice")
    with pytest.raises(ConnectionRequired): connections.store.owner(url.rsplit("/", 1)[1])

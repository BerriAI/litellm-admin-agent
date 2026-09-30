"""Exercise the real AgentChat transport, authorization boundary and agent runner."""
import json
from contextlib import asynccontextmanager

import pytest

from auth import AccessDenied, Principal
from connections import Connection, ConnectionRequired
from core import Journal, SlackThreads
from test_agent import FakeAuthorizer, FakeConnections, FakeMCP, FakeSlack, ScriptedModel, channel, event


def mention(ts="1.1", user="Uadmin", text="Create a team key", **fields):
    body = event(event_id="Ev" + ts, user=user, channel_type="channel")
    body["event"].update(type="app_mention", channel="Cchannel", ts=ts, text="<@BOT> " + text, **fields)
    return body


def followup(ts="2.2", user="Uadmin", text="What budget did you set?", **fields):
    body = mention(ts, user, text)
    body["event"].update(type="message", text=text, thread_ts="1.1", **fields)
    return body


@pytest.mark.asyncio
@pytest.mark.parametrize("channel_type", ["channel", "group"])
async def test_thread_conversation_keeps_context_but_sends_keys_only_to_requester(channel_type):
    client, model, mcp = FakeSlack(), ScriptedModel(), FakeMCP()
    @asynccontextmanager
    async def connect(config, credential): yield mcp
    transport = channel(client, Journal(":memory:"), model, connect,
                        authorizer=FakeAuthorizer(), connections=FakeConnections())
    await transport.handle_event(mention(channel_type=channel_type))
    await transport.handle_event(followup(channel_type=channel_type))
    assert len(mcp.calls) == 1
    assert any(item.get("role") == "assistant" for item in model.inputs[-1])
    public = [p for p in client.posts + client.updates if p["channel"] == "Cchannel"]
    assert "sk-created" not in json.dumps(public)
    assert "sk-created" not in json.dumps(model.inputs)
    assert all(p["thread_ts"] == "1.1" for p in client.posts if p["channel"] == "Cchannel")
    keys = [p for p in client.posts if "sk-created" in p["text"]]
    assert len(keys) == 1 and keys[0]["channel"] == "Uadmin"


@pytest.mark.asyncio
async def test_thread_and_replay_records_survive_restart_including_old_event_ids(tmp_path):
    path = str(tmp_path / "journal.sqlite3")
    client, mcp = FakeSlack(), FakeMCP()
    @asynccontextmanager
    async def connect(config, credential): yield mcp
    journal = Journal(path)
    transport = channel(client, journal, ScriptedModel(), connect,
                        authorizer=FakeAuthorizer(), connections=FakeConnections())
    await transport.handle_event(mention())
    assert len(mcp.calls) == 1
    journal.claim("old-deployed-event", "slack:Uadmin")
    journal.db.close()

    journal = Journal(path)
    transport = channel(client, journal, ScriptedModel(), connect,
                        authorizer=FakeAuthorizer(), connections=FakeConnections())
    duplicate = mention()
    duplicate.update(event_id="second-event-for-same-message")
    duplicate["event"]["type"] = "message"
    await transport.handle_event(duplicate)
    await transport.handle_event({**mention("3.3"), "event_id": "old-deployed-event"})
    assert len(mcp.calls) == 1
    # A failed multi-ID claim must roll back all new IDs.
    assert journal.db.execute("SELECT 1 FROM events WHERE id='second-event-for-same-message'").fetchone() is None
    await transport.handle_event(followup())
    assert len(mcp.calls) == 2  # The new process receives untagged replies.
    assert client.posts[-2]["thread_ts"] == "1.1"
    journal.db.close()


@pytest.mark.asyncio
async def test_each_admin_uses_their_own_credential_and_history_in_a_shared_thread():
    class Connections:
        version = "one"
        def get(self, user): return Connection(user, self.version, user + "-credential")
    class Authorizer:
        async def require_slack_admin(self, user, client, credential):
            assert credential == user + "-credential"
            if user not in {"Uadmin", "Ubob"}: raise AccessDenied()
            return Principal(user, user + "@example.com", "slack", user)
    credentials = []
    @asynccontextmanager
    async def connect(config, credential):
        credentials.append(credential)
        yield FakeMCP()
    connections, model, client = Connections(), ScriptedModel(), FakeSlack()
    model.index = 2  # Text-only turns let us inspect context for every participant.
    transport = channel(client, Journal(":memory:"), model, connect,
                        authorizer=Authorizer(), connections=connections)
    await transport.handle_event(mention(text="Alice context"))
    await transport.handle_event(followup("2.2", user="Ubob", text="Bob context"))
    assert model.inputs[-1] == [{"role": "user", "content": "Bob context"}]
    await transport.handle_event(followup("3.3", text="My follow-up"))
    assert model.inputs[-1][0]["content"] == "Alice context"
    assert "Bob context" not in json.dumps(model.inputs[-1])
    before = len(model.inputs)
    await transport.handle_event(followup("4.4", user="Uregular"))
    assert len(model.inputs) == before
    # Another thread and a replacement connection each start with fresh context.
    await transport.handle_event(mention("5.5", text="Other thread"))
    assert len(model.inputs[-1]) == 1
    connections.version = "two"
    await transport.handle_event(followup("6.6", text="After reconnect"))
    assert len(model.inputs[-1]) == 1
    assert credentials == ["Uadmin-credential", "Ubob-credential", "Uadmin-credential",
                           "Uadmin-credential", "Uadmin-credential"]


@pytest.mark.asyncio
async def test_connection_links_are_private_and_unverified_requests_do_not_follow_threads():
    class Connections:
        async def link(self, user): return "https://example.com/connect/private-token"
        def get(self, user): raise ConnectionRequired()
    client, journal, model = FakeSlack(), Journal(":memory:"), ScriptedModel()
    transport = channel(client, journal, model, authorizer=FakeAuthorizer(), connections=Connections())
    await transport.handle_event(mention())
    assert "private-token" in client.posts[0]["text"] and client.posts[0]["channel"] == "Uadmin"
    assert "private-token" not in client.posts[1]["text"] and client.posts[1]["channel"] == "Cchannel"
    await transport.handle_event(followup())
    assert len(client.posts) == 2 and not model.inputs
    assert not journal.db.execute("SELECT * FROM slack_threads").fetchall()


@pytest.mark.asyncio
async def test_rejected_and_unrelated_channel_events_never_reach_the_runner():
    client, model = FakeSlack(), ScriptedModel()
    transport = channel(client, Journal(":memory:"), model,
                        authorizer=FakeAuthorizer(), connections=FakeConnections())
    await transport.handle_event(mention(user="Uother"))
    assert "couldn’t be verified" in client.posts[-1]["text"]
    await transport.handle_event(followup())  # Denied mention did not subscribe.
    await transport.handle_event({**mention(), "team_id": "Tother"})
    await transport.handle_event(mention(bot_id="Bbot"))
    await transport.handle_event(mention(subtype="message_changed"))
    unrelated = followup()
    unrelated["event"].pop("thread_ts")
    await transport.handle_event(unrelated)
    assert not model.inputs and len(client.posts) == 1


@pytest.mark.asyncio
async def test_revocation_after_key_creation_stops_private_delivery():
    class Authorizer(FakeAuthorizer):
        revoked = False
        async def require_slack_admin(self, *args):
            if self.revoked: raise AccessDenied()
            return await super().require_slack_admin(*args)
    auth, client, mcp, model = Authorizer(), FakeSlack(), FakeMCP(), ScriptedModel()
    @asynccontextmanager
    async def connect(config, credential):
        yield mcp
        auth.revoked = True
    transport = channel(client, Journal(":memory:"), model, connect,
                        authorizer=auth, connections=FakeConnections())
    await transport.handle_event(mention())
    assert len(mcp.calls) == 1
    assert "sk-created" not in json.dumps(client.posts + client.updates)
    assert "run stopped" in client.updates[-1]["text"]
    before = len(model.inputs)
    await transport.handle_event(followup())
    assert len(model.inputs) == before


@pytest.mark.asyncio
async def test_thread_tracking_expires_and_is_bounded(monkeypatch):
    journal = Journal(":memory:")
    subscriptions = SlackThreads(journal)
    monkeypatch.setattr("core.time.time", lambda: 0)
    await subscriptions.add("old")
    monkeypatch.setattr("core.time.time", lambda: 7 * 86400)
    assert not await subscriptions.contains("old")
    for i in range(1001):
        monkeypatch.setattr("core.time.time", lambda i=i: 7 * 86400 + i)
        await subscriptions.add(str(i))
    assert not await subscriptions.contains("0")
    assert await subscriptions.contains("1000")
    assert journal.db.execute("SELECT COUNT(*) FROM slack_threads").fetchone()[0] == 1000


@pytest.mark.parametrize("needs_connection", [False, True])
@pytest.mark.asyncio
async def test_failed_private_delivery_is_reported_without_leaking_or_repeating_actions(needs_connection):
    class Client(FakeSlack):
        async def chat_postMessage(self, **kwargs):
            if kwargs["channel"] == "Uadmin": raise RuntimeError("DM unavailable")
            return await super().chat_postMessage(**kwargs)
    class Connections(FakeConnections):
        def get(self, user):
            if needs_connection: raise ConnectionRequired()
            return super().get(user)
        async def link(self, user): return "https://example.com/connect/private-token"
    mcp, client, journal = FakeMCP(), Client(), Journal(":memory:")
    @asynccontextmanager
    async def connect(config, credential): yield mcp
    transport = channel(client, journal, ScriptedModel(), connect,
                        authorizer=FakeAuthorizer(), connections=Connections())
    await transport.handle_event(mention())
    assert len(mcp.calls) == (0 if needs_connection else 1)
    replies = json.dumps(client.posts + client.updates, ensure_ascii=False)
    assert "sk-created" not in replies and "private-token" not in replies
    assert "couldn’t" in replies
    assert journal.db.execute("SELECT DISTINCT status FROM events").fetchall() == [("reply_failed",)]
    await transport.handle_event(mention())
    assert len(mcp.calls) == (0 if needs_connection else 1)

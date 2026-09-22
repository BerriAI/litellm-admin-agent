"""Slack Socket Mode adapter and hosted service entry point."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal

import httpx2
from aiohttp import web
from agents import set_tracing_disabled
from dotenv import load_dotenv
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler

from agent import Settings, mcp_session
from auth import AccessDenied, AdminAuthorizer, AuthorizationUnavailable
from core import Journal, all_tools, valid_dm_event
from connections import ConnectionRequired, ConnectionStore, Connections
from engine import AgentBusy, AgentRunner
from admin_api import add_admin_api_routes
from sso import LiteLLMSSO


def chunks(text: str, size: int = 3000):
    for i in range(0, len(text), size):
        yield text[i:i + size]


def build_listener(settings: Settings, journal: Journal, model=None, connect=mcp_session,
                   *, authorizer, connections, runner=None):
    runner = runner or AgentRunner(settings, journal, model, connect)

    async def process(body, client):
        if not valid_dm_event(body, settings.workspace):
            return
        event = body["event"]
        event_id = body["event_id"]
        if not journal.claim(event_id, "slack:" + event["user"]):
            return
        channel, thread = event["channel"], event.get("thread_ts")
        pending_ts = None
        status = "failed"
        try:
            command = event["text"].strip().casefold()
            if command == "disconnect":
                await authorizer.slack_email(event["user"], client)
                connections.disconnect(event["user"])
                runner.conversations = {k: v for k, v in runner.conversations.items()
                                        if not k[0].startswith("slack:" + event["user"] + ":")}
                await client.chat_postMessage(channel=channel, thread_ts=thread,
                    text="Your LiteLLM account is disconnected. Your saved credential has been removed.")
                status = "completed"
                return
            if command == "connect":
                raise ConnectionRequired()
            connection = connections.get(event["user"])
            principal = await authorizer.require_slack_admin(event["user"], client, connection.credential)
            if principal.user_id != connection.user_id:
                raise AccessDenied()

            async def verify():
                current = connections.get(event["user"])
                if current.version != connection.version:
                    raise AccessDenied()
                if await authorizer.require_slack_admin(event["user"], client, connection.credential) != principal:
                    raise AccessDenied()

            if len(event["text"]) > 16000:
                await client.chat_postMessage(channel=channel, thread_ts=thread, text="Please keep each request under 16,000 characters.")
                journal.finish(event_id, "rejected")
                return
            pending = await client.chat_postMessage(channel=channel, thread_ts=thread,
                text="Working on your request…", unfurl_links=False, unfurl_media=False)
            pending_ts = pending["ts"]
            outcome = await runner.execute(event["text"], principal, channel + ":" + (thread or "main") + ":" + connection.version, event_id, verify, connection.credential)
            # Revocation during a run must also stop private data delivery.
            await verify()
            parts = list(chunks(outcome.answer))
            await client.chat_update(channel=channel, ts=pending_ts, text=parts[0])
            for part in parts[1:]:
                await client.chat_postMessage(channel=channel, thread_ts=thread, text=part, unfurl_links=False, unfurl_media=False)
            for reference, secret in outcome.secrets.items():
                await verify()
                await client.chat_postMessage(channel=channel, thread_ts=thread,
                    text=f"{reference}: `{secret}`\nSave this key securely. It was kept out of the model’s tool results.",
                    unfurl_links=False, unfurl_media=False)
            status = outcome.status
        except ConnectionRequired:
            status = "connection_required"
            try:
                link = await connections.link(event["user"])
                answer = (f"Connect your own LiteLLM admin account here: <{link}|Connect account>\n"
                          "This private link expires in 10 minutes. Complete the secure connection page. Never paste keys into Slack. "
                          "Then send your request again.")
                if pending_ts:
                    await client.chat_update(channel=channel, ts=pending_ts, text="Your account connection changed. The run stopped; inspect gateway state before retrying changes.")
                else:
                    await client.chat_postMessage(channel=channel, thread_ts=thread, text=answer,
                                                  unfurl_links=False, unfurl_media=False)
            except (AccessDenied, AuthorizationUnavailable):
                await client.chat_postMessage(channel=channel, thread_ts=thread,
                    text="I couldn’t verify your Slack workspace membership. Please try again later.")
        except AgentBusy:
            status = "busy"
            answer = "The agent is busy. No operation started for this request. Please send it again shortly."
            if pending_ts:
                await client.chat_update(channel=channel, ts=pending_ts, text=answer)
            else:
                await client.chat_postMessage(channel=channel, thread_ts=thread, text=answer)
        except (AccessDenied, AuthorizationUnavailable) as exc:
            status = "denied" if isinstance(exc, AccessDenied) else "authorization_unavailable"
            answer = ("Your LiteLLM admin session couldn’t be verified. Your Slack email must match an active LiteLLM proxy-admin account. Send connect to reconnect."
                      if isinstance(exc, AccessDenied) else "I can’t verify your admin access right now. Please try again later.")
            if pending_ts:
                answer += " The run stopped; check any requested changes in the gateway before retrying."
            try:
                if pending_ts:
                    await client.chat_update(channel=channel, ts=pending_ts, text=answer)
                else:
                    await client.chat_postMessage(channel=channel, thread_ts=thread, text=answer)
            except Exception:
                status = "reply_failed"
        except Exception as exc:
            logging.warning("Slack event %s failed (%s); event will not be replayed", event_id, type(exc).__name__)
            status = "reply_failed"
        finally:
            journal.finish(event_id, status)

    tasks = set()
    async def handle(body, client):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            await process(body, client)
        finally:
            tasks.discard(task)
    handle.tasks = tasks
    return handle


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list-tools", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--web", action="store_true", help="Serve A2A and health checks alongside Slack")
    args = parser.parse_args()
    load_dotenv()
    os.umask(0o077)
    set_tracing_disabled(True)
    settings = Settings.read()
    settings.validate()
    slack_enabled = settings.slack_enabled
    if not slack_enabled and not args.web and not args.check and not args.list_tools:
        raise ValueError("Enable Slack or use --web")
    if slack_enabled and not args.web and not args.check and not args.list_tools:
        raise ValueError("Slack account connections require the web server; start with python app.py --web")
    if args.list_tools:
        # Setup-only credential; the running service never reads this variable.
        credential = os.environ["LITELLM_SETUP_KEY"]
        async with mcp_session(settings, credential) as session:
            available = await all_tools(session)
        print(json.dumps([{"name": t.name, "description": t.description} for t in available], indent=2))
        return
    slack_app = AsyncApp(token=settings.bot_token) if slack_enabled else None
    if slack_app:
        identity = await slack_app.client.auth_test()
        if identity.get("team_id") != settings.workspace:
            raise ValueError("Slack bot token belongs to a different workspace")
        await slack_app.client.users_info(user=identity["user_id"])
    if args.check:
        print(f"Configuration verified; Slack enabled={slack_enabled}; {len(settings.tool_names)} tools configured. Run doctor.py for gateway compatibility checks.")
        return
    async with httpx2.AsyncClient() as auth_client:
        authorizer = AdminAuthorizer(settings.gateway_url, settings.workspace, auth_client)
        journal = Journal(settings.db_path)
        connections = Connections(settings, ConnectionStore(journal.db, settings.encryption_key), authorizer,
                                  slack_app.client, LiteLLMSSO(settings.gateway_url, settings.public_url, auth_client)) if slack_app else None
        runner = AgentRunner(settings, journal)
        listener = build_listener(settings, journal, authorizer=authorizer, connections=connections, runner=runner)
        socket = None
        if slack_app:
            slack_app.event("message")(listener)
            socket = AsyncSocketModeHandler(slack_app, settings.app_token)
        server = None
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        async def ready():
            return runner.accepting and not stop.is_set() and (socket is None or await socket.client.is_connected())
        try:
            if args.web:
                from web import create_web_app
                web_app = create_web_app(settings, authorizer, runner, journal, connections, ready=ready)
                add_admin_api_routes(web_app, settings.gateway_url, authorizer, auth_client, read_only=settings.read_only)
                server = web.AppRunner(web_app, access_log=None, shutdown_timeout=20)
                await server.setup()
                await web.TCPSite(server, "0.0.0.0", int(os.getenv("PORT", "10000"))).start()
            if slack_enabled:
                await socket.connect_async()
            print(f"LiteLLM Admin ready; Slack enabled={slack_enabled}; proxy_admin access required.", flush=True)
            await stop.wait()
        finally:
            runner.accepting = False
            if socket:
                await socket.close_async()
            if listener.tasks:
                _, pending = await asyncio.wait(listener.tasks, timeout=20)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            await runner.close()
            if server:
                await server.cleanup()
            journal.db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())

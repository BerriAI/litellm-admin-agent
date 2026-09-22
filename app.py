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
from engine import AgentRunner
from admin_api import add_admin_api_routes
from sso import LiteLLMSSO


def chunks(text: str, size: int = 3000):
    for i in range(0, len(text), size):
        yield text[i:i + size]


def build_listener(settings: Settings, journal: Journal, model=None, connect=mcp_session,
                   *, authorizer, connections, runner=None):
    runner = runner or AgentRunner(settings, journal, model, connect)

    async def handle(body, client):
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
                          "This private link expires in 10 minutes. Sign in with LiteLLM SSO and confirm the code on the gateway. "
                          "Then send your request again.")
                if pending_ts:
                    await client.chat_update(channel=channel, ts=pending_ts, text="Your account connection changed. The run stopped; inspect gateway state before retrying changes.")
                else:
                    await client.chat_postMessage(channel=channel, thread_ts=thread, text=answer,
                                                  unfurl_links=False, unfurl_media=False)
            except (AccessDenied, AuthorizationUnavailable):
                await client.chat_postMessage(channel=channel, thread_ts=thread,
                    text="I couldn’t verify your BerriAI Slack membership. Please try again later.")
        except (AccessDenied, AuthorizationUnavailable) as exc:
            status = "denied" if isinstance(exc, AccessDenied) else "authorization_unavailable"
            answer = ("Your LiteLLM admin session couldn’t be verified. Your BerriAI Slack email must match an active LiteLLM proxy-admin account. Send connect to sign in again with SSO."
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
    slack_enabled = os.getenv("SLACK_ENABLED", "true").lower() in ("true", "1")
    if not slack_enabled and not args.web and not args.check and not args.list_tools:
        raise ValueError("Enable Slack or use --web")
    if args.list_tools:
        # Setup-only credential; the running service never reads this variable.
        credential = os.environ["LITELLM_SETUP_KEY"]
        async with mcp_session(settings, credential) as session:
            available = await all_tools(session)
        print(json.dumps([{"name": t.name, "description": t.description} for t in available], indent=2))
        return
    slack_app = AsyncApp(token=settings.bot_token)
    identity = await slack_app.client.auth_test()
    if identity.get("team_id") != settings.workspace:
        raise ValueError("Slack bot token belongs to a different workspace")
    # Fail startup clearly if the installed token is missing the new role-lookup scopes.
    if slack_enabled or args.check:
        await slack_app.client.users_info(user=identity["user_id"])
    if args.check:
        print(f"Slack identity and user lookup verified; {len(settings.tool_names)} tools configured. No messages or administrative changes sent.")
        return
    async with httpx2.AsyncClient() as auth_client:
        authorizer = AdminAuthorizer(settings.gateway_url, settings.workspace, auth_client)
        journal = Journal(settings.db_path)
        connections = Connections(settings, ConnectionStore(journal.db, settings.encryption_key), authorizer,
                                  slack_app.client, LiteLLMSSO(settings.gateway_url, auth_client))
        runner = AgentRunner(settings, journal)
        slack_app.event("message")(build_listener(settings, journal, authorizer=authorizer,
                                                  connections=connections, runner=runner))
        socket = AsyncSocketModeHandler(slack_app, settings.app_token)
        server = None
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        try:
            if args.web:
                from web import create_web_app
                web_app = create_web_app(settings, authorizer, runner, journal, connections)
                add_admin_api_routes(web_app, settings.gateway_url, authorizer, auth_client)
                server = web.AppRunner(web_app, access_log=None)
                await server.setup()
                await web.TCPSite(server, "0.0.0.0", int(os.getenv("PORT", "10000"))).start()
            if slack_enabled:
                await socket.connect_async()
            print(f"LiteLLM Admin ready; Slack enabled={slack_enabled}; proxy_admin access required.", flush=True)
            await stop.wait()
        finally:
            await socket.close_async()
            if server:
                await server.cleanup()
            journal.db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())

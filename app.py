"""Slack Socket Mode adapter and hosted service entry point."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import signal

import httpx2
from aiohttp import web
from agents import set_tracing_disabled
from dotenv import load_dotenv
from agentchat.channels import Slack
from agentchat.models import Message
from slack_sdk.web.async_client import AsyncWebClient

from agent import Settings, mcp_session
from auth import AccessDenied, AdminAuthorizer, AuthorizationUnavailable
from core import Journal, SlackThreads, all_tools
from connections import ConnectionRequired, ConnectionStore, Connections
from engine import AgentBusy, AgentRunner
from sso import LiteLLMSSO
from slack_tools import slack_user_tool


def chunks(text: str, size: int = 3000):
    for i in range(0, len(text), size):
        yield text[i:i + size]


def build_listener(settings: Settings, journal: Journal, client, model=None, connect=mcp_session,
                   *, authorizer, connections, runner=None):
    runner = runner or AgentRunner(settings, journal, model, connect)

    async def handle(channel: Slack, message: Message):
        if (message.metadata.get("team_id") != settings.workspace
                or message.metadata.get("channel_type") not in {"im", "channel", "group"}):
            return
        user = message.sender.id
        event_id = message.metadata["event_id"]
        # Preserve old event-ID records and coalesce app_mention/message deliveries.
        event_ids = list(dict.fromkeys([event_id, message.id]))
        if not journal.claim_many(event_ids, "slack:" + user):
            return
        private = message.metadata["channel_type"] == "im"
        pending = None
        ran = False
        status = "failed"

        async def reply(answer):
            if pending:
                await client.chat_update(channel=message.metadata["channel_id"],
                                         ts=pending.metadata["message_timestamp"], text=answer)
            else:
                await channel.reply(message, answer)

        async def send_private(answer):
            try:
                await client.chat_postMessage(channel=user, text=answer,
                                              unfurl_links=False, unfurl_media=False)
                return True
            except Exception as exc:
                logging.warning("Private Slack reply failed (%s)", type(exc).__name__)
                return False

        try:
            command = message.text.casefold()
            if command == "disconnect":
                await authorizer.slack_email(user, client)
                connections.disconnect(user)
                runner.conversations = {k: v for k, v in runner.conversations.items()
                                        if not k[0].startswith("slack:" + user + ":")}
                await reply("Your LiteLLM account is disconnected. Your saved credential has been removed.")
                status = "completed"
                return
            if command == "connect":
                raise ConnectionRequired()
            connection = connections.get(user)
            principal = await authorizer.require_slack_admin(user, client, connection.credential)
            if principal.user_id != connection.user_id:
                raise AccessDenied()

            async def verify():
                current = connections.get(user)
                if current.version != connection.version:
                    raise AccessDenied()
                if await authorizer.require_slack_admin(user, client, connection.credential) != principal:
                    raise AccessDenied()

            if len(message.text) > 16000:
                status = "rejected"
                await reply("Please keep each request under 16,000 characters.")
                return
            await channel.subscribe(message)
            history = None
            text = message.text
            if private:
                pending = await channel.reply(message, "Working on your request…")
            else:
                try:
                    async with asyncio.timeout(15):
                        messages = await channel.thread_history(message, limit=30)
                except Exception as exc:
                    logging.warning("Slack thread history failed (%s)", type(exc).__name__)
                    status = "context_unavailable"
                    await reply("I couldn’t read this thread, so I haven’t run any operations. Try again, or start a new thread with the complete request.")
                    return
                history = [{"role": item.role, "content": f"<@{item.sender.id}>: " +
                            re.sub(r"\bsk-[A-Za-z0-9_-]{8,}", "[key redacted]", item.text[:4000])}
                           for item in messages]
                text = f"<@{user}>: {message.text}"
            outcome = await runner.execute(text, principal,
                message.conversation_id + ":" + connection.version, event_id, verify, connection.credential,
                extra_tools=(slack_user_tool(channel, settings.workspace, verify),),
                history=history, check_reply=not private and bool(message.metadata["requires_subscription"]))
            if outcome.status == "ignored":
                status = "ignored"
                return
            ran = True
            # Revocation during a run must also stop private data delivery.
            await verify()
            parts = list(chunks(outcome.answer))
            await reply(parts[0])
            for part in parts[1:]:
                await channel.reply(message, part)
            for reference, secret in outcome.secrets.items():
                await verify()
                if not await send_private(f"{reference}: `{secret}`\nSave this key securely. It was kept out of the model’s tool results."):
                    status = "reply_failed"
                    await channel.reply(message, "Your request finished, but I couldn’t deliver a generated key in a DM. Check the key in your gateway before retrying; creating it again may make a duplicate.")
                    return
            status = outcome.status
        except ConnectionRequired:
            status = "connection_required"
            if not private and message.metadata["requires_subscription"] and not ran:
                return
            try:
                link = await connections.link(user)
                delivered = await send_private(f"Connect your own LiteLLM admin account here: <{link}|Connect account>\n"
                    "This private link expires in 10 minutes. Complete the secure connection page. Never paste keys into Slack. "
                    "Then send your request again; in a channel, mention me again.")
                if not delivered:
                    status = "reply_failed"
                    await reply("I couldn’t send you a private connection link. Open LiteLLM Admin in Slack Apps and send connect in a DM.")
                elif pending or ran:
                    await reply("Your account connection changed. The run stopped; inspect gateway state before retrying changes. I sent you a private link to reconnect.")
                elif not private:
                    await reply("I sent you a private link to connect your LiteLLM admin account. Once connected, mention me again here.")
            except (AccessDenied, AuthorizationUnavailable):
                await reply("I couldn’t verify your Slack workspace membership. Please try again later.")
        except AgentBusy:
            status = "busy"
            await reply("The agent is busy. No operation started for this request. Please send it again shortly.")
        except (AccessDenied, AuthorizationUnavailable) as exc:
            status = "denied" if isinstance(exc, AccessDenied) else "authorization_unavailable"
            if not private and message.metadata["requires_subscription"] and not ran:
                return
            answer = ("Your LiteLLM admin session couldn’t be verified. Your Slack email must match an active LiteLLM proxy-admin account. Send connect to reconnect."
                      if isinstance(exc, AccessDenied) else "I can’t verify your admin access right now. Please try again later.")
            if pending or ran:
                answer += " The run stopped; check any requested changes in the gateway before retrying."
            await reply(answer)
        except Exception as exc:
            logging.warning("Slack event %s failed (%s); event will not be replayed", event_id, type(exc).__name__)
            status = "reply_failed"
        finally:
            for identifier in event_ids:
                journal.finish(identifier, status)

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
    slack_client = AsyncWebClient(token=settings.bot_token) if slack_enabled else None
    if slack_client and args.check:
        identity = await slack_client.auth_test()
        if identity.get("team_id") != settings.workspace:
            raise ValueError("Slack bot token belongs to a different workspace")
        await slack_client.users_info(user=identity["user_id"])
    if args.check:
        print(f"Configuration verified; Slack enabled={slack_enabled}; {len(settings.tool_names)} tools configured. Run doctor.py for gateway compatibility checks.")
        return
    async with httpx2.AsyncClient() as auth_client:
        authorizer = AdminAuthorizer(settings.gateway_url, settings.workspace, auth_client)
        journal = Journal(settings.db_path)
        connections = Connections(settings, ConnectionStore(journal.db, settings.encryption_key), authorizer,
                                  slack_client, LiteLLMSSO(settings.gateway_url, settings.public_url, auth_client)) if slack_client else None
        runner = AgentRunner(settings, journal)
        slack = None
        if slack_client:
            slack = Slack(bot_token=settings.bot_token, app_token=settings.app_token,
                          web_client=slack_client, workspace_id=settings.workspace,
                          thread_subscriptions=SlackThreads(journal))
            slack.bind(build_listener(settings, journal, slack_client, authorizer=authorizer,
                                      connections=connections, runner=runner))
        transport_task = None
        stop_task = None
        server = None
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        async def ready():
            return runner.accepting and not stop.is_set() and (slack is None or await slack.is_connected())
        try:
            if args.web:
                from web import create_web_app
                web_app = create_web_app(settings, authorizer, runner, journal, connections, ready=ready)
                server = web.AppRunner(web_app, access_log=None, shutdown_timeout=20)
                await server.setup()
                await web.TCPSite(server, "0.0.0.0", int(os.getenv("PORT", "10000"))).start()
            stop_task = asyncio.create_task(stop.wait())
            if slack:
                transport_task = asyncio.create_task(slack.run())
                done, _ = await asyncio.wait({transport_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
                if transport_task in done:
                    await transport_task  # Fail startup if Socket Mode cannot connect.
            else:
                await stop_task
        finally:
            runner.accepting = False
            if slack:
                await slack.close()
            for task in (transport_task, stop_task):
                if task:
                    task.cancel()
            await asyncio.gather(*(t for t in (transport_task, stop_task) if t), return_exceptions=True)
            await runner.close()
            if server:
                await server.cleanup()
            journal.db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())

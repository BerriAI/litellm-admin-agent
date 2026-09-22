"""A2A 0.3 JSON-RPC endpoint with independently verified gateway callers."""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from urllib.parse import urlparse

from aiohttp import web

from auth import AccessDenied, AuthorizationUnavailable


def agent_card(public_url: str) -> dict:
    parsed = urlparse(public_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("AGENT_PUBLIC_URL must be the hosted HTTPS URL")
    return {
        "name": "LiteLLM Admin", "description": "Manage keys, teams and budgets. LiteLLM proxy admins only.",
        "url": public_url.rstrip("/") + "/a2a", "version": "1.0.0", "protocolVersion": "0.3.0",
        "preferredTransport": "JSONRPC", "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
        "securitySchemes": {
            "gatewayCaller": {"type": "http", "scheme": "bearer"},
            "gatewayService": {"type": "apiKey", "in": "header", "name": "X-Admin-Agent-Token"},
        },
        "security": [{"gatewayCaller": [], "gatewayService": []}],
        "skills": [{"id": "litellm-admin", "name": "Gateway administration", "tags": ["keys", "teams", "budgets"],
                    "description": "Read spend and budgets; manage keys, teams, and users when requested."}],
    }


def error(rpc_id, code: int, message: str, status=200):
    return web.json_response({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}},
                             status=status, headers={"Cache-Control": "no-store"})


def identifier(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 200 and all(ord(c) >= 32 for c in value)


def create_web_app(settings, authorizer, runner, journal):
    if len(settings.service_token) < 32:
        raise ValueError("ADMIN_AGENT_SERVICE_TOKEN must have at least 32 characters")
    card = agent_card(settings.public_url)
    app = web.Application(client_max_size=32000)
    active = 0

    async def health(_):
        return web.json_response({"status": "ok"})

    async def discovery(_):
        return web.json_response(card)

    async def send(request):
        nonlocal active
        supplied = request.headers.get("X-Admin-Agent-Token", "")
        if not hmac.compare_digest(supplied.encode(), settings.service_token.encode()):
            return error(None, -32001, "Gateway authentication required", 401)
        scheme, _, bearer = request.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer":
            return error(None, -32001, "Caller authentication required", 401)
        try:
            principal = await authorizer.require_gateway_admin(bearer)
        except AccessDenied:
            return error(None, -32003, "LiteLLM proxy_admin access required", 403)
        except AuthorizationUnavailable:
            return error(None, -32002, "Admin authorization is temporarily unavailable", 503)
        try:
            body = await request.json()
        except (ValueError, UnicodeError):
            return error(None, -32700, "Invalid JSON")
        if not isinstance(body, dict):
            return error(None, -32600, "A single JSON-RPC request is required")
        rpc_id = body.get("id")
        if body.get("jsonrpc") != "2.0" or not (identifier(rpc_id) or type(rpc_id) is int):
            return error(None, -32600, "A JSON-RPC request ID is required")
        if body.get("method") != "message/send":
            return error(rpc_id, -32601, "Only message/send is supported")
        params = body.get("params")
        message = params.get("message") if isinstance(params, dict) else None
        if not isinstance(message, dict) or message.get("role") != "user" or not identifier(message.get("messageId")):
            return error(rpc_id, -32602, "A user message with messageId is required")
        context = message.get("contextId") or str(uuid.uuid4())
        parts = message.get("parts")
        if (not identifier(context) or message.get("taskId") or not isinstance(parts, list) or not 1 <= len(parts) <= 20
                or any(not isinstance(p, dict) or p.get("kind") != "text" or not isinstance(p.get("text"), str) for p in parts)):
            return error(rpc_id, -32602, "Only text messages and contextId are supported")
        text = "\n".join(p["text"] for p in parts).strip()
        if not text or len(text) > 16000:
            return error(rpc_id, -32602, "Message must contain 1–16,000 characters")
        if active >= 16:
            return error(rpc_id, -32005, "Service is busy; no operation started", 429)
        # Each ID is unique for this authenticated user across contexts and restarts.
        def event_key(kind, value):
            return "a2a:" + hashlib.sha256(json.dumps([principal.actor, kind, value]).encode()).hexdigest()
        event_id = event_key("message", message["messageId"])
        if not journal.claim_many([event_id, event_key("rpc", rpc_id)], principal.actor):
            return error(rpc_id, -32009, "Request was already received. It will not be replayed; inspect gateway state before retrying a change.", 409)

        async def verify():
            if await authorizer.require_gateway_admin(bearer) != principal:
                raise AccessDenied()

        active += 1
        status = "failed"
        try:
            outcome = await runner.execute(text, principal, context, event_id, verify)
            await verify()
            result_parts = [{"kind": "text", "text": outcome.answer}]
            for reference, secret in outcome.secrets.items():
                result_parts.append({"kind": "text", "text": f"{reference}: {secret}\nSave this key securely."})
            status = outcome.status
            return web.json_response({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "kind": "message", "role": "agent", "messageId": str(uuid.uuid4()),
                "contextId": context, "parts": result_parts,
            }}, headers={"Cache-Control": "no-store"})
        except AccessDenied:
            status = "denied"
            return error(rpc_id, -32003, "Admin access was revoked. Inspect gateway state before retrying changes.", 403)
        except AuthorizationUnavailable:
            return error(rpc_id, -32002, "Admin access could not be reverified. Inspect gateway state before retrying changes.", 503)
        except Exception:
            return error(rpc_id, -32603, "Request stopped. Inspect gateway state before retrying changes.", 500)
        finally:
            active -= 1
            journal.finish(event_id, status)

    app.router.add_get("/healthz", health)
    app.router.add_get("/.well-known/agent-card.json", discovery)
    app.router.add_get("/.well-known/agent.json", discovery)
    app.router.add_post("/a2a", send)
    return app

"""Role-gated backend for the shared personal_admin MCP server."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import httpx2
from aiohttp import web

from auth import AccessDenied, AuthorizationUnavailable


def add_admin_api_routes(app: web.Application, gateway_url: str, authorizer, client) -> None:
    operations = json.loads((Path(__file__).parent / "admin-operations.json").read_text())["operations"]
    routes = {"admin_api_" + operation["operation_id"]: operation for operation in operations}

    def error(message: str, status: int):
        return web.json_response({"error": message}, status=status, headers={"Cache-Control": "no-store"})

    async def forward(request: web.Request):
        header = request.headers.get("Authorization", "")
        scheme, _, credential = header.partition(" ")
        if scheme.casefold() != "bearer" or not credential:
            return error("A personal gateway admin credential is required.", 401)
        operation = routes[request.match_info.route.name]
        try:
            principal = await authorizer.require_gateway_admin(credential)
            path = operation["path"]
            for name, value in request.match_info.items():
                if value in ("", ".", "..") or any(c in value for c in ("/", "\\", "\r", "\n", "\x00")):
                    return error("Invalid resource identifier.", 400)
                path = path.replace("{" + name + "}", quote(value, safe=""))
            body = await request.read()
            if body:
                if request.content_type != "application/json":
                    return error("The request body must be JSON.", 415)
                try:
                    json.loads(body)
                except (ValueError, UnicodeDecodeError):
                    return error("Invalid JSON request body.", 400)
            response = await client.request(
                operation["method"], gateway_url + path,
                params=list(request.query.items()), content=body,
                headers={"Authorization": "Bearer " + credential,
                         "Content-Type": "application/json", "litellm-changed-by": principal.user_id},
                timeout=httpx2.Timeout(60, read=120), follow_redirects=False,
            )
            if await authorizer.require_gateway_admin(credential) != principal:
                raise AccessDenied()
            if 300 <= response.status_code < 400:
                return error("The gateway returned an unexpected redirect.", 502)
            # The upstream key remains the execution identity. Do not expose it
            # if an upstream error happens to echo the authenticating credential.
            content = response.content.replace(credential.encode(), b"[credential redacted]")
            return web.Response(body=content, status=response.status_code, headers={
                "Content-Type": response.headers.get("Content-Type", "application/json"),
                "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            })
        except AccessDenied:
            return error("Only current LiteLLM gateway admins may use these tools.", 403)
        except AuthorizationUnavailable:
            return error("Admin access could not be verified.", 503)
        except (httpx2.TimeoutException, httpx2.NetworkError):
            # A write may already have reached the gateway. Never replay it here.
            return error("The gateway did not confirm the outcome. Do not repeat a change; inspect gateway state first.", 504)

    for name, operation in routes.items():
        app.router.add_route(operation["method"], "/admin-api" + operation["path"], forward, name=name)

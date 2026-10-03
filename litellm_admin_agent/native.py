from __future__ import annotations

import hmac
import math
import time

from aiohttp import web

from litellm_admin_agent.auth import AccessDenied, AuthorizationUnavailable
from litellm_admin_agent.connections import ConnectionRequired


class NativeConnections:
    def __init__(self, connections):
        self.connections = connections

    def get(self, slack_user):
        return self.connections.get(slack_user)

    def disconnect(self, slack_user):
        self.connections.disconnect(slack_user)

    async def link(self, slack_user):
        connection = self.connections
        await connection.authorizer.slack_email(slack_user, connection.slack)
        token = connection.store.issue(connection.owner(slack_user))
        return connection.settings.gateway_url + "/liteadmin/slack/connect/" + token

    def add_routes(self, app):
        app.router.add_get("/internal/liteadmin/links/{token}", self.link_details)
        app.router.add_post("/internal/liteadmin/links/{token}", self.complete)

    def _owner(self, request):
        supplied = request.headers.get("X-LiteLLM-Admin-Agent-Token", "")
        expected = self.connections.settings.service_token
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise web.HTTPUnauthorized()
        try:
            owner = self.connections.store.owner(request.match_info["token"])
        except ConnectionRequired:
            raise web.HTTPGone() from None
        workspace, slack_user = owner.split(":", 1)
        if workspace != self.connections.settings.workspace:
            raise web.HTTPForbidden()
        return owner, workspace, slack_user

    async def link_details(self, request):
        _, workspace, slack_user = self._owner(request)
        try:
            email = await self.connections.authorizer.slack_email(slack_user, self.connections.slack)
        except AccessDenied:
            raise web.HTTPForbidden() from None
        except AuthorizationUnavailable:
            raise web.HTTPServiceUnavailable() from None
        return web.json_response({"workspace_id": workspace, "slack_user_id": slack_user, "email": email},
                                 headers={"Cache-Control": "no-store"})

    async def complete(self, request):
        owner, _, slack_user = self._owner(request)
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError()
            credential, expires, user_id = (data.get(key) for key in ("credential", "expires_at", "user_id"))
            if (not isinstance(credential, str) or not credential.startswith("litellm_login_")
                    or type(expires) not in (int, float) or not math.isfinite(expires)
                    or not time.time() < expires <= time.time() + 86460
                    or not isinstance(user_id, str) or not user_id):
                raise ValueError()
        except (ValueError, TypeError):
            raise web.HTTPBadRequest() from None
        try:
            principal = await self.connections.authorizer.require_slack_admin(
                slack_user, self.connections.slack, credential)
            if principal.user_id != user_id:
                raise AccessDenied()
            self.connections.store.finish(request.match_info["token"], owner, user_id, credential, expires)
        except AccessDenied:
            raise web.HTTPForbidden() from None
        except AuthorizationUnavailable:
            raise web.HTTPServiceUnavailable() from None
        except ConnectionRequired:
            raise web.HTTPGone() from None
        return web.json_response({"status": "connected"}, headers={"Cache-Control": "no-store"})

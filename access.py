"""Enroll verified administrators' own keys in the shared admin MCP server."""
from __future__ import annotations

import asyncio
import hashlib

from auth import AccessDenied, AdminAuthorizer, Principal


class ToolAccessUnavailable(Exception):
    """Automatic enrollment could not be verified; do not start an agent run."""


class AdminToolAccess:
    def __init__(self, authorizer: AdminAuthorizer, alias: str, server_id: str):
        if alias != "personal_admin":
            raise ValueError("Automatic enrollment is limited to personal_admin")
        self.authorizer = authorizer
        self.alias = alias
        if not server_id:
            raise ValueError("Automatic enrollment requires the configured MCP server ID")
        self.server_id = server_id
        self.lock = asyncio.Lock()

    async def _request(self, method: str, path: str, credential: str, **kwargs):
        try:
            response = await self.authorizer.client.request(
                method, self.authorizer.base_url + path,
                headers={"Authorization": "Bearer " + credential},
                timeout=15, follow_redirects=False, **kwargs,
            )
            response.raise_for_status()
            return response.json()
        except Exception:
            # HTTP bodies and exception messages can contain credentials.
            raise ToolAccessUnavailable() from None

    async def _visible(self, credential: str) -> bool:
        rows = await self._request("GET", "/v1/mcp/server", credential)
        if isinstance(rows, dict):
            rows = rows.get("servers", rows.get("data"))
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ToolAccessUnavailable()
        return any(row.get("alias") == self.alias and row.get("server_id") == self.server_id for row in rows)

    async def _wait_until_visible(self, credential: str) -> None:
        # The gateway caches object permissions separately from the key. A saved
        # grant can take one management-cache TTL to become effective. Poll reads
        # only; never repeat the permission update to force a cache refresh.
        for delay in (0, 1, 2, 4, 8, 15, 15, 15, 10):
            if delay:
                await asyncio.sleep(delay)
            if await self._visible(credential):
                return
        raise ToolAccessUnavailable()

    async def ensure(self, principal: Principal, credential: str) -> None:
        async with self.lock:
            current = await self.authorizer.require_gateway_admin(credential)
            if current.user_id != principal.user_id:
                raise AccessDenied()
            if await self._visible(credential):
                return

            # No caller-supplied key ID: inspect only the authenticating key.
            data = await self._request("GET", "/key/info", credential)
            info = data.get("info") if isinstance(data, dict) else None
            key_hash = hashlib.sha256(credential.encode()).hexdigest()
            if (not isinstance(info, dict) or info.get("user_id") != current.user_id
                    or data.get("key") not in (credential, key_hash)
                    or info.get("blocked") or info.get("status") in ("expired", "revoked", "deleted")):
                raise ToolAccessUnavailable()
            permission = info.get("object_permission")
            servers = permission.get("mcp_servers") if isinstance(permission, dict) else None
            if not isinstance(servers, list) or any(not isinstance(item, str) for item in servers):
                # An unrestricted key should already see this server. Do not turn
                # a registry/configuration failure into an unrelated scope change.
                raise ToolAccessUnavailable()
            if self.server_id in servers:
                await self._wait_until_visible(credential)
                return

            # Recheck the live role immediately before the grant. The gateway also
            # authorizes this update using the same personal key, never a service key.
            if (await self.authorizer.require_gateway_admin(credential)).user_id != principal.user_id:
                raise AccessDenied()
            await self._request("POST", "/key/update", credential, json={
                "key": key_hash,
                "object_permission": {"mcp_servers": [item for item in servers
                    if item not in (self.alias, "no-mcp-servers")] + [self.server_id]},
            })
            # /key/update merges nested permission fields. Omitted model, budget,
            # other-object and per-tool restrictions retain their stored values.
            await self._wait_until_visible(credential)

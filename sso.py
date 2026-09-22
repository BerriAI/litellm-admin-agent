"""LiteLLM device sign-in: browser SSO with a server-held polling secret.

This uses the same supported flow as `lite login`. It does not pretend to be a
loopback OAuth client or send a gateway credential through a browser callback.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

from auth import AuthorizationUnavailable


class SignInExpired(Exception):
    pass


@dataclass(frozen=True)
class DeviceFlow:
    login_id: str
    user_code: str
    expires_at: float
    poll_secret: str = field(repr=False)


@dataclass(frozen=True)
class SignInResult:
    user_id: str = ""
    credential: str = field(default="", repr=False)
    teams: tuple[tuple[str, str], ...] = ()


class LiteLLMSSO:
    def __init__(self, gateway_url, client):
        self.gateway_url = gateway_url
        self.client = client

    async def _request(self, method, path, **kwargs):
        try:
            response = await self.client.request(method, self.gateway_url + path,
                timeout=15, follow_redirects=False, **kwargs)
            if response.status_code in (400, 401, 403, 404, 410):
                raise SignInExpired()
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except SignInExpired:
            raise
        except Exception:
            # Responses/errors can contain credentials. Never log their bodies.
            raise AuthorizationUnavailable() from None

    async def start(self) -> DeviceFlow:
        data = await self._request("POST", "/sso/cli/start", json={})
        try:
            login_id, secret, code, ttl = (data[k] for k in
                ("login_id", "poll_secret", "user_code", "expires_in"))
            if (not isinstance(login_id, str) or not re.fullmatch(r"cli-[A-Za-z0-9_-]{12,124}", login_id)
                    or not isinstance(secret, str) or not 32 <= len(secret) <= 1024
                    or not isinstance(code, str) or not re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}", code)
                    or type(ttl) is not int or not 1 <= ttl <= 3600):
                raise ValueError()
            return DeviceFlow(login_id, code, time.time() + min(ttl, 600), secret)
        except (ValueError, KeyError, TypeError):
            raise AuthorizationUnavailable() from None

    def sign_in_url(self, flow: DeviceFlow) -> str:
        # Only the trusted gateway can be a destination. Do not follow any URL
        # returned in a response or put the polling secret in browser content.
        return self.gateway_url + "/sso/key/generate?" + urlencode({
            "source": "litellm-cli", "key": flow.login_id,
        })

    async def poll(self, flow: DeviceFlow, team_id: str | None = None) -> SignInResult:
        if flow.expires_at <= time.time():
            raise SignInExpired()
        data = await self._request("GET", "/sso/cli/poll/" + flow.login_id,
            headers={"x-litellm-cli-poll-secret": flow.poll_secret},
            params={"team_id": team_id} if team_id else None)
        if data.get("status") == "pending":
            return SignInResult()
        try:
            if data.get("status") != "ready" or not isinstance(data.get("user_id"), str) or not data["user_id"]:
                raise ValueError()
            if data.get("requires_team_selection") is True:
                teams = data.get("teams")
                if (not isinstance(teams, list) or not teams or len(teams) > 1000
                        or any(not isinstance(t, str) or not t or len(t) > 512 for t in teams)):
                    raise ValueError()
                details = data.get("team_details") or []
                aliases = {t["team_id"]: t["team_alias"] for t in details
                           if isinstance(t, dict) and isinstance(t.get("team_id"), str)
                           and isinstance(t.get("team_alias"), str)}
                return SignInResult(user_id=data["user_id"],
                    teams=tuple((t, aliases.get(t) or t) for t in teams))
            credential = data.get("key")
            if not isinstance(credential, str) or not 1 <= len(credential) <= 8192 or any(c.isspace() for c in credential):
                raise ValueError()
            if team_id and data.get("team_id") != team_id:
                raise ValueError()
            return SignInResult(user_id=data["user_id"], credential=credential)
        except (ValueError, KeyError, TypeError):
            raise AuthorizationUnavailable() from None

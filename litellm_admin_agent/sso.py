"""Browser authorization-code login against the configured LiteLLM gateway."""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

from litellm_admin_agent.auth import AuthorizationUnavailable


class SignInExpired(Exception):
    pass


@dataclass(frozen=True)
class OAuthFlow:
    client_id: str
    expires_at: float
    state: str = field(repr=False)
    code_verifier: str = field(repr=False)


@dataclass(frozen=True)
class SignInResult:
    user_id: str
    expires_at: float
    credential: str = field(repr=False)


class LiteLLMSSO:
    def __init__(self, gateway_url, public_url, client):
        self.gateway_url = gateway_url
        self.callback_url = public_url + "/oauth/callback"
        self.client = client

    async def _request(self, path, *, parse_response=True, **kwargs):
        try:
            response = await self.client.post(self.gateway_url + path,
                timeout=15, follow_redirects=False, **kwargs)
            if response.status_code in (400, 401, 403, 410):
                raise SignInExpired()
            response.raise_for_status()
            if not parse_response:
                return {}
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except SignInExpired:
            raise
        except Exception:
            # Upstream error bodies may contain credentials or authorization codes.
            raise AuthorizationUnavailable() from None

    async def start(self) -> OAuthFlow:
        data = await self._request("/register", json={
            "client_name": "LiteLLM Admin", "redirect_uris": [self.callback_url],
            "grant_types": ["authorization_code"], "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })
        client_id = data.get("client_id")
        if (not isinstance(client_id, str) or not 1 <= len(client_id) <= 8192
                or data.get("redirect_uris") != [self.callback_url]
                or data.get("token_endpoint_auth_method") != "none"):
            raise AuthorizationUnavailable()
        return OAuthFlow(client_id, time.time() + 600, secrets.token_urlsafe(32), secrets.token_urlsafe(64))

    def sign_in_url(self, flow: OAuthFlow) -> str:
        challenge = base64.urlsafe_b64encode(hashlib.sha256(flow.code_verifier.encode()).digest()).rstrip(b"=").decode()
        return self.gateway_url + "/authorize?" + urlencode({
            "client_id": flow.client_id, "redirect_uri": self.callback_url,
            "response_type": "code", "state": flow.state,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "resource": self.gateway_url,
        })

    async def exchange(self, flow: OAuthFlow, code: str) -> SignInResult:
        if flow.expires_at <= time.time() or not code or len(code) > 16384:
            raise SignInExpired()
        data = await self._request("/token", data={
            "grant_type": "authorization_code", "code": code, "client_id": flow.client_id,
            "redirect_uri": self.callback_url, "code_verifier": flow.code_verifier,
            "resource": self.gateway_url,
        })
        # This app deliberately keeps a bounded session and asks for SSO again
        # on expiry. It does not retain or use the optional renewal credential.
        refresh = data.get("refresh_token")
        if isinstance(refresh, str) and refresh:
            try:
                await self._request("/revoke", parse_response=False, data={"client_id": flow.client_id, "token": refresh,
                                                     "token_type_hint": "refresh_token"})
            except (AuthorizationUnavailable, SignInExpired):
                logging.warning("Unused SSO refresh token could not be revoked; it was discarded")
        credential, user_id, ttl = (data.get(k) for k in ("access_token", "user_id", "expires_in"))
        token_type = data.get("token_type")
        if (not isinstance(token_type, str) or token_type.casefold() != "bearer"
                or not isinstance(credential, str) or not 1 <= len(credential) <= 8192
                or any(c.isspace() for c in credential)
                or not isinstance(user_id, str) or not user_id
                or type(ttl) is not int or not 1 <= ttl <= 366 * 86400):
            raise AuthorizationUnavailable()
        return SignInResult(user_id, time.time() + ttl, credential)

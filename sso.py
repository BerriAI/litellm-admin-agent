"""Browser authorization-code login against the configured LiteLLM gateway."""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from auth import AuthorizationUnavailable

SCOPE = "proxy:admin"
SESSION_SECONDS = 86400


class SignInExpired(Exception):
    pass


class GatewayIncompatible(AuthorizationUnavailable):
    pass


@dataclass(frozen=True)
class OAuthFlow:
    client_id: str
    expires_at: float
    state: str = field(repr=False)
    code_verifier: str = field(repr=False)
    resource: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    revocation_endpoint: str = ""


@dataclass(frozen=True)
class SignInResult:
    expires_at: float
    credential: str = field(repr=False)
    refresh_token: str = field(repr=False)
    client_id: str
    resource: str
    token_endpoint: str
    revocation_endpoint: str
    session_expires_at: float


def _secret(value):
    return isinstance(value, str) and 1 <= len(value) <= 8192 and not any(c.isspace() for c in value)


class LiteLLMSSO:
    def __init__(self, gateway_url, public_url, client):
        self.gateway_url = gateway_url
        self.callback_url = public_url + "/oauth/callback"
        self.client = client

    def _endpoint(self, url):
        try:
            parsed, trusted = urlsplit(url), urlsplit(self.gateway_url)
            if (trusted.scheme != "https" or not trusted.hostname or trusted.username or trusted.password
                    or parsed.scheme != "https" or parsed.netloc != trusted.netloc or parsed.username or parsed.password
                    or parsed.query or parsed.fragment or not parsed.path.startswith("/")):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise GatewayIncompatible() from None
        return url

    def _bound(self, session):
        if session.resource != self.gateway_url:
            raise GatewayIncompatible()
        self._endpoint(session.token_endpoint)
        self._endpoint(session.revocation_endpoint)

    async def _request(self, url, *, method="POST", parse_response=True, **kwargs):
        self._endpoint(url)
        try:
            response = await self.client.request(method, url, timeout=15, follow_redirects=False, **kwargs)
            if method == "GET" and response.status_code == 404:
                raise GatewayIncompatible()
            if response.status_code in (400, 401, 403, 410):
                raise SignInExpired()
            response.raise_for_status()
            if not parse_response:
                return {}
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except (SignInExpired, GatewayIncompatible):
            raise
        except Exception:
            raise AuthorizationUnavailable() from None

    async def start(self) -> OAuthFlow:
        gateway = urlsplit(self.gateway_url)
        discovery = gateway._replace(path="/.well-known/oauth-authorization-server" + gateway.path + "/oauth/api")
        metadata = await self._request(discovery.geturl(), method="GET")
        supported = {"scopes_supported": {SCOPE}, "response_types_supported": {"code"},
                     "grant_types_supported": {"authorization_code", "refresh_token"},
                     "code_challenge_methods_supported": {"S256"}, "token_endpoint_auth_methods_supported": {"none"}}
        if (metadata.get("issuer") != self.gateway_url + "/oauth/api"
                or any(not isinstance(metadata.get(key), list) or not all(isinstance(item, str) for item in metadata[key])
                       or not values.issubset(metadata[key]) for key, values in supported.items())):
            raise GatewayIncompatible()
        endpoints = {key: self._endpoint(metadata.get(key)) for key in (
            "authorization_endpoint", "token_endpoint", "revocation_endpoint", "registration_endpoint")}
        data = await self._request(endpoints.pop("registration_endpoint"), json={
            "client_name": "LiteLLM Admin", "redirect_uris": [self.callback_url],
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })
        if (not _secret(data.get("client_id")) or data.get("redirect_uris") != [self.callback_url]
                or data.get("token_endpoint_auth_method") != "none"):
            raise AuthorizationUnavailable()
        return OAuthFlow(data["client_id"], time.time() + 600, secrets.token_urlsafe(32), secrets.token_urlsafe(64),
                         resource=self.gateway_url, **endpoints)

    def sign_in_url(self, flow: OAuthFlow) -> str:
        self._bound(flow)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(flow.code_verifier.encode()).digest()).rstrip(b"=").decode()
        return self._endpoint(flow.authorization_endpoint) + "?" + urlencode({
            "client_id": flow.client_id, "redirect_uri": self.callback_url,
            "response_type": "code", "state": flow.state,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "resource": flow.resource, "scope": SCOPE,
        })

    def _tokens(self, data, binding, started, deadline):
        credential, refresh, ttl = (data.get(k) for k in ("access_token", "refresh_token", "expires_in"))
        token_type = data.get("token_type")
        if (not isinstance(token_type, str) or token_type.casefold() != "bearer"
                or not _secret(credential) or not _secret(refresh) or type(ttl) is not int or not 1 <= ttl <= 366 * 86400
                or data.get("scope", SCOPE) != SCOPE):
            raise AuthorizationUnavailable()
        return SignInResult(min(started + ttl, deadline), credential, refresh, binding.client_id, binding.resource,
                            binding.token_endpoint, binding.revocation_endpoint, deadline)

    async def exchange(self, flow: OAuthFlow, code: str) -> SignInResult:
        self._bound(flow)
        if flow.expires_at <= time.time() or not code or len(code) > 16384:
            raise SignInExpired()
        started = time.time()
        data = await self._request(flow.token_endpoint, data={
            "grant_type": "authorization_code", "code": code, "client_id": flow.client_id,
            "redirect_uri": self.callback_url, "code_verifier": flow.code_verifier, "resource": flow.resource,
        })
        return self._tokens(data, flow, started, started + SESSION_SECONDS)

    async def refresh(self, session: SignInResult) -> SignInResult:
        self._bound(session)
        if session.session_expires_at <= time.time():
            raise SignInExpired()
        started = time.time()
        data = await self._request(session.token_endpoint, data={
            "grant_type": "refresh_token", "refresh_token": session.refresh_token,
            "client_id": session.client_id, "resource": session.resource,
        })
        result = self._tokens(data, session, started, session.session_expires_at)
        if result.refresh_token == session.refresh_token:
            raise AuthorizationUnavailable()
        return result

    async def revoke(self, session: SignInResult) -> None:
        original_gateway = LiteLLMSSO(session.resource, "", self.client)
        await original_gateway._request(session.revocation_endpoint, parse_response=False, data={
            "client_id": session.client_id, "token": session.refresh_token, "token_type_hint": "refresh_token",
        })

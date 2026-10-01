import base64
import hashlib
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest

from auth import AuthorizationUnavailable
from sso import GatewayIncompatible, OAuthFlow, LiteLLMSSO, SignInExpired

GATEWAY = "https://gateway.example"
APP = "https://admin.example"


def flow():
    return OAuthFlow("registered-client", time.time() + 600, "private-state", "private-pkce-verifier",
                     GATEWAY, GATEWAY, GATEWAY + "/authorize", GATEWAY + "/token", GATEWAY + "/revoke")


def token_body(**override):
    return {"access_token": "personal-session", "user_id": "alice", "token_type": "Bearer",
            "expires_in": 300, "refresh_token": "refresh-secret", "refresh_expires_in": 86400,
            "scope": "proxy:admin", **override}


@pytest.mark.asyncio
async def test_code_flow_discovers_fixed_gateway_and_keeps_bound_rotating_session():
    requests = []
    def respond(request):
        requests.append(request)
        if request.url.path == "/.well-known/litellm-cli-auth":
            return httpx2.Response(200, json=contract())
        if request.url.path == "/register":
            return httpx2.Response(201, json={"client_id": "registered-client", "redirect_uris": [APP + "/oauth/callback"],
                                             "token_endpoint_auth_method": "none"})
        if request.url.path == "/revoke":
            return httpx2.Response(200)
        return httpx2.Response(200, json=token_body())
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        sso = LiteLLMSSO(GATEWAY, APP, client)
        login = await sso.start()
        url = urlparse(sso.sign_in_url(login))
        query = parse_qs(url.query)
        assert url.scheme == "https" and url.netloc == "gateway.example" and url.path == "/authorize"
        assert query["redirect_uri"] == [APP + "/oauth/callback"]
        assert query["resource"] == [GATEWAY]
        assert query["code_challenge_method"] == ["S256"]
        expected = base64.urlsafe_b64encode(hashlib.sha256(login.code_verifier.encode()).digest()).rstrip(b"=").decode()
        assert query["code_challenge"] == [expected]
        assert login.code_verifier not in sso.sign_in_url(login) and login.code_verifier not in repr(login)
        before = time.time()
        result = await sso.exchange(login, "one-time-code")
        assert result.credential == "personal-session" and result.user_id == "alice"
        assert before + 300 <= result.expires_at <= time.time() + 300
        assert result.refresh_token == "refresh-secret"
        assert result.client_id == login.client_id and result.issuer == result.resource == GATEWAY
        assert query["scope"] == ["proxy:admin"]
        assert "personal-session" not in repr(result)
        body = parse_qs(requests[2].content.decode())
        assert body["code_verifier"] == [login.code_verifier]
        assert body["redirect_uri"] == [APP + "/oauth/callback"]
        assert body["code"] == ["one-time-code"]
        assert len(requests) == 3
        assert requests[0].method == "GET"
        assert "refresh-secret" not in repr(result)
        assert not any("authorization" in r.headers for r in requests)


@pytest.mark.asyncio
async def test_expired_flow_never_contacts_gateway():
    def respond(request): raise AssertionError("Expired sign-in reached gateway")
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        with pytest.raises(SignInExpired):
            await LiteLLMSSO(GATEWAY, APP, client).exchange(replace(flow(), expires_at=0), "code")


@pytest.mark.asyncio
@pytest.mark.parametrize("status,exception", [(400, SignInExpired), (403, SignInExpired), (410, SignInExpired),
                                              (429, AuthorizationUnavailable), (500, AuthorizationUnavailable), (302, AuthorizationUnavailable)])
async def test_errors_are_redacted_and_redirects_never_followed(status, exception):
    requests = []
    def respond(request):
        requests.append(request)
        return httpx2.Response(status, text="private-upstream-secret", headers={"Location": "https://evil.example"})
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        with pytest.raises(exception) as caught:
            await LiteLLMSSO(GATEWAY, APP, client).exchange(flow(), "code")
    assert "private-upstream-secret" not in str(caught.value)
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], {}, token_body(access_token="bad credential"), token_body(user_id=None),
    token_body(token_type=123), token_body(token_type="Basic"), token_body(expires_in=True), token_body(expires_in=-1),
    token_body(scope="proxy:read"), token_body(refresh_token=None), token_body(refresh_expires_in=86401)])
async def test_malformed_token_response_fails_closed(body):
    def respond(request):
        return httpx2.Response(200) if request.url.path == "/revoke" else httpx2.Response(200, json=body)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        with pytest.raises(AuthorizationUnavailable):
            await LiteLLMSSO(GATEWAY, APP, client).exchange(flow(), "code")


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [{"client_id": ""}, {"redirect_uris": ["https://evil.example/callback"]},
                                     {"token_endpoint_auth_method": "client_secret_basic"}])
async def test_malformed_registration_fails_closed(override):
    body = {"client_id": "registered-client", "redirect_uris": [APP + "/oauth/callback"],
            "token_endpoint_auth_method": "none", **override}
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json=(
            contract() if r.url.path == "/.well-known/litellm-cli-auth" else body)))) as client:
        with pytest.raises(AuthorizationUnavailable):
            await LiteLLMSSO(GATEWAY, APP, client).start()


def contract(**overrides):
    return {
        "contract_version": 1, "issuer": GATEWAY, "resource": GATEWAY,
        "authorization_endpoint": GATEWAY + "/authorize", "token_endpoint": GATEWAY + "/token",
        "registration_endpoint": GATEWAY + "/register", "revocation_endpoint": GATEWAY + "/revoke",
        "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "hosted_app": {"scopes_supported": ["proxy:read", "proxy:admin"], "access_token_ttl": 300,
                       "refresh_token_ttl": 86400}, **overrides,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [
    {"hosted_app": None}, {"hosted_app": False}, {"contract_version": True},
    {"issuer": "https://other.example"}, {"resource": "https://other.example"},
    {"token_endpoint": "https://other.example/token"}, {"token_endpoint": "https://user:pass@gateway.example/token"},
    {"token_endpoint": GATEWAY + "/token?leak=1"}, {"code_challenge_methods_supported": ["plain"]},
    {"grant_types_supported": [{}]}, {"token_endpoint_auth_methods_supported": ["client_secret_basic"]},
])
async def test_incompatible_discovery_never_registers_or_sends_credentials(changes):
    requests = []
    def respond(request):
        requests.append(request)
        return httpx2.Response(200, json=contract(**changes))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        with pytest.raises(GatewayIncompatible):
            await LiteLLMSSO(GATEWAY, APP, client).start()
    assert len(requests) == 1 and requests[0].method == "GET"


@pytest.mark.asyncio
async def test_refresh_is_bound_rotates_and_does_not_extend_consent():
    requests = []
    def respond(request):
        requests.append(request)
        return httpx2.Response(200, json=token_body(access_token="next-access", refresh_token="next-refresh"))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        sso = LiteLLMSSO(GATEWAY, APP, client)
        session = sso._tokens(token_body(), flow(), time.time())
        session = replace(session, refresh_expires_at=time.time() + 600)
        renewed = await sso.refresh(session)
        assert renewed.credential == "next-access" and renewed.refresh_token == "next-refresh"
        assert renewed.refresh_expires_at == session.refresh_expires_at
        body = parse_qs(requests[0].content.decode())
        assert body == {"grant_type": ["refresh_token"], "refresh_token": ["refresh-secret"],
                        "client_id": ["registered-client"], "resource": [GATEWAY]}
        await sso.revoke(renewed)
        assert parse_qs(requests[1].content.decode())["token"] == ["next-refresh"]
        with pytest.raises(GatewayIncompatible):
            await sso.refresh(replace(session, issuer="https://old.example"))
        with pytest.raises(GatewayIncompatible):
            await sso.revoke(replace(session, revocation_endpoint="https://other.example/revoke"))
        assert len(requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [{"user_id": "other"}, {"refresh_token": "refresh-secret"}, {"scope": "proxy:read"}])
async def test_refresh_rejects_different_identity_scope_or_unrotated_token(changes):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(
            200, json=token_body(**changes)))) as client:
        sso = LiteLLMSSO(GATEWAY, APP, client)
        session = sso._tokens(token_body(), flow(), time.time())
        with pytest.raises(AuthorizationUnavailable):
            await sso.refresh(session)

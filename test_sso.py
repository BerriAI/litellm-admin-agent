import base64
import hashlib
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest

from auth import AuthorizationUnavailable
from sso import OAuthFlow, LiteLLMSSO, SignInExpired

GATEWAY = "https://gateway.example"
APP = "https://admin.example"


def flow():
    return OAuthFlow("registered-client", time.time() + 600, "private-state", "private-pkce-verifier")


def token_body(**override):
    return {"access_token": "personal-session", "user_id": "alice", "token_type": "Bearer",
            "expires_in": 3600, "refresh_token": "unused-refresh-secret", **override}


@pytest.mark.asyncio
async def test_code_flow_uses_fixed_callback_pkce_and_discards_refresh_token():
    requests = []
    def respond(request):
        requests.append(request)
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
        assert before + 3600 <= result.expires_at <= time.time() + 3600
        assert "personal-session" not in repr(result)
        body = parse_qs(requests[1].content.decode())
        assert body["code_verifier"] == [login.code_verifier]
        assert body["redirect_uri"] == [APP + "/oauth/callback"]
        assert body["code"] == ["one-time-code"]
        assert requests[2].url.path == "/revoke"
        assert parse_qs(requests[2].content.decode())["token"] == ["unused-refresh-secret"]
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
    token_body(token_type=123), token_body(token_type="Basic"), token_body(expires_in=True), token_body(expires_in=-1)])
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
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json=body))) as client:
        with pytest.raises(AuthorizationUnavailable):
            await LiteLLMSSO(GATEWAY, APP, client).start()


@pytest.mark.asyncio
async def test_refresh_revocation_failure_never_exposes_or_saves_refresh_token(caplog):
    def respond(request):
        if request.url.path == "/revoke":
            return httpx2.Response(500, text="unused-refresh-secret")
        return httpx2.Response(200, json=token_body())
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        result = await LiteLLMSSO(GATEWAY, APP, client).exchange(flow(), "code")
    assert result.credential == "personal-session"
    assert "unused-refresh-secret" not in repr(result) + caplog.text

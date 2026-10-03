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
                     GATEWAY, GATEWAY + "/authorize", GATEWAY + "/token", GATEWAY + "/revoke")


def token_body(**override):
    return {"access_token": "personal-session", "token_type": "Bearer",
            "expires_in": 3600, "refresh_token": "refresh-secret", "scope": "proxy:admin", **override}


def metadata(**overrides):
    return {"issuer": GATEWAY + "/oauth/api", "authorization_endpoint": GATEWAY + "/authorize",
            "token_endpoint": GATEWAY + "/token", "registration_endpoint": GATEWAY + "/register",
            "revocation_endpoint": GATEWAY + "/revoke", "scopes_supported": ["proxy:admin"],
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"], **overrides}


@pytest.mark.asyncio
async def test_standard_code_flow_discovers_endpoints_and_retains_bound_refresh_token():
    requests = []
    def respond(request):
        requests.append(request)
        if request.url.path.startswith("/.well-known/"):
            return httpx2.Response(200, json=metadata())
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
        assert result.credential == "personal-session" and result.refresh_token == "refresh-secret"
        assert before + 3600 <= result.expires_at <= time.time() + 3600
        assert "personal-session" not in repr(result)
        body = parse_qs(requests[2].content.decode())
        assert body["code_verifier"] == [login.code_verifier]
        assert body["redirect_uri"] == [APP + "/oauth/callback"]
        assert body["code"] == ["one-time-code"]
        assert requests[0].url.path == "/.well-known/oauth-authorization-server/oauth/api"
        assert len(requests) == 3 and query["scope"] == ["proxy:admin"]
        assert result.resource == GATEWAY and result.client_id == login.client_id
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
@pytest.mark.parametrize("body", [[], {}, token_body(access_token="bad credential"), token_body(refresh_token=None),
    token_body(token_type=123), token_body(token_type="Basic"), token_body(expires_in=True), token_body(expires_in=-1), token_body(scope="other")])
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
            metadata() if r.url.path.startswith("/.well-known/") else body)))) as client:
        with pytest.raises(AuthorizationUnavailable):
            await LiteLLMSSO(GATEWAY, APP, client).start()


@pytest.mark.parametrize("changes", [{"issuer": "https://other.example/oauth/api"}, {"scopes_supported": []},
    {"token_endpoint": "https://other.example/token"}, {"token_endpoint": GATEWAY + "/token?leak=1"},
    {"token_endpoint": "https://user:pass@gateway.example/token"}, {"code_challenge_methods_supported": ["plain"]}])
@pytest.mark.asyncio
async def test_invalid_discovery_never_registers_or_sends_credentials(changes):
    requests = []
    def respond(request):
        requests.append(request)
        return httpx2.Response(200, json=metadata(**changes))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        with pytest.raises(GatewayIncompatible):
            await LiteLLMSSO(GATEWAY, APP, client).start()
    assert len(requests) == 1 and requests[0].method == "GET"


@pytest.mark.asyncio
async def test_refresh_rotates_without_extending_local_deadline_and_revoke_uses_saved_binding():
    requests = []
    def respond(request):
        requests.append(request)
        return httpx2.Response(200, json=token_body(access_token="renewed", refresh_token="rotated"))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        sso = LiteLLMSSO(GATEWAY, APP, client)
        session = sso._tokens(token_body(), flow(), time.time(), time.time() + 600)
        renewed = await sso.refresh(session)
        assert renewed.credential == "renewed" and renewed.refresh_token == "rotated"
        assert renewed.session_expires_at == session.session_expires_at == renewed.expires_at
        assert parse_qs(requests[0].content.decode()) == {"grant_type": ["refresh_token"],
            "refresh_token": ["refresh-secret"], "client_id": ["registered-client"], "resource": [GATEWAY]}
        await sso.revoke(renewed)
        assert parse_qs(requests[1].content.decode())["token"] == ["rotated"]
        for invalid in (replace(session, resource="https://other.example"),
                        replace(session, token_endpoint="https://other.example/token")):
            with pytest.raises(GatewayIncompatible):
                await sso.refresh(invalid)
        with pytest.raises(SignInExpired):
            await sso.refresh(replace(session, session_expires_at=0))
        assert len(requests) == 2


@pytest.mark.parametrize("changes", [{"refresh_token": "refresh-secret"}, {"scope": "other"}])
@pytest.mark.asyncio
async def test_refresh_rejects_reused_token_or_changed_scope(changes):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(
            200, json=token_body(**changes)))) as client:
        sso = LiteLLMSSO(GATEWAY, APP, client)
        session = sso._tokens(token_body(), flow(), time.time(), time.time() + 86400)
        with pytest.raises(AuthorizationUnavailable):
            await sso.refresh(session)


@pytest.mark.asyncio
async def test_discovery_inserts_well_known_before_issuer_path():
    requested = []
    def respond(request):
        requested.append(request.url.path)
        if request.url.path.startswith("/.well-known/"):
            return httpx2.Response(200, json=metadata(issuer=GATEWAY + "/tenant/oauth/api"))
        return httpx2.Response(201, json={"client_id": "registered", "redirect_uris": [APP + "/oauth/callback"],
                                        "token_endpoint_auth_method": "none"})
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        await LiteLLMSSO(GATEWAY + "/tenant", APP, client).start()
    assert requested == ["/.well-known/oauth-authorization-server/tenant/oauth/api", "/register"]


@pytest.mark.asyncio
async def test_gateway_without_api_oauth_discovery_requests_an_upgrade():
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(404))) as client:
        with pytest.raises(GatewayIncompatible):
            await LiteLLMSSO(GATEWAY, APP, client).start()


@pytest.mark.asyncio
async def test_reconfigured_gateway_revokes_only_at_the_saved_original_origin():
    requests = []
    def respond(request):
        requests.append(request)
        return httpx2.Response(200)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        original = LiteLLMSSO(GATEWAY, APP, client)
        session = original._tokens(token_body(), flow(), time.time(), time.time() + 86400)
        replacement = LiteLLMSSO("https://replacement.example", APP, client)
        with pytest.raises(GatewayIncompatible): await replacement.refresh(session)
        await replacement.revoke(session)
    assert len(requests) == 1 and str(requests[0].url) == GATEWAY + "/revoke"
    assert parse_qs(requests[0].content.decode())["token"] == ["refresh-secret"]

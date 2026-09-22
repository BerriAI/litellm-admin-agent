import time

import httpx2
import pytest

from auth import AuthorizationUnavailable
from sso import DeviceFlow, LiteLLMSSO, SignInExpired


def flow():
    return DeviceFlow("cli-abcdefghijklmnopqrstuvwx", "ABCD-EFGH", time.time() + 600, "private-poll-secret")


@pytest.mark.asyncio
async def test_gateway_device_flow_uses_fixed_origin_and_secret_header():
    requests = []
    def respond(request):
        requests.append(request)
        if request.method == "POST":
            return httpx2.Response(200, json={"login_id": flow().login_id, "user_code": "ABCD-EFGH",
                "poll_secret": "s" * 43, "expires_in": 600,
                "verification_uri_complete": "https://evil.example/steal"})
        return httpx2.Response(200, json={"status": "ready", "key": "personal-session", "user_id": "alice", "team_id": "engineering"})
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        sso = LiteLLMSSO("https://gateway.example", client)
        login = await sso.start()
        url = sso.sign_in_url(login)
        assert url.startswith("https://gateway.example/sso/key/generate?source=litellm-cli&key=cli-")
        assert login.poll_secret not in url and login.poll_secret not in repr(login)
        result = await sso.poll(login, "engineering")
        assert result.credential == "personal-session"
        assert "personal-session" not in repr(result)
        assert requests[1].headers["x-litellm-cli-poll-secret"] == "s" * 43
        assert "team_id=engineering" in str(requests[1].url)
        assert not any("authorization" in r.headers for r in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"status": "pending"},
    {"status": "ready", "user_id": "alice", "requires_team_selection": True,
     "teams": ["one", "two"], "team_details": [{"team_id": "one", "team_alias": "Engineering"}]},
])
async def test_pending_and_team_selection_do_not_produce_a_credential(body):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json=body))) as client:
        result = await LiteLLMSSO("https://gateway.example", client).poll(flow())
    assert not result.credential
    if body["status"] == "ready":
        assert result.teams == (("one", "Engineering"), ("two", "two"))


@pytest.mark.asyncio
async def test_expired_flow_never_contacts_gateway():
    def respond(request): raise AssertionError("Expired sign-in reached gateway")
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as client:
        with pytest.raises(SignInExpired):
            await LiteLLMSSO("https://gateway.example", client).poll(DeviceFlow("cli-expired", "ABCD-EFGH", 0, "secret"))


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
            await LiteLLMSSO("https://gateway.example", client).poll(flow())
    assert "private-upstream-secret" not in str(caught.value)
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], {}, {"status": "ready", "user_id": "alice"},
    {"status": "ready", "user_id": "alice", "key": "bad credential"},
    {"status": "ready", "user_id": "alice", "key": "secret", "team_id": "other"},
    {"status": "ready", "user_id": "alice", "requires_team_selection": True, "teams": [123]},
])
async def test_malformed_response_or_changed_team_fails_closed(body):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json=body))) as client:
        with pytest.raises(AuthorizationUnavailable):
            await LiteLLMSSO("https://gateway.example", client).poll(flow(), "requested-team")


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [{"login_id": "../stolen"}, {"poll_secret": ""}, {"user_code": "<script>"}, {"expires_in": -1}])
async def test_malformed_start_fails_closed(override):
    body = {"login_id": flow().login_id, "poll_secret": "s" * 43, "user_code": "ABCD-EFGH", "expires_in": 600, **override}
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json=body))) as client:
        with pytest.raises(AuthorizationUnavailable):
            await LiteLLMSSO("https://gateway.example", client).start()

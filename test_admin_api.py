import json

import httpx2
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from admin_api import add_admin_api_routes
from auth import AdminAuthorizer


KEY = "caller-admin-key"


class Gateway:
    def __init__(self):
        self.requests = []
        self.status = 200
        self.fail = False
        self.revoke = False
        self.admin_revoked = False

    def handle(self, request):
        self.requests.append(request)
        bearer = request.headers["Authorization"].removeprefix("Bearer ")
        if request.url.path == "/user/info" and not request.url.query:
            role = "proxy_admin" if bearer == KEY and not self.admin_revoked else "internal_user"
            return httpx2.Response(200, json={"user_id": bearer, "user_info": {
                "user_id": bearer, "user_email": "admin@example.com", "user_role": role,
            }})
        if self.fail:
            raise httpx2.ReadTimeout("Uncertain outcome")
        if self.revoke:
            self.admin_revoked = True
        return httpx2.Response(self.status, json={"spend": 12.5, "echo": KEY, "key": "sk-newly-created"},
                              headers={"Location": "https://other.example.com", "Set-Cookie": "unwanted=1"})

    @property
    def forwarded(self):
        return [r for r in self.requests if r.url.path != "/user/info" or r.url.query]


@pytest_asyncio.fixture
async def service():
    gateway = Gateway()
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as upstream:
        auth = AdminAuthorizer("https://gateway.example.com", "Tberri", upstream)
        app = web.Application(client_max_size=32000)
        add_admin_api_routes(app, "https://gateway.example.com", auth, upstream)
        async with TestClient(TestServer(app)) as client:
            yield client, gateway


def headers(key=KEY):
    return {"Authorization": "Bearer " + key}


@pytest.mark.asyncio
async def test_verified_admin_can_read_with_own_key_without_key_or_team_permission_changes(service):
    client, gateway = service
    result = await client.get("/admin-api/user/info?user_id=tin%40berri.ai", headers=headers())
    assert result.status == 200
    body = await result.json()
    assert body["spend"] == 12.5
    assert body["echo"] == "[credential redacted]"
    assert result.headers["Cache-Control"] == "no-store"
    assert "Set-Cookie" not in result.headers and "Location" not in result.headers
    assert len(gateway.forwarded) == 1
    assert gateway.forwarded[0].url.params["user_id"] == "tin@berri.ai"
    assert all(r.method == "GET" and r.headers["Authorization"] == "Bearer " + KEY for r in gateway.requests)


@pytest.mark.parametrize("request_headers,status", [({}, 401), (headers("ordinary-user"), 403),
    ({**headers("ordinary-user"), "X-LiteLLM-User-Role": "proxy_admin", "X-LiteLLM-User-Id": KEY}, 403)])
@pytest.mark.parametrize("path", ["/key/generate", "/model/new"])
@pytest.mark.asyncio
async def test_non_admin_cannot_invoke_tools_even_with_spoofed_metadata(service, request_headers, status, path):
    client, gateway = service
    result = await client.post("/admin-api" + path, headers=request_headers, json={"user_role": "proxy_admin"})
    assert result.status == status
    assert not gateway.forwarded


@pytest.mark.asyncio
async def test_admin_mutation_forwards_body_and_uses_real_audit_actor(service):
    client, gateway = service
    result = await client.post("/admin-api/team/new", headers={**headers(), "litellm-changed-by": "spoofed"},
                               json={"team_alias": "example", "max_budget": 10})
    assert result.status == 200
    request = gateway.forwarded[0]
    assert request.method == "POST"
    assert request.headers["Authorization"] == "Bearer " + KEY
    assert request.headers["litellm-changed-by"] == KEY
    assert json.loads(request.content) == {"team_alias": "example", "max_budget": 10}


@pytest.mark.parametrize("status", [401, 403, 429, 500])
@pytest.mark.parametrize("path", ["/key/generate", "/model/new"])
@pytest.mark.asyncio
async def test_native_api_restrictions_remain_enforced_and_are_not_retried(service, status, path):
    client, gateway = service
    gateway.status = status
    response = await client.post("/admin-api" + path, headers=headers(), json={})
    assert response.status == status
    assert len(gateway.forwarded) == 1


@pytest.mark.asyncio
async def test_role_revocation_during_operation_suppresses_private_result(service):
    client, gateway = service
    gateway.revoke = True
    response = await client.post("/admin-api/key/generate", headers=headers(), json={})
    assert response.status == 403
    assert "sk-newly-created" not in await response.text()
    assert len(gateway.forwarded) == 1


@pytest.mark.parametrize("path", ["/key/generate", "/model/new"])
@pytest.mark.asyncio
async def test_uncertain_mutation_is_never_retried(service, path):
    client, gateway = service
    gateway.fail = True
    response = await client.post("/admin-api" + path, headers=headers(), json={})
    assert response.status == 504
    assert "Do not repeat a change" in await response.text()
    assert len(gateway.forwarded) == 1


@pytest.mark.parametrize("path", ["/admin-api/config", "/admin-api/cache/flushall", "/admin-api/anything"])
@pytest.mark.asyncio
async def test_unselected_api_routes_are_not_exposed(service, path):
    client, gateway = service
    assert (await client.post(path, headers=headers(), json={})).status == 404
    assert not gateway.requests


@pytest.mark.parametrize("identifier", ["..%2Fother", "a%2Fb", "a%5Cb"])
@pytest.mark.asyncio
async def test_path_parameters_cannot_escape_the_selected_route(service, identifier):
    client, gateway = service
    response = await client.post("/admin-api/key/"+identifier+"/reset_spend", headers=headers(), json={})
    assert response.status in (400, 404)
    assert not gateway.forwarded


@pytest.mark.asyncio
async def test_redirect_is_not_forwarded_or_followed(service):
    client, gateway = service
    gateway.status = 302
    response = await client.post("/admin-api/key/generate", headers=headers(), json={})
    assert response.status == 502
    assert "Location" not in response.headers
    assert len(gateway.forwarded) == 1

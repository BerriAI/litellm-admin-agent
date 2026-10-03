from types import SimpleNamespace

import litellm_admin_agent.auth as auth_module

import httpx2
import pytest

from litellm_admin_agent.auth import AccessDenied, AdminAuthorizer, AuthorizationUnavailable, EnterpriseRequired


class Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        status, data = result if isinstance(result, tuple) else (200, result)
        return httpx2.Response(status, json=data, request=httpx2.Request("GET", url))


def account(role="proxy_admin", **extra):
    return {"user_id": "admin-id", "user_email": "admin@example.com", "user_role": role, **extra}


def auth(client):
    return AdminAuthorizer("https://gateway.example.com", "Tberri", client)


def info(role="proxy_admin", **extra):
    return {"user_id": "admin-id", "user_info": account(role, **extra)}


ENTERPRISE = {"has_license": True, "license_type": "enterprise"}


@pytest.mark.asyncio
async def test_caller_bearer_is_used_and_service_key_never_substituted():
    client = Client(info(), ENTERPRISE)
    principal = await auth(client).require_gateway_admin("caller-secret")
    assert principal.user_id == "admin-id"
    assert [url for url, _ in client.calls] == ["https://gateway.example.com/user/info",
                                                "https://gateway.example.com/health/license"]
    for _, kwargs in client.calls:
        assert kwargs["headers"] == {"Authorization": "Bearer caller-secret"}
        assert kwargs["params"] is None
        assert kwargs["follow_redirects"] is False


@pytest.mark.parametrize("license", [{"has_license": False, "license_type": "community"},
    {"has_license": True, "license_type": "community"}, {"license_type": "Enterprise"}, {}])
@pytest.mark.asyncio
async def test_gateway_without_enterprise_license_denied(license):
    with pytest.raises(EnterpriseRequired):
        await auth(Client(info(), license)).require_gateway_admin("caller")


@pytest.mark.asyncio
async def test_enterprise_license_is_cached_until_it_expires(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth_module.time, "monotonic", lambda: now[0])
    client = Client(info(), ENTERPRISE, info(), info(), (200, {"license_type": "community"}))
    authorizer = auth(client)
    await authorizer.require_gateway_admin("caller")
    now[0] += AdminAuthorizer.LICENSE_TTL - 1
    await authorizer.require_gateway_admin("caller")
    assert [url.rsplit("/", 1)[-1] for url, _ in client.calls] == ["info", "license", "info"]
    now[0] += 1
    with pytest.raises(EnterpriseRequired):
        await authorizer.require_gateway_admin("caller")
    assert [url.rsplit("/", 1)[-1] for url, _ in client.calls][-2:] == ["info", "license"]


@pytest.mark.asyncio
async def test_missing_enterprise_license_is_not_cached():
    client = Client(info(), {"license_type": "community"}, info(), ENTERPRISE)
    authorizer = auth(client)
    with pytest.raises(EnterpriseRequired):
        await authorizer.require_gateway_admin("caller")
    assert (await authorizer.require_gateway_admin("caller")).user_id == "admin-id"
    assert [url.rsplit("/", 1)[-1] for url, _ in client.calls] == ["info", "license", "info", "license"]


@pytest.mark.parametrize("license", [(500, {}), (404, {}), TimeoutError(), []])
@pytest.mark.asyncio
async def test_license_errors_fail_closed(license):
    with pytest.raises(AuthorizationUnavailable):
        await auth(Client(info(), license)).require_gateway_admin("caller")


@pytest.mark.parametrize("data", [info("internal_user"), info("proxy_admin_viewer"), info("team_admin"),
    info(blocked=True), info(deleted=True), info(is_active=False), {**info(), "user_id": "spoofed"}, {}, (401, {}), (403, {})])
@pytest.mark.asyncio
async def test_gateway_non_admins_and_invalid_identity_denied(data):
    with pytest.raises(AccessDenied):
        await auth(Client(data)).require_gateway_admin("caller")


@pytest.mark.parametrize("data", [(500, {}), (302, {}), [], TimeoutError(), "not-json-object"])
@pytest.mark.asyncio
async def test_identity_errors_fail_closed(data):
    with pytest.raises(AuthorizationUnavailable):
        await auth(Client(data)).require_gateway_admin("caller")


@pytest.mark.parametrize("bearer", ["", "too many tokens", "x" * 8193])
@pytest.mark.asyncio
async def test_missing_or_malformed_bearer_never_requests_identity(bearer):
    client = Client()
    with pytest.raises(AccessDenied):
        await auth(client).require_gateway_admin(bearer)
    assert client.calls == []


class Slack:
    def __init__(self, **extra):
        self.user = {"id": "Uadmin", "team_id": "Tberri", "profile": {"email": "Admin@Example.com"}, **extra}
    async def users_info(self, **kwargs):
        return {"ok": True, "user": self.user}


@pytest.mark.asyncio
async def test_slack_uses_personal_credential_and_matches_verified_email():
    client = Client(info(), ENTERPRISE)
    principal = await auth(client).require_slack_admin("Uadmin", Slack(), "personal-key")
    assert principal.actor == "slack:Uadmin:admin-id"
    assert len(client.calls) == 2
    assert client.calls[0][1]["params"] is None
    assert client.calls[0][1]["headers"] == {"Authorization": "Bearer personal-key"}


@pytest.mark.parametrize("extra", [{"id": "other"}, {"team_id": "other"}, {"deleted": True}, {"is_bot": True},
    {"is_app_user": True}, {"is_restricted": True}, {"is_ultra_restricted": True}, {"is_stranger": True}, {"profile": {}}])
@pytest.mark.asyncio
async def test_slack_guest_bot_wrong_workspace_and_missing_email_denied(extra):
    client = Client()
    with pytest.raises(AccessDenied):
        await auth(client).require_slack_admin("Uadmin", Slack(**extra), "key")
    assert not client.calls


@pytest.mark.parametrize("data", [info(user_email="other@example.com"), info(user_email=""), info("internal_user")])
@pytest.mark.asyncio
async def test_wrong_person_or_non_admin_key_denied(data):
    with pytest.raises(AccessDenied):
        await auth(Client(data, ENTERPRISE)).require_slack_admin("Uadmin", Slack(), "key")


@pytest.mark.asyncio
async def test_slack_missing_scopes_fails_closed():
    class MissingScope:
        async def users_info(self, **kwargs):
            raise RuntimeError("missing_scope")
    with pytest.raises(AuthorizationUnavailable):
        await auth(Client()).require_slack_admin("Uadmin", MissingScope(), "key")

"""Check deployment prerequisites without posting messages, calling an LLM, or running admin tools."""
import argparse
import asyncio
import os
import tempfile
from pathlib import Path

import httpx2
from dotenv import load_dotenv
from slack_sdk.web.async_client import AsyncWebClient

from agent import Settings, mcp_session
from auth import AdminAuthorizer
from configure_mcp import registration
from core import all_tools, is_read_only


async def check(settings: Settings, *, offline: bool, credential: str = "") -> list[str]:
    settings.validate()
    parent = Path(settings.db_path).parent
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(dir=parent):
        pass
    results = ["Configuration, encryption key, URL boundaries and writable state directory: OK"]
    if offline:
        return results + ["Network checks skipped (offline)."]
    if not credential:
        raise ValueError("Set LITELLM_SETUP_KEY to a personal proxy-admin key for read-only gateway checks. Do not put setup credentials on the service.")
    async with httpx2.AsyncClient(timeout=15, follow_redirects=False) as client:
        auth = AdminAuthorizer(settings.gateway_url, settings.workspace, client)
        await auth.require_gateway_admin(credential)
        results.append("Gateway credential has a live proxy_admin identity: OK")
        headers = {"Authorization": "Bearer " + credential}
        spec = await client.get(settings.gateway_url + "/openapi.json", headers=headers)
        spec.raise_for_status()
        expected = registration(spec.json(), settings.gateway_url, settings.public_url)
        results.append("Gateway management routes and operation IDs: OK")
        registered = await client.get(settings.gateway_url + "/v1/mcp/server", headers=headers)
        registered.raise_for_status()
        servers = registered.json()
        if isinstance(servers, dict):
            servers = servers.get("servers", servers.get("data"))
        if not isinstance(servers, list) or any(not isinstance(row, dict) for row in servers):
            raise ValueError("Unexpected gateway MCP registration list")
        matches = [row for row in servers if row.get("alias") == settings.mcp_alias]
        if (len(matches) != 1 or matches[0].get("url") != expected["url"]
                or matches[0].get("credentials") or matches[0].get("auth_type") != "bearer_token"):
            raise ValueError("The personal_admin registration must use this agent’s /admin-api backend, bearer_token auth and no stored credentials. Inspect the registration before continuing.")
        results.append("MCP backend URL and bearer authentication configuration: OK")
        # LiteLLM redacts stored secrets from this listing. An empty response is
        # not evidence that no credential is stored in the gateway database.
        results.append("Stored MCP credentials are redacted by the gateway. The setup helper creates an empty credential configuration; verify that existing registrations have no shared backend credential.")
        models = await client.get(settings.model_url.rstrip("/") + ("/models" if settings.model_url.endswith("/v1") else "/v1/models"), headers=headers)
        models.raise_for_status()
        if settings.model not in {m.get("id") for m in models.json().get("data", [])}:
            raise ValueError("LITELLM_MODEL is not in the setup caller’s model catalog. Use a configured gateway model name.")
        results.append("Configured model is visible to the caller (no inference performed): OK")
    async with mcp_session(settings, credential) as session:
        available = {tool.name for tool in await all_tools(session)}
    missing = settings.tool_names - available
    if missing:
        raise ValueError(f"{len(missing)} configured MCP tools are missing. Run configure_mcp.py --write-tool-names and apply the registration before deploying.")
    if settings.read_only and not any(is_read_only(name) for name in settings.tool_names):
        raise ValueError("No recognized read tools selected for this read-only deployment")
    results.append(f"Native MCP discovery and exact allowlist ({len(settings.tool_names)} tools): OK")
    if settings.slack_enabled:
        slack = AsyncWebClient(token=settings.bot_token)
        identity = await slack.auth_test()
        if identity.get("team_id") != settings.workspace:
            raise ValueError("Slack bot belongs to a different workspace")
        scopes = set(identity.headers.get("x-oauth-scopes", "").replace(" ", "").split(","))
        if not {"chat:write", "im:history", "users:read", "users:read.email"} <= scopes:
            raise ValueError("Slack bot is missing required scopes. Reinstall the app using slack-manifest.json.")
        await slack.users_info(user=identity["user_id"])
        # Validates the Socket Mode app token without opening a second listener.
        await AsyncWebClient(token=settings.app_token).apps_connections_open()
        results.append("Slack workspace, installed bot scopes and Socket Mode app token: OK")
    if settings.connection_auth_mode == "sso":
        results.append("SSO still requires a browser smoke test and the gateway’s exact hosted callback allowlist. This check does not start a login.")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Validate local configuration only")
    args = parser.parse_args()
    load_dotenv()
    os.umask(0o077)
    try:
        results = asyncio.run(check(Settings.read(), offline=args.offline, credential=os.getenv("LITELLM_SETUP_KEY", "")))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    except Exception as exc:
        # SDK exceptions may echo gateway responses, OAuth URLs or credentials.
        raise SystemExit(f"Preflight failed ({type(exc).__name__}). Check gateway reachability, identity, MCP registration and Slack tokens; details withheld to protect credentials.") from None
    print("\n".join(results))


if __name__ == "__main__":
    main()

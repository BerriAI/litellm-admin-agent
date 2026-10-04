"""Check deployment prerequisites without posting messages, calling an LLM, or running admin tools."""
import argparse
import asyncio
import os
import tempfile
from pathlib import Path

import httpx2
from dotenv import load_dotenv
from slack_sdk.web.async_client import AsyncWebClient

from litellm_admin_agent.agent import Settings, mcp_session
from litellm_admin_agent.auth import AdminAuthorizer, EnterpriseRequired
from litellm_admin_agent.core import all_tools, is_read_only
from litellm_admin_mcp.catalog import BY_NAME


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
        results.append("Gateway credential has a live proxy_admin identity and LiteLLM Enterprise license: OK")
        headers = {"Authorization": "Bearer " + credential}
        models = await client.get(settings.model_url.rstrip("/") + ("/models" if settings.model_url.endswith("/v1") else "/v1/models"), headers=headers)
        models.raise_for_status()
        if settings.model not in {m.get("id") for m in models.json().get("data", [])}:
            raise ValueError("LITELLM_MODEL is not in the setup caller’s model catalog. Use a configured gateway model name.")
        results.append("Configured model is visible to the caller (no inference performed): OK")
    async with mcp_session(settings, credential) as session:
        available = {tool.name for tool in await all_tools(session)}
    selected = settings.tool_names or frozenset(available & BY_NAME.keys())
    if settings.read_only:
        selected = frozenset(name for name in selected if is_read_only(name))
    missing = selected - available
    if missing:
        raise ValueError(f"{len(missing)} configured MCP tools are missing. Check the connector version, canonical tool names and gateway endpoint availability.")
    if not selected:
        raise ValueError("No recognized LiteLLM Admin MCP tools were discovered")
    if settings.read_only and not any(is_read_only(name) for name in selected):
        raise ValueError("No recognized read tools selected for this read-only deployment")
    results.append(f"LiteLLM Admin MCP discovery and selected tools ({len(selected)} tools): OK")
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
    except EnterpriseRequired:
        raise SystemExit(EnterpriseRequired.message) from None
    except Exception as exc:
        # SDK exceptions may echo gateway responses, OAuth URLs or credentials.
        raise SystemExit(f"Preflight failed ({type(exc).__name__}). Check gateway reachability, identity, Admin MCP connection and Slack tokens; details withheld to protect credentials.") from None
    print("\n".join(results))


if __name__ == "__main__":
    main()

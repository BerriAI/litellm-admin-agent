"""Preview or register the dedicated LiteLLM admin MCP server using the deployed spec."""
import argparse
import json
import os
from pathlib import Path

import httpx2
from dotenv import load_dotenv, set_key
from agent import trusted_url


ROOT = Path(__file__).parent


def registration(spec: dict, base_url: str, agent_url: str) -> dict:
    trusted_url(agent_url, "AGENT_PUBLIC_URL", origin_only=True)
    trusted_url(base_url, "LITELLM_BASE_URL", origin_only=True)
    inventory = json.loads((ROOT / "admin-operations.json").read_text())
    operation_ids = []
    for entry in inventory["operations"]:
        op = spec.get("paths", {}).get(entry["path"], {}).get(entry["method"].lower())
        if op and op.get("operationId"):
            if op["operationId"] != entry["operation_id"]:
                raise ValueError(f"Gateway operation ID changed for {entry['method']} {entry['path']}; review and update admin-operations.json before enabling it")
            operation_ids.append(op["operationId"])
    if not operation_ids:
        raise ValueError("The proxy spec contains none of the selected admin operations")
    return {
        "server_name": "personal_admin",
        "alias": "personal_admin",
        "description": "Models, keys, teams, budgets, and reporting for the private Slack admin agent",
        "url": agent_url.rstrip("/") + "/admin-api",
        "spec_path": base_url + "/openapi.json",
        "transport": "http",
        "auth_type": "bearer_token",
        "credentials": {},
        "allowed_tools": sorted(set(operation_ids)),
        # The backend checks the caller's live proxy_admin role for every call.
        # Gateway discovery is open to keys so team/key MCP scopes need no grants.
        "allow_all_keys": True,
        "available_on_public_internet": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Create the named MCP registration; default only prints a redacted preview")
    parser.add_argument("--write-tool-names", action="store_true", help="Save the compatible tool allowlist in the local env file")
    parser.add_argument("--env-file", default=str(ROOT / ".env"))
    args = parser.parse_args()
    load_dotenv(args.env_file)
    base_url = os.getenv("LITELLM_BASE_URL", "").rstrip("/").removesuffix("/v1")
    trusted_url(base_url, "LITELLM_BASE_URL", origin_only=True)
    admin_key = os.getenv("LITELLM_ADMIN_KEY", "")
    if args.apply and not admin_key:
        raise ValueError("Add LITELLM_ADMIN_KEY to the private .env file first")
    with httpx2.Client(timeout=30, follow_redirects=False) as client:
        headers = {"Authorization": f"Bearer {admin_key}"} if admin_key else {}
        result = client.get(base_url + "/openapi.json", headers=headers)
        result.raise_for_status()
        payload = registration(result.json(), base_url, os.getenv("AGENT_PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL", ""))
        if args.write_tool_names:
            env_file = Path(args.env_file)
            if not env_file.is_file():
                raise ValueError("Run setup_env.py first to create the private env file")
            env_file.chmod(0o600)
            set_key(str(env_file), "ADMIN_TOOL_NAMES", ",".join("personal_admin-" + name for name in payload["allowed_tools"]))
        if not args.apply:
            print(json.dumps(payload, indent=2))
            return
        existing = client.get(base_url + "/v1/mcp/server", headers=headers)
        existing.raise_for_status()
        rows = existing.json()
        if isinstance(rows, dict):
            rows = rows.get("servers", rows.get("data"))
        if not isinstance(rows, list):
            raise ValueError("Unexpected server list response; no registration was changed")
        if any(row.get("alias") == "personal_admin" or row.get("server_name") == "personal_admin" for row in rows):
            raise ValueError("personal_admin already exists; inspect it before updating. No change was made")
        try:
            created = client.post(base_url + "/v1/mcp/server", headers=headers, json=payload)
            created.raise_for_status()
        except (httpx2.TimeoutException, httpx2.NetworkError):
            raise RuntimeError("Registration outcome is uncertain. Inspect MCP Servers before retrying; this tool will not replay the request") from None
        data = created.json()
        print(json.dumps({"status": "created", "server_id": data.get("server_id"), "alias": "personal_admin", "operation_count": len(payload["allowed_tools"])}))


if __name__ == "__main__":
    main()

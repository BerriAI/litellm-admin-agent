"""Preview or register the dedicated LiteLLM admin MCP server using the deployed spec."""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx2
from dotenv import load_dotenv


ROOT = Path(__file__).parent


def registration(spec: dict, base_url: str, admin_key: str) -> dict:
    inventory = json.loads((ROOT / "admin-operations.json").read_text())
    operation_ids = []
    for entry in inventory["operations"]:
        op = spec.get("paths", {}).get(entry["path"], {}).get(entry["method"].lower())
        if op and op.get("operationId"):
            operation_ids.append(op["operationId"])
    if not operation_ids:
        raise ValueError("The proxy spec contains none of the selected admin operations")
    return {
        "server_name": "litellm_admin",
        "alias": "litellm_admin",
        "description": "Keys, teams, budgets, and reporting for the private Slack admin agent",
        "url": base_url,
        "spec_path": base_url + "/openapi.json",
        "transport": "http",
        "auth_type": "bearer_token",
        "credentials": {"auth_value": admin_key},
        "allowed_tools": sorted(set(operation_ids)),
        "allow_all_keys": False,
        "available_on_public_internet": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Create the named MCP registration; default only prints a redacted preview")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env")
    base_url = os.getenv("LITELLM_BASE_URL", "https://gateway.litellm-sandbox.ai/v1").rstrip("/").removesuffix("/v1")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("Configure an HTTPS proxy URL without embedded credentials")
    admin_key = os.getenv("LITELLM_ADMIN_KEY", "")
    if args.apply and not admin_key:
        raise ValueError("Add LITELLM_ADMIN_KEY to the private .env file first")
    with httpx2.Client(timeout=30, follow_redirects=False) as client:
        result = client.get(base_url + "/openapi.json")
        result.raise_for_status()
        payload = registration(result.json(), base_url, admin_key)
        if not args.apply:
            payload["credentials"] = {"auth_value": "<from LITELLM_ADMIN_KEY; never printed>"}
            print(json.dumps(payload, indent=2))
            return
        headers = {"Authorization": f"Bearer {admin_key}"}
        existing = client.get(base_url + "/v1/mcp/server", headers=headers)
        existing.raise_for_status()
        rows = existing.json()
        if isinstance(rows, dict):
            rows = rows.get("servers", rows.get("data"))
        if not isinstance(rows, list):
            raise ValueError("Unexpected server list response; no registration was changed")
        if any(row.get("alias") == "litellm_admin" or row.get("server_name") == "litellm_admin" for row in rows):
            raise ValueError("litellm_admin already exists; inspect it before updating. No change was made")
        try:
            created = client.post(base_url + "/v1/mcp/server", headers=headers, json=payload)
            created.raise_for_status()
        except (httpx2.TimeoutException, httpx2.NetworkError):
            raise RuntimeError("Registration outcome is uncertain. Inspect MCP Servers before retrying; this tool will not replay the request") from None
        data = created.json()
        print(json.dumps({"status": "created", "server_id": data.get("server_id"), "alias": "litellm_admin", "operation_count": len(payload["allowed_tools"])}))


if __name__ == "__main__":
    main()

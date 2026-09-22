"""Preview or register the hosted A2A agent. Never print service credentials."""
import argparse
import asyncio
import copy
import json

import httpx2
from dotenv import load_dotenv

from agent import Settings
from web import agent_card


def registration(settings):
    if len(settings.service_token) < 32:
        raise ValueError("A service token of at least 32 characters is required")
    # The gateway supplies the private hop credential; callers supply only their
    # own bearer. Keep backend-only auth out of the gateway-facing agent card.
    card = agent_card(settings.public_url)
    del card["securitySchemes"]["gatewayService"]
    card["security"] = [{"gatewayCaller": []}]
    return {
        "agent_name": "litellm-admin",
        "agent_card_params": card,
        "litellm_params": {"make_public": False},
        "static_headers": {"X-Admin-Agent-Token": settings.service_token},
        "extra_headers": ["Authorization"],
    }


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    load_dotenv()
    settings = Settings.read()
    payload = registration(settings)
    if not args.apply:
        preview = copy.deepcopy(payload)
        preview["static_headers"]["X-Admin-Agent-Token"] = "[private service token]"
        print(json.dumps(preview, indent=2))
        return
    async with httpx2.AsyncClient(timeout=30, follow_redirects=False) as client:
        # Check the hosted endpoint first, then avoid creating duplicate registrations.
        health = await client.get(settings.public_url + "/healthz")
        health.raise_for_status()
        headers = {"Authorization": "Bearer " + settings.admin_key}
        listed = await client.get(settings.gateway_url + "/v1/agents", headers=headers)
        listed.raise_for_status()
        data = listed.json()
        agents = data if isinstance(data, list) else data.get("agents", [])
        if any(a.get("agent_name") == payload["agent_name"] for a in agents):
            raise SystemExit("litellm-admin already exists. Inspect it before updating; no duplicate was created.")
        result = await client.post(settings.gateway_url + "/v1/agents", headers=headers, json=payload)
        # Upstream response can echo secrets. Report only status and the resulting ID.
        if result.status_code >= 400:
            raise SystemExit(f"Registration returned HTTP {result.status_code}; response withheld to protect credentials.")
        print(json.dumps({"status": "registered", "agent_id": result.json().get("agent_id")}))


if __name__ == "__main__":
    asyncio.run(main())

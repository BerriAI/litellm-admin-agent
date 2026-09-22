# LiteLLM Admin

A shared admin assistant for BerriAI Slack and the LiteLLM sandbox gateway. It uses GPT-5.4 through the gateway and a native OpenAPI-derived MCP server with 62 selected management operations.

## Deployment status

Private source: https://github.com/BerriAI/litellm-admin-agent. Automated checks currently pass (73 tests).

The previous Tin-only bot is running on Tin’s Mac. This version adds shared, role-based Slack access and an A2A entry point and is prepared for Render. The hosted service, Slack scope reinstall, gateway registration, and final cutover still require completion. Do not run two Slack listeners during cutover: separate local journals cannot deduplicate each other’s work.

## Who can use it

Any BerriAI member can find **LiteLLM Admin** in Slack Apps and open a DM. Operations require an exact match between the verified Slack profile email and one LiteLLM user with the current `proxy_admin` role. Guests, bots, users from other workspaces, viewers, and ordinary users are denied. Slack owner/admin status alone does not grant gateway administration. The old `SLACK_ADMIN_USER_IDS` setting is obsolete; it does not bypass this check.

Gateway callers must provide their own LiteLLM bearer credential. The gateway forwards it plus a private service token; the service validates the caller with `/user/info`. Caller-supplied role or user headers and message metadata grant no access. Auth is refreshed before running the model, before each administrative tool call, and before delivering results. Lookup errors fail closed.

Gateway agent registry permissions may make metadata visible to non-admins. The backend independently blocks their operations; registration alone is not an admin-only UI visibility control.

## What it can do

Read actual keys, teams, user records, budgets and spending; create and update keys; associate keys with teams; manage team membership and budgets using the selected operations in `admin-operations.json`. It discovers tool argument schemas dynamically. It is not every Admin UI feature. Add operations deliberately through `configure_mcp.py` and update the exact tool allowlist.

For named-person key spending it resolves the user, reads their individual key objects, and labels stored key spend and available period information. User totals can differ from the sum of current keys. Explicit date ranges need filtered reports.

Only user-requested changes are allowed by the instructions. Uncertain writes stop the run and are never retried automatically. Identical calls are cached within a run. A persistent SQLite journal prevents Slack delivery retries or repeated A2A request/message IDs from repeating operations. The journal stores actor IDs, tool names and statuses, but no request bodies, credentials or raw outputs.

Generated virtual keys are removed from model tool results and sent separately to the verified requester. Provider credentials and tokens are redacted. Conversation history lives in memory, is isolated by transport/user/conversation, and clears on restart. Tracing is disabled. Admin operations use the configured service credential; the local journal records the actual requesting identity.

## Architecture

- `app.py`: Slack Socket Mode and process lifecycle.
- `auth.py`: Slack profile/email matching and live LiteLLM role checks.
- `agent.py`: configuration, MCP connection and model instructions.
- `engine.py`: shared Agents SDK runner and conversation isolation.
- `core.py`: tool validation, secret handling and persistent action journal.
- `web.py`: A2A 0.3 JSON-RPC `message/send`; text only, no streaming/tasks/push.
- `register_agent.py`: redacted registration preview and explicit apply command.
- `configure_mcp.py`: existing native LiteLLM admin MCP setup.

## Local setup

Use Python 3.12, a virtual environment, and `pip install -r requirements-dev.txt`. Copy `.env.example` to a private `.env` and fill it locally. Never commit or paste credentials into chat.

The BerriAI Slack app is `A0C3AE23W9H`; use the existing app rather than creating another. `slack-manifest.json` adds `users:read` and `users:read.email` to the existing `chat:write` and `im:history` permissions. Save the new scopes and reinstall in BerriAI. Keep Socket Mode enabled with the existing `connections:write` app token and `message.im` events. The app’s Messages tab allows DMs.

Set an administrator credential for `LITELLM_ADMIN_KEY`. Optional model/MCP credential overrides inherit it when blank. The existing MCP URL is `https://gateway.litellm-sandbox.ai/litellm_admin/mcp`. `ADMIN_TOOL_NAMES` must contain the exact discovered names, including the `litellm_admin-` prefix. An empty list refuses startup.

Commands:

```sh
python app.py --list-tools
python app.py --check
python -m pytest -q
python app.py
# With A2A HTTP endpoints and Slack:
python app.py --web
```

`--check` validates Slack workspace/user lookup and configured MCP tools without posting or invoking administrative tools. It does not exercise an LLM request. Tests use the real Agents SDK loop with deterministic model/MCP responses and real local HTTP requests for A2A; they do not prove hosted gateway forwarding.

## Render

`render.yaml` defines one Starter Python web service in Oregon, a 1 GB persistent disk at `/var/data`, and a `/healthz` health check. Keep a single instance because SQLite and in-memory conversations are local to the service. Free services sleep and do not provide the persistent journal required for this deployment. Review current plan and disk pricing before creating the service.

Build: `pip install -r requirements.txt`.
Start: `python app.py --web`.
Python: `3.12.13`.
Store Slack tokens, the gateway admin key and `ADMIN_AGENT_SERVICE_TOKEN` as private Render environment values. Generate a random 32+ character service token, also used by the gateway registration. The service gets its public URL from `RENDER_EXTERNAL_URL`; set `AGENT_PUBLIC_URL` only when overriding it. Set `STATE_DB=/var/data/events.sqlite3` so replay protection survives deploys. Automatic deploys start disabled for a controlled cutover.

A Dockerfile is also supplied. Its build context explicitly excludes credentials and state; it runs as a non-root user. When mounting a Docker data volume, ensure UID 10001 can write it.

## Gateway registration and verification

After the service is healthy, set its actual HTTPS URL and matching private service token in the local configuration. Run `python register_agent.py` to preview the registration without showing secrets, then `python register_agent.py --apply` to create it. Existing `litellm-admin` registrations stop the helper rather than creating duplicates.

Registration uses `litellm_params.make_public=false`, static `X-Admin-Agent-Token`, and `extra_headers=["Authorization"]`. Do not add a provider API key that replaces the original caller’s bearer. The gateway routes requests; it does not host the Python agent.

Verify against the actual deployed gateway:

1. Hosted `/healthz` is healthy and the agent card reports protocol 0.3.0.
2. Missing/invalid caller or service credentials cannot invoke an operation.
3. A real `proxy_admin` caller can run a read-only budget query through `/a2a/{agent_id}`.
4. A real ordinary-user credential is denied even with spoofed admin metadata/headers.
5. Slack allows an actual matching proxy admin and denies a non-admin.
6. The Render blueprint starts with `SLACK_ENABLED=false`, leaving the Mac listener active while A2A is verified. Stop the Mac listener, then set Render `SLACK_ENABLED=true` and redeploy. Retain the Mac files for rollback. Copy the current SQLite journal using SQLite’s backup API if continuity is needed. Never copy a live database file directly.

Until these live checks pass, describe the hosted integration as prepared, not verified.

## Known scope and limits

This is an internal sandbox assistant. There is no public sign-up, automatic Slack role assignment, user impersonation, or automatic escalation from regular user to admin. New admins receive access by the normal gateway role-management process. This assistant does not create invitations or email people unless explicitly requested.

Synchronous A2A responses may time out during long runs. Repeated request IDs are rejected rather than replayed; inspect state after an uncertain result before asking for the change again. Authorization requests add latency and depend on Slack and the gateway being available. This version has bounded in-memory conversations and a serialized agent runner, suitable for a small internal admin group.

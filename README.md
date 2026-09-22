# LiteLLM Admin

A shared admin assistant for BerriAI Slack and the LiteLLM sandbox gateway. It uses GPT-5.4 through the gateway and a native OpenAPI-derived MCP server with 62 selected management operations.

## Deployment status

Private source: https://github.com/BerriAI/litellm-admin-agent. The service is live at https://litellm-admin-agent.onrender.com on Render Starter, with Slack enabled and a persistent disk. The old Mac listener is stopped and its LaunchAgent is disabled to prevent duplicate processing after reboot.

Render service: `srv-daoudt5g1s2s738nju1g`. Blueprint: `exs-daou10ijnfac73e6q0g0`. Gateway agent: `litellm-admin`, ID `b55a5cc9-bb4d-4f87-8969-20bb4439494d`. Invoke through `https://gateway.litellm-sandbox.ai/a2a/b55a5cc9-bb4d-4f87-8969-20bb4439494d` using your own bearer credential.

The dedicated `personal_admin` MCP registration has 62 operations and **no stored backend credential**. Live read-only checks verified caller identity, rejected missing/invalid backend credentials, and completed a gateway identity/budget lookup. Hosted checks also rejected duplicate request IDs and ordinary users with spoofed admin metadata. The original `litellm_admin` registration remains separate for the stopped Mac bot. Each Slack admin connects their own account through LiteLLM SSO.

## Who can use it

Any BerriAI member can find **LiteLLM Admin** in Slack Apps and open a DM.

1. Send **connect** and open the private link (valid for ten minutes).
2. Choose **Continue with LiteLLM SSO**, then **Open LiteLLM SSO**.
3. Sign in using the same email as Slack. Enter the short verification code from the connection page when LiteLLM asks for it. The gateway currently labels this page “CLI Login”.
4. Return to the connection page and choose **I’ve signed in — finish connecting**. If you belong to multiple teams, choose one for model access and usage attribution.
5. Return to Slack and send your request.

No API key is entered. The agent verifies the resulting session against the gateway’s current `proxy_admin` role and an exact email match to the verified Slack profile before saving it encrypted. Send **disconnect** to delete the saved session and invalidate pending links/sign-ins. An expired session requires another SSO sign-in. Existing saved personal-key connections remain usable until replaced or disconnected.

The shared `personal_admin` MCP server authorizes operations by the caller’s live `proxy_admin` role. Its backend is this service’s `/admin-api` endpoint, which forwards only the 62 selected gateway routes with the same personal bearer and the real caller’s audit identity. No key or team permission changes are needed. The gateway registration uses `allow_all_keys=true` for discovery; actual calls are independently denied to ordinary users, viewers, missing credentials, and revoked admins by the backend. The MCP name and tool schemas may therefore be discoverable to other authenticated gateway users. The server is not anonymous/public and stores no backend credential.

Guests, bots, users from other workspaces, viewers, and ordinary gateway users cannot operate the agent. Slack owner/admin status alone does not grant gateway administration. No shared `LITELLM_ADMIN_KEY`, model key, or MCP key is read by the running service. Old environment values do not provide a fallback.

Both model requests and administrative tool calls use the requesting user’s personal credential. The credential is sent as gateway MCP authentication and as `x-mcp-personal_admin-authorization: Bearer …` to the admin-only backend, which forwards it to the gateway API. The model never receives that credential as text. This preserves native gateway identity and API/model restrictions; model access and usage are also associated with that credential.

Gateway callers supply their own LiteLLM bearer on each request and do not need a Slack connection. The gateway forwards it plus a private service token; the agent validates `/user/info` and executes using that same bearer. Claimed role/user headers or message metadata grant no access. Access is rechecked before execution, each admin tool, and result delivery. Disconnecting during a Slack request prevents subsequent tools and private result delivery; it cannot undo an operation already sent.

Gateway registry metadata may be visible to non-admins. The backend independently blocks their operations; registration alone is not an admin-only UI visibility control.

Sign-in uses LiteLLM’s device flow (`POST /sso/cli/start`, browser SSO, then `/sso/cli/poll/{login_id}`), the same flow as `lite login`. The polling secret stays encrypted on Render; the browser only sees the verification code and gateway login URL. Polling happens when the user clicks the finish button, with strict Origin, CSRF and browser binding. Team selections are limited to memberships returned by LiteLLM. A new connect link or disconnect invalidates an in-flight login before it can save a credential. No hosted OAuth redirect exception, shared admin key, IdP client secret, or gateway configuration change is needed.

This flow issues a time-limited personal session, not a refresh token. LiteLLM defaults to 24 hours; the gateway’s `CLI_JWT_EXPIRATION_HOURS` / `LITELLM_CLI_JWT_EXPIRATION_HOURS` setting controls the actual lifetime. The agent does not extend the lifetime or silently generate a long-lived key. Expired sessions prompt the user to reconnect. Disconnect removes the agent’s saved copy; the gateway-issued session expires on its own.

## What it can do

Read actual keys, teams, user records, budgets and spending; create and update keys; associate keys with teams; manage team membership and budgets using the selected operations in `admin-operations.json`. It discovers tool argument schemas dynamically. It is not every Admin UI feature. Add operations deliberately through `configure_mcp.py` and update the exact tool allowlist.

For named-person key spending it resolves the user, reads their individual key objects, and labels stored key spend and available period information. User totals can differ from the sum of current keys. Explicit date ranges need filtered reports.

Only user-requested changes are allowed by the instructions. Uncertain writes stop the run and are never retried automatically. Identical calls are cached within a run. A persistent SQLite journal prevents Slack delivery retries or repeated A2A request/message IDs from repeating operations. The event/action journal stores actor IDs, tool names and statuses, but no request bodies, credentials or raw outputs.

Generated virtual keys are removed from model tool results and sent separately to the verified requester. Provider credentials and tokens are redacted. Conversation history lives in memory, is isolated by transport/user/conversation, and clears on restart. Tracing is disabled. Admin operations use the caller’s personal credential; the local journal also records the requesting identity. Saved account credentials live in a separate encrypted table in the persistent database. No raw credential is stored in the journal.

## Architecture

- `app.py`: Slack Socket Mode and process lifecycle.
- `auth.py`: Slack profile/email matching and live LiteLLM role checks.
- `admin_api.py`: role-gated backend for the shared MCP server; selected routes only and no shared credentials.
- `connections.py`: private SSO connection pages, CSRF/browser protection, expiring links and encrypted sessions.
- `sso.py`: LiteLLM device sign-in client and validated team selection.
- `agent.py`: configuration, MCP connection and model instructions.
- `engine.py`: shared Agents SDK runner and conversation isolation.
- `core.py`: tool validation, secret handling and persistent action journal.
- `web.py`: A2A 0.3 JSON-RPC `message/send`; text only, no streaming/tasks/push.
- `register_agent.py`: redacted registration preview and explicit apply command.
- `configure_mcp.py`: existing native LiteLLM admin MCP setup.

## Local setup

Use Python 3.12, a virtual environment, and `pip install -r requirements-dev.txt`. Copy `.env.example` to a private `.env` and fill it locally. Never commit or paste credentials into chat.

The BerriAI Slack app is `A0C3AE23W9H`; use the existing app rather than creating another. `slack-manifest.json` adds `users:read` and `users:read.email` to the existing `chat:write` and `im:history` permissions. Those scopes are already installed in BerriAI. Keep Socket Mode enabled with the existing `connections:write` app token and `message.im` events. The app’s Messages tab allows DMs.

Set `LITELLM_MCP_URL=https://gateway.litellm-sandbox.ai/personal_admin/mcp` and `LITELLM_MCP_ALIAS=personal_admin`. The MCP registration must use `url=https://litellm-admin-agent.onrender.com/admin-api`, `spec_path=https://gateway.litellm-sandbox.ai/openapi.json`, empty stored credentials, and the selected operation allowlist. `allow_all_keys=true` is safe only with this role-gated backend; never enable it while the registration points directly at the gateway API. `ADMIN_TOOL_NAMES` must contain the exact discovered names including the `personal_admin-` prefix. Generate `CREDENTIAL_ENCRYPTION_KEY` with `cryptography.fernet.Fernet.generate_key()` and keep it stable across deploys. Losing or replacing it makes existing saved credentials unreadable, requiring admins to reconnect.

Commands:

```sh
python app.py --check
python -m pytest -q
python app.py --web
```

`--check` validates configuration and Slack workspace/profile access without posting or invoking administrative tools. It does not exercise a personal credential or LLM request. Optional `--list-tools` uses the explicit setup-only `LITELLM_SETUP_KEY`; this variable is not read by normal service startup. `configure_mcp.py --apply` and `register_agent.py --apply` use a private local `LITELLM_ADMIN_KEY` for one-time registration only. Do not add that setup credential to Render.

Browser verification also covers native form submission: `Referrer-Policy: same-origin` preserves the same-origin POST header required by CSRF protection. Browser-session, expired-link, and account-verification failures have separate messages; logs record only the failure category.

Tests cover SSO pending/expired sessions, team selection, malformed gateway responses, encrypted restart persistence, link replay and disconnect races. They also exercise the real Agents SDK loop, caller-credential propagation to both clients, two-user isolation, role revocation, disconnect during a run, uncertain mutation handling, HTTP A2A requests, CSRF/browser binding, expired/replayed links, and encrypted persistence.

## Render

`render.yaml` defines one Starter Python web service in Oregon, a 1 GB persistent disk at `/var/data`, and a `/healthz` health check. Keep a single instance because SQLite and in-memory conversations are local to the service. Free services sleep and do not provide the persistent journal required for this deployment. Review current plan and disk pricing before creating the service.

Build: `pip install -r requirements.txt`.
Start: `python app.py --web`.
Python: `3.12.13`.
The five prompted Blueprint values are:

| Field | Purpose |
| --- | --- |
| `SLACK_BOT_TOKEN` | Existing app’s bot token |
| `SLACK_APP_TOKEN` | Existing app’s Socket Mode token |
| `CREDENTIAL_ENCRYPTION_KEY` | Encrypts each admin’s saved session and pending sign-in |
| `ADMIN_TOOL_NAMES` | Exact allowlist of 62 `personal_admin-` tools |
| `ADMIN_AGENT_SERVICE_TOKEN` | Authenticates gateway-to-agent requests |

There is no shared admin key in the hosted settings. Store secret fields as private Render environment values. Generate a random 32+ character service token, also used by the gateway registration. The service gets its public URL from `RENDER_EXTERNAL_URL`; set `AGENT_PUBLIC_URL` only when overriding it. Set `STATE_DB=/var/data/events.sqlite3` so replay protection survives deploys. Automatic code deploys remain disabled. Blueprint changes are synced automatically; use a manual deploy for code-only changes. `SLACK_ENABLED=true` is the current hosted setting.

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
6. During a future migration, set the new listener to `SLACK_ENABLED=false` until the previous listener is stopped. The current cutover is complete: Render uses `SLACK_ENABLED=true`; the Mac LaunchAgent is disabled and unloaded. Retain the Mac files for rollback. Copy the current SQLite journal using SQLite’s backup API if continuity is needed. Never copy a live database file directly.

Verification covers the actual hosted role gate, native MCP caller forwarding, read-only admin tool use, and ordinary-user rejection. Neither existing keys nor team grants are modified. Temporary test users and keys are removed afterward.

## Known scope and limits

This is an internal sandbox assistant. There is no public sign-up, automatic Slack role assignment, user impersonation, or automatic escalation from regular user to admin. New admins receive access by the normal gateway role-management process. This assistant does not create invitations or email people unless explicitly requested.

Synchronous A2A responses may time out during long runs. Repeated request IDs are rejected rather than replayed; inspect state after an uncertain result before asking for the change again. Authorization requests add latency and depend on Slack and the gateway being available. This version has bounded in-memory conversations and a serialized agent runner, suitable for a small internal admin group.

# LiteLLM Admin Agent

Run a private Slack assistant for your own LiteLLM gateway. Ask about keys, teams, budgets and spending; optionally enable administrative changes. Each person connects their own gateway admin account. Model usage and tool calls use that person’s credential.

**Deployment model:** one service, one gateway, one Slack workspace. You create your own Slack app from the included manifest and host the service yourself. No Slack Marketplace listing or shared multi-workspace service is required. Slack DMs are supported; channels and group DMs are intentionally ignored.

New installations are **read-only by default**. Writes require the operator to set `ADMIN_READ_ONLY=false`. This is enforced in the tool layer and HTTP backend, independently of model instructions.

## Prerequisites

- A LiteLLM gateway on HTTPS, with a database, a model that supports tool calling, and native OpenAPI MCP server registration (`/v1/mcp/server`, an alias-specific `/personal_admin/mcp`, and per-request backend authorization forwarding).
- Gateway users with the **`proxy_admin`** role and email addresses matching their Slack profiles. Slack admin/owner status alone does not grant access. Ordinary users, viewers, guests and bots are denied.
- Permission to create/install a custom Slack app in your workspace. Your Slack organization may require an owner to approve the installation.
- A dedicated HTTPS origin for the agent, reachable by users and the gateway, plus persistent writable storage. Outbound HTTPS/WSS access to Slack and HTTPS access to your gateway are required.
- Docker Compose, or a paid Render web service with a persistent disk. For local setup helpers: Python 3.12.

Compatibility is capability-based: `configure_mcp.py` checks the gateway’s actual OpenAPI routes and `doctor.py` checks native MCP discovery. Older gateways without these MCP features need an upgrade. The shipped route inventory was captured on LiteLLM 1.103.0; it is not a claim that all releases of that version support hosted OAuth. See [gateway compatibility](docs/compatibility.md).

## 1. Get the code and create private configuration

```sh
git clone https://github.com/BerriAI/litellm-admin-agent.git
cd litellm-admin-agent
python3.12 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements.txt
python setup_env.py
```

`setup_env.py` creates a mode-0600 `.env` with unique encryption and service secrets. It refuses to overwrite an existing file. Save the encryption key in your secret manager: it must stay the same across restarts and upgrades.

Fill in these fields in `.env`:

| Field | Value |
| --- | --- |
| `LITELLM_BASE_URL` | Your gateway URL, e.g. `https://gateway.example.com/v1` |
| `LITELLM_MODEL` | A model name configured on **your** gateway and accessible to your admins |
| `AGENT_PUBLIC_URL` | The agent’s dedicated HTTPS origin, e.g. `https://admin.example.com`; no subpath |
| `SLACK_WORKSPACE_ID` | Your workspace’s `T…` ID; find it in the Slack web URL |
| `SLACK_BOT_TOKEN` | The installed app’s `xoxb-…` token |
| `SLACK_APP_TOKEN` | The app’s Socket Mode `xapp-…` token |

Leave `CONNECTION_AUTH_MODE=api_key` for the portable installation path. Users submit their **personal** virtual key on a private browser page, never in Slack. The connection is encrypted, expires after 24 hours, and is reauthorized against the gateway before use. For browser SSO without key entry, see [SSO setup](docs/compatibility.md#optional-browser-sso).

Do not use shared/master credentials for runtime requests. Setup-only `LITELLM_ADMIN_KEY` and `LITELLM_SETUP_KEY` are read only by the explicitly invoked setup helpers; normal startup never uses them.

## 2. Create and install your Slack app

1. Open [Slack’s app dashboard](https://api.slack.com/apps), choose **Create New App → From a manifest**, and select your workspace.
2. Paste the contents of [`slack-manifest.json`](slack-manifest.json). Review and create the app.
3. Under **Basic Information → App-Level Tokens**, create a token with the `connections:write` scope. Save it as `SLACK_APP_TOKEN`.
4. Under **OAuth & Permissions**, choose **Install to Workspace** and approve the requested scopes. Save the bot token as `SLACK_BOT_TOKEN`.
5. Confirm **Socket Mode** is enabled. The manifest subscribes to `message.im` and enables the app’s Messages tab. No Slack event Request URL is needed.

The bot requests only `chat:write`, `im:history`, `users:read` and `users:read.email`. Reinstall the app after changing scopes. Each deployment gets its own app tokens; do not reuse an app across multiple running listeners.

## 3. Deploy

Validate your configuration first:

```sh
python doctor.py --offline
```

### Docker Compose

```sh
docker compose up -d --build
```

The included Compose file binds port 10000 to localhost and keeps state in the `admin-state` named volume. Put a TLS reverse proxy on the same host in front of it. For example, a host-installed Caddy configuration:

```caddyfile
admin.example.com {
    reverse_proxy 127.0.0.1:10000
}
```

Point DNS at the host first. If your reverse proxy is containerized or remote, use its private network address instead of localhost. Do not expose plain HTTP to users. Avoid access logs containing `/connect/*` paths or `/oauth/callback` query strings: they contain short-lived login material. Forward the original Origin header unchanged.

The image runs as UID 10001 with a read-only root filesystem, dropped capabilities and persistent `/var/data`. Compose passes only explicitly listed runtime settings, so setup credentials in your local environment are not injected into the container.

### Render

Create a Render Blueprint using this repository (or your accessible fork) and [`render.yaml`](render.yaml). Choose the paid plan with a persistent disk and fill in your own gateway, model, Slack workspace/tokens, and encryption key. Render generates a service token and provides `RENDER_EXTERNAL_URL`; put that URL in your local `.env` as `AGENT_PUBLIC_URL` for the setup helpers. Copy the generated service token locally only if you want optional A2A registration.

After the next step, copy the generated `ADMIN_TOOL_NAMES` value from local `.env` into Render. Use a single instance and manual deployments. This consumes paid hosting resources; the blueprint does not deploy a gateway or configure DNS for you.

Both options expose `/healthz` for liveness, `/readyz` for local database/Slack connectivity, and a landing page at `/`. Readiness does not prove that a user can run a model or tool; finish the checks below.

## 4. Register the gateway tools and verify

The app must be reachable by your gateway at `AGENT_PUBLIC_URL` before using its tools. Provide `LITELLM_ADMIN_KEY` to your **local setup process** using your secret manager or a private environment. This is a one-time gateway setup credential; do not add it to Render.

```sh
# Preview the registration and save the compatible tool names in local .env.
python configure_mcp.py --write-tool-names
# Create the dedicated registration after reviewing the preview.
python configure_mcp.py --apply
# Reload ADMIN_TOOL_NAMES in Docker; on Render copy it into environment settings.
docker compose up -d --force-recreate
```

The helper creates `personal_admin`, points its backend at **your agent’s `/admin-api`**, and stores no backend credential. It refuses duplicate registrations. If `personal_admin` already exists, inspect it before changing it; never set `allow_all_keys=true` on a registration pointing directly at your gateway API. Discovery can be visible to other gateway users, but the backend independently requires a live proxy admin for every call.

Set `LITELLM_SETUP_KEY` in the local setup process to your personal proxy-admin key, then run:

```sh
python doctor.py
```

This verifies identity, model availability, compatible management routes, exact MCP tool discovery, Slack workspace/scopes and the Socket Mode app token. It does not invoke an LLM, run management tools or send Slack messages. Remove setup credentials from your environment afterward.

## 5. Connect and do a first read

1. Find **LiteLLM Admin** under Slack Apps and open a DM.
2. Send **connect** and open the private link within ten minutes.
3. Connect your own LiteLLM proxy-admin account. In personal-key mode, use a key for the same account/email as Slack. In SSO mode, sign in and consent on your gateway.
4. Return to Slack and ask: **“List my teams and their current budgets.”**
5. Confirm that a regular gateway user is denied and that **“Create a key”** is refused while read-only mode is enabled.

Send **disconnect** to delete the saved credential and invalidate pending connection links. It stops subsequent tools and result delivery in an in-flight request; it cannot undo an operation already sent. Revoke the credential in LiteLLM if you also need to invalidate it outside this app.

When you are ready to permit changes, set `ADMIN_READ_ONLY=false` and redeploy. The model is instructed to change state only when requested, but write mode does not include a separate human approval workflow. Use a test gateway to validate your chosen model and administrative workflows before enabling writes in production. The operation inventory is bounded; this is not every Admin UI feature.

## Operations and development

- [Operations, backups, upgrades and troubleshooting](docs/operations.md)
- [Gateway compatibility, SSO and optional A2A registration](docs/compatibility.md)
- [Security model and launch acceptance checks](SECURITY.md)

```sh
pip install --require-hashes -r requirements-dev.txt
python -m pytest -q
docker build -t litellm-admin-agent:smoke .
python scripts/smoke_container.py
```

CI runs the tests and boots the real image, checking readiness, runtime assets, non-root execution and replay protection after a container restart. The smoke test uses no external credentials and sends no Slack messages. Update dependency inputs in `requirements.in` / `requirements-dev.in`, then regenerate both hash-locked files with `uv pip compile --python-version 3.12 --generate-hashes`.

Source availability and licensing are separate from deployment setup. Before a public launch, the repository owner must make the source accessible to the intended users and publish the intended license. This change does not change repository visibility or grant an open-source license.

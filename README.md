# LiteLLM Admin Agent

Manage your LiteLLM gateway from a Slack DM.

- Ask about keys, teams, budgets and spending.
- Connect with your own LiteLLM admin account.
- Start in read-only mode. Enable changes after testing.
- Host one agent for one gateway and one Slack workspace.

## Before you start

- Use a LiteLLM gateway with HTTPS, a database and a model that supports tool calling. Check the [gateway requirements](docs/compatibility.md) for admin MCP support.
- Give each user a LiteLLM `proxy_admin` account with the same email as their Slack profile.
- Get permission to create and install a Slack app in your workspace.
- Install Python 3.12 for the setup commands. Choose Docker Compose or a paid Render service with persistent storage for hosting.

## 1. Create your configuration

```sh
git clone https://github.com/BerriAI/litellm-admin-agent.git
cd litellm-admin-agent
python3.12 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements.txt
python setup_env.py
```

- Open the new `.env` file to enter your settings.
- Keep `.env` private. Save the generated `CREDENTIAL_ENCRYPTION_KEY` in your secret manager and keep it across upgrades.
- Edit your existing `.env` if you have one.

## 2. Install your Slack app

- Open [Slack’s app dashboard](https://api.slack.com/apps). Choose **Create New App → From a manifest**, then select your workspace.
- Paste [`slack-manifest.json`](slack-manifest.json) and create the app.
- Under **Basic Information → App-Level Tokens**, create a token with `connections:write`. Save it in `.env` as `SLACK_APP_TOKEN`.
- Under **OAuth & Permissions**, install the app to your workspace. Save the bot token as `SLACK_BOT_TOKEN`.
- Copy your workspace’s `T…` ID from the Slack web URL into `SLACK_WORKSPACE_ID`.
- Enable **Socket Mode** and the app’s **Messages** tab. Use one running agent per Slack app.

## 3. Choose your gateway and login method

Set these values in `.env`. For Render, enter the same settings under your service’s **Environment** tab and keep the local `.env` for the setup commands.

- **Gateway URL:** set `LITELLM_BASE_URL`, for example `https://gateway.example.com/v1`.
- **Model:** set `LITELLM_MODEL` to a model name your admins can use on that gateway.
- **API-key login:** keep `CONNECTION_AUTH_MODE=api_key`. Users enter their own proxy-admin virtual key on a private browser page. Keep keys out of Slack messages.
- **SSO login:** set `CONNECTION_AUTH_MODE=sso`. Configure [SSO and the callback URL on your gateway](docs/compatibility.md#optional-browser-sso) before using this mode.
- **Agent URL:** set `AGENT_PUBLIC_URL` to the agent’s HTTPS address, such as `https://admin.example.com`, without a path. For Render, fill this into your local `.env` after deployment.

You choose **one login method for the deployment**. Each Slack user connects their own account through that method.

## 4. Deploy

### Render

- Create a Blueprint from this repository or your fork using [`render.yaml`](render.yaml).
- Choose a paid plan with a persistent disk and keep one instance.
- Enter your gateway, model, Slack settings and generated `CREDENTIAL_ENCRYPTION_KEY`. Choose your `CONNECTION_AUTH_MODE` in the service’s **Environment** tab.
- Deploy, then copy the service’s HTTPS URL into your local `.env` as `AGENT_PUBLIC_URL`.
- Keep the service token that Render generates. You need it for [optional gateway Agents registration](docs/compatibility.md#optional-gateway-agents--a2a).

### Docker Compose

- Set `AGENT_PUBLIC_URL` in `.env` to the HTTPS address you plan to use.
- Run:

```sh
python doctor.py --offline
docker compose up -d --build
```

- Point your domain at the host and put an HTTPS reverse proxy in front of port 10000. For Caddy on the same host:

```caddyfile
admin.example.com {
    reverse_proxy 127.0.0.1:10000
}
```

- Use a private network address if you run the reverse proxy in another container or on another host.
- Keep the `admin-state` volume across restarts and upgrades.

## 5. Connect the gateway tools

Run these setup commands on your computer after deployment.

- Add `LITELLM_ADMIN_KEY` to your local setup environment using your secret manager. Use this credential for setup; keep it out of the hosted service’s settings.
- Preview the gateway tool registration and save the tool names to `.env`:

```sh
python configure_mcp.py --write-tool-names
```

- Review the preview, then create the registration:

```sh
python configure_mcp.py --apply
```

- Use the agent’s `/admin-api` address from the preview as the backend, with no stored backend credential. Inspect an existing `personal_admin` registration before changing it.
- **Render:** copy `ADMIN_TOOL_NAMES` from local `.env` into the service’s **Environment** tab, then deploy.
- **Docker:** reload the settings with `docker compose up -d --force-recreate`.
- Set `LITELLM_SETUP_KEY` in your local environment to your personal proxy-admin key, then check the setup:

```sh
python doctor.py
```

- Run this check to verify your gateway, model access, tool setup and Slack tokens without making model requests, changing gateway state or sending Slack messages.
- Remove the setup credentials from your local environment after the check.

## 6. Connect from Slack

- Open **LiteLLM Admin** under Slack Apps and send **connect**.
- Open the private link within ten minutes.
- Enter your personal gateway key or sign in with SSO, depending on the method you chose for the deployment.
- Return to Slack and ask: **“List my teams and their current budgets.”**
- Check that a gateway admin can use the agent and that a regular gateway user cannot.
- Send **disconnect** to remove your saved connection. To revoke the credential itself, revoke it in LiteLLM.

## Enable changes

- Keep `ADMIN_READ_ONLY=true` while you check the setup.
- Test your model and write actions on a test gateway. Set `ADMIN_READ_ONLY=false` and redeploy to let admins create keys or change budgets and teams.
- In write mode, users can request changes without a separate approval step. Check gateway state before retrying a change after a timeout.

## More help

- [Gateway requirements, SSO and gateway Agents registration](docs/compatibility.md)
- [Troubleshooting, backups and upgrades](docs/operations.md)
- [Security and launch checks](SECURITY.md)
- [Development and tests](docs/development.md)

## License

Use, modify and redistribute this software under the [MIT License](LICENSE), including for commercial use. Keep the copyright and license notice with your copies.

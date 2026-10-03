# LiteLLM Admin Agent

Manage your LiteLLM gateway from Slack DMs and channel threads, using the standalone
[LiteLLM Admin MCP](https://github.com/BerriAI/litellm-admin-mcp) connector.

- Ask about models, keys, teams, budgets and spending.
- Connect with your own LiteLLM admin account.
- Add model deployments, create keys and update team budgets when you ask.
- Host one agent for one gateway and one Slack workspace.

## Before you start

- Use a LiteLLM gateway with HTTPS, a database and a model that supports tool calling. Check the [gateway requirements](docs/compatibility.md) for supported management APIs.
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
- **API-key login:** set `CONNECTION_AUTH_MODE=api_key`. Users enter their own proxy-admin virtual key on a private browser page. Keep keys out of Slack messages.
- **SSO login:** set `CONNECTION_AUTH_MODE=sso`. Configure [SSO and the callback URL on your gateway](docs/compatibility.md#optional-browser-sso) before using this mode.
- **Agent URL:** set `AGENT_PUBLIC_URL` to the agent’s HTTPS address, such as `https://admin.example.com`, without a path. For Render, fill this into your local `.env` after deployment.

You choose **one login method for the deployment**. Each Slack user connects their own account through that method.

## 4. Deploy

### Render

- Create a Blueprint from this repository or your fork using [`render.yaml`](render.yaml).
- Choose a paid plan with a persistent disk and keep one instance.
- Enter your gateway, model, Slack settings and generated `CREDENTIAL_ENCRYPTION_KEY`. When Render asks for `CONNECTION_AUTH_MODE`, enter `api_key` or `sso`.
- To change the login method later, update `CONNECTION_AUTH_MODE` in the service’s **Environment** tab and redeploy. Blueprint updates keep your choice.
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

## 5. Check the connection

The agent includes a pinned LiteLLM Admin MCP package and launches it locally
for each request with that administrator's credential. It discovers tools from
your gateway automatically; no gateway MCP registration or separate MCP service
is needed.

- Set `LITELLM_SETUP_KEY` in your local environment to your personal proxy-admin key.
- Run the read-only preflight:

```sh
python doctor.py
```

This checks gateway identity, model visibility, connector discovery and Slack
configuration without making model requests, changing gateway state or sending
Slack messages. Remove the setup credential afterward.

To restrict tools, set `ADMIN_TOOL_NAMES` to canonical connector names such as
`list_keys,list_teams,create_key`. An empty value enables all reviewed tools
available on your gateway, subject to read-only mode. An explicitly selected
tool that is unavailable stops the request.

To use a separately hosted LiteLLM Admin MCP, set `ADMIN_MCP_URL` to its trusted
HTTPS endpoint, for example `https://admin-mcp.example.com/mcp`. The agent sends
the requesting user's gateway bearer credential to that connector. Configure it
for the same gateway and only use a server you operate and trust. Its own
allowlist and read-only settings also apply.

## 6. Connect from Slack

- Open **LiteLLM Admin** under Slack Apps and send **connect**.
- Open the private link within ten minutes.
- Enter your personal gateway key or sign in with SSO, depending on the method you chose for the deployment.
- Return to Slack and ask: **“List my teams and their current budgets.”**
- Check that a gateway admin can use the agent and that a regular gateway user cannot.
- Send **disconnect** to remove your saved connection and revoke its SSO grant. Personal API keys are revoked separately in LiteLLM.

Mention **@LiteLLM Admin** in any channel where the bot has been added. It replies
in a thread; continue there without mentioning it again. DMs also retain context.
Every request checks the sender's own connected account and current `proxy_admin`
role. Admins share the visible channel-thread context, fetched from Slack with
speaker identities before each turn. Each operation uses the current sender's own
credential; private DM history and tool results are not shared across admins.
AgentChat supplies the native thread history, speaker-preserving model input and
optional reply filter. Untagged thread replies are checked for relevance before opening admin tools.
Replies that supply missing information continue the task; side conversations
addressed to teammates receive no bot response. The agent knows its configured model name.
Ordinary channel answers are visible to channel participants. Sign-in links and
generated keys are sent only to the requesting admin in a DM.

You can mention someone in a request, for example **“Create a key for @teammate.”**
The agent uses AgentChat's native Slack profile lookup to find their email, then
matches it to an existing LiteLLM user. It asks for clarification if Slack does
not expose an email or the gateway match is ambiguous. The included manifest
already requests `users:read` and `users:read.email`; no extra permission is needed
when both are already installed. A Slack profile lookup does not grant admin access.

Only a verified admin request starts thread tracking. After connecting from a
channel prompt, mention the bot again. Threads are followed for seven days after
the last verified admin message, up to 1,000 active threads. Tracked threads survive
restarts, and channel context is recovered from Slack; private DM model history
clears on restart. If thread history cannot be read, the app reports this and runs
no operations. Existing installations
must [update and reinstall the Slack manifest](docs/operations.md#upgrade-slack-conversations).

## Optional read-only mode

- After connecting your admin account, you can request changes without an extra setup step.
- Set `ADMIN_READ_ONLY=true` and redeploy if you want to restrict your deployment to lookups.
- Check gateway state before retrying a change after a timeout.

## Add a model from chat

- Ask to add a deployment with its public model name, exact provider/model ID, and authentication reference. For example: **“Add a model named support-chat using openai/gpt-4.1 and the existing gateway credential openai-production.”**
- The agent looks for existing deployments, creates the requested model, and checks the returned deployment ID. Adding it does not test provider inference or provision provider-side access.
- Keep provider API keys out of chat. Use a credential already stored in LiteLLM, a gateway environment-variable reference, or the provider authentication configured on your gateway. Supply provider-specific settings such as an Azure API base/version when required.
- Your gateway needs a database, `STORE_MODEL_IN_DB=True`, and the model management endpoints. See [model creation requirements](docs/compatibility.md#model-creation).
- Existing installations should follow the [Admin MCP migration guide](docs/operations.md#migrate-to-the-standalone-admin-mcp) to update legacy settings.

## More help

- [Gateway requirements, SSO and gateway Agents registration](docs/compatibility.md)
- [Troubleshooting, backups and upgrades](docs/operations.md)
- [Security and launch checks](SECURITY.md)
- [Development and tests](docs/development.md)
- [Contributing and proposing changes](CONTRIBUTING.md)

## License

Use, modify and redistribute this software under the [MIT License](LICENSE), including for commercial use. Keep the copyright and license notice with your copies.

# Gateway compatibility

This is a single-tenant service: one trusted HTTPS gateway origin and one Slack workspace per installation. Subpath hosting, automatic workspace onboarding, Slack Marketplace distribution, enterprise-wide Slack installation and horizontally scaled workers are not supported.

The gateway must support:

- `/user/info` with the supplied bearer, returning matching top-level/user-record IDs and a live `proxy_admin` role, with the user’s actual email.
- A LiteLLM Enterprise license. `/health/license` with the supplied bearer must report `license_type: "enterprise"`; otherwise every request is refused. A confirmed license is cached for one hour, so removing it takes up to an hour to stop the agent; adding one takes effect on the next request.
- `/v1/models` and chat completions using that same personal credential. Choose a model with reliable tool calling.
- `/openapi.json` and the management endpoints you want to use. The connector
  discovers exact argument schemas and exposes only reviewed routes present on
  that gateway. Missing routes are omitted; changed operation IDs fail discovery
  until reviewed.
- Network access from the agent (or hosted connector) to those gateway APIs.

The separately versioned [LiteLLM Admin MCP](https://github.com/BerriAI/litellm-admin-mcp)
package owns the tool catalog and management API integration. The agent uses its
standard MCP interface over a local subprocess by default, or Streamable HTTP
when `ADMIN_MCP_URL` is configured. Native gateway MCP registration and access to
an agent `/admin-api` backend are no longer required.

Personal-key mode (`CONNECTION_AUTH_MODE=api_key`) does not require gateway OAuth. Each key must belong to an active proxy-admin user, have model access, and match the Slack user’s verified email. Stored connections expire after 24 hours; the gateway’s own key expiry and revocation can shorten that. Connecting does not broaden a key’s gateway permissions.

## Model creation

Model creation uses `POST /model/new`. Deployment lookup uses `GET /v2/model/info`
when available, with `GET /v1/model/info` as a fallback. Setup includes only the
routes present in the gateway's OpenAPI spec.

- Connect a database and enable `STORE_MODEL_IN_DB=True` on the gateway.
- Configure provider authentication on the gateway, or use a stored credential
  through `litellm_params.litellm_credential_name`. An environment-variable
  reference is resolved by the gateway, not by the agent service.
- Provide the exact provider/model ID and any required endpoint/version settings.
  The agent does not provision cloud deployments or grant provider-side access.
- Model creation remains subject to the caller's gateway permissions, feature
  entitlements and validation. Registering a deployment is not an inference test.
- `ADMIN_READ_ONLY=true` disables model creation while retaining model lookups.

## Native Enterprise deployment

A LiteLLM image that includes the native Slack integration can run this package as a dedicated worker with `CONNECTION_AUTH_MODE=native`. The gateway and worker use the same `ADMIN_AGENT_SERVICE_TOKEN`, and the gateway sets `LITELLM_ADMIN_AGENT_URL` to the worker's private HTTP address. Keep that address on the deployment network; do not add a public ingress for the worker

In this mode, Slack links open `/liteadmin/slack/connect/` on the existing gateway. The user signs in through the gateway's normal SSO, confirms the connection, and the gateway hands a personal session to the worker over the private network. The worker independently verifies the user's current admin role and matching Slack email before consuming the link. Sessions expire after 24 hours; `connect` renews them, while `disconnect` removes the worker's saved copy and invalidates pending links. It does not revoke an exported session credential at the gateway

There is no hosted OAuth callback or separate agent domain. `AGENT_PUBLIC_URL` defaults to the gateway origin when omitted. The worker still needs outbound access to Slack and HTTPS access to the gateway. Run one worker per Slack app and preserve its encrypted state volume and encryption key

Install the package with its locked dependencies, then run `litellm-admin-agent --web`. The source checkout's `python app.py --web` remains supported

## Optional browser SSO

Set `CONNECTION_AUTH_MODE=sso` only on a gateway that implements the hosted **proxy API** authorization-code flow:

- Dynamic client registration at `/register` with an exact HTTPS redirect URI and `token_endpoint_auth_method=none`.
- `/authorize` using S256 PKCE, `resource=<gateway origin>` and the gateway’s configured SSO provider/consent.
- `/token` returning `access_token`, `token_type=Bearer`, `user_id` and `expires_in`.
- The gateway’s exact callback allowlist:

```text
LITELLM_PROXY_API_OAUTH_REDIRECT_URIS=https://admin.example.com/oauth/callback
```

This setting is separate from MCP OAuth redirect configuration. Do not use wildcards. The gateway must already have its own SSO provider configured; this app does not need a separate Google/Okta client secret.

The original integration used LiteLLM source commit `445c1cc0e04bd98e226c917232c60bab0f20d46a` for hosted callbacks. This repository does not assert that a particular published gateway image contains it. Verify support in your release or use personal-key mode; do not deploy the historical BerriAI private overlay as a general installation dependency.

A login round trip is required to validate SSO: send `connect`, sign in, confirm return to the browser page, and make a read request in Slack. An unsupported callback must fail closed. The app does not silently switch authentication modes.

Sessions and pending PKCE material are encrypted. State, CSRF, exact Origin, secure cookies, expiring links and verified Slack email bind the flow to the requester. Refresh tokens are revoked when supported and discarded; the app retains only the time-limited access session. Disconnect deletes the stored copy rather than revoking the gateway session.

## Optional gateway Agents / A2A

Slack does not require an A2A registration. To expose the same service in your gateway’s Agents UI, copy the service’s `ADMIN_AGENT_SERVICE_TOKEN` into your private local setup environment and provide a setup-only `LITELLM_ADMIN_KEY`:

```sh
python register_agent.py
python register_agent.py --apply
```

The preview hides the service token. Registration sets `make_public=false`, forwards the original caller’s Authorization header and adds a private `X-Admin-Agent-Token`. The service independently checks the caller’s current admin role. Claimed metadata/role headers are ignored. No Slack account is required for this transport.

Only A2A 0.3 JSON-RPC `message/send` is supported: text messages, synchronous replies, no streaming/tasks/push. Request and message IDs are unique per authenticated caller and persisted across restarts. Duplicates return 409. Busy requests return 429; when the response explicitly says no operation started, retry later with new IDs. After timeouts or uncertain outcomes, inspect gateway state before sending another write.

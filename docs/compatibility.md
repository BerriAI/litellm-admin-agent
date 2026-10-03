# Gateway compatibility

This is a single-tenant service: one trusted HTTPS gateway origin and one Slack workspace per installation. Subpath hosting, automatic workspace onboarding, Slack Marketplace distribution, enterprise-wide Slack installation and horizontally scaled workers are not supported.

The gateway must support:

- `/user/info` with the supplied bearer, returning matching top-level/user-record IDs and a live `proxy_admin` role, with the user’s actual email.
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

## Optional browser SSO

Set `CONNECTION_AUTH_MODE=sso` with a normal gateway release that supports delegated API OAuth. The app discovers standard authorization-server metadata at `/.well-known/oauth-authorization-server/oauth/api`, with issuer `<gateway>/oauth/api` and scope `proxy:admin`. A source commit or custom gateway image is not an installation dependency.

Configure the app's exact HTTPS callback on the gateway:

```text
LITELLM_OAUTH_ADMIN_REDIRECT_URIS=https://admin.example.com/oauth/callback
```

The gateway retains its existing SSO provider configuration. The app needs no Google/Okta client secret or gateway MCP registration. It registers a public OAuth client, requests the gateway resource with S256 PKCE and `scope=proxy:admin`, and follows the gateway's normal sign-in and consent flow.

The token endpoint returns standard `access_token`, `token_type`, `expires_in`, `refresh_token` and `scope` fields. Identity and current admin permissions come from `/user/info`. The app stores encrypted credentials and renews them for at most 24 hours after connection; gateway policy can end access sooner. Renewal never extends that local deadline.

State, CSRF, exact Origin, secure cookies, expiring links and verified Slack email bind the connection to its requester. Disconnect removes local access immediately and revokes the gateway grant. Failed revocation stays encrypted for retry at startup or the next connection operation. Resources intentionally created through the app remain after disconnect.

After upgrading, existing SSO users reconnect once. Test a complete round trip: send `connect`, finish gateway sign-in, return to the app, make an admin read request, then disconnect. Unsupported gateways fail closed; the app never silently changes authentication modes.

## Optional gateway Agents / A2A

Slack does not require an A2A registration. To expose the same service in your gateway’s Agents UI, copy the service’s `ADMIN_AGENT_SERVICE_TOKEN` into your private local setup environment and provide a setup-only `LITELLM_ADMIN_KEY`:

```sh
python register_agent.py
python register_agent.py --apply
```

The preview hides the service token. Registration sets `make_public=false`, forwards the original caller’s Authorization header and adds a private `X-Admin-Agent-Token`. The service independently checks the caller’s current admin role. Claimed metadata/role headers are ignored. No Slack account is required for this transport.

Only A2A 0.3 JSON-RPC `message/send` is supported: text messages, synchronous replies, no streaming/tasks/push. Request and message IDs are unique per authenticated caller and persisted across restarts. Duplicates return 409. Busy requests return 429; when the response explicitly says no operation started, retry later with new IDs. After timeouts or uncertain outcomes, inspect gateway state before sending another write.

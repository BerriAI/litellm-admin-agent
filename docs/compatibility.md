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

Set `CONNECTION_AUTH_MODE=sso` to reuse your gateway's configured SSO provider. The app discovers hosted administrator authorization from `/.well-known/litellm-cli-auth` on `LITELLM_BASE_URL`; it does not need Google/Okta client secrets or a custom gateway image.

Use a normal gateway release that advertises `proxy:admin` in `hosted_app.scopes_supported`, with contract version 1, S256 PKCE, public-client registration, refresh tokens and revocation. Missing support produces a **Gateway update required** message before redirecting to sign-in. The app trusts only the configured gateway origin for the issuer, resource and token endpoints.

Allow the app's exact HTTPS callback on the gateway:

```text
LITELLM_PROXY_API_OAUTH_ADMIN_REDIRECT_URIS=https://admin.example.com/oauth/callback
```

This is a separate opt-in from the reporting-only `LITELLM_PROXY_API_OAUTH_REDIRECT_URIS` and MCP OAuth redirect settings. Do not use wildcards. The gateway must have its normal SSO provider and shared grant storage configured. Keep the callback configuration and shared storage when upgrading the standard gateway deployment.

The app requests explicit `proxy:admin` consent. The gateway checks the user's current administrator role and existing permissions on each use; connecting does not confer a new role. A login round trip is required to validate the installation: send `connect`, sign in, confirm return to the browser page, then make a read request in Slack.

Access tokens last up to five minutes. Encrypted rotating refresh tokens renew them for at most 24 hours after consent. The app records refresh attempts before sending them; a timeout or interrupted rotation requires reconnecting instead of replaying the refresh or an administrator action. Sessions are bound to their gateway origin, verified Slack email and browser flow. Disconnect removes local access immediately and revokes the gateway token family. If revocation is temporarily unavailable, encrypted cleanup records survive restart and are retried on startup and subsequent requests.

Existing SSO connections from the prototype did not retain bound refresh state and require one new sign-in after upgrading. Personal-key connections are unchanged. Changing the gateway origin never forwards an existing SSO credential to the new gateway; reconnect to the new gateway instead.

## Optional gateway Agents / A2A

Slack does not require an A2A registration. To expose the same service in your gateway’s Agents UI, copy the service’s `ADMIN_AGENT_SERVICE_TOKEN` into your private local setup environment and provide a setup-only `LITELLM_ADMIN_KEY`:

```sh
python register_agent.py
python register_agent.py --apply
```

The preview hides the service token. Registration sets `make_public=false`, forwards the original caller’s Authorization header and adds a private `X-Admin-Agent-Token`. The service independently checks the caller’s current admin role. Claimed metadata/role headers are ignored. No Slack account is required for this transport.

Only A2A 0.3 JSON-RPC `message/send` is supported: text messages, synchronous replies, no streaming/tasks/push. Request and message IDs are unique per authenticated caller and persisted across restarts. Duplicates return 409. Busy requests return 429; when the response explicitly says no operation started, retry later with new IDs. After timeouts or uncertain outcomes, inspect gateway state before sending another write.

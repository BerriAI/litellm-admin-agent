# Gateway compatibility

This is a single-tenant service: one trusted HTTPS gateway origin and one Slack workspace per installation. Subpath hosting, automatic workspace onboarding, Slack Marketplace distribution, enterprise-wide Slack installation and horizontally scaled workers are not supported.

The gateway must support:

- `/user/info` with the supplied bearer, returning matching top-level/user-record IDs and a live `proxy_admin` role, with the user’s actual email.
- `/v1/models` and chat completions using that same personal credential. Choose a model with reliable tool calling.
- Native MCP server creation/listing at `/v1/mcp/server`, an alias-specific streamable HTTP endpoint, OpenAPI tools, `allow_all_keys`, and per-request `x-mcp-personal_admin-authorization` forwarding.
- HTTPS access from the gateway to the agent’s `/admin-api` backend. Firewall rules must allow the selected management routes and methods.

`configure_mcp.py` intersects the shipped route inventory with the live OpenAPI spec. Missing routes are omitted; changed operation IDs fail setup until reviewed because read/write classification must stay accurate. `--write-tool-names` saves the compatible subset. `doctor.py` verifies it against live MCP discovery. Do not substitute a stored shared backend key to work around a compatibility failure.

- Inspect existing `personal_admin` registrations for shared backend credentials. You cannot confirm their absence from a server listing because LiteLLM redacts stored secrets.
- Point the registration at the agent’s `/admin-api` backend. Do not enable `allow_all_keys=true` on a registration that points at the gateway API.

Personal-key mode (`CONNECTION_AUTH_MODE=api_key`) does not require gateway OAuth. Each key must belong to an active proxy-admin user, have model access, and match the Slack user’s verified email. Stored connections expire after 24 hours; the gateway’s own key expiry and revocation can shorten that. Connecting does not broaden a key’s gateway permissions.

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

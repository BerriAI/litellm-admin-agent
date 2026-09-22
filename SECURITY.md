# Security and launch acceptance

The service accepts DMs only from its configured Slack workspace. Slack membership, non-guest status, gateway `proxy_admin` role and matching verified email are independently checked. A2A requires both a private service token and the caller’s own live admin credential. Browser connection links are private, single-use and valid for ten minutes.

There is no shared runtime administrator credential. Model calls and management requests use each requester’s credential. Saved credentials are encrypted with Fernet; deployment operators who possess both the database and encryption key can decrypt them. Keep both protected. Generated virtual keys are removed from model tool results and delivered separately to the verified requester. SDK tracing is disabled; a gateway/model provider’s own logging is outside this service.

Connected gateway admins can request reads and changes by default. Set `ADMIN_READ_ONLY=true` to block non-GET tools and non-GET backend routes. In write mode, model instructions constrain requested changes, but this is not a deterministic per-operation approval system. Untrusted model/tool content may still influence an authorized write-capable session. Restrict enabled tools, validate your chosen model on a test gateway, and limit administrative access accordingly.

The backend is restricted to a reviewed route inventory. It rechecks the caller before forwarding and before releasing results, sets the actual audit identity, rejects redirects and does not retry requests. A timeout or MCP error from a write is treated as an uncertain outcome. Persistent replay protection prevents transport redelivery from repeating an accepted event; it cannot undo completed operations or recognize semantically duplicated requests with fresh IDs.

Before exposing a new deployment to users, its operator should verify:

- The repository/release is accessible to those users and distributions include the MIT license notice.
- The service uses its own Slack app, gateway URLs, model, encryption key and service token.
- TLS works; login material and Authorization headers are excluded from proxy logs.
- `doctor.py` passes against the target gateway. A real admin can connect and perform a read in Slack; a regular user and mismatched email are denied.
- An authorized admin can complete a reversible test-object workflow on a test gateway. If you choose read-only mode, verify that it blocks writes through both the agent and direct backend access.
- Disconnect/revocation stops further operations, a restart preserves encrypted connections and replay protection, and a backup can be restored.

The automated suite and container smoke cover local security boundaries and packaging. They do not replace installation-specific browser/Slack/gateway verification, a penetration test, or an availability certification. This service currently supports one replica and has no high-availability or multi-tenant guarantees.

If you discover a security issue, report it privately through the repository’s Security Advisories feature if enabled, or your established private channel to the maintainers. Do not include live credentials in public issues, screenshots or logs.

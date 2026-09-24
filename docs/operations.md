# Operating the service

## State and capacity

Run exactly **one process and one replica** per deployment. Slack Socket Mode deliveries, SQLite state and in-memory conversation history are local to this service. Multiple replicas are not a high-availability configuration.

`STATE_DB` contains encrypted connections, expiring connection links, replay identifiers and an audit journal with actor IDs/tool names/statuses. It does not store tool arguments or results. Conversations are in memory, isolated per caller/transport/conversation, bounded to 100 conversations and 20 messages each, and clear on restart.

Requests execute serially. `MAX_PENDING_REQUESTS` defaults to 8 including the active run, `QUEUE_TIMEOUT_SECONDS` to 30 and `RUN_TIMEOUT_SECONDS` to 180. Run deadlines do not undo completed gateway actions. Queue rejection starts no tools. The agent never automatically retries an uncertain write. Slack delivery retries and duplicate A2A IDs cannot replay an accepted event.

The process stops accepting new work on SIGTERM/SIGINT and drains or cancels active handlers before closing its database. Leave at least 75 seconds of shutdown grace with the provided configuration. If a host kills the process abruptly, its journal preserves the received event ID; inspect any `started`/`outcome_unknown` actions before retrying.

## Monitoring

- `/healthz`: process HTTP liveness.
- `/readyz`: usable database connection and connected Slack socket when enabled. Returns 503 during startup/disconnect/shutdown.
- `doctor.py`: operator-run gateway/model-catalog/MCP/Slack preflight. It does not prove end-to-end inference or tool execution.
- Service logs: failure stage and exception class, without upstream bodies, messages or credentials. Journal statuses distinguish completion, denial, replay prevention and uncertain operations.

Monitor disk space, process restarts, readiness, latency and failed/uncertain requests. The durable journal is retained indefinitely to preserve replay protection; size the volume and back it up. Do not delete journal rows casually. Keep proxy access logs from capturing login-link paths, authorization codes or request bodies. Model requests and administrative responses pass through your gateway and chosen model provider; configure their retention independently.

## Backup and restore

Keep the encryption key in a secret manager **separate from the database backup**. Losing it makes saved credentials unreadable. Backup files contain sensitive encrypted sessions and identity metadata; restrict and encrypt backup storage.

For Docker, create a consistent SQLite snapshot inside the persistent volume, then copy it out. Choose a new backup name per run:

```sh
docker compose exec admin-agent python -c "import sqlite3; source=sqlite3.connect('/var/data/events.sqlite3'); target=sqlite3.connect('/var/data/backup.sqlite3'); source.backup(target); target.close(); source.close()"
docker compose cp admin-agent:/var/data/backup.sqlite3 ./backup.sqlite3
chmod 600 backup.sqlite3
```

Use SQLite’s backup API or stop the process; do not copy just the main database file while WAL writes are active. On Render, run the equivalent backup through the service shell and transfer it to private backup storage.

Restore with the service stopped. Restore the snapshot as `STATE_DB`, preserve UID 10001 write permissions for Docker, and restore the matching encryption key. Do not leave old `-wal`/`-shm` files from another database alongside the restored snapshot. Start one instance, check readiness and test a read with a reconnected admin. Restoring an older snapshot also rolls replay protection back: inspect any actions since that snapshot before resubmitting requests.

## Upgrades and existing deployments

Back up first. Pin the reviewed commit/image, rebuild, keep the state volume and encryption key, and run the preflight and a read-only smoke request after upgrading. Roll back the image while retaining the same database unless a release explicitly changes its schema.

This release preserves the existing credential tables but changes deployment templates:

- Replace BerriAI-specific workspace/gateway/model values with your own.
- Keep `CONNECTION_AUTH_MODE=sso` for existing SSO deployments. The Render Blueprint asks for a login method on creation and uses `sync: false` to preserve your choice on later updates. The Docker `.env` template starts with `api_key`.
- If you synced an earlier Render Blueprint that set `CONNECTION_AUTH_MODE=api_key`, restore `sso` in the service’s **Environment** tab and redeploy. Updating the Blueprint alone does not undo that setting.
- `ADMIN_READ_ONLY` defaults to false, so connected admins can request changes. Set it to true for a read-only deployment. If you deployed the earlier template with `ADMIN_READ_ONLY=true`, remove that setting or change it to false to use the new default behavior.
- The image now includes all connection/SSO assets and the pinned connector package. Compose injects only runtime configuration.
- Do not sync the generic Render blueprint over an existing service without reviewing its environment changes. Keep its current URLs, tokens, encryption key and state disk.

### Migrate to the standalone Admin MCP

The agent now consumes the public LiteLLM Admin MCP package. Its old `/admin-api`
backend, gateway registration helper and duplicated route inventory have been
removed. Existing saved connections and the journal keep their current schema.

1. Back up state and preserve your encryption key, login method, URLs and tokens.
2. Remove `LITELLM_MCP_URL` and `LITELLM_MCP_ALIAS` from the service environment.
   Leave `ADMIN_MCP_URL` empty for the bundled connector, or set it to the HTTPS
   `/mcp` endpoint of your trusted standalone connector.
3. Convert any explicit `ADMIN_TOOL_NAMES` allowlist to the connector's canonical
   names. Preserve your intended restrictions. For example:

   | Previous name | New name |
   | --- | --- |
   | `personal_admin-generate_key_fn_key_generate_post` | `create_key` |
   | `personal_admin-list_keys_key_list_get` | `list_keys` |
   | `personal_admin-add_new_model_model_new_post` | `add_model` |
   | `personal_admin-model_info_v2_v2_model_info_get` | `list_models` |
   | `personal_admin-model_info_v1_v1_model_info_get` | `get_model` |

   The [connector catalog](https://github.com/BerriAI/litellm-admin-mcp/blob/main/src/litellm_admin_mcp/operations.json)
   maps every operation ID to its canonical name. Clear `ADMIN_TOOL_NAMES` only
   if you intend to enable all compatible reviewed tools.
4. Rebuild/redeploy with the new hash-locked requirements. For Docker, use
   `docker compose up -d --build --force-recreate`.
5. Run `python doctor.py` with your personal setup credential and verify a read
   through the agent. Model writes also require `ADMIN_READ_ONLY=false` and the
   [model creation prerequisites](compatibility.md#model-creation).
6. Retire the old `personal_admin` gateway MCP registration after confirming no
   other clients use it. This migration does not edit or delete it automatically.

Future connector upgrades come through the agent's pinned package dependency.
Live discovery picks up compatible routes; explicit tool restrictions continue
to apply. See the connector's own release notes when changing its version.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Bot does not appear or accept DMs | Install the manifest into the correct workspace; enable the Messages tab and `message.im`; reconnect the Slack client if necessary |
| Missing scopes or workspace mismatch | Reinstall the app and use that installation’s bot token and workspace ID |
| `/readyz` returns 503 | Slack app token / `connections:write`, outbound WSS, socket disconnects, persistent storage and process shutdown |
| Connection denied | Current gateway `proxy_admin` role, exact email match, key ownership, account/key expiry and guest/bot status |
| Browser session rejected | Open a fresh private link in one browser; preserve Origin; HTTPS is required; the public URL must be an origin without a path |
| SSO callback rejected | Hosted proxy API OAuth support and the exact callback allowlist; use explicitly configured personal-key mode if unsupported |
| Admin tools unavailable | Run `doctor.py`; check the installed connector, gateway APIs, personal credential and canonical tool allowlist; for hosted mode also check `ADMIN_MCP_URL` |
| Writes refused | Read-only mode is enabled; changing model instructions cannot bypass it |
| 429 / busy | Reduce traffic or tune bounded queue limits; this is a single-runner service |
| Timeout or uncertain write | Inspect the affected gateway object and audit trail; do not blindly submit the write again |

To remove an installation, stop its service, revoke/uninstall its Slack app, remove its gateway MCP/A2A registrations, and dispose of its state/secrets/backups according to your retention policy. Disconnecting one user does not uninstall the app.

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
- Existing SSO deployments should explicitly keep `CONNECTION_AUTH_MODE=sso`; the new templates select personal-key mode for new installations.
- `ADMIN_READ_ONLY` defaults to false, so connected admins can request changes. Set it to true for a read-only deployment. If you deployed the earlier template with `ADMIN_READ_ONLY=true`, remove that setting or change it to false to use the new default behavior.
- The image now includes all connection/SSO/backend assets. Compose injects only runtime configuration.
- Do not sync the generic Render blueprint over an existing service without reviewing its environment changes. Keep its current URLs, tokens, encryption key and state disk.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Bot does not appear or accept DMs | Install the manifest into the correct workspace; enable the Messages tab and `message.im`; reconnect the Slack client if necessary |
| Missing scopes or workspace mismatch | Reinstall the app and use that installation’s bot token and workspace ID |
| `/readyz` returns 503 | Slack app token / `connections:write`, outbound WSS, socket disconnects, persistent storage and process shutdown |
| Connection denied | Current gateway `proxy_admin` role, exact email match, key ownership, account/key expiry and guest/bot status |
| Browser session rejected | Open a fresh private link in one browser; preserve Origin; HTTPS is required; the public URL must be an origin without a path |
| SSO callback rejected | Hosted proxy API OAuth support and the exact callback allowlist; use explicitly configured personal-key mode if unsupported |
| Admin tools unavailable | Run `doctor.py`; check `personal_admin` backend URL, empty stored credentials, per-request bearer forwarding and the exact tool allowlist |
| Writes refused | Read-only mode is enabled; changing model instructions cannot bypass it |
| 429 / busy | Reduce traffic or tune bounded queue limits; this is a single-runner service |
| Timeout or uncertain write | Inspect the affected gateway object and audit trail; do not blindly submit the write again |

To remove an installation, stop its service, revoke/uninstall its Slack app, remove its gateway MCP/A2A registrations, and dispose of its state/secrets/backups according to your retention policy. Disconnecting one user does not uninstall the app.

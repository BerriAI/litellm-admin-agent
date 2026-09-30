# Development

Use Python 3.12 and run these commands from the repository root.

## Run the tests

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt
python -m pytest -q
```

## Check the Docker image

```sh
docker build -t litellm-admin-agent:smoke .
python scripts/smoke_container.py
```

- Use the smoke test to check startup, readiness and replay protection across a restart.
- Run the smoke test without gateway or Slack credentials.
- Use GitHub Actions to run the test suite and container smoke test on pushes and pull requests.

## Update dependencies

- Edit `requirements.in` or `requirements-dev.in`.
- Regenerate the dependency files with hashes:

```sh
uv pip compile --python-version 3.12 --generate-hashes requirements.in -o requirements.txt
uv pip compile --python-version 3.12 --generate-hashes requirements-dev.in -o requirements-dev.txt
```

- Run the tests and Docker checks before opening a pull request.

## Connector boundary

The public `litellm-admin-mcp` release owns route selection, OpenAPI schemas,
management API calls and transport authorization. Add or change gateway tools
there first, then update this agent's pinned dependency. Agent tests cover the
conversation runner, private key delivery, caller propagation and model creation
through a real connector subprocess; connector tests cover direct MCP policies
and both transports. The old HTTP backend and registration tests moved with that
responsibility.

## Slack transport boundary

AgentChat's public `Slack` channel owns Socket Mode, normalization, acknowledgements
and subscribed thread routing. The app binds its existing authenticated runner
through `Slack.bind`; it does not add a second agent loop or history store.
`Journal.claim_many` claims both Slack's event ID and the canonical message ID in
one transaction so retries, duplicate event types and pre-upgrade replay records
cannot repeat a write. The SQLite subscription adapter stores only thread IDs and
last-activity times. Regression tests use real AgentChat and the real Agents SDK
with fake Slack and gateway I/O.

The dependency is temporarily pinned to immutable AgentChat commit
`dd888021b5ed225d848566aeec094c45b566d2f1` in the author's fork, with archive hashes
in both lock files. This includes the transport fixes proposed in
[BerriAI/agentchat#4](https://github.com/BerriAI/agentchat/pull/4). Move the pin to a
reviewed upstream release/commit after that change merges; do not use a mutable
branch URL or vendor a separate copy into this app.

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

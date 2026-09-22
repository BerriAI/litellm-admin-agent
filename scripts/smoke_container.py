"""Start a built image without external credentials; verify HTTP and durable state."""
import json
from http.client import HTTPException
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid

from cryptography.fernet import Fernet


IMAGE = os.getenv("SMOKE_IMAGE", "litellm-admin-agent:smoke")
NAME = "admin-agent-smoke-" + uuid.uuid4().hex[:10]
VOLUME = NAME + "-state"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def wait_ready(port):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=1) as response:
                assert json.load(response) == {"status": "ready"}
                return
        except (urllib.error.URLError, OSError, HTTPException):
            time.sleep(.25)
    raise RuntimeError("Container did not become ready")


try:
    docker("volume", "create", VOLUME)
    docker("run", "--detach", "--name", NAME, "--read-only", "--cap-drop=ALL",
           "--security-opt=no-new-privileges:true", "--tmpfs", "/tmp", "--publish", "127.0.0.1::10000",
           "--mount", f"source={VOLUME},target=/var/data",
           "--env", "SLACK_ENABLED=false", "--env", "LITELLM_BASE_URL=https://gateway.example.com/v1",
           "--env", "LITELLM_MODEL=test", "--env", "AGENT_PUBLIC_URL=https://admin.example.com",
           "--env", "CREDENTIAL_ENCRYPTION_KEY=" + Fernet.generate_key().decode(),
           "--env", "ADMIN_AGENT_SERVICE_TOKEN=" + uuid.uuid4().hex + uuid.uuid4().hex, IMAGE)
    port = docker("port", NAME, "10000/tcp").rsplit(":", 1)[1]
    wait_ready(port)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/.well-known/agent-card.json") as response:
        assert json.load(response)["url"] == "https://admin.example.com/a2a"
    # Check every formerly missing runtime asset inside the actual image.
    docker("exec", NAME, "python", "-c", "import sso, admin_api; from pathlib import Path; assert Path('connect.js').is_file(); assert not Path('.env').exists()")
    assert docker("exec", NAME, "id", "-u") == "10001"
    docker("exec", NAME, "python", "-c", "from core import Journal; j=Journal('/var/data/events.sqlite3'); assert j.claim('smoke-event','smoke-actor')")
    docker("restart", "--time", "25", NAME)
    port = docker("port", NAME, "10000/tcp").rsplit(":", 1)[1]
    wait_ready(port)
    docker("exec", NAME, "python", "-c", "from core import Journal; j=Journal('/var/data/events.sqlite3'); assert not j.claim('smoke-event','smoke-actor')")
    docker("exec", NAME, "python", "doctor.py", "--offline")
    print("Container smoke passed: non-root startup, runtime assets, readiness, discovery, private build context and replay protection across restart.")
except Exception:
    print(docker("logs", "--tail", "40", NAME))
    raise
finally:
    subprocess.run(["docker", "rm", "--force", NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "volume", "rm", VOLUME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

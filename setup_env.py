"""Create a private deployment configuration with unique secrets; never overwrite one."""
import argparse
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


def initialize(destination: Path) -> None:
    template = Path(__file__).with_name(".env.example").read_text()
    template = template.replace("CREDENTIAL_ENCRYPTION_KEY=\n", "CREDENTIAL_ENCRYPTION_KEY=" + Fernet.generate_key().decode() + "\n")
    template = template.replace("ADMIN_AGENT_SERVICE_TOKEN=\n", "ADMIN_AGENT_SERVICE_TOKEN=" + secrets.token_urlsafe(48) + "\n")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(template)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".env"))
    args = parser.parse_args()
    try:
        initialize(args.output)
    except FileExistsError:
        raise SystemExit("Configuration already exists. Edit it directly; preserve its encryption key.") from None
    print("Private configuration created. Fill in your gateway, model, public URL and Slack settings; then run doctor.py --offline.")


if __name__ == "__main__":
    main()

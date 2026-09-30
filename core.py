"""Authorization, replay protection, and the boundary around admin MCP calls."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import jsonschema
from mcp import types


from litellm_admin_mcp.catalog import BY_NAME


def is_read_only(name: str) -> bool:
    operation = BY_NAME.get(name)
    return bool(operation and operation.read_only)


def reply_text(text: str) -> str:
    """Recover an echoed legacy speaker envelope, leaving other JSON and code intact."""
    try:
        value = json.loads(text)
    except ValueError:
        return text
    if (isinstance(value, dict) and value.keys() == {"sender_id", "text"}
            and isinstance(value["sender_id"], str) and isinstance(value["text"], str)):
        return value["text"]
    return text


class ToolOutcomeUnknown(RuntimeError):
    """A request may have reached the upstream service; never replay it automatically."""


class Journal:
    def __init__(self, path: str):
        if path != ":memory:":
            parent = Path(path).parent
            parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, actor TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS actions (
                event_id TEXT NOT NULL, tool TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS slack_threads (
                id TEXT PRIMARY KEY, updated_at REAL NOT NULL
            );
        """)

    def claim(self, event_id: str, actor: str) -> bool:
        with self.db:
            result = self.db.execute(
                "INSERT OR IGNORE INTO events(id,actor,status) VALUES(?,?,'started')",
                (event_id, actor),
            )
        return result.rowcount == 1

    def finish(self, event_id: str, status: str) -> None:
        with self.db:
            self.db.execute("UPDATE events SET status=? WHERE id=?", (status, event_id))

    def claim_many(self, event_ids: list[str], actor: str) -> bool:
        try:
            with self.db:
                for event_id in event_ids:
                    self.db.execute("INSERT INTO events(id,actor,status) VALUES(?,?,'started')", (event_id, actor))
            return True
        except sqlite3.IntegrityError:
            return False

    def audit(self, event_id: str, tool: str, status: str) -> None:
        # No request arguments, raw results, messages or credentials are written here.
        with self.db:
            self.db.execute("INSERT INTO actions(event_id,tool,status) VALUES(?,?,?)", (event_id, tool, status))


class SlackThreads:
    """Remember at most 1,000 accepted threads for seven days since last admin activity."""

    def __init__(self, journal: Journal):
        self.db = journal.db

    async def contains(self, conversation_id: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM slack_threads WHERE id=? AND updated_at>?",
            (conversation_id, time.time() - 7 * 86400),
        ).fetchone() is not None

    async def add(self, conversation_id: str) -> None:
        now = time.time()
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO slack_threads VALUES(?,?)", (conversation_id, now))
            self.db.execute("DELETE FROM slack_threads WHERE updated_at<=?", (now - 7 * 86400,))
            self.db.execute("DELETE FROM slack_threads WHERE id IN "
                            "(SELECT id FROM slack_threads ORDER BY updated_at DESC LIMIT -1 OFFSET 1000)")


_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")
_SENSITIVE_FIELDS = frozenset({
    "token", "api_key", "access_token", "refresh_token", "password", "secret",
    "client_secret", "authorization", "authentication_token", "credential_values",
})


@dataclass
class SecretBoundary:
    """Keep returned virtual keys out of model context; deliver directly to the requester."""
    keys: dict[str, str] = field(default_factory=dict)

    def model_params(self, value: Any) -> dict:
        # Model creation can return serialized DB parameters, including provider
        # secrets. Keep only identifiers needed to inspect/verify a deployment.
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return {}
        if not isinstance(value, dict):
            return {}
        return {name: self.clean(value[name]) for name in ("model", "litellm_credential_name")
                if isinstance(value.get(name), str)}

    def clean(self, value: Any) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for k, v in value.items():
                if k.lower() == "litellm_params":
                    cleaned[k] = self.model_params(v)
                elif k.lower() in {"token", "api_key"} and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v):
                    # Hashed virtual-key identifiers are needed for management/reporting.
                    cleaned["key_hash"] = v
                else:
                    cleaned[k] = "[redacted]" if k.lower() in _SENSITIVE_FIELDS else self.clean(v)
            return cleaned
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            # MCP often encodes the entire REST response as one text content block.
            try:
                decoded = json.loads(value)
            except (ValueError, TypeError):
                decoded = None
            if isinstance(decoded, (dict, list)):
                return json.dumps(self.clean(decoded))
            def replace(match: re.Match) -> str:
                secret = match.group()
                reference = next((k for k, v in self.keys.items() if v == secret), None)
                if reference is None:
                    reference = f"returned_key_{len(self.keys) + 1}"
                    self.keys[reference] = secret
                # LiteLLM key endpoints accept the hashed token for later management.
                return f"[{reference}; key_hash={hashlib.sha256(secret.encode()).hexdigest()}; delivered privately]"
            return _KEY_PATTERN.sub(replace, value)
        return value


async def all_tools(session: Any) -> list[types.Tool]:
    result = []
    cursor = None
    seen = set()
    while True:
        page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
        result.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return result
        if cursor in seen:
            raise RuntimeError("MCP returned a repeated pagination cursor")
        seen.add(cursor)


class ToolBridge:
    def __init__(
        self, tools: list[types.Tool], allowed: frozenset[str],
        invoke: Callable[..., Awaitable[Any]], journal: Journal, event_id: str,
        ensure_authorized: Callable[[], Awaitable[None]] | None = None,
        read_only: bool = False,
    ):
        available = {t.name: t for t in tools}
        allowed = allowed or frozenset(available.keys() & BY_NAME.keys())
        if not allowed or allowed - BY_NAME.keys():
            raise ValueError("Select available LiteLLM Admin MCP tool names before starting the agent")
        # The connector also filters writes before discovery. In read-only mode,
        # configured writes are intentionally absent, not missing dependencies.
        if read_only:
            allowed = frozenset(name for name in allowed if is_read_only(name))
        if allowed - available.keys():
            raise ValueError("Select available LiteLLM Admin MCP tool names before starting the agent")
        self.tools = {name: available[name] for name in allowed}
        self.read_only = read_only
        self.invoke = invoke
        self.journal = journal
        self.event_id = event_id
        self.ensure_authorized = ensure_authorized
        self.secrets = SecretBoundary()
        self.completed: dict[str, str] = {}
        self.unknown = False
        self.mutation_attempted = False
        self.lock = asyncio.Lock()

    def search(self, query: str) -> list[dict]:
        terms = re.findall(r"[a-z0-9]+", query.lower())
        ranked = sorted(
            self.tools.values(),
            key=lambda t: (-sum(term in (t.name + " " + (t.description or "")).lower() for term in terms), t.name),
        )
        return [
            {"name": t.name, "description": (t.description or "")[:6000],
             "route": BY_NAME[t.name].path, "read_only": is_read_only(t.name),
             "input_schema": t.input_schema}
            for t in ranked[:5]
        ]

    async def call(self, name: str, arguments: dict) -> str:
        if name not in self.tools:
            return json.dumps({"error": "Tool is not enabled for this agent."})
        try:
            jsonschema.validate(arguments, self.tools[name].input_schema)
        except jsonschema.ValidationError as exc:
            return json.dumps({"error": "Invalid arguments", "field": list(exc.absolute_path), "rule": exc.validator})
        fingerprint = json.dumps([name, arguments], sort_keys=True, separators=(",", ":"))
        async with self.lock:
            if self.ensure_authorized:
                await self.ensure_authorized()
            if self.unknown:
                raise ToolOutcomeUnknown("An earlier tool outcome is unknown; this run has stopped.")
            if fingerprint in self.completed:
                return self.completed[fingerprint]
            self.journal.audit(self.event_id, name, "started")
            read_only = is_read_only(name)
            if not read_only:
                self.mutation_attempted = True
            try:
                response = await self.invoke(name=name, arguments=arguments)
                data = response.model_dump(mode="json", by_alias=True)
                cleaned = self.secrets.clean(data)
                encoded = json.dumps(cleaned)
                if not read_only and data.get("isError"):
                    # MCP can return a timeout/HTTP 5xx as a normal error result.
                    # A mutation may have committed before that error was produced.
                    raise ToolOutcomeUnknown("The gateway did not confirm the write; inspect state before retrying")
                if len(encoded) > 80000:
                    encoded = json.dumps({"notice": "Result exceeds the response limit. Use pagination or a narrower query.", "partial_result": encoded[:80000]})
                # Fetch successful reads again so a verification lookup sees
                # changes made since the earlier lookup. Keep writes deduplicated.
                if not read_only or data.get("isError"):
                    self.completed[fingerprint] = encoded
                self.journal.audit(self.event_id, name, "tool_error" if data.get("isError") else "completed")
                return encoded
            except asyncio.CancelledError:
                self.unknown = not read_only
                self.journal.audit(self.event_id, name, "read_failed" if read_only else "outcome_unknown")
                raise
            except Exception as exc:
                logging.warning("Admin tool %s failed (%s)", name, type(exc).__name__)
                if read_only:
                    self.journal.audit(self.event_id, name, "read_failed")
                    encoded = json.dumps({"error": "This read-only lookup failed.", "error_type": type(exc).__name__,
                                          "changes_made": False, "next_step": "Use a different, narrower read tool. Do not repeat this exact failed request."})
                    self.completed[fingerprint] = encoded
                    return encoded
                # A timeout/cancellation may happen after a mutation committed upstream.
                self.unknown = True
                self.journal.audit(self.event_id, name, "outcome_unknown")
                raise ToolOutcomeUnknown("Tool outcome could not be verified. Inspect state before retrying.") from None

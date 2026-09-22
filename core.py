"""Authorization, replay protection, and the boundary around admin MCP calls."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import jsonschema
from mcp import types


_OPERATIONS = {
    prefix + item["operation_id"]: item
    for item in json.loads((Path(__file__).parent / "admin-operations.json").read_text())["operations"]
    for prefix in ("litellm_admin-", "personal_admin-")
}


def is_read_only(name: str) -> bool:
    # Use our captured route inventory; unknown tools default to possible writes.
    return _OPERATIONS.get(name, {}).get("method") == "GET"


class ToolOutcomeUnknown(RuntimeError):
    """A request may have reached the upstream service; never replay it automatically."""


def authorized_event(body: dict, workspace: str, admins: frozenset[str]) -> bool:
    return valid_dm_event(body, workspace) and body["event"]["user"] in admins


def valid_dm_event(body: dict, workspace: str) -> bool:
    event = body.get("event", {})
    return bool(
        body.get("team_id") == workspace
        and isinstance(event.get("user"), str) and event["user"]
        and event.get("channel_type") == "im"
        and not event.get("bot_id")
        and not event.get("subtype")
        and isinstance(event.get("text"), str)
        and event["text"].strip()
        and event.get("channel")
        and event.get("ts")
        and body.get("event_id")
    )


class Journal:
    def __init__(self, path: str):
        if path != ":memory:":
            parent = Path(path).parent
            parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, actor TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS actions (
                event_id TEXT NOT NULL, tool TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
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


_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")
_SENSITIVE_FIELDS = frozenset({
    "token", "api_key", "access_token", "refresh_token", "password", "secret",
    "client_secret", "authorization", "authentication_token", "credential_values",
})


@dataclass
class SecretBoundary:
    """Keep returned virtual keys out of model context; deliver directly to the requester."""
    keys: dict[str, str] = field(default_factory=dict)

    def clean(self, value: Any) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for k, v in value.items():
                if k.lower() in {"token", "api_key"} and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v):
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
    ):
        available = {t.name: t for t in tools}
        if not allowed or allowed - available.keys():
            raise ValueError("Select exact, available MCP tool names before starting the agent")
        self.tools = {name: available[name] for name in allowed}
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
             "route": _OPERATIONS.get(t.name, {}).get("path"), "read_only": is_read_only(t.name),
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
                if len(encoded) > 80000:
                    encoded = json.dumps({"notice": "Result exceeds the response limit. Use pagination or a narrower query.", "partial_result": encoded[:80000]})
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

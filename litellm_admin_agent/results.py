"""Preserve schema structure and secret-field context across MCP result pages."""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Final

from pydantic import JsonValue, TypeAdapter


SENSITIVE_FIELDS: Final = frozenset({
    "token", "api_key", "access_token", "refresh_token", "password", "secret",
    "client_secret", "authorization", "authentication_token", "credential_values",
})
KEY_PATTERN: Final = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")
_SCHEMA_MAPS: Final = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})
_SCHEMA_ARRAYS: Final = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})
_SCHEMA_CHILDREN: Final = frozenset({
    "additionalProperties", "additionalItems", "unevaluatedProperties", "unevaluatedItems",
    "not", "contains", "propertyNames", "if", "then", "else", "contentSchema",
})
_ANNOTATIONS: Final = frozenset({"default", "example", "examples"})
_MODEL_IDENTIFIERS: Final = frozenset({"model", "litellm_credential_name"})
_JSON: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)


def pointer_parts(path: str) -> tuple[str, ...]:
    if path and (not path.startswith("/") or re.search(r"~(?![01])", path)):
        raise ValueError("Invalid result path")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in path.split("/")[1:])


def _schema_payload(path: tuple[str, ...]) -> bool:
    """Names in schema maps are not keywords; annotations can contain credentials."""
    context = "tool"
    sensitive = False
    for part in path:
        if context == "tool":
            context = "schema" if part in {"inputSchema", "outputSchema"} else "literal"
        elif context == "map":
            sensitive = sensitive or part.lower() in SENSITIVE_FIELDS | {"litellm_params"}
            context = "schema"
        elif context == "array" or (context == "items" and part.isdecimal()):
            context = "schema"
        elif context in {"schema", "items"}:
            if part in _ANNOTATIONS or (sensitive and part in {"const", "enum"}):
                return True
            if part in _SCHEMA_MAPS or part == "dependencies":
                context = "map"
            elif part in _SCHEMA_ARRAYS:
                context = "array"
            elif part == "items":
                context = "items"
            elif part in _SCHEMA_CHILDREN:
                context = "schema"
            else:
                context = "value" if part in {"const", "enum"} else "literal"
        elif context == "value" and part.lower() in SENSITIVE_FIELDS | {"litellm_params"}:
            return True
    return False


def clean_schema(value: JsonValue, path: tuple[str, ...]) -> JsonValue:
    # Iterative traversal preserves field definitions, including credential names.
    # Omit literal annotations, and never deliver schema examples as generated keys.
    root: list[JsonValue] = [None]
    pending: list[tuple[JsonValue, tuple[str, ...], dict[str, JsonValue] | list[JsonValue], str | int]] = [(value, path, root, 0)]
    while pending:
        item, location, parent, key = pending.pop()
        cleaned: JsonValue
        if _schema_payload(location):
            cleaned = "[redacted]"
        elif isinstance(item, dict):
            cleaned = {}
            pending.extend((child, (*location, name), cleaned, name) for name, child in item.items()
                           if not _schema_payload((*location, name)))
        elif isinstance(item, list):
            children: list[JsonValue] = [None for _ in item]
            cleaned = children
            pending.extend((child, (*location, str(index)), children, index) for index, child in enumerate(item))
        elif isinstance(item, str):
            cleaned = KEY_PATTERN.sub("[redacted]", item)
        else:
            cleaned = item
        if isinstance(parent, list) and isinstance(key, int):
            parent[key] = cleaned
        elif isinstance(parent, dict) and isinstance(key, str):
            parent[key] = cleaned
    return root[0]


def clean_data_at(
    value: JsonValue, path: tuple[str, ...], clean: Callable[[JsonValue], JsonValue],
    *, complete: bool = True,
) -> JsonValue:
    lowered = tuple(part.lower() for part in path)
    if SENSITIVE_FIELDS.intersection(lowered):
        if (complete and lowered[-1] in {"token", "api_key"}
                and not SENSITIVE_FIELDS.intersection(lowered[:-1]) and "litellm_params" not in lowered
                and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)):
            return value
        return "[redacted]"
    if "litellm_params" in lowered:
        tail = lowered[lowered.index("litellm_params") + 1:]
        if not tail:
            wrapped = clean({"litellm_params": value})
            return wrapped.get("litellm_params") if isinstance(wrapped, dict) else "[redacted]"
        if len(tail) != 1 or tail[0] not in _MODEL_IDENTIFIERS or not isinstance(value, str):
            return "[redacted]"
    return clean(value)


def clean_payload(
    value: JsonValue, *, source: str, path: str, clean: Callable[[JsonValue], JsonValue],
) -> JsonValue:
    location = pointer_parts(path)
    def sanitize(item: JsonValue, parts: tuple[str, ...], complete: bool = True) -> JsonValue:
        return (clean_schema(item, parts) if source.startswith("schema:") else
                clean_data_at(item, parts, clean, complete=complete))
    if not isinstance(value, dict) or value.get("format") != "litellm-admin-page-v1":
        return sanitize(value, location)
    if value.get("source_tool") != source or value.get("path", "") != path:
        raise ValueError("Mismatched result page")
    result = {key: clean(child) for key, child in value.items() if key not in {"value", "entries"}}
    if "value" in value:
        complete = value.get("complete") is True and value.get("offset", 0) == 0
        if isinstance(value["value"], str):
            complete = complete and value.get("total") == len(value["value"])
        result["value"] = sanitize(value["value"], location, complete)
    if "entries" in value:
        entries = value["entries"]
        if not isinstance(entries, list):
            raise ValueError("Invalid result entries")
        cleaned_entries: list[JsonValue] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Invalid result entry")
            name, entry_path = entry.get("key", entry.get("index")), entry.get("path")
            if not isinstance(name, (str, int)) or isinstance(name, bool) or not isinstance(entry_path, str):
                raise ValueError("Invalid result entry path")
            child_path = (*location, str(name))
            if pointer_parts(entry_path) != child_path:
                raise ValueError("Mismatched result entry path")
            cleaned_entries.append({key: sanitize(child, child_path, entry.get("complete") is True)
                                    if key in {"value", "preview"} else clean(child)
                                    for key, child in entry.items()})
        result["entries"] = cleaned_entries
    return result


def clean_response(
    data: dict[str, JsonValue], *, source: str, path: str, clean: Callable[[JsonValue], JsonValue],
) -> dict[str, JsonValue]:
    result = {key: clean(value) for key, value in data.items() if key not in {"content", "structuredContent"}}
    if "structuredContent" in data:
        result["structuredContent"] = clean_payload(data["structuredContent"], source=source, path=path, clean=clean)
    content = data.get("content", [])
    if not isinstance(content, list):
        raise ValueError("Invalid MCP content")
    blocks: list[JsonValue] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            raw = block["text"]
            assert isinstance(raw, str)
            try:
                value = _JSON.validate_json(raw)
            except ValueError:
                if raw.lstrip().startswith(("{", "[")):
                    raise ValueError("Unreadable JSON result") from None
                value = raw
            cleaned = clean_payload(value, source=source, path=path, clean=clean)
            blocks.append({**{key: clean(child) for key, child in block.items() if key != "text"},
                           "text": json.dumps(cleaned)})
        else:
            blocks.append(clean(block))
    result["content"] = blocks
    return result

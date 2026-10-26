import json
from dataclasses import replace
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
import jsonschema
from mcp import types
from pydantic import JsonValue, TypeAdapter

from litellm_admin_agent.auth import AccessDenied
from litellm_admin_agent.core import HELPER_NAMES, Journal, ToolBridge
from test_launch import valid_settings


def tool(name: str) -> types.Tool:
    field = "name" if name == "describe_admin_tool" else "result_id"
    schema = ({"type": "object", "required": [field], "properties": {field: {"type": "string"}}}
              if name in HELPER_NAMES else {"type": "object"})
    return types.Tool(name=name, input_schema=schema)


def result(value: JsonValue, *, error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(value))], is_error=error)


def page(source: str, token: str = "result-1") -> dict[str, JsonValue]:
    return {"format": "litellm-admin-page-v1", "result_id": token, "source_tool": source,
            "read_tool": "read_admin_result", "has_more": True}


class Connector:
    def __init__(self, *responses: types.CallToolResult | Exception) -> None:
        self.responses = iter(responses)
        self.calls: list[tuple[str, dict[str, JsonValue]]] = []

    async def invoke(self, name: str, arguments: dict[str, JsonValue]) -> types.CallToolResult:
        self.calls.append((name, arguments))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def bridge(
    connector: Connector, *, read_only: bool = False,
    ensure_authorized: Callable[[], Awaitable[None]] | None = None,
) -> ToolBridge:
    return ToolBridge(
        [tool(name) for name in ("list_keys", "create_key", "delete_keys", *sorted(HELPER_NAMES))],
        frozenset({"list_keys", "create_key"}), connector.invoke, Journal(":memory:"), "event", ensure_authorized=ensure_authorized, read_only=read_only,
    )


def test_helpers_are_discoverable_without_expanding_operation_allowlist(tmp_path: Path) -> None:
    selected = bridge(Connector())
    assert set(selected.tools) == {"list_keys", "create_key", *HELPER_NAMES}
    found = selected.search("read_admin_result")
    assert found[0]["name"] == "read_admin_result"
    assert found[0]["read_only"] is True
    assert found[0]["route"] is None
    replace(valid_settings(tmp_path), tool_names=frozenset({"list_keys"})).validate()
    with pytest.raises(ValueError):
        replace(valid_settings(tmp_path), tool_names=frozenset({"list_keys", *HELPER_NAMES})).validate()


@pytest.mark.asyncio
async def test_compact_results_and_compact_schemas_can_be_read_in_same_run() -> None:
    connector = Connector(result(page("list_keys")), result({"keys": ["first"]}),
                          result({"keys": ["second"]}), result(page("schema:list_keys", "schema-1")),
                          result({"name": "list_keys", "inputSchema": {"type": "object"}}))
    selected = bridge(connector)
    await selected.call("list_keys", {})
    first = await selected.call("read_admin_result", {"result_id": "result-1"})
    second = await selected.call("read_admin_result", {"result_id": "result-1"})
    assert "first" in first and "second" in second
    await selected.call("describe_admin_tool", {"name": "list_keys"})
    assert "inputSchema" in await selected.call("read_admin_result", {"result_id": "schema-1"})
    assert selected.mutation_attempted is False
    assert [name for name, _ in connector.calls] == [
        "list_keys", "read_admin_result", "read_admin_result", "describe_admin_tool", "read_admin_result",
    ]


@pytest.mark.asyncio
async def test_helpers_cannot_reach_disabled_operations_or_other_runs_results() -> None:
    connector = Connector(result(page("list_keys")))
    first = bridge(connector)
    await first.call("list_keys", {})
    assert "not enabled" in await first.call("describe_admin_tool", {"name": "delete_keys"})
    assert "not enabled" in await first.call("describe_admin_tool", {"name": "read_admin_result"})
    assert "not from" in await first.call("read_admin_result", {"result_id": "other-token"})
    second = bridge(connector)
    assert "not from" in await second.call("read_admin_result", {"result_id": "result-1"})
    assert len(connector.calls) == 1


@pytest.mark.parametrize("response", [result(page("delete_keys")), result(page("list_keys"), error=True),
    result({"result_id": "result-1", "source_tool": "list_keys"}), result("invalid page")])
@pytest.mark.asyncio
async def test_only_successful_source_matched_pages_grant_result_access(response: types.CallToolResult) -> None:
    connector = Connector(response)
    selected = bridge(connector)
    await selected.call("list_keys", {})
    assert "not from" in await selected.call("read_admin_result", {"result_id": "result-1"})
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_structured_page_grants_same_run_result_access() -> None:
    connector = Connector(types.CallToolResult(content=[], structured_content=page("list_keys")), result({"keys": []}))
    selected = bridge(connector)
    await selected.call("list_keys", {})
    assert response_payload(await selected.call("read_admin_result", {"result_id": "result-1"})) == {"keys": []}


@pytest.mark.asyncio
async def test_read_only_helpers_cannot_describe_or_execute_writes() -> None:
    connector = Connector(result({"name": "list_keys"}))
    selected = bridge(connector, read_only=True)
    assert set(selected.tools) == {"list_keys", *HELPER_NAMES}
    assert "not enabled" in await selected.call("describe_admin_tool", {"name": "create_key"})
    assert "not enabled" in await selected.call("create_key", {})
    assert "list_keys" in await selected.call("describe_admin_tool", {"name": "list_keys"})
    assert len(connector.calls) == 1
    assert selected.mutation_attempted is False


@pytest.mark.asyncio
async def test_helper_failure_does_not_mark_mutation_outcome_unknown() -> None:
    connector = Connector(TimeoutError(), result({"key_hash": "created"}))
    selected = bridge(connector)
    assert "read-only lookup failed" in await selected.call("describe_admin_tool", {"name": "create_key"})
    assert selected.unknown is False
    assert selected.mutation_attempted is False
    assert "created" in await selected.call("create_key", {})
    await selected.call("create_key", {})
    assert [name for name, _ in connector.calls] == ["describe_admin_tool", "create_key"]


@pytest.mark.asyncio
async def test_saved_result_read_rechecks_authorization() -> None:
    decisions = iter([None, AccessDenied()])

    async def verify() -> None:
        failure = next(decisions)
        if failure is not None:
            raise failure

    connector = Connector(result(page("list_keys")))
    selected = bridge(connector, ensure_authorized=verify)
    await selected.call("list_keys", {})
    with pytest.raises(AccessDenied):
        await selected.call("read_admin_result", {"result_id": "result-1"})
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_prior_run_write_result_requires_inspection_without_repeating_write() -> None:
    connector = Connector(result(page("create_key")))
    first = bridge(connector)
    await first.call("create_key", {})
    second = bridge(connector)
    denied = await second.call("read_admin_result", {"result_id": "result-1"})
    assert "Inspect current state" in denied
    assert "Never repeat a write" in denied
    assert [name for name, _ in connector.calls] == ["create_key"]


def schema_response() -> dict[str, JsonValue]:
    return {"name": "create_key", "inputSchema": {
        "type": "object", "required": ["litellm_params"], "properties": {
            "litellm_params": {"type": "object", "required": ["model"], "properties": {
                "model": {"type": "string"}, "api_key": {"type": "string", "default": "provider-secret"}}},
            "api_key": {"type": "string", "examples": ["sk-example123456789"], "enum": ["provider-secret"]},
            "default": {"type": "string"}, "mode": {"type": "string", "enum": ["full", "compact"]},
        }}}


def response_payload(encoded: str) -> JsonValue:
    response = types.CallToolResult.model_validate_json(encoded)
    content = response.content[0]
    assert isinstance(content, types.TextContent)
    adapter: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
    return adapter.validate_json(content.text)


@pytest.mark.asyncio
async def test_schema_structure_survives_without_credential_literals_or_private_delivery() -> None:
    description = schema_response()
    connector = Connector(result(description))
    selected = bridge(connector)
    output = response_payload(await selected.call("describe_admin_tool", {"name": "create_key"}))
    assert isinstance(output, dict)
    schema = output["inputSchema"]
    assert isinstance(schema, dict) and schema["required"] == ["litellm_params"]
    jsonschema.Draft202012Validator.check_schema(schema)
    properties = schema["properties"]
    assert isinstance(properties, dict)
    assert properties["litellm_params"] == {"type": "object", "required": ["model"],
        "properties": {"model": {"type": "string"}, "api_key": {"type": "string"}}}
    assert properties["api_key"] == {"type": "string"}
    assert properties["default"] == {"type": "string"}
    assert properties["mode"] == {"type": "string", "enum": ["full", "compact"]}
    assert selected.secrets.keys == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("view", ["full", "page"])
async def test_paged_schema_preserves_definitions_but_redacts_annotation_fragments(view: str) -> None:
    path = "/inputSchema/properties/api_key/default"
    secret = "provider-secret"
    fragment: JsonValue = secret if view == "full" else {**page("schema:create_key"), "path": path, "value": secret}
    connector = Connector(result(page("schema:create_key")), result(schema_response()), result(fragment))
    selected = bridge(connector)
    await selected.call("describe_admin_tool", {"name": "create_key"})
    schema = response_payload(await selected.call("read_admin_result", {"result_id": "result-1", "view": "full"}))
    assert isinstance(schema, dict) and "litellm_params" in json.dumps(schema)
    encoded = await selected.call("read_admin_result", {"result_id": "result-1", "path": path, "view": view})
    assert secret not in encoded and "[redacted]" in encoded
    assert selected.secrets.keys == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api_key", "/nested/password", "/litellm_params/aws_secret_access_key"])
@pytest.mark.parametrize("view", ["full", "page"])
async def test_saved_data_fragments_retain_sensitive_parent_context(path: str, view: str) -> None:
    secret = "provider-secret"
    fragment: JsonValue = secret if view == "full" else {**page("list_keys"), "path": path, "value": secret}
    connector = Connector(result(page("list_keys")), result(fragment))
    selected = bridge(connector)
    await selected.call("list_keys", {})
    encoded = await selected.call("read_admin_result", {"result_id": "result-1", "path": path, "view": view})
    assert secret not in encoded and "[redacted]" in encoded


@pytest.mark.asyncio
async def test_page_entries_and_previews_retain_source_context_in_text_and_structured_content() -> None:
    payload: dict[str, JsonValue] = {**page("list_keys"), "entries": [
        {"key": "api_key", "path": "/api_key", "value": "provider-secret"},
        {"key": "litellm_params", "path": "/litellm_params", "preview": {
            "model": "openai/example", "api_key": "provider-secret", "aws_secret_access_key": "provider-secret"}},
        {"key": "safe/name", "path": "/safe~1name", "value": "visible"},
    ]}
    response = result(payload)
    response.structured_content = payload
    selected = bridge(Connector(response))
    encoded = await selected.call("list_keys", {})
    assert "provider-secret" not in encoded
    assert "openai/example" in encoded and "visible" in encoded
    assert json.loads(encoded)["structuredContent"] == response_payload(encoded)


@pytest.mark.asyncio
@pytest.mark.parametrize("entry_path", ["/safe", "/api~2key", "api_key"])
async def test_mismatched_page_paths_fail_closed(entry_path: str) -> None:
    payload: dict[str, JsonValue] = {**page("list_keys"), "entries": [
        {"key": "api_key", "path": entry_path, "value": "provider-secret"}]}
    selected = bridge(Connector(result(payload)))
    encoded = await selected.call("list_keys", {})
    assert "read-only lookup failed" in encoded and "provider-secret" not in encoded
    assert selected.result_sources == {}


@pytest.mark.asyncio
async def test_schema_literals_and_dependency_names_are_not_annotation_keywords() -> None:
    schema: dict[str, JsonValue] = {"type": "object", "const": {"default": "keep"},
        "dependentRequired": {"default": ["other"]}, "required": ["api_key"],
        "properties": {"default": {"type": "string"}},
        "allOf": [{"properties": {"api_key": {"type": "string", "default": "provider-secret"}}}]}
    selected = bridge(Connector(result({"inputSchema": schema})))
    output = response_payload(await selected.call("describe_admin_tool", {"name": "create_key"}))
    assert isinstance(output, dict) and isinstance(output["inputSchema"], dict)
    cleaned = output["inputSchema"]
    assert cleaned["const"] == schema["const"]
    assert cleaned["dependentRequired"] == schema["dependentRequired"]
    assert cleaned["required"] == schema["required"]
    assert cleaned["properties"] == schema["properties"]
    assert "provider-secret" not in json.dumps(cleaned)


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", ['{"inputSchema":{"default":"provider-secret"}',
    '{"properties":' * 210 + '{"default":"provider-secret"}' + '}' * 210])
async def test_unreadable_schema_json_fails_closed(raw: str) -> None:
    response = types.CallToolResult(content=[types.TextContent(type="text", text=raw)])
    selected = bridge(Connector(response))
    encoded = await selected.call("describe_admin_tool", {"name": "create_key"})
    assert "read-only lookup failed" in encoded and "provider-secret" not in encoded
    assert selected.secrets.keys == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("view", ["full", "page", "entry"])
async def test_complete_hash_identifiers_remain_usable_in_saved_results(view: str) -> None:
    token = "a" * 64
    path = "/keys/0/token" if view != "entry" else "/keys/0"
    fragment: JsonValue = token
    if view == "page":
        fragment = {**page("list_keys"), "path": path, "value": token, "complete": True, "offset": 0, "total": 64}
    elif view == "entry":
        fragment = {**page("list_keys"), "path": path, "entries": [
            {"key": "token", "path": path + "/token", "value": token, "complete": True}]}
    selected = bridge(Connector(result(page("list_keys")), result(fragment)))
    await selected.call("list_keys", {})
    encoded = await selected.call("read_admin_result", {"result_id": "result-1", "path": path,
        "view": "full" if view == "full" else "page"})
    assert token in encoded


@pytest.mark.asyncio
@pytest.mark.parametrize("path,complete,total", [
    ("/api_key", False, 128), ("/api_key", True, 128),
    ("/password/token", True, 64), ("/litellm_params/api_key", True, 64),
])
async def test_hex_chunks_and_provider_secrets_are_not_virtual_key_hashes(path: str, complete: bool, total: int) -> None:
    token = "a" * 64
    fragment: dict[str, JsonValue] = {**page("list_keys"), "path": path, "value": token,
        "complete": complete, "offset": 0, "total": total}
    selected = bridge(Connector(result(page("list_keys")), result(fragment)))
    await selected.call("list_keys", {})
    encoded = await selected.call("read_admin_result", {"result_id": "result-1", "path": path})
    assert token not in encoded and "[redacted]" in encoded


@pytest.mark.asyncio
@pytest.mark.parametrize("path,value,expected", [
    ("/litellm_params/model", "openai/example", "openai/example"),
    ("/litellm_params/model", {"aws_secret_access_key": "provider-secret"}, "[redacted]"),
    ("/litellm_params/model/aws_secret_access_key", "provider-secret", "[redacted]"),
])
async def test_model_parameter_fragments_allow_only_string_identifiers(path: str, value: JsonValue, expected: str) -> None:
    selected = bridge(Connector(result(page("list_keys")), result(value)))
    await selected.call("list_keys", {})
    encoded = await selected.call("read_admin_result", {"result_id": "result-1", "path": path, "view": "full"})
    assert response_payload(encoded) == expected
    assert "provider-secret" not in encoded

"""Exercise the real Agent loop and packaged stdio MCP against a local gateway."""
import copy
import json
from dataclasses import replace

import pytest
from agents import ModelResponse
from agents.usage import Usage
from aiohttp import web
from aiohttp.test_utils import TestServer
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from auth import Principal
from core import Journal, SecretBoundary
from engine import AgentRunner
from test_agent import ScriptedModel, settings


LOOKUPS = [
    ("list_models", "model_info_v2_v2_model_info_get", "/v2/model/info", {"model": "support-chat", "page": 1, "size": 10}, "modelId"),
    ("get_model", "model_info_v1_v1_model_info_get", "/v1/model/info", {}, "litellm_model_id"),
]
DEPLOYMENT = {
    "model_name": "support-chat",
    "litellm_params": {"model": "openai/gpt-4.1", "litellm_credential_name": "openai-production"},
    "model_info": {},
}
PROVIDER_PARAMS = {
    **DEPLOYMENT["litellm_params"], "api_key": "sk-provider-secret12345678",
    "aws_secret_access_key": "provider-secret-aws",
    "vertex_credentials": {"private_key": "provider-secret-gcp"},
    "extra_headers": {"Authorization": "Bearer provider-secret-header"},
}


def model_spec(lookup_id, lookup_path, id_param):
    return {"paths": {
        "/model/new": {"post": {"operationId": "add_new_model_model_new_post", "requestBody": {
            "required": True, "content": {"application/json": {"schema": {
                "type": "object", "required": ["model_name", "litellm_params", "model_info"],
                "properties": {"model_name": {"type": "string"}, "model_info": {"type": "object"},
                               "litellm_params": {"type": "object", "required": ["model"],
                                                  "properties": {"model": {"type": "string"}}}},
            }}}}}},
        lookup_path: {"get": {"operationId": lookup_id, "parameters": [
            {"in": "query", "name": name, "schema": {"type": kind}}
            for name, kind in [(id_param, "string"), ("model", "string"), ("page", "integer"), ("size", "integer")]
        ]}},
        "/model/delete": {"post": {"operationId": "delete_model_model_delete_post"}},
    }}


@pytest.mark.parametrize("params", [PROVIDER_PARAMS, json.dumps(PROVIDER_PARAMS)])
def test_model_parameters_keep_identifiers_without_delivering_provider_secrets(params):
    boundary = SecretBoundary()
    cleaned = boundary.clean({"content": [{"text": json.dumps({"model_id": "deployment-1", "litellm_params": params})}]})
    assert json.loads(cleaned["content"][0]["text"]) == {
        "model_id": "deployment-1", "litellm_params": DEPLOYMENT["litellm_params"]}
    assert boundary.keys == {}


@pytest.mark.parametrize("lookup_name,lookup_id,lookup_path,initial_query,id_param", LOOKUPS)
@pytest.mark.asyncio
async def test_agent_creates_and_verifies_model_through_packaged_mcp(lookup_name, lookup_id, lookup_path, initial_query, id_param):
    forwarded = []
    deployment = None
    credential = "personal-admin-key"

    async def gateway(request):
        nonlocal deployment
        assert request.headers["Authorization"] == "Bearer " + credential
        if request.path == "/user/info":
            return web.json_response({"user_id": "admin", "user_info": {"user_id": "admin", "user_role": "proxy_admin"}})
        if request.path == "/openapi.json":
            return web.json_response(model_spec(lookup_id, lookup_path, id_param))
        forwarded.append((request.method, request.path, dict(request.query)))
        assert request.headers["litellm-changed-by"] == "admin"
        if request.path == "/model/new":
            assert request.method == "POST" and deployment is None
            assert await request.json() == DEPLOYMENT
            deployment = {**DEPLOYMENT, "model_info": {"id": "deployment-1"}, "litellm_params": PROVIDER_PARAMS}
            return web.json_response({"model_id": "deployment-1", "litellm_params": json.dumps(PROVIDER_PARAMS)})
        assert request.method == "GET" and request.path == lookup_path
        return web.json_response({"data": [deployment] if deployment else []})

    class CreateModel(ScriptedModel):
        async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **kwargs):
            self.inputs.append(copy.deepcopy(input))
            steps = [
                ("find_admin_tools", {"query": "model info"}),
                ("call_admin_tool", {"name": lookup_name, "arguments": {"query": initial_query}}),
                ("find_admin_tools", {"query": "add new model"}),
                ("call_admin_tool", {"name": "add_model", "arguments": {"body": DEPLOYMENT}}),
                ("call_admin_tool", {"name": lookup_name, "arguments": {"query": {id_param: "deployment-1"}}}),
            ]
            if self.index < len(steps):
                name, arguments = steps[self.index]
                output = [ResponseFunctionToolCall(type="function_call", id=f"fc{self.index}", call_id=f"c{self.index}",
                                                  name=name, arguments=json.dumps(arguments))]
            else:
                output = [ResponseOutputMessage(type="message", id="done", role="assistant", status="completed", content=[
                    ResponseOutputText(type="output_text", text="Added support-chat; verified deployment-1.", annotations=[])])]
            self.index += 1
            return ModelResponse(output=output, usage=Usage(), response_id=f"r{self.index}")

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", gateway)
    async with TestServer(app) as upstream:
        # Loopback HTTP is a connector test facility; production settings require HTTPS.
        config = replace(settings(), model_url=str(upstream.make_url("/v1")), tool_names=frozenset())
        async def verify(): pass  # The real MCP performs its own live role checks.
        model, journal = CreateModel(), Journal(":memory:")
        outcome = await AgentRunner(config, journal, model).execute(
            "Add support-chat using openai/gpt-4.1 and the stored credential openai-production",
            Principal("admin", "", "gateway", "admin"), "chat", "create-model", verify, credential,
        )
    assert outcome.status == "completed" and "deployment-1" in outcome.answer
    assert [(method, path) for method, path, _ in forwarded] == [
        ("GET", lookup_path), ("POST", "/model/new"), ("GET", lookup_path)]
    assert forwarded[-1][2][id_param] == "deployment-1"
    assert "provider-secret" not in json.dumps(model.inputs)
    assert outcome.secrets == {}
    assert journal.db.execute("SELECT tool,status FROM actions WHERE status='completed'").fetchall() == [
        (lookup_name, "completed"), ("add_model", "completed"), (lookup_name, "completed")]

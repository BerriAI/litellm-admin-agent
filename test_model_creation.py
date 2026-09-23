"""Exercise model discovery, creation and verification through the agent/backend."""
import copy
import json
from contextlib import asynccontextmanager
from dataclasses import replace

import httpx2
import pytest
from agents import ModelResponse
from agents.usage import Usage
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from mcp import types
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from admin_api import add_admin_api_routes
from auth import AdminAuthorizer, Principal
from configure_mcp import registration
from core import Journal, SecretBoundary
from engine import AgentRunner
from test_admin_api import Gateway, KEY, headers
from test_agent import ScriptedModel, response, settings


CREATE = "add_new_model_model_new_post"
LOOKUPS = [
    ("model_info_v2_v2_model_info_get", "/v2/model/info", {"model": "support-chat", "page": 1, "size": 10}, "modelId"),
    ("model_info_v1_v1_model_info_get", "/v1/model/info", {}, "litellm_model_id"),
]
DEPLOYMENT = {
    "model_name": "support-chat",
    "litellm_params": {"model": "openai/gpt-4.1", "litellm_credential_name": "openai-production"},
    "model_info": {},
}
PROVIDER_PARAMS = {
    **DEPLOYMENT["litellm_params"],
    "api_key": "sk-provider-secret12345678",
    "aws_secret_access_key": "provider-secret-aws",
    "vertex_credentials": {"private_key": "provider-secret-gcp"},
    "extra_headers": {"Authorization": "Bearer provider-secret-header"},
}


def model_spec(lookup_id, lookup_path):
    # These are the gateway operation IDs, not names derived from our inventory.
    return {"paths": {
        "/model/new": {"post": {"operationId": CREATE}},
        lookup_path: {"get": {"operationId": lookup_id}},
        "/model/delete": {"post": {"operationId": "delete_model_model_delete_post"}},
        "/model/update": {"post": {"operationId": "update_model_model_update_post"}},
    }}


@pytest.mark.parametrize("lookup_id,lookup_path,initial_query,id_param", LOOKUPS)
def test_setup_exposes_creation_and_available_lookup_without_model_delete_or_update(lookup_id, lookup_path, initial_query, id_param):
    payload = registration(model_spec(lookup_id, lookup_path), "https://gateway.example.com", "https://agent.example.com")
    assert set(payload["allowed_tools"]) == {CREATE, lookup_id}


@pytest.mark.parametrize("params", [PROVIDER_PARAMS, json.dumps(PROVIDER_PARAMS)])
def test_model_parameters_keep_identifiers_without_leaking_or_privately_delivering_provider_secrets(params):
    boundary = SecretBoundary()
    cleaned = boundary.clean({"content": [{"text": json.dumps({"model_id": "deployment-1", "litellm_params": params})}]})
    result = json.loads(cleaned["content"][0]["text"])
    assert result == {"model_id": "deployment-1", "litellm_params": DEPLOYMENT["litellm_params"]}
    assert boundary.keys == {}


@pytest.mark.parametrize("lookup_id,lookup_path,initial_query,id_param", LOOKUPS)
@pytest.mark.asyncio
async def test_agent_creates_and_verifies_model_through_authorized_backend(lookup_id, lookup_path, initial_query, id_param):
    create_name, lookup_name = "personal_admin-" + CREATE, "personal_admin-" + lookup_id

    class ModelGateway(Gateway):
        def __init__(self):
            super().__init__()
            self.deployment = None

        def handle(self, request):
            if request.url.path == "/user/info":
                return super().handle(request)
            self.requests.append(request)
            assert request.headers["Authorization"] == "Bearer " + KEY
            assert request.headers["litellm-changed-by"] == KEY
            if request.url.path == "/model/new":
                assert request.method == "POST" and self.deployment is None
                assert json.loads(request.content) == DEPLOYMENT
                self.deployment = {**DEPLOYMENT, "model_info": {"id": "deployment-1"},
                                   "litellm_params": PROVIDER_PARAMS}
                # LiteLLM can return its DB record with JSON-serialized params.
                return httpx2.Response(200, json={"model_id": "deployment-1", "model_name": "support-chat",
                                                "litellm_params": json.dumps(PROVIDER_PARAMS)})
            assert request.method == "GET" and request.url.path == lookup_path
            return httpx2.Response(200, json={"data": [self.deployment] if self.deployment else []})

    class CreateModel(ScriptedModel):
        async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **kwargs):
            self.inputs.append(copy.deepcopy(input))
            steps = [
                ("find_admin_tools", {"query": "model info"}),
                ("call_admin_tool", {"name": lookup_name, "arguments": initial_query}),
                ("find_admin_tools", {"query": "add new model"}),
                ("call_admin_tool", {"name": create_name, "arguments": DEPLOYMENT}),
                ("call_admin_tool", {"name": lookup_name, "arguments": {id_param: "deployment-1"}}),
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

    gateway = ModelGateway()
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as upstream:
        authorizer = AdminAuthorizer("https://gateway.example.com", "T", upstream)
        app = web.Application()
        add_admin_api_routes(app, "https://gateway.example.com", authorizer, upstream)
        async with TestClient(TestServer(app)) as backend:
            class MCP:
                async def list_tools(self, params=None):
                    return types.ListToolsResult(tools=[
                        types.Tool(name=lookup_name, description="Read model deployment info", inputSchema={"type": "object"}),
                        types.Tool(name=create_name, description="Add a new model deployment", inputSchema={
                            "type": "object", "required": ["model_name", "litellm_params", "model_info"],
                            "properties": {"model_name": {"type": "string"}, "model_info": {"type": "object"},
                                           "litellm_params": {"type": "object", "required": ["model"],
                                                              "properties": {"model": {"type": "string"}}}},
                        }),
                    ])

                async def call_tool(self, name, arguments):
                    if name == create_name:
                        result = await backend.post("/admin-api/model/new", json=arguments, headers=headers())
                    else:
                        assert name == lookup_name
                        result = await backend.get("/admin-api" + lookup_path, params=arguments, headers=headers())
                    assert result.status == 200
                    return response(await result.json())

            @asynccontextmanager
            async def connect(config, credential):
                assert credential == KEY
                yield MCP()

            async def verify():
                await authorizer.require_gateway_admin(KEY)

            payload = registration(model_spec(lookup_id, lookup_path), "https://gateway.example.com", "https://agent.example.com")
            config = replace(settings(), tool_names=frozenset("personal_admin-" + name for name in payload["allowed_tools"]))
            model, journal = CreateModel(), Journal(":memory:")
            outcome = await AgentRunner(config, journal, model, connect).execute(
                "Add support-chat using openai/gpt-4.1 and the stored credential openai-production",
                Principal(KEY, "", "gateway", KEY), "chat", "create-model", verify, KEY,
            )
            assert outcome.status == "completed" and "deployment-1" in outcome.answer
            assert [(r.method, r.url.path) for r in gateway.forwarded] == [
                ("GET", lookup_path), ("POST", "/model/new"), ("GET", lookup_path),
            ]
            assert gateway.forwarded[-1].url.params[id_param] == "deployment-1"
            assert "provider-secret" not in json.dumps(model.inputs)
            assert outcome.secrets == {}
            assert journal.db.execute("SELECT tool,status FROM actions WHERE status='completed'").fetchall() == [
                (lookup_name, "completed"), (create_name, "completed"), (lookup_name, "completed"),
            ]

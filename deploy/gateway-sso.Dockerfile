FROM 654278500801.dkr.ecr.us-east-1.amazonaws.com/litellm/backend@sha256:7d6078854024451567480419d77f45fbd5a146c7cb7e5cdd615a2a7a7390bb58
COPY --chown=nonroot gateway_dcr_flow.py /app/litellm/proxy/_experimental/mcp_server/gateway_dcr_flow.py
COPY --chown=nonroot native_client_consent.py /app/litellm/proxy/common_utils/html_forms/native_client_consent.py
RUN python -m py_compile /app/litellm/proxy/_experimental/mcp_server/gateway_dcr_flow.py /app/litellm/proxy/common_utils/html_forms/native_client_consent.py

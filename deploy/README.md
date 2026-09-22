# Sandbox gateway SSO deployment

The browser connection needs hosted proxy-API OAuth support on the gateway before deploying the corresponding app change. The sandbox backend image in `gateway-sso-build.json` retains the exact deployed base image and replaces only the two listed modules. No gateway-model or UI image is changed. The source modules matched the base release before this patch.

To reproduce the image, check out the exact LiteLLM source commit in the manifest. Copy its two source files into an empty build directory with their basenames, copy `gateway-sso.Dockerfile` there as `Dockerfile`, and build for `linux/amd64`. The manifest records the source hashes and published image digest.

The deployment is managed by Argo CD from `BerriAI/litellm-ops`, `apps/overlays/berrie-litellm-prod/litellm-patch.yaml`. PR https://github.com/BerriAI/litellm-ops/pull/185 pins the backend image by digest and sets exactly `https://litellm-admin-agent.onrender.com/oauth/callback` in `LITELLM_PROXY_API_OAUTH_REDIRECT_URIS`. A full rendered-overlay comparison confirms that only the backend image and this environment setting changed. Do not patch the Deployment directly: Argo restores its source configuration.

Rollback reverts the ops commit `824b92771656dbd555599e1b38ed1a5350f7f3a0`. Roll the app back to `f2b052315141d9e652eac8cdaf2751c50b512546` as well if restoring the old CLI/device sign-in. Existing encrypted account connections remain usable across either version; pending sign-ins must be restarted. Remove the temporary backend image pin when a subsequent chart release includes the hosted OAuth change.

Validation: 183 focused gateway tests passed, and all 142 app tests passed locally and in GitHub Actions. Gateway lint, type and test-quality gates passed. Local `make check` reported an unrelated generated OpenAPI docstring whitespace difference under Python 3.13; that generated-only change was discarded. Live browser verification is recorded separately after rollout.

#!/usr/bin/env bash
# Refuses anything that would weaken the trust chain before a byte is built.
set -euo pipefail

fail() { echo "::error title=npm trusted publish::$1"; exit 1; }

if [[ "${NODE_AUTH_TOKEN_SET:-false}" == "true" ]]; then
  fail "NODE_AUTH_TOKEN is set. This action publishes only through OIDC trusted publishing; remove the token."
fi
if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]]; then
  fail "No OIDC token available. Grant the job 'permissions: id-token: write'."
fi
if [[ "$(git rev-parse --is-shallow-repository)" == "true" ]]; then
  fail "Shallow clone. Versioning reads commit history; use actions/checkout with fetch-depth: 0."
fi
if [[ "${DRY_RUN:-false}" != "true" && "${GITHUB_EVENT_NAME:-}" != "push" ]]; then
  fail "Publishing runs only on push (got '${GITHUB_EVENT_NAME:-}'). Use dry-run: true elsewhere."
fi
echo "preflight: OIDC available, no static token, full history, event ${GITHUB_EVENT_NAME:-?}"

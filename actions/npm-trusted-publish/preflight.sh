#!/usr/bin/env bash
# Refuses anything that would weaken the trust chain before a byte is downloaded.
set -euo pipefail

fail() { echo "::error title=npm trusted publish::$1"; exit 1; }

if [[ "${NODE_AUTH_TOKEN_SET:-false}" == "true" ]]; then
  fail "NODE_AUTH_TOKEN is set. This action publishes only through OIDC trusted publishing; remove the token."
fi
if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]]; then
  fail "No OIDC token available. Grant the job 'permissions: id-token: write'."
fi
[[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]] \
  || fail "Deploy runs only from workflow_dispatch (got '${GITHUB_EVENT_NAME:-}')."
[[ "${TAG:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag must be v<major>.<minor>.<patch>, got '${TAG:-}'"
# npm provenance names this run's commit. Running at the tag makes that the released commit,
# and the workflow and action code are the ones that were released with it.
if [[ "${GITHUB_REF:-}" != "refs/tags/$TAG" ]]; then
  fail "Run at the release tag: gh workflow run <file> --ref $TAG -f tag=$TAG (got ref '${GITHUB_REF:-}')."
fi
echo "preflight: OIDC available, no static token, running at $GITHUB_REF ($GITHUB_SHA)"

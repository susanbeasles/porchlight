#!/usr/bin/env bash
# Refuses to sign when the identity is missing or signing would disclose a private repo.
set -euo pipefail

fail() { echo "::error title=cosign attest::$1"; exit 1; }

if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]]; then
  fail "No OIDC token available. Grant the job 'permissions: id-token: write'."
fi
if [[ "${PRIVATE_REPO:-}" == "true" && "${ALLOW_PRIVATE:-false}" != "true" ]]; then
  fail "Private repository. Rekor is public: the repo and workflow names would be published. Set allow-private-repo: true to accept that."
fi
if ! command -v jq >/dev/null; then
  fail "jq is required to build the provenance predicate."
fi
echo "preflight: OIDC available, repository ${GITHUB_REPOSITORY:-?}"

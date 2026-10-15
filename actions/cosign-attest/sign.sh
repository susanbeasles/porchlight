#!/usr/bin/env bash
# Keyless sign + SLSA v1 provenance per subject, then verify both bundles before returning.
# The bundles are plain files; nothing is sent to the GitHub attestations API.
set -euo pipefail
shopt -s nullglob globstar

fail() { echo "::error title=cosign attest::$1"; exit 1; }

issuer="https://token.actions.githubusercontent.com"
identity="${IDENTITY:-}"
[[ -n "$identity" ]] || identity="https://github.com/${GITHUB_WORKFLOW_REF:?}"

# Expand subjects. Each non-empty line is a glob that must match at least one regular file.
files=()
while IFS= read -r pattern; do
  pattern="${pattern#"${pattern%%[![:space:]]*}"}"
  pattern="${pattern%"${pattern##*[![:space:]]}"}"
  [[ -z "$pattern" ]] && continue
  # Unquoted so the line globs; IFS empty so it does not word-split on spaces.
  # shellcheck disable=SC2206
  saved_ifs="$IFS"; IFS=
  matches=( $pattern )
  IFS="$saved_ifs"
  ((${#matches[@]})) || fail "Subject '$pattern' matched no files."
  for f in "${matches[@]}"; do
    [[ -f "$f" ]] || fail "Subject '$f' is not a regular file."
    files+=("$f")
  done
done <<< "${SUBJECTS:-}"
((${#files[@]})) || fail "No subjects given."
subjects=("${files[@]}")

# Chained with &&: set -e is suspended inside a function called from an || list, so a
# failed first check must not be masked by a passing second one.
verify_pair() {
  cosign verify-blob --bundle "$1.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$1" &&
  cosign verify-blob-attestation --bundle "$1.intoto.sigstore.json" --type "$PREDICATE_TYPE" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$1"
}

if [[ "${VERIFY_ONLY:-false}" == "true" ]]; then
  [[ -z "${CHECKSUMS_FILE:-}" ]] || fail "checksums-file is for signing; list SHA256SUMS as a subject to verify it"
  for f in "${files[@]}"; do
    for b in "$f.sigstore.json" "$f.intoto.sigstore.json"; do [[ -f "$b" ]] || fail "missing bundle $b"; done
    verify_pair "$f" || fail "bundles for $f do not verify against $identity"
    echo "verified: $f"
  done
  echo "identity=$identity" >> "${GITHUB_OUTPUT:?}"
  exit 0
fi

# SHA256SUMS over the subjects by basename, so it checks in any download directory.
if [[ -n "${CHECKSUMS_FILE:-}" ]]; then
  dupes=$(for f in "${files[@]}"; do basename "$f"; done | sort | uniq -d)
  [[ -z "$dupes" ]] || fail "Subjects share basenames, so SHA256SUMS would be ambiguous: $dupes"
  : > "$CHECKSUMS_FILE"
  for f in "${files[@]}"; do
    printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$(basename "$f")" >> "$CHECKSUMS_FILE"
  done
  files+=("$CHECKSUMS_FILE")
fi

server="${GITHUB_SERVER_URL:-https://github.com}"
predicate="${RUNNER_TEMP:?}/cosign-attest-predicate.json"
jq -n \
  --arg server "$server" \
  --arg repo "${GITHUB_REPOSITORY:?}" \
  --arg ref "${GITHUB_REF:?}" \
  --arg sha "${GITHUB_SHA:?}" \
  --arg workflow_ref "${GITHUB_WORKFLOW_REF:?}" \
  --arg event "${GITHUB_EVENT_NAME:?}" \
  --arg repo_id "${GITHUB_REPOSITORY_ID:-}" \
  --arg owner_id "${GITHUB_REPOSITORY_OWNER_ID:-}" \
  --arg run_id "${GITHUB_RUN_ID:?}" \
  --arg attempt "${GITHUB_RUN_ATTEMPT:-1}" \
  --arg runner "${RUNNER_ENVIRONMENT:-unknown}" \
  '{
    buildDefinition: {
      buildType: "https://actions.github.io/buildtypes/workflow/v1",
      externalParameters: {
        workflow: {
          ref: $ref,
          repository: ($server + "/" + $repo),
          path: ($workflow_ref | sub("^[^/]+/[^/]+/"; "") | sub("@.*$"; ""))
        }
      },
      internalParameters: {
        github: {
          event_name: $event,
          repository_id: $repo_id,
          repository_owner_id: $owner_id,
          runner_environment: $runner
        }
      },
      resolvedDependencies: [
        { uri: ("git+" + $server + "/" + $repo + "@" + $ref), digest: { gitCommit: $sha } }
      ]
    },
    runDetails: {
      builder: { id: ($server + "/" + $workflow_ref) },
      metadata: { invocationId: ($server + "/" + $repo + "/actions/runs/" + $run_id + "/attempts/" + $attempt) }
    }
  }' > "$predicate"

bundles=()
summary="| File | sha256 | Signature bundle | Attestation bundle |\n|---|---|---|---|\n"
for f in "${files[@]}"; do
  sig="$f.sigstore.json"
  att="$f.intoto.sigstore.json"
  digest="$(sha256sum "$f" | cut -d' ' -f1)"
  echo "::group::$f ($digest)"
  cosign sign-blob --yes --bundle "$sig" "$f"
  cosign attest-blob --yes --predicate "$predicate" --type "$PREDICATE_TYPE" --bundle "$att" "$f"
  # Fail closed: a bundle that does not verify against this exact identity is never returned.
  verify_pair "$f"
  echo "::endgroup::"
  bundles+=("$sig" "$att")
  summary+="| \`$f\` | \`$digest\` | \`$sig\` | \`$att\` |\n"
done

delim="EOF_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
{
  echo "identity=$identity"
  echo "bundles<<$delim"
  printf '%s\n' "${bundles[@]}"
  echo "$delim"
  echo "files<<$delim"
  printf '%s\n' "${subjects[@]}"
  [[ -z "${CHECKSUMS_FILE:-}" ]] || echo "$CHECKSUMS_FILE"
  printf '%s\n' "${bundles[@]}"
  echo "$delim"
} >> "${GITHUB_OUTPUT:?}"

{
  echo "### cosign attest"
  echo
  echo "Identity: \`$identity\`  Issuer: \`$issuer\`"
  echo
  printf '%b' "$summary"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

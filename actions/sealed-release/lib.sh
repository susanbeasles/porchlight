# shellcheck shell=bash
# Shared helpers for draft.sh and publish.sh. Sourced, not executed.

fail() { echo "::error title=sealed release::$1"; exit 1; }

[[ "${TAG:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag must be v<major>.<minor>.<patch>, got '${TAG:-}'"
[[ "${TARGET:-}" =~ ^[0-9a-f]{40}$ ]] || fail "target must be a full commit SHA, got '${TARGET:-}'"
: "${GH_REPO:?}"

# Commit SHA the tag points at, empty when the tag does not exist. Any error but 404 fails.
tag_commit() {
  local out
  if out=$(gh api "repos/$GH_REPO/git/ref/tags/$TAG" --jq '.object.type + " " + .object.sha' 2>&1); then
    [[ "$out" == commit\ * ]] || fail "tag $TAG is not a lightweight tag on a commit: $out"
    echo "${out#commit }"
  elif [[ "$out" == *"HTTP 404"* ]]; then
    echo ""
  else
    fail "could not look up tag $TAG: $out"
  fi
}

# Every release (drafts included) carrying this tag name, as a JSON array.
releases_for_tag() {
  gh api --paginate "repos/$GH_REPO/releases?per_page=100" \
    | jq -s --arg t "$TAG" '[.[][] | select(.tag_name == $t) | {id, draft, target_commitish}]'
}

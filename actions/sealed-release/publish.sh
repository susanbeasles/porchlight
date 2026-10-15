#!/usr/bin/env bash
# Uploads the artifacts to the draft, proves the release holds exactly those bytes, then
# publishes it. Publishing creates the tag at the target commit, and that is checked too.
set -euo pipefail
source "$GITHUB_ACTION_PATH/lib.sh"

[[ "${RELEASE_ID:-}" =~ ^[0-9]+$ ]] || fail "release-id must be the draft phase's output"
mapfile -t files < <(printf '%s\n' "${FILES:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d')
((${#files[@]})) || fail "no files to release"
for f in "${files[@]}"; do [[ -f "$f" ]] || fail "not a file: $f"; done
dupes=$(for f in "${files[@]}"; do basename "$f"; done | sort | uniq -d)
[[ -z "$dupes" ]] || fail "files share basenames: $dupes"

rel=$(gh api "repos/$GH_REPO/releases/$RELEASE_ID")
jq -e --arg t "$TAG" --arg c "$TARGET" '.draft == true and .tag_name == $t and .target_commitish == $c' <<< "$rel" >/dev/null \
  || fail "release $RELEASE_ID is not the draft for $TAG at $TARGET"

gh release upload "$TAG" "${files[@]}" --clobber

# The draft must hold exactly these files. Strays from an earlier failed run are removed;
# they were never public.
assets=$(gh api --paginate "repos/$GH_REPO/releases/$RELEASE_ID/assets?per_page=100" | jq -s 'add // []')
want=$(for f in "${files[@]}"; do basename "$f"; done | jq -R . | jq -s .)
for stray in $(jq -r --argjson w "$want" '.[] | select(.name as $n | $w | index($n) | not) | .id' <<< "$assets"); do
  gh api -X DELETE "repos/$GH_REPO/releases/assets/$stray" >/dev/null
  echo "publish: removed stray draft asset $stray"
done

# Download every asset back by id and compare bytes with what was built and signed.
check="$(mktemp -d)"
trap 'rm -rf "$check"' EXIT
for f in "${files[@]}"; do
  name=$(basename "$f")
  aid=$(jq -r --arg n "$name" '[.[] | select(.name == $n and .state == "uploaded")][0].id // empty' <<< "$assets")
  [[ -n "$aid" ]] || fail "asset $name is missing from the draft"
  gh api -H "Accept: application/octet-stream" "repos/$GH_REPO/releases/assets/$aid" > "$check/$name"
  have=$(sha256sum "$check/$name" | cut -d' ' -f1)
  local_sum=$(sha256sum "$f" | cut -d' ' -f1)
  [[ "$have" == "$local_sum" ]] || fail "asset $name on the draft does not match the local file ($have != $local_sum)"
  echo "publish: $name $have"
done

url=$(gh api -X PATCH "repos/$GH_REPO/releases/$RELEASE_ID" -F draft=false -f make_latest=true --jq .html_url)
at=$(tag_commit)
[[ "$at" == "$TARGET" ]] || fail "published, but tag $TAG points at '${at:-nothing}', not $TARGET"
echo "publish: $TAG is live at $url"
echo "url=$url" >> "$GITHUB_OUTPUT"
{
  echo "### Sealed release $TAG"
  echo
  echo "$url, tag at \`$TARGET\`"
  echo
  for f in "${files[@]}"; do echo "- \`$(basename "$f")\`"; done
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

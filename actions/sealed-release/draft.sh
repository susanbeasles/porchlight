#!/usr/bin/env bash
# Opens a draft for a tag that does not exist yet. Re-running a failed release reuses its own
# draft (same tag, same commit); anything else carrying the tag is refused.
set -euo pipefail
source "$GITHUB_ACTION_PATH/lib.sh"

# Assigned, not tested inline, so a failed lookup stops the script under set -e.
at=$(tag_commit)
[[ -z "$at" ]] || fail "tag $TAG already exists at $at; a released version is never rebuilt"

existing=$(releases_for_tag)
case "$(jq length <<< "$existing")" in
  0)
    id=$(gh api -X POST "repos/$GH_REPO/releases" \
      -f tag_name="$TAG" -f target_commitish="$TARGET" -f name="$TAG" \
      -F draft=true -F generate_release_notes=true --jq .id)
    echo "draft: created release $id for $TAG at $TARGET"
    ;;
  1)
    jq -e --arg c "$TARGET" '.[0].draft == true and .[0].target_commitish == $c' <<< "$existing" >/dev/null \
      || fail "a release for $TAG already exists and is not this run's draft: $(jq -c '.[0]' <<< "$existing")"
    id=$(jq -r '.[0].id' <<< "$existing")
    echo "draft: reusing draft $id for $TAG at $TARGET"
    ;;
  *)
    fail "several releases carry $TAG; delete the stale drafts by hand: $(jq -c . <<< "$existing")"
    ;;
esac
echo "release-id=$id" >> "$GITHUB_OUTPUT"

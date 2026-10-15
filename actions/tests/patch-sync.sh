#!/usr/bin/env bash
# docs/ci/install-workflows.patch must install exactly docs/ci/release.yml and deploy.yml.
# Applies it in a throwaway directory; never touches .github/ in the repository.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q
git -C "$tmp" apply "$root/docs/ci/install-workflows.patch"
for f in release deploy; do
  cmp -s "$root/docs/ci/$f.yml" "$tmp/.github/workflows/$f.yml" \
    || { echo "install-workflows.patch is stale for $f.yml; regenerate it (ADR-0008)" >&2; exit 1; }
done
[[ "$(cd "$tmp" && find . -path ./.git -prune -o -type f -print | sort)" == $'./.github/workflows/deploy.yml\n./.github/workflows/release.yml' ]] \
  || { echo "install-workflows.patch touches files beyond the two workflows" >&2; exit 1; }
echo "install-workflows.patch: in sync with docs/ci, installs exactly two files"

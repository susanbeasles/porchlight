# sealed release

Two-phase GitHub release. The release is never visible half-built, and the tag only ever
points at a complete release. See [ADR-0008](../../docs/adr/0008-supply-chain-actions.md).

- **`phase: draft`** fails if the tag already exists. It opens a draft for the tag at
  `target` (default `$GITHUB_SHA`). A re-run of the same commit reuses its own draft. Any
  other release carrying the tag is refused.
- **`phase: publish`**:
  1. Uploads `files` to the draft and removes stray assets left by an earlier failed run.
  2. Downloads every asset back by id and compares its sha256 with the local file.
  3. Publishes the release, which creates the tag.
  4. Checks that the tag points at `target`.

```yaml
- id: draft
  uses: ./actions/sealed-release
  with: { phase: draft, tag: v1.2.3 }
# ... produce and sign files ...
- uses: ./actions/sealed-release
  with:
    phase: publish
    tag: v1.2.3
    release-id: ${{ steps.draft.outputs.release-id }}
    files: ${{ steps.sign.outputs.files }}
```

Needs `contents: write`, plus `gh` and `jq` on the runner (both are on GitHub-hosted
runners). Turn on release immutability (Settings > General > Releases) so that a published
release's assets and tag can never change.
